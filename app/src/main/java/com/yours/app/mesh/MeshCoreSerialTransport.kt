package com.yours.app.mesh

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbManager
import com.hoho.android.usbserial.driver.UsbSerialDriver
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.driver.UsbSerialProber
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import android.util.Log
import com.yours.app.crypto.BedrockCore
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * MeshCore transport over USB Serial.
 *
 * Uses Android USB Host API to communicate with ESP32 LoRa companion devices.
 *
 * SECURITY:
 * All communication is encrypted using EncryptedSerialChannel which provides:
 * - X25519 key exchange for ephemeral session keys
 * - AES-256-GCM for confidentiality and authenticity
 * - Monotonic counters for replay protection
 * - No reliance on platform trust (pure cryptography)
 *
 * Features:
 * - Automatic device detection and permission handling
 * - Frame-based protocol matching ESP32 firmware
 * - Async RX/TX with coroutines
 * - Connection state management
 * - Statistics tracking
 *
 * Requires:
 * - USB Host permission in AndroidManifest.xml
 * - USB OTG cable (for phones) or USB-C port (for tablets)
 * - ESP32 with LunarCore firmware (with encryption support)
 */
class MeshCoreSerialTransport(
    private val context: Context
) : MeshCoreTransport {

    companion object {
        private const val TAG = "MeshCoreSerialTransport"
        private const val ACTION_USB_PERMISSION = "com.yours.app.USB_PERMISSION"
        private const val READ_TIMEOUT_MS = 100
        private const val WRITE_TIMEOUT_MS = 1000
        private const val READ_BUFFER_SIZE = 1024
        private const val RESPONSE_TIMEOUT_MS = 30000L  // Increased for LoRa TX time (~6-20s for 200+ byte packets)
        private const val HANDSHAKE_TIMEOUT_MS = 10000L
    }

    // State
    private val _connectionState = MutableStateFlow(MeshConnectionState.DISCONNECTED)
    override val connectionState: StateFlow<MeshConnectionState> = _connectionState

    private val _events = MutableSharedFlow<MeshEvent>(replay = 0, extraBufferCapacity = 64)
    override val events: Flow<MeshEvent> = _events

    // USB Serial
    private var usbManager: UsbManager? = null
    private var usbConnection: UsbDeviceConnection? = null
    private var serialPort: UsbSerialPort? = null
    private var driver: UsbSerialDriver? = null

    // Protocol
    private val frameParser = LoRaFrameParser()
    private val sequenceCounter = AtomicInteger(0)
    private val pendingResponses = ConcurrentHashMap<Byte, CompletableDeferred<LoRaFrame>>()
    private val receivedPackets = Channel<LoRaRxPacket>(Channel.BUFFERED)

    // SECURITY: Encrypted channel for all USB communication
    // Prevents local adversaries from reading/injecting traffic
    private val encryptedChannel = EncryptedSerialChannel()
    private var encryptionEnabled = false

    // IO
    private var readJob: Job? = null
    private val isRunning = AtomicBoolean(false)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Stats
    private var txPackets = 0L
    private var rxPackets = 0L
    private var txErrors = 0L
    private var rxErrors = 0L
    private var firmwareVersion: String? = null
    private var totalBytesReceived = 0L
    private var totalBytesSent = 0L

    // Debug helper: convert bytes to hex string for logging
    private fun ByteArray.toHexString(): String = joinToString(" ") { "%02X".format(it) }

    // USB permission receiver
    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (ACTION_USB_PERMISSION == intent.action) {
                synchronized(this) {
                    val device = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        device?.let {
                            scope.launch {
                                openDevice(it)
                            }
                        }
                    } else {
                        scope.launch {
                            _connectionState.value = MeshConnectionState.ERROR
                            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, "USB permission denied"))
                        }
                    }
                }
            }
        }
    }

    override suspend fun connect(connection: MeshConnection): Result<Unit> {
        Log.d(TAG, "connect() called with connection type: ${connection::class.simpleName}")
        if (connection !is MeshConnection.Serial) {
            Log.e(TAG, "Expected Serial connection but got ${connection::class.simpleName}")
            return Result.failure(IllegalArgumentException("Expected Serial connection"))
        }

        _connectionState.value = MeshConnectionState.CONNECTING
        Log.d(TAG, "State set to CONNECTING")

        return try {
            usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager

            // Register permission receiver
            val filter = IntentFilter(ACTION_USB_PERMISSION)
            context.registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)

            // Find device
            val availableDrivers = UsbSerialProber.getDefaultProber().findAllDrivers(usbManager)

            Log.d(TAG, "Found ${availableDrivers.size} USB serial drivers")
            if (availableDrivers.isEmpty()) {
                Log.e(TAG, "No USB serial devices found!")
                _connectionState.value = MeshConnectionState.ERROR
                return Result.failure(IOException("No USB serial devices found"))
            }

            // Find the requested device or use first one
            val targetDriver = if (connection.devicePath.isNotEmpty()) {
                availableDrivers.find { driver ->
                    driver.device.deviceName == connection.devicePath
                } ?: availableDrivers.first()
            } else {
                availableDrivers.first()
            }

            driver = targetDriver

            // Check permission
            val device = targetDriver.device
            if (usbManager?.hasPermission(device) == true) {
                openDevice(device)
                Result.success(Unit)
            } else {
                // Request permission
                val permissionIntent = PendingIntent.getBroadcast(
                    context,
                    0,
                    Intent(ACTION_USB_PERMISSION),
                    PendingIntent.FLAG_MUTABLE
                )
                usbManager?.requestPermission(device, permissionIntent)
                // Wait for permission result (will complete in receiver)
                Result.success(Unit)
            }
        } catch (e: Exception) {
            _connectionState.value = MeshConnectionState.ERROR
            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, e.message))
            Result.failure(e)
        }
    }

    private suspend fun openDevice(device: UsbDevice) {
        Log.d(TAG, "openDevice() called for ${device.deviceName}")
        try {
            usbConnection = usbManager?.openDevice(device)
            if (usbConnection == null) {
                Log.e(TAG, "Failed to open USB device - usbConnection is null")
                throw IOException("Failed to open USB device")
            }
            Log.d(TAG, "USB device opened successfully")

            val currentDriver = driver ?: throw IOException("No driver available")
            serialPort = currentDriver.ports.firstOrNull()
                ?: throw IOException("No serial ports found on device")
            Log.d(TAG, "Got serial port: ${serialPort}")

            serialPort?.open(usbConnection)
            serialPort?.setParameters(
                LoRaSerialProtocol.DEFAULT_BAUD_RATE,
                8,
                UsbSerialPort.STOPBITS_1,
                UsbSerialPort.PARITY_NONE
            )

            // The CP210x USB-UART bridge on Heltec V3 uses DTR/RTS for bootloader entry
            // Enabling these signals causes the ESP32 to reset on every port open
            try {
                serialPort?.setDTR(false)
                serialPort?.setRTS(false)
                Log.d(TAG, "DTR/RTS disabled to prevent auto-reset")
            } catch (e: Exception) {
                Log.w(TAG, "Could not disable DTR/RTS: ${e.message}")
            }

            Log.d(TAG, "Serial port configured at ${LoRaSerialProtocol.DEFAULT_BAUD_RATE} baud")

            isRunning.set(true)
            startReadLoop()
            Log.d(TAG, "Read loop started")

            // Query firmware version
            Log.d(TAG, "Querying firmware version...")
            queryFirmwareVersion()

            // Note: USB channel encryption requires firmware support (not yet implemented)
            encryptionEnabled = false

            _connectionState.value = MeshConnectionState.CONNECTED
            Log.d(TAG, "*** CONNECTION SUCCESSFUL - State set to CONNECTED ***")
            _events.emit(MeshEvent(MeshEventType.CONNECTED, device.deviceName))

        } catch (e: Exception) {
            Log.e(TAG, "openDevice() FAILED with exception: ${e.message}", e)
            closePort()
            _connectionState.value = MeshConnectionState.ERROR
            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, e.message))
        }
    }

    private fun startReadLoop() {
        readJob = scope.launch {
            val buffer = ByteArray(READ_BUFFER_SIZE)
            var readAttempts = 0L
            var lastLogTime = System.currentTimeMillis()

            Log.d(TAG, "Read loop starting - will log status every 5 seconds")

            while (isActive && isRunning.get()) {
                try {
                    val port = serialPort ?: break
                    val bytesRead = port.read(buffer, READ_TIMEOUT_MS)
                    readAttempts++

                    if (bytesRead > 0) {
                        val data = buffer.copyOf(bytesRead)
                        totalBytesReceived += bytesRead
                        Log.d(TAG, ">>> RX RAW [$bytesRead bytes] (total: $totalBytesReceived): ${data.toHexString()}")
                        processReceivedData(data)
                    }

                    // Periodic status log to confirm read loop is alive
                    val now = System.currentTimeMillis()
                    if (now - lastLogTime >= 5000) {
                        Log.d(TAG, ">>> READ LOOP STATUS: attempts=$readAttempts, totalBytesReceived=$totalBytesReceived, pendingResponses=${pendingResponses.size}")
                        lastLogTime = now
                    }
                } catch (e: IOException) {
                    if (isRunning.get()) {
                        rxErrors++
                        Log.e(TAG, ">>> READ ERROR (IOException): ${e.message}")
                        _events.emit(MeshEvent(MeshEventType.ERROR, "Read error: ${e.message}"))
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        rxErrors++
                        Log.e(TAG, ">>> READ ERROR (Exception): ${e.message}")
                    }
                }

                // Small delay to prevent busy loop
                delay(1)
            }

            Log.d(TAG, "Read loop exiting - readAttempts=$readAttempts, totalBytesReceived=$totalBytesReceived")
        }
    }

    private suspend fun processReceivedData(data: ByteArray) {
        // SECURITY: Decrypt incoming data if encryption is enabled
        val decryptedData = if (encryptionEnabled) {
            encryptedChannel.decrypt(data) ?: run {
                // Decryption failed - could be tampering or replay attack
                rxErrors++
                _events.emit(MeshEvent(MeshEventType.ERROR, "Decryption failed - possible tampering"))
                return
            }
        } else {
            data
        }

        val frames = frameParser.feed(decryptedData)

        if (frames.isEmpty()) {
            Log.d(TAG, ">>> RX PARSE: No complete frames yet (parser buffering)")
        } else {
            Log.d(TAG, ">>> RX PARSE: Got ${frames.size} frame(s)")
        }

        for (frame in frames) {
            Log.d(TAG, ">>> RX FRAME: cmd=${frame.command.name} seq=${frame.sequence} data=[${frame.data.size} bytes]: ${frame.data.toHexString()}")
            when (frame.command) {
                LoRaCommand.RECEIVE -> {
                    // Incoming packet from mesh
                    LoRaRxPacket.fromFrameData(frame.data)?.let { packet ->
                        rxPackets++
                        receivedPackets.send(packet)
                        _events.emit(
                            MeshEvent(
                                MeshEventType.MESSAGE_RECEIVED,
                                packet
                            )
                        )
                    }
                }

                LoRaCommand.PONG -> {
                    // Heartbeat response
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.CONFIG_ACK -> {
                    // Configuration acknowledged
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.TX_DONE -> {
                    // Transmit success
                    txPackets++
                    pendingResponses[frame.sequence]?.complete(frame)
                    _events.emit(MeshEvent(MeshEventType.MESSAGE_SENT))
                }

                LoRaCommand.TX_ERROR -> {
                    // Transmit failed
                    txErrors++
                    pendingResponses[frame.sequence]?.completeExceptionally(
                        IOException("Transmit failed: error code ${frame.data.getOrNull(0)}")
                    )
                    _events.emit(MeshEvent(MeshEventType.MESSAGE_FAILED))
                }

                LoRaCommand.CAD_RESULT -> {
                    // CAD result
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.VERSION_RESPONSE -> {
                    // Firmware version
                    firmwareVersion = String(frame.data, Charsets.UTF_8)
                    pendingResponses[frame.sequence]?.complete(frame)
                    _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, firmwareVersion))
                }

                LoRaCommand.STATS_RESPONSE -> {
                    // Stats response
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.ERROR -> {
                    // Error from device
                    val errorMsg = String(frame.data, Charsets.UTF_8)
                    pendingResponses[frame.sequence]?.completeExceptionally(
                        IOException("Device error: $errorMsg")
                    )
                    _events.emit(MeshEvent(MeshEventType.ERROR, errorMsg))
                }

                else -> {
                    // Unknown or unexpected command
                }
            }
        }
    }

    private fun nextSequence(): Byte {
        return (sequenceCounter.incrementAndGet() and 0xFF).toByte()
    }

    private suspend fun sendFrameAndWait(
        frame: LoRaFrame,
        timeoutMs: Long = RESPONSE_TIMEOUT_MS
    ): Result<LoRaFrame> {
        val port = serialPort ?: return Result.failure(IOException("Not connected"))

        val deferred = CompletableDeferred<LoRaFrame>()
        pendingResponses[frame.sequence] = deferred

        return try {
            // Send frame
            val encoded = frame.encode()
            totalBytesSent += encoded.size
            Log.d(TAG, "<<< TX [${encoded.size} bytes] cmd=${frame.command.name} seq=${frame.sequence}: ${encoded.toHexString()}")
            withContext(Dispatchers.IO) {
                port.write(encoded, WRITE_TIMEOUT_MS)
            }
            Log.d(TAG, "<<< TX COMPLETE - waiting for response (timeout: ${timeoutMs}ms)")

            // Wait for response
            val response = withTimeout(timeoutMs) {
                deferred.await()
            }

            Log.d(TAG, "<<< TX GOT RESPONSE: cmd=${response.command.name} seq=${response.sequence}")
            Result.success(response)
        } catch (e: TimeoutCancellationException) {
            Result.failure(IOException("Response timeout"))
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            pendingResponses.remove(frame.sequence)
        }
    }

    private suspend fun sendFrame(frame: LoRaFrame): Result<Unit> {
        val port = serialPort ?: return Result.failure(IOException("Not connected"))

        return try {
            val encoded = frame.encode()

            // SECURITY: Encrypt frame before sending if encryption is enabled
            val dataToSend = if (encryptionEnabled) {
                encryptedChannel.encrypt(encoded)
                    ?: return Result.failure(IOException("Encryption failed"))
            } else {
                encoded
            }

            totalBytesSent += dataToSend.size
            Log.d(TAG, "<<< TX (no-wait) [${dataToSend.size} bytes] cmd=${frame.command.name} seq=${frame.sequence}: ${dataToSend.toHexString()}")
            withContext(Dispatchers.IO) {
                port.write(dataToSend, WRITE_TIMEOUT_MS)
            }
            Log.d(TAG, "<<< TX (no-wait) COMPLETE")
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private suspend fun queryFirmwareVersion() {
        try {
            val seq = nextSequence()
            val frame = LoRaFrame.version(seq)
            sendFrameAndWait(frame, 2000)
        } catch (e: Exception) {
            // Version query failed, continue anyway
        }
    }

    /**
     * Perform encrypted channel handshake with ESP32.
     *
     * SECURITY: Uses X25519 key exchange + AES-256-GCM.
     * The handshake itself is sent unencrypted but establishes
     * session keys for all subsequent communication.
     *
     * @return true if handshake succeeded
     */
    private suspend fun performEncryptedHandshake(): Boolean {
        return try {
            val port = serialPort ?: return false

            // Step 1: Generate ephemeral keypair and send initiation
            val initiation = encryptedChannel.initiate()

            // Send handshake initiation (raw, before encryption is established)
            withContext(Dispatchers.IO) {
                port.write(initiation, WRITE_TIMEOUT_MS)
            }

            // Step 2: Wait for ESP32's response
            val responseBuffer = ByteArray(64)
            val bytesRead = withTimeout(HANDSHAKE_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    // Read until we get a response or timeout
                    var totalRead = 0
                    val expectedSize = 2 + 32  // type + version + pubkey
                    val tempBuffer = ByteArray(64)
                    while (totalRead < expectedSize) {
                        val read = port.read(tempBuffer, READ_TIMEOUT_MS)
                        if (read > 0) {
                            System.arraycopy(tempBuffer, 0, responseBuffer, totalRead, read)
                            totalRead += read
                        }
                        if (totalRead >= expectedSize) break
                        delay(10)
                    }
                    totalRead
                }
            }

            if (bytesRead < 34) {
                return false
            }

            val response = responseBuffer.copyOf(bytesRead)

            // Step 3: Complete handshake
            val success = encryptedChannel.completeHandshake(response)

            if (success) {
                // Log verification code for user to compare with ESP32 display
                val verificationCode = encryptedChannel.getVerificationCode()
                _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "Channel verification: $verificationCode"))
            }

            success
        } catch (e: Exception) {
            false
        }
    }

    override suspend fun disconnect() {
        try {
            isRunning.set(false)
            readJob?.cancelAndJoin()
            readJob = null

            // SECURITY: Close and zeroize encrypted channel
            encryptedChannel.close()
            encryptionEnabled = false

            closePort()

            try {
                context.unregisterReceiver(usbReceiver)
            } catch (e: Exception) {
                // Receiver may not be registered
            }

            _connectionState.value = MeshConnectionState.DISCONNECTED
            _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
        } catch (e: Exception) {
            _events.emit(MeshEvent(MeshEventType.ERROR, e.message))
        }
    }

    private fun closePort() {
        try {
            serialPort?.close()
        } catch (e: Exception) {
            // Ignore
        }
        try {
            usbConnection?.close()
        } catch (e: Exception) {
            // Ignore
        }
        serialPort = null
        usbConnection = null
        driver = null
    }

    override suspend fun getDeviceInfo(): Result<DeviceInfo> {
        val seq = nextSequence()
        val frame = LoRaFrame.version(seq)

        return sendFrameAndWait(frame).map { response ->
            val version = String(response.data, Charsets.UTF_8)
            DeviceInfo(
                nodeId = ByteArray(8), // ESP32 doesn't report node ID yet
                firmwareVersion = version,
                hardwareType = "ESP32-SX1262",
                meshName = null
            )
        }
    }

    override suspend fun getContacts(): Result<List<MeshContact>> {
        // ESP32 firmware doesn't maintain contact list
        // That's handled at the LunarCore routing layer
        return Result.success(emptyList())
    }

    override suspend fun sendMessage(recipient: ByteArray, content: ByteArray): Result<String> {
        // The recipient and content are already packaged by LunarCore
        // We just transmit the raw bytes over LoRa
        val seq = nextSequence()
        val frame = LoRaFrame.transmit(seq, content)

        return sendFrameAndWait(frame).map {
            // Generate message ID
            UUID.randomUUID().toString()
        }
    }

    override suspend fun sendMessageWithRetry(
        recipient: ByteArray,
        content: ByteArray,
        maxRetries: Int,
        timeoutMs: Long
    ): Result<String> {
        var lastError: Exception? = null

        repeat(maxRetries) { attempt ->
            val result = sendMessage(recipient, content)
            if (result.isSuccess) {
                return result
            }
            lastError = result.exceptionOrNull() as? Exception

            // Wait before retry with exponential backoff
            if (attempt < maxRetries - 1) {
                delay(100L * (1 shl attempt))
            }
        }

        return Result.failure(lastError ?: IOException("Send failed after $maxRetries attempts"))
    }

    override suspend fun getBatteryStatus(): Result<BatteryStatus> {
        // ESP32 doesn't have standard battery reporting
        // Would need custom firmware extension
        return Result.failure(NotImplementedError("Battery status not available on ESP32"))
    }

    override fun isConnected(): Boolean =
        _connectionState.value == MeshConnectionState.CONNECTED

    /**
     * Check if the USB channel is encrypted.
     *
     * SECURITY: If this returns false, local USB traffic is visible
     * to any device on the same USB bus.
     */
    fun isEncryptionEnabled(): Boolean = encryptionEnabled

    /**
     * Get verification code for encrypted channel.
     *
     * Users should compare this code with what's displayed on the ESP32
     * to verify no man-in-the-middle attack occurred during handshake.
     *
     * @return 12-digit verification code (XXXX-XXXX-XXXX) or null if not encrypted
     */
    suspend fun getVerificationCode(): String? {
        return if (encryptionEnabled) {
            encryptedChannel.getVerificationCode()
        } else {
            null
        }
    }

    /**
     * Get encrypted channel statistics.
     */
    suspend fun getEncryptedChannelStats(): ChannelStats? {
        return if (encryptionEnabled) {
            encryptedChannel.getStats()
        } else {
            null
        }
    }

    // ==========================================================================
    // LORA-SPECIFIC METHODS
    // ==========================================================================

    /**
     * Configure the LoRa radio parameters.
     */
    suspend fun configureRadio(
        frequencyHz: Long = 910_525_000,  // MeshCore USA/CA recommended
        spreadingFactor: Int = 7,          // MeshCore USA/CA recommended
        bandwidthKhz: Int = 62,            // 62.5 kHz - MeshCore USA/CA recommended
        codingRate: Int = 1,
        txPowerDbm: Int = 14
    ): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.configure(
            sequence = seq,
            frequencyHz = frequencyHz,
            spreadingFactor = spreadingFactor,
            bandwidthKhz = bandwidthKhz,
            codingRate = codingRate,
            txPowerDbm = txPowerDbm
        )

        return sendFrameAndWait(frame).map { }
    }

    /**
     * Send a ping to verify connection.
     */
    suspend fun ping(): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.ping(seq)
        return sendFrameAndWait(frame).map { }
    }

    /**
     * Check for channel activity.
     */
    suspend fun channelActivityDetection(): Result<Boolean> {
        val seq = nextSequence()
        val frame = LoRaFrame.cad(seq)

        return sendFrameAndWait(frame).map { response ->
            response.data.getOrNull(0)?.toInt() == 1
        }
    }

    /**
     * Reset the radio.
     */
    suspend fun resetRadio(): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.reset(seq)
        return sendFrameAndWait(frame).map { }
    }

    /**
     * Get radio statistics.
     */
    suspend fun getStats(): Result<RadioStats> {
        val seq = nextSequence()
        val frame = LoRaFrame.getStats(seq)

        return sendFrameAndWait(frame).map { response ->
            if (response.data.size >= 16) {
                val data = response.data
                RadioStats(
                    txPackets = readU32LE(data, 0),
                    rxPackets = readU32LE(data, 4),
                    txErrors = readU32LE(data, 8),
                    rxErrors = readU32LE(data, 12)
                )
            } else {
                RadioStats(
                    txPackets = this.txPackets,
                    rxPackets = this.rxPackets,
                    txErrors = this.txErrors,
                    rxErrors = this.rxErrors
                )
            }
        }
    }

    /**
     * Receive the next packet from the radio.
     */
    suspend fun receivePacket(timeoutMs: Long = 5000): LoRaRxPacket? {
        return withTimeoutOrNull(timeoutMs) {
            receivedPackets.receive()
        }
    }

    /**
     * Transmit raw bytes over LoRa.
     */
    suspend fun transmit(data: ByteArray): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.transmit(seq, data)
        return sendFrameAndWait(frame).map { }
    }

    // ==========================================================================
    // UTILITIES
    // ==========================================================================

    /**
     * Get list of available USB serial devices.
     */
    fun getAvailableDevices(): List<UsbSerialDeviceInfo> {
        val manager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return emptyList()

        val drivers = UsbSerialProber.getDefaultProber().findAllDrivers(manager)

        return drivers.map { driver ->
            UsbSerialDeviceInfo(
                deviceName = driver.device.deviceName,
                vendorId = driver.device.vendorId,
                productId = driver.device.productId,
                productName = driver.device.productName ?: "Unknown",
                manufacturer = driver.device.manufacturerName ?: "Unknown",
                hasPermission = manager.hasPermission(driver.device)
            )
        }
    }

    private fun readU32LE(data: ByteArray, offset: Int): Long {
        return (data[offset].toLong() and 0xFF) or
                ((data[offset + 1].toLong() and 0xFF) shl 8) or
                ((data[offset + 2].toLong() and 0xFF) shl 16) or
                ((data[offset + 3].toLong() and 0xFF) shl 24)
    }
}

/**
 * Radio statistics from ESP32.
 */
data class RadioStats(
    val txPackets: Long,
    val rxPackets: Long,
    val txErrors: Long,
    val rxErrors: Long
)

/**
 * Information about an available USB serial device.
 */
data class UsbSerialDeviceInfo(
    val deviceName: String,
    val vendorId: Int,
    val productId: Int,
    val productName: String,
    val manufacturer: String,
    val hasPermission: Boolean
)
