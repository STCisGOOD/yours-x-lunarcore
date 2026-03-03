package com.yours.app.mesh

import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.util.Log
import com.hoho.android.usbserial.driver.UsbSerialDriver
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.driver.UsbSerialProber
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/**
 * Reticulum Adapter - Implements UniversalMeshTransport for Reticulum/RNode protocol.
 *
 * Reticulum is a cryptography-based networking stack for building reliable
 * networks over any medium. This adapter uses KISS framing over USB Serial
 * to communicate with RNode hardware running LunarCore firmware.
 *
 * ## Protocol Details
 * - Transport: KISS TNC over USB Serial (115200 baud)
 * - Framing: KISS with RNode extensions
 * - Identity: Ed25519 public keys, hashed to 16-byte destination addresses
 * - Encryption: Fernet tokens (AES-128-CBC + HMAC-SHA256)
 *
 * ## Reticulum Destination Hashes
 * Reticulum uses 16-byte "destination hashes" derived from:
 * SHA-256(appName || publicKey)[0:16]
 *
 * Reference: https://reticulum.network/
 */
class ReticulumAdapter(
    private val context: Context
) : UniversalMeshTransport {

    companion object {
        private const val TAG = "ReticulumAdapter"

        // Default serial baud rate for RNode
        const val DEFAULT_BAUD_RATE = 115200

        // RNode detection response
        val RNODE_DETECT_MAGIC = byteArrayOf(0x08) // Detection response

        // Reticulum app name for destination hashing
        const val RETICULUM_APP_NAME = "yours.messaging"

        // Timeouts
        const val CONNECT_TIMEOUT_MS = 10_000L
        const val COMMAND_TIMEOUT_MS = 5_000L
    }

    override val meshType: MeshType = MeshType.RETICULUM

    // Connection state
    private val _connectionState = MutableStateFlow<UniversalConnectionState>(
        UniversalConnectionState.Disconnected
    )
    override val connectionState: StateFlow<UniversalConnectionState> = _connectionState

    // Incoming messages
    private val _incomingMessages = MutableSharedFlow<UniversalMessage>(
        replay = 0,
        extraBufferCapacity = 64
    )
    override val incomingMessages: Flow<UniversalMessage> = _incomingMessages

    // Mesh events
    private val _meshEvents = MutableSharedFlow<UniversalMeshEvent>(
        replay = 0,
        extraBufferCapacity = 64
    )
    override val meshEvents: Flow<UniversalMeshEvent> = _meshEvents

    // USB Serial components
    private var usbSerialPort: UsbSerialPort? = null
    private var kissTransport: KissTransport? = null

    // Device info
    private var deviceInfo: RNodeDeviceInfo? = null
    private var localAddress: UniversalAddress? = null

    // RNode radio configuration
    private var radioConfig = RNodeRadioConfig()

    // Stats
    private var rxCount: Long = 0
    private var txCount: Long = 0
    private var lastRssi: Int = 0
    private var lastSnr: Float = 0f

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // =========================================================================
    // UniversalMeshTransport Implementation
    // =========================================================================

    override suspend fun connect(config: MeshConnectionConfig): Result<Unit> {
        return when (config) {
            is MeshConnectionConfig.UsbSerial -> connectSerial(config.devicePath, config.baudRate)
            else -> Result.failure(UnsupportedOperationException(
                "Reticulum adapter only supports USB Serial connections for RNode"
            ))
        }
    }

    override suspend fun disconnect() {
        _connectionState.value = UniversalConnectionState.Disconnected

        kissTransport?.close()
        kissTransport = null

        try {
            usbSerialPort?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing serial port", e)
        }
        usbSerialPort = null

        deviceInfo = null
        localAddress = null
    }

    override suspend fun sendMessage(message: UniversalMessage): Result<String> {
        val kiss = kissTransport
            ?: return Result.failure(IllegalStateException("Not connected to RNode"))

        // Build Reticulum packet
        // Format: [destination_hash (16)] [source_hash (16)] [flags (1)] [payload]
        val destHash = message.recipient.reticulumHash
            ?: deriveReticulumHash(message.recipient.publicKey)

        val sourceHash = localAddress?.reticulumHash
            ?: return Result.failure(IllegalStateException("Local address not set"))

        val packet = buildReticulumPacket(destHash, sourceHash, message.payload)

        return try {
            kiss.sendData(packet)
            txCount++

            scope.launch {
                _meshEvents.emit(UniversalMeshEvent.MessageDelivered(message.id))
            }

            Result.success(message.id)
        } catch (e: Exception) {
            scope.launch {
                _meshEvents.emit(UniversalMeshEvent.MessageFailed(message.id, e.message ?: "Send failed"))
            }
            Result.failure(e)
        }
    }

    override suspend fun getDeviceInfo(): Result<MeshDeviceInfo> {
        val info = deviceInfo
        return Result.success(MeshDeviceInfo(
            meshType = MeshType.RETICULUM,
            deviceName = "RNode (LunarCore)",
            firmwareVersion = info?.firmwareVersion ?: "Unknown",
            hardwareModel = "ESP32-S3 + SX1262",
            localAddress = localAddress
        ))
    }

    override suspend fun discoverPeers(timeout: Long): Result<List<UniversalAddress>> {
        // Reticulum uses announce packets for discovery
        // For now, return empty - would need to implement announce tracking
        return Result.success(emptyList())
    }

    override suspend fun pingPeer(address: UniversalAddress): Result<Long> {
        // Reticulum doesn't have built-in ping, but we could implement a custom ping
        return Result.failure(UnsupportedOperationException(
            "Direct ping not yet implemented for Reticulum"
        ))
    }

    // =========================================================================
    // Serial Connection
    // =========================================================================

    private suspend fun connectSerial(devicePath: String, baudRate: Int): Result<Unit> {
        _connectionState.value = UniversalConnectionState.Connecting

        return try {
            val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
            val availableDrivers = UsbSerialProber.getDefaultProber().findAllDrivers(usbManager)

            if (availableDrivers.isEmpty()) {
                _connectionState.value = UniversalConnectionState.Error("No USB serial devices found")
                return Result.failure(IllegalStateException("No USB serial devices found"))
            }

            // Find the matching device
            val driver = availableDrivers.find { driver ->
                driver.device.deviceName == devicePath
            } ?: availableDrivers.first()

            val connection = usbManager.openDevice(driver.device)
            if (connection == null) {
                _connectionState.value = UniversalConnectionState.Error("USB permission denied")
                return Result.failure(SecurityException("USB permission denied"))
            }

            val port = driver.ports.first()
            port.open(connection)
            port.setParameters(
                baudRate,
                UsbSerialPort.DATABITS_8,
                UsbSerialPort.STOPBITS_1,
                UsbSerialPort.PARITY_NONE
            )
            port.dtr = true
            port.rts = true

            usbSerialPort = port

            // Create KISS transport
            val inputStream = UsbSerialInputStream(port)
            val outputStream = UsbSerialOutputStream(port)
            val kiss = KissTransport(inputStream, outputStream)
            kissTransport = kiss

            // Start receiving frames
            kiss.startReading()
            startFrameProcessing(kiss)

            // Detect RNode
            val detected = withTimeoutOrNull(CONNECT_TIMEOUT_MS) {
                detectRNode(kiss)
            }

            if (detected != true) {
                disconnect()
                _connectionState.value = UniversalConnectionState.Error("RNode detection failed")
                return Result.failure(IllegalStateException("RNode detection failed"))
            }

            // Query device info
            queryDeviceInfo(kiss)

            // Configure radio with default settings
            configureRadio(kiss, radioConfig)

            // Enable radio
            kiss.setRadioState(true)

            // Generate local address from device identity
            generateLocalAddress()

            _connectionState.value = UniversalConnectionState.Connected

            scope.launch {
                _meshEvents.emit(UniversalMeshEvent.DeviceStatusChanged(
                    getDeviceInfo().getOrNull() ?: MeshDeviceInfo(
                        meshType = MeshType.RETICULUM,
                        deviceName = "RNode",
                        firmwareVersion = "Unknown"
                    )
                ))
            }

            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed", e)
            disconnect()
            _connectionState.value = UniversalConnectionState.Error(e.message ?: "Connection failed")
            Result.failure(e)
        }
    }

    /**
     * Detect RNode device by sending detect command and waiting for response.
     */
    private suspend fun detectRNode(kiss: KissTransport): Boolean = suspendCancellableCoroutine { cont ->
        var detectedResumed = false

        val job = scope.launch {
            kiss.frames.collect { frame ->
                if (frame is KissFrame.RNodeCommand &&
                    frame.command == KissTransport.RNODE_DETECT) {
                    if (!detectedResumed) {
                        detectedResumed = true
                        Log.i(TAG, "RNode detected!")
                        cont.resume(true, null)
                    }
                    return@collect
                }
            }
        }

        kiss.detectRNode()

        scope.launch {
            delay(COMMAND_TIMEOUT_MS)
            job.cancel()
            if (!detectedResumed) {
                cont.resume(false, null)
            }
        }

        cont.invokeOnCancellation {
            job.cancel()
        }
    }

    /**
     * Query device information from RNode.
     */
    private suspend fun queryDeviceInfo(kiss: KissTransport) {
        kiss.queryFirmwareVersion()
        kiss.queryProtocolVersion()
        kiss.queryPlatform()
        kiss.queryBoard()
        kiss.queryHardwareSerial()

        // Wait a bit for responses
        delay(500)
    }

    /**
     * Configure radio parameters.
     */
    private fun configureRadio(kiss: KissTransport, config: RNodeRadioConfig) {
        kiss.setFrequency(config.frequencyHz)
        kiss.setBandwidth(config.bandwidthHz)
        kiss.setSpreadingFactor(config.spreadingFactor)
        kiss.setCodingRate(config.codingRate)
        kiss.setTxPower(config.txPowerDbm)
    }

    /**
     * Start processing incoming KISS frames.
     */
    private fun startFrameProcessing(kiss: KissTransport) {
        scope.launch {
            kiss.frames.collect { frame ->
                processFrame(frame)
            }
        }
    }

    /**
     * Process a received KISS frame.
     */
    private suspend fun processFrame(frame: KissFrame) {
        when (frame) {
            is KissFrame.DataFrame -> {
                processDataFrame(frame)
            }
            is KissFrame.RNodeCommand -> {
                processRNodeResponse(frame)
            }
            else -> {
                Log.d(TAG, "Received KISS command: $frame")
            }
        }
    }

    /**
     * Process an incoming data frame (Reticulum packet).
     */
    private suspend fun processDataFrame(frame: KissFrame.DataFrame) {
        val data = frame.data
        if (data.size < 33) {
            Log.w(TAG, "Data frame too short: ${data.size}")
            return
        }

        rxCount++

        // Parse Reticulum packet
        // Format: [destination_hash (16)] [source_hash (16)] [flags (1)] [payload]
        val destHash = data.copyOfRange(0, 16)
        val sourceHash = data.copyOfRange(16, 32)
        val flags = data[32]
        val payload = if (data.size > 33) data.copyOfRange(33, data.size) else ByteArray(0)

        Log.d(TAG, "Received packet: dest=${destHash.toHex()}, src=${sourceHash.toHex()}, flags=$flags, payload=${payload.size} bytes")

        // Convert to UniversalMessage
        val message = UniversalMessage(
            id = UUID.randomUUID().toString(),
            sender = UniversalAddress(
                did = "did:reticulum:${sourceHash.toHex()}",
                publicKey = ByteArray(0), // We don't know the full public key from just the hash
                reticulumHash = sourceHash
            ),
            recipient = UniversalAddress(
                did = "did:reticulum:${destHash.toHex()}",
                publicKey = ByteArray(0),
                reticulumHash = destHash
            ),
            payload = payload,
            timestamp = System.currentTimeMillis(),
            meshType = MeshType.RETICULUM,
            metadata = MessageMetadata(
                rssi = lastRssi,
                snr = lastSnr
            )
        )

        _incomingMessages.emit(message)
    }

    /**
     * Process an RNode response/status message.
     */
    private fun processRNodeResponse(frame: KissFrame.RNodeCommand) {
        val cmd = frame.command
        val data = frame.data

        when (cmd) {
            KissTransport.RNODE_FW_VERSION -> {
                if (data.isNotEmpty()) {
                    val major = data[0].toInt() and 0xFF
                    val minor = if (data.size > 1) data[1].toInt() and 0xFF else 0
                    val patch = if (data.size > 2) data[2].toInt() and 0xFF else 0
                    val version = "$major.$minor.$patch"
                    deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(firmwareVersion = version)
                    Log.i(TAG, "Firmware version: $version")
                }
            }
            KissTransport.RNODE_PROTOCOL_VERSION -> {
                if (data.isNotEmpty()) {
                    val version = data[0].toInt() and 0xFF
                    deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(protocolVersion = version)
                    Log.i(TAG, "Protocol version: $version")
                }
            }
            KissTransport.RNODE_PLATFORM -> {
                if (data.isNotEmpty()) {
                    val platform = data[0].toInt() and 0xFF
                    deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(platform = platform)
                    Log.i(TAG, "Platform: $platform")
                }
            }
            KissTransport.RNODE_BOARD -> {
                if (data.isNotEmpty()) {
                    val board = data[0].toInt() and 0xFF
                    deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(board = board)
                    Log.i(TAG, "Board: $board")
                }
            }
            KissTransport.RNODE_MCU -> {
                if (data.isNotEmpty()) {
                    val mcu = data[0].toInt() and 0xFF
                    deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(mcu = mcu)
                    Log.i(TAG, "MCU: $mcu")
                }
            }
            KissTransport.RNODE_HW_SERIAL -> {
                deviceInfo = (deviceInfo ?: RNodeDeviceInfo()).copy(hardwareSerial = data)
                Log.i(TAG, "Hardware serial: ${data.toHex()}")
            }
            KissTransport.RNODE_STAT_RSSI -> {
                if (data.size >= 2) {
                    val rssi = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).short.toInt()
                    lastRssi = rssi
                    Log.d(TAG, "RSSI: $rssi dBm")
                }
            }
            KissTransport.RNODE_STAT_SNR -> {
                if (data.isNotEmpty()) {
                    val snr = data[0].toInt() / 4.0f
                    lastSnr = snr
                    Log.d(TAG, "SNR: $snr dB")
                }
            }
            KissTransport.RNODE_STAT_RX -> {
                if (data.size >= 4) {
                    val count = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).int.toLong()
                    Log.d(TAG, "RX count: $count")
                }
            }
            KissTransport.RNODE_STAT_TX -> {
                if (data.size >= 4) {
                    val count = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).int.toLong()
                    Log.d(TAG, "TX count: $count")
                }
            }
            KissTransport.RNODE_ERROR -> {
                Log.e(TAG, "RNode error: ${data.toHex()}")
            }
            KissTransport.RNODE_INFO -> {
                Log.i(TAG, "RNode info: ${String(data, Charsets.UTF_8)}")
            }
        }
    }

    /**
     * Generate local address from device identity.
     */
    private fun generateLocalAddress() {
        val hwSerial = deviceInfo?.hardwareSerial ?: ByteArray(8)

        // Generate a deterministic public key placeholder from hardware serial
        // In a real implementation, this would use the device's actual Ed25519 key
        val publicKeyPlaceholder = sha256(hwSerial)

        val reticulumHash = deriveReticulumHash(publicKeyPlaceholder)

        localAddress = UniversalAddress(
            did = "did:reticulum:${reticulumHash.toHex()}",
            publicKey = publicKeyPlaceholder,
            reticulumHash = reticulumHash
        )
    }

    // =========================================================================
    // Reticulum-Specific Methods
    // =========================================================================

    /**
     * Set radio frequency.
     */
    fun setFrequency(frequencyHz: Long) {
        radioConfig = radioConfig.copy(frequencyHz = frequencyHz)
        kissTransport?.setFrequency(frequencyHz)
    }

    /**
     * Set radio bandwidth.
     */
    fun setBandwidth(bandwidthHz: Long) {
        radioConfig = radioConfig.copy(bandwidthHz = bandwidthHz)
        kissTransport?.setBandwidth(bandwidthHz)
    }

    /**
     * Set spreading factor (7-12).
     */
    fun setSpreadingFactor(sf: Int) {
        radioConfig = radioConfig.copy(spreadingFactor = sf)
        kissTransport?.setSpreadingFactor(sf)
    }

    /**
     * Set coding rate (5-8).
     */
    fun setCodingRate(cr: Int) {
        radioConfig = radioConfig.copy(codingRate = cr)
        kissTransport?.setCodingRate(cr)
    }

    /**
     * Set TX power.
     */
    fun setTxPower(powerDbm: Int) {
        radioConfig = radioConfig.copy(txPowerDbm = powerDbm)
        kissTransport?.setTxPower(powerDbm)
    }

    /**
     * Get current radio configuration.
     */
    fun getRadioConfig(): RNodeRadioConfig = radioConfig

    /**
     * Get RX packet count.
     */
    fun getRxCount(): Long = rxCount

    /**
     * Get TX packet count.
     */
    fun getTxCount(): Long = txCount

    /**
     * Get last RSSI reading.
     */
    fun getLastRssi(): Int = lastRssi

    /**
     * Get last SNR reading.
     */
    fun getLastSnr(): Float = lastSnr

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Build a Reticulum packet.
     */
    private fun buildReticulumPacket(
        destHash: ByteArray,
        sourceHash: ByteArray,
        payload: ByteArray
    ): ByteArray {
        val packet = ByteArray(33 + payload.size)
        System.arraycopy(destHash, 0, packet, 0, 16)
        System.arraycopy(sourceHash, 0, packet, 16, 16)
        packet[32] = 0x00 // Flags
        System.arraycopy(payload, 0, packet, 33, payload.size)
        return packet
    }

    /**
     * Derive Reticulum destination hash from public key.
     */
    private fun deriveReticulumHash(publicKey: ByteArray): ByteArray {
        val appNameHash = sha256(RETICULUM_APP_NAME.toByteArray(Charsets.UTF_8))
        val combined = appNameHash + publicKey
        return sha256(combined).copyOf(16)
    }

    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

/**
 * USB Serial input stream wrapper.
 */
private class UsbSerialInputStream(
    private val port: UsbSerialPort
) : java.io.InputStream() {
    private val buffer = ByteArray(4096)

    override fun read(): Int {
        val buf = ByteArray(1)
        val bytesRead = port.read(buf, 100)
        return if (bytesRead > 0) buf[0].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val bytesRead = port.read(buffer, 100)
        if (bytesRead > 0) {
            val toCopy = minOf(bytesRead, len)
            System.arraycopy(buffer, 0, b, off, toCopy)
            return toCopy
        }
        return 0
    }

    override fun available(): Int = 0
}

/**
 * USB Serial output stream wrapper.
 */
private class UsbSerialOutputStream(
    private val port: UsbSerialPort
) : java.io.OutputStream() {
    override fun write(b: Int) {
        port.write(byteArrayOf(b.toByte()), 100)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        port.write(b.copyOfRange(off, off + len), 1000)
    }

    override fun flush() {
        // USB serial flushes automatically
    }
}
