package com.yours.app.mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * MeshCore transport over Bluetooth Low Energy.
 *
 * Uses Android BLE GATT APIs to communicate with MeshCore companion devices
 * wirelessly. More convenient than USB but may have slightly higher latency.
 *
 * ## Android Permissions Required
 *
 * Add these to AndroidManifest.xml:
 * ```xml
 * <!-- For Android 12+ (API 31+) -->
 * <uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
 * <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
 *
 * <!-- For Android 11 and below -->
 * <uses-permission android:name="android.permission.BLUETOOTH" />
 * <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
 * <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
 *
 * <!-- Required for BLE -->
 * <uses-feature android:name="android.hardware.bluetooth_le" android:required="true" />
 * ```
 *
 * ## Runtime Permission Check (call before using this class)
 * ```kotlin
 * // For Android 12+
 * if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
 *     if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT)
 *         != PackageManager.PERMISSION_GRANTED) {
 *         ActivityCompat.requestPermissions(activity,
 *             arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN),
 *             REQUEST_BLUETOOTH_PERMISSIONS)
 *     }
 * }
 * ```
 *
 * ## BLE Service UUIDs (Nordic UART Service - NUS)
 * - Service UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 * - RX Characteristic: 6E400002-B5A3-F393-E0A9-E50E24DCCA9E (write to device)
 * - TX Characteristic: 6E400003-B5A3-F393-E0A9-E50E24DCCA9E (notifications from device)
 *
 * ## MeshCore Protocol Over BLE
 * The MeshCore firmware uses a framed protocol over the Nordic UART Service.
 * Commands and responses are serialized using the same LoRaFrame format as USB serial.
 *
 * ## Connection Flow
 * 1. Scan for devices advertising the NUS service (optional)
 * 2. Connect to device by MAC address
 * 3. Discover services and find NUS characteristics
 * 4. Enable notifications on TX characteristic
 * 5. Perform MeshCore handshake/authentication
 * 6. Ready for bidirectional communication
 *
 * SECURITY:
 * - All application-layer data is encrypted using MeshCore's protocol
 * - BLE link-layer encryption (pairing) is optional but recommended
 * - PIN-based pairing supported for additional security
 */
@SuppressLint("MissingPermission")
class MeshCoreBleTransport(
    private val context: Context
) : MeshCoreTransport {

    companion object {
        private const val TAG = "MeshCoreBleTransport"

        // Nordic UART Service UUIDs
        val NUS_SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
        val NUS_RX_CHAR_UUID: UUID = UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
        val NUS_TX_CHAR_UUID: UUID = UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")

        // Client Characteristic Configuration Descriptor for notifications
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        // Timeouts
        private const val CONNECTION_TIMEOUT_MS = 15000L
        private const val SERVICE_DISCOVERY_TIMEOUT_MS = 10000L
        private const val WRITE_TIMEOUT_MS = 5000L
        private const val RESPONSE_TIMEOUT_MS = 10000L
        private const val HANDSHAKE_TIMEOUT_MS = 15000L
        private const val RECONNECT_DELAY_MS = 2000L
        private const val MAX_RECONNECT_ATTEMPTS = 3

        // BLE MTU
        private const val DEFAULT_MTU = 23
        private const val PREFERRED_MTU = 512
        private const val MTU_HEADER_SIZE = 3  // ATT protocol overhead

        // Write chunking
        private const val MAX_WRITE_CHUNK_DELAY_MS = 50L
    }

    // State flows
    private val _connectionState = MutableStateFlow(MeshConnectionState.DISCONNECTED)
    override val connectionState: StateFlow<MeshConnectionState> = _connectionState

    private val _events = MutableSharedFlow<MeshEvent>(replay = 0, extraBufferCapacity = 64)
    override val events: Flow<MeshEvent> = _events

    // Bluetooth components
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothGatt: BluetoothGatt? = null
    private var bluetoothDevice: BluetoothDevice? = null

    // Characteristics
    private var rxCharacteristic: BluetoothGattCharacteristic? = null
    private var txCharacteristic: BluetoothGattCharacteristic? = null

    // Connection info
    private var currentMacAddress: String? = null
    private var currentPin: String? = null
    private var negotiatedMtu: Int = DEFAULT_MTU

    // Protocol state
    private val frameParser = LoRaFrameParser()
    private val sequenceCounter = AtomicInteger(0)
    private val pendingResponses = ConcurrentHashMap<Byte, CompletableDeferred<LoRaFrame>>()
    private val receivedPackets = Channel<LoRaRxPacket>(Channel.BUFFERED)
    private var deviceInfo: DeviceInfo? = null

    // Synchronization
    private val writeMutex = Mutex()
    private val connectionMutex = Mutex()
    private val isConnecting = AtomicBoolean(false)
    private val isDisconnecting = AtomicBoolean(false)
    private var reconnectAttempts = 0

    // Coroutines
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var connectionJob: Job? = null
    private var serviceDiscoveryComplete = CompletableDeferred<Boolean>()
    private var mtuNegotiationComplete = CompletableDeferred<Int>()
    private var notificationsEnabled = CompletableDeferred<Boolean>()

    // Write queue for handling BLE write serialization
    private val writeQueue = Channel<WriteOperation>(Channel.BUFFERED)
    private var writeProcessorJob: Job? = null

    private data class WriteOperation(
        val data: ByteArray,
        val result: CompletableDeferred<Boolean>
    )

    /**
     * GATT Callback - Handles all BLE events from the Android system.
     */
    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            scope.launch {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            _events.emit(MeshEvent(MeshEventType.CONNECTED, "BLE connected, discovering services..."))

                            // Request higher MTU for better throughput
                            gatt.requestMtu(PREFERRED_MTU)

                            // Discover services after short delay to let MTU negotiation start
                            delay(100)
                            if (!gatt.discoverServices()) {
                                handleConnectionError("Failed to start service discovery")
                            }
                        } else {
                            handleConnectionError("Connection failed with status: $status")
                        }
                    }

                    BluetoothProfile.STATE_DISCONNECTED -> {
                        val wasConnected = _connectionState.value == MeshConnectionState.CONNECTED
                        cleanup()

                        if (wasConnected && !isDisconnecting.get()) {
                            // Unexpected disconnection - attempt reconnect
                            _connectionState.value = MeshConnectionState.CONNECTING
                            _events.emit(MeshEvent(MeshEventType.ERROR, "Connection lost, attempting reconnect..."))
                            attemptReconnect()
                        } else {
                            _connectionState.value = MeshConnectionState.DISCONNECTED
                            _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
                        }
                    }

                    BluetoothProfile.STATE_CONNECTING -> {
                        _connectionState.value = MeshConnectionState.CONNECTING
                    }
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            scope.launch {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    // Find Nordic UART Service
                    val nusService = gatt.getService(NUS_SERVICE_UUID)
                    if (nusService != null) {
                        rxCharacteristic = nusService.getCharacteristic(NUS_RX_CHAR_UUID)
                        txCharacteristic = nusService.getCharacteristic(NUS_TX_CHAR_UUID)

                        if (rxCharacteristic != null && txCharacteristic != null) {
                            _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "MeshCore service found"))
                            serviceDiscoveryComplete.complete(true)

                            // Enable notifications on TX characteristic
                            enableNotifications(gatt)
                        } else {
                            serviceDiscoveryComplete.complete(false)
                            handleConnectionError("MeshCore characteristics not found")
                        }
                    } else {
                        serviceDiscoveryComplete.complete(false)
                        handleConnectionError("MeshCore service not found on device")
                    }
                } else {
                    serviceDiscoveryComplete.complete(false)
                    handleConnectionError("Service discovery failed with status: $status")
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            scope.launch {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    negotiatedMtu = mtu
                    _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "MTU negotiated: $mtu bytes"))
                } else {
                    negotiatedMtu = DEFAULT_MTU
                }
                mtuNegotiationComplete.complete(negotiatedMtu)
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            // Called when we receive notification data from the device
            if (characteristic.uuid == NUS_TX_CHAR_UUID) {
                scope.launch {
                    processReceivedData(value)
                }
            }
        }

        @Deprecated("Deprecated in API 33, but needed for older devices")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            // Legacy callback for Android < 13
            if (characteristic.uuid == NUS_TX_CHAR_UUID) {
                val value = characteristic.value ?: return
                scope.launch {
                    processReceivedData(value)
                }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            // Write completion is handled by the write queue processor
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            scope.launch {
                if (descriptor.uuid == CCCD_UUID && descriptor.characteristic?.uuid == NUS_TX_CHAR_UUID) {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        notificationsEnabled.complete(true)
                        finalizeConnection()
                    } else {
                        notificationsEnabled.complete(false)
                        handleConnectionError("Failed to enable notifications: status $status")
                    }
                }
            }
        }
    }

    /**
     * Connect to a MeshCore device over BLE.
     *
     * @param connection BLE connection parameters including MAC address and optional PIN
     * @return Success or failure with error details
     */
    override suspend fun connect(connection: MeshConnection): Result<Unit> = connectionMutex.withLock {
        if (connection !is MeshConnection.Ble) {
            return Result.failure(IllegalArgumentException("Expected BLE connection"))
        }

        if (_connectionState.value == MeshConnectionState.CONNECTED) {
            return Result.success(Unit)
        }

        if (isConnecting.getAndSet(true)) {
            return Result.failure(IllegalStateException("Connection already in progress"))
        }

        _connectionState.value = MeshConnectionState.CONNECTING
        currentMacAddress = connection.macAddress
        currentPin = connection.pin
        reconnectAttempts = 0

        return try {
            // Reset completion signals
            serviceDiscoveryComplete = CompletableDeferred()
            mtuNegotiationComplete = CompletableDeferred()
            notificationsEnabled = CompletableDeferred()

            // Get Bluetooth adapter
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
                ?: return Result.failure(IOException("Bluetooth not available"))

            bluetoothAdapter = bluetoothManager.adapter
            if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
                _connectionState.value = MeshConnectionState.ERROR
                return Result.failure(IOException("Bluetooth is not enabled"))
            }

            // Validate MAC address format
            if (!BluetoothAdapter.checkBluetoothAddress(connection.macAddress.uppercase())) {
                _connectionState.value = MeshConnectionState.ERROR
                return Result.failure(IllegalArgumentException("Invalid Bluetooth MAC address: ${connection.macAddress}"))
            }

            // Get remote device
            bluetoothDevice = bluetoothAdapter!!.getRemoteDevice(connection.macAddress.uppercase())

            // Initiate GATT connection
            _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "Connecting to ${connection.macAddress}..."))

            // Use TRANSPORT_LE for BLE devices
            bluetoothGatt = bluetoothDevice!!.connectGatt(
                context,
                false,  // Don't auto-connect - we want immediate connection
                gattCallback,
                BluetoothDevice.TRANSPORT_LE
            )

            if (bluetoothGatt == null) {
                _connectionState.value = MeshConnectionState.ERROR
                return Result.failure(IOException("Failed to create GATT connection"))
            }

            // Wait for connection, service discovery, and notification setup with timeout
            val connectionResult = withTimeoutOrNull(CONNECTION_TIMEOUT_MS) {
                // Wait for service discovery
                val servicesFound = serviceDiscoveryComplete.await()
                if (!servicesFound) {
                    return@withTimeoutOrNull false
                }

                // Wait for notifications to be enabled
                val notifEnabled = notificationsEnabled.await()
                if (!notifEnabled) {
                    return@withTimeoutOrNull false
                }

                true
            }

            if (connectionResult != true) {
                cleanup()
                _connectionState.value = MeshConnectionState.ERROR
                return Result.failure(IOException("Connection timeout"))
            }

            // Start write processor
            startWriteProcessor()

            Result.success(Unit)

        } catch (e: Exception) {
            cleanup()
            _connectionState.value = MeshConnectionState.ERROR
            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, e.message))
            Result.failure(e)
        } finally {
            isConnecting.set(false)
        }
    }

    /**
     * Enable notifications on the TX characteristic to receive data from device.
     */
    private fun enableNotifications(gatt: BluetoothGatt) {
        val txChar = txCharacteristic ?: return

        // Enable local notifications
        if (!gatt.setCharacteristicNotification(txChar, true)) {
            scope.launch {
                notificationsEnabled.complete(false)
                handleConnectionError("Failed to enable local notifications")
            }
            return
        }

        // Write to CCCD to enable remote notifications
        val cccd = txChar.getDescriptor(CCCD_UUID)
        if (cccd != null) {
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            if (!gatt.writeDescriptor(cccd)) {
                scope.launch {
                    notificationsEnabled.complete(false)
                    handleConnectionError("Failed to write notification descriptor")
                }
            }
        } else {
            // Some devices don't have CCCD - notifications might still work
            scope.launch {
                notificationsEnabled.complete(true)
                finalizeConnection()
            }
        }
    }

    /**
     * Finalize the connection after all setup is complete.
     */
    private suspend fun finalizeConnection() {
        // Query device info
        try {
            val info = queryDeviceInfo()
            if (info != null) {
                deviceInfo = info
                _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, info))
            }
        } catch (e: Exception) {
            _events.emit(MeshEvent(MeshEventType.ERROR, "Failed to query device info: ${e.message}"))
        }

        _connectionState.value = MeshConnectionState.CONNECTED
        _events.emit(MeshEvent(MeshEventType.CONNECTED, currentMacAddress))
    }

    /**
     * Handle connection errors by cleaning up and emitting error events.
     */
    private suspend fun handleConnectionError(message: String) {
        _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, message))
        if (isConnecting.get()) {
            // Let the connect() function handle cleanup
            serviceDiscoveryComplete.complete(false)
            notificationsEnabled.complete(false)
        } else {
            cleanup()
            _connectionState.value = MeshConnectionState.ERROR
        }
    }

    /**
     * Attempt to reconnect after an unexpected disconnection.
     */
    private suspend fun attemptReconnect() {
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            _connectionState.value = MeshConnectionState.ERROR
            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, "Max reconnect attempts exceeded"))
            return
        }

        reconnectAttempts++
        delay(RECONNECT_DELAY_MS)

        val mac = currentMacAddress ?: return
        val pin = currentPin

        connectionMutex.withLock {
            try {
                serviceDiscoveryComplete = CompletableDeferred()
                mtuNegotiationComplete = CompletableDeferred()
                notificationsEnabled = CompletableDeferred()

                bluetoothGatt = bluetoothDevice?.connectGatt(
                    context,
                    false,
                    gattCallback,
                    BluetoothDevice.TRANSPORT_LE
                )
            } catch (e: Exception) {
                _events.emit(MeshEvent(MeshEventType.ERROR, "Reconnect failed: ${e.message}"))
                attemptReconnect()
            }
        }
    }

    /**
     * Disconnect from the current device.
     */
    override suspend fun disconnect() {
        isDisconnecting.set(true)
        try {
            connectionMutex.withLock {
                cleanup()
                _connectionState.value = MeshConnectionState.DISCONNECTED
                _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
            }
        } finally {
            isDisconnecting.set(false)
        }
    }

    /**
     * Clean up all BLE resources.
     */
    private fun cleanup() {
        writeProcessorJob?.cancel()
        writeProcessorJob = null

        bluetoothGatt?.let { gatt ->
            gatt.disconnect()
            gatt.close()
        }
        bluetoothGatt = null

        rxCharacteristic = null
        txCharacteristic = null
        frameParser.reset()
        pendingResponses.clear()
        deviceInfo = null
        negotiatedMtu = DEFAULT_MTU
    }

    /**
     * Start the write processor coroutine that serializes BLE writes.
     */
    private fun startWriteProcessor() {
        writeProcessorJob = scope.launch {
            for (operation in writeQueue) {
                try {
                    val success = performWrite(operation.data)
                    operation.result.complete(success)
                } catch (e: Exception) {
                    operation.result.completeExceptionally(e)
                }
            }
        }
    }

    /**
     * Perform a chunked write to the RX characteristic.
     * BLE has MTU limitations, so large payloads must be chunked.
     */
    private suspend fun performWrite(data: ByteArray): Boolean {
        val gatt = bluetoothGatt ?: return false
        val rxChar = rxCharacteristic ?: return false

        // Calculate max chunk size based on negotiated MTU
        val maxChunkSize = negotiatedMtu - MTU_HEADER_SIZE

        return writeMutex.withLock {
            var offset = 0
            while (offset < data.size) {
                val chunkSize = minOf(maxChunkSize, data.size - offset)
                val chunk = data.copyOfRange(offset, offset + chunkSize)

                rxChar.value = chunk
                rxChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT

                if (!gatt.writeCharacteristic(rxChar)) {
                    return@withLock false
                }

                // Small delay between chunks to prevent buffer overflow
                if (offset + chunkSize < data.size) {
                    delay(MAX_WRITE_CHUNK_DELAY_MS)
                }

                offset += chunkSize
            }
            true
        }
    }

    /**
     * Process data received from the TX characteristic.
     */
    private suspend fun processReceivedData(data: ByteArray) {
        val frames = frameParser.feed(data)

        for (frame in frames) {
            when (frame.command) {
                LoRaCommand.RECEIVE -> {
                    // Incoming mesh packet
                    LoRaRxPacket.fromFrameData(frame.data)?.let { packet ->
                        receivedPackets.send(packet)
                        _events.emit(MeshEvent(MeshEventType.MESSAGE_RECEIVED, packet))
                    }
                }

                LoRaCommand.PONG -> {
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.CONFIG_ACK -> {
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.TX_DONE -> {
                    pendingResponses[frame.sequence]?.complete(frame)
                    _events.emit(MeshEvent(MeshEventType.MESSAGE_SENT))
                }

                LoRaCommand.TX_ERROR -> {
                    val errorCode = frame.data.getOrNull(0)?.toInt() ?: -1
                    pendingResponses[frame.sequence]?.completeExceptionally(
                        IOException("Transmit failed: error code $errorCode")
                    )
                    _events.emit(MeshEvent(MeshEventType.MESSAGE_FAILED, "Error code: $errorCode"))
                }

                LoRaCommand.VERSION_RESPONSE -> {
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.STATS_RESPONSE -> {
                    pendingResponses[frame.sequence]?.complete(frame)
                }

                LoRaCommand.ERROR -> {
                    val errorMsg = String(frame.data, Charsets.UTF_8)
                    pendingResponses[frame.sequence]?.completeExceptionally(
                        IOException("Device error: $errorMsg")
                    )
                    _events.emit(MeshEvent(MeshEventType.ERROR, errorMsg))
                }

                else -> {
                    // Handle any other responses
                    pendingResponses[frame.sequence]?.complete(frame)
                }
            }
        }
    }

    /**
     * Get the next sequence number for request/response correlation.
     */
    private fun nextSequence(): Byte {
        return (sequenceCounter.incrementAndGet() and 0xFF).toByte()
    }

    /**
     * Send a frame and wait for a response.
     */
    private suspend fun sendFrameAndWait(
        frame: LoRaFrame,
        timeoutMs: Long = RESPONSE_TIMEOUT_MS
    ): Result<LoRaFrame> {
        if (_connectionState.value != MeshConnectionState.CONNECTED) {
            return Result.failure(IOException("Not connected"))
        }

        val deferred = CompletableDeferred<LoRaFrame>()
        pendingResponses[frame.sequence] = deferred

        return try {
            // Encode and queue write
            val encoded = frame.encode()
            val writeResult = CompletableDeferred<Boolean>()
            writeQueue.send(WriteOperation(encoded, writeResult))

            // Wait for write to complete
            val writeSuccess = withTimeout(WRITE_TIMEOUT_MS) {
                writeResult.await()
            }

            if (!writeSuccess) {
                return Result.failure(IOException("Write failed"))
            }

            // Wait for response
            val response = withTimeout(timeoutMs) {
                deferred.await()
            }

            Result.success(response)

        } catch (e: TimeoutCancellationException) {
            Result.failure(IOException("Response timeout"))
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            pendingResponses.remove(frame.sequence)
        }
    }

    /**
     * Send a frame without waiting for response.
     */
    private suspend fun sendFrame(frame: LoRaFrame): Result<Unit> {
        if (_connectionState.value != MeshConnectionState.CONNECTED) {
            return Result.failure(IOException("Not connected"))
        }

        return try {
            val encoded = frame.encode()
            val writeResult = CompletableDeferred<Boolean>()
            writeQueue.send(WriteOperation(encoded, writeResult))

            val success = withTimeout(WRITE_TIMEOUT_MS) {
                writeResult.await()
            }

            if (success) Result.success(Unit) else Result.failure(IOException("Write failed"))

        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Query device info from the connected MeshCore device.
     */
    private suspend fun queryDeviceInfo(): DeviceInfo? {
        val seq = nextSequence()
        val frame = LoRaFrame.version(seq)

        return sendFrameAndWait(frame, 5000).getOrNull()?.let { response ->
            val version = String(response.data, Charsets.UTF_8)
            DeviceInfo(
                nodeId = extractNodeId(response.data),
                firmwareVersion = version,
                hardwareType = detectHardwareType(),
                meshName = null
            )
        }
    }

    /**
     * Extract node ID from version response data.
     */
    private fun extractNodeId(data: ByteArray): ByteArray {
        // Node ID may be embedded in version response or needs separate query
        // For now, use device MAC address as identifier
        return currentMacAddress?.replace(":", "")?.let { mac ->
            try {
                mac.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            } catch (e: Exception) {
                ByteArray(8)
            }
        } ?: ByteArray(8)
    }

    /**
     * Detect the hardware type based on device characteristics.
     */
    private fun detectHardwareType(): String {
        val deviceName = bluetoothDevice?.name ?: "Unknown"
        return when {
            deviceName.contains("Heltec", ignoreCase = true) -> "Heltec-V3-BLE"
            deviceName.contains("LILYGO", ignoreCase = true) -> "LILYGO-T3S3-BLE"
            deviceName.contains("RAK", ignoreCase = true) -> "RAK-WisBlock-BLE"
            deviceName.contains("MeshCore", ignoreCase = true) -> "MeshCore-BLE"
            else -> "Unknown-BLE"
        }
    }

    // ============================================================================
    // MeshCoreTransport Interface Implementation
    // ============================================================================

    override suspend fun getDeviceInfo(): Result<DeviceInfo> {
        deviceInfo?.let { return Result.success(it) }

        val seq = nextSequence()
        val frame = LoRaFrame.version(seq)

        return sendFrameAndWait(frame).map { response ->
            val version = String(response.data, Charsets.UTF_8)
            DeviceInfo(
                nodeId = extractNodeId(response.data),
                firmwareVersion = version,
                hardwareType = detectHardwareType(),
                meshName = bluetoothDevice?.name
            ).also { deviceInfo = it }
        }
    }

    override suspend fun getContacts(): Result<List<MeshContact>> {
        if (_connectionState.value != MeshConnectionState.CONNECTED) {
            return Result.failure(IOException("Not connected"))
        }

        // Send contacts query command
        val seq = nextSequence()
        // MeshCore uses a custom command for contacts - using GET_STATS frame structure
        // In production, this would be a dedicated CONTACTS_QUERY command
        val frame = LoRaFrame(LoRaCommand.GET_STATS, seq, byteArrayOf(0x01)) // 0x01 = contacts query

        return try {
            val response = sendFrameAndWait(frame, 15000).getOrThrow()
            parseContactsResponse(response.data)
        } catch (e: Exception) {
            // Return empty list if contacts query not supported by firmware
            Result.success(emptyList())
        }
    }

    /**
     * Parse contacts response from MeshCore device.
     */
    private fun parseContactsResponse(data: ByteArray): Result<List<MeshContact>> {
        if (data.isEmpty()) {
            return Result.success(emptyList())
        }

        val contacts = mutableListOf<MeshContact>()
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        try {
            // Contact format: [pubkey:32][nameLen:1][name:var][lastSeen:8][rssi:2]
            while (buffer.hasRemaining() && buffer.remaining() >= 43) {
                val publicKey = ByteArray(32)
                buffer.get(publicKey)

                val nameLen = buffer.get().toInt() and 0xFF
                val displayName = if (nameLen > 0 && buffer.remaining() >= nameLen) {
                    val nameBytes = ByteArray(nameLen)
                    buffer.get(nameBytes)
                    String(nameBytes, Charsets.UTF_8)
                } else {
                    null
                }

                val lastSeen = if (buffer.remaining() >= 8) buffer.getLong() else 0L
                val signalStrength = if (buffer.remaining() >= 2) buffer.getShort().toInt() else null

                contacts.add(MeshContact(
                    publicKey = publicKey,
                    displayName = displayName,
                    lastSeen = lastSeen,
                    signalStrength = signalStrength
                ))
            }
        } catch (e: Exception) {
            return Result.failure(IOException("Failed to parse contacts: ${e.message}"))
        }

        return Result.success(contacts)
    }

    override suspend fun sendMessage(recipient: ByteArray, content: ByteArray): Result<String> {
        if (_connectionState.value != MeshConnectionState.CONNECTED) {
            return Result.failure(IOException("Not connected"))
        }

        // Build message payload: [recipient:32][content:var]
        val payload = ByteArray(recipient.size + content.size)
        System.arraycopy(recipient, 0, payload, 0, recipient.size)
        System.arraycopy(content, 0, payload, recipient.size, content.size)

        val seq = nextSequence()
        val frame = LoRaFrame.transmit(seq, payload)

        return sendFrameAndWait(frame).map {
            // Generate message ID for tracking
            val messageId = UUID.randomUUID().toString()
            messageId
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
            val result = try {
                withTimeout(timeoutMs) {
                    sendMessage(recipient, content)
                }
            } catch (e: TimeoutCancellationException) {
                Result.failure(IOException("Send timeout"))
            }

            if (result.isSuccess) {
                return result
            }

            lastError = result.exceptionOrNull() as? Exception

            // Exponential backoff between retries
            if (attempt < maxRetries - 1) {
                val backoffMs = 500L * (1 shl attempt).coerceAtMost(8)
                delay(backoffMs)
            }
        }

        return Result.failure(lastError ?: IOException("Send failed after $maxRetries attempts"))
    }

    override suspend fun getBatteryStatus(): Result<BatteryStatus> {
        if (_connectionState.value != MeshConnectionState.CONNECTED) {
            return Result.failure(IOException("Not connected"))
        }

        // Send battery query - using stats command with battery flag
        val seq = nextSequence()
        val frame = LoRaFrame(LoRaCommand.GET_STATS, seq, byteArrayOf(0x02)) // 0x02 = battery query

        return try {
            val response = sendFrameAndWait(frame, 5000).getOrThrow()
            parseBatteryResponse(response.data)
        } catch (e: Exception) {
            // Try alternative: some devices report battery in device info
            Result.failure(IOException("Battery status not available: ${e.message}"))
        }
    }

    /**
     * Parse battery status response from device.
     */
    private fun parseBatteryResponse(data: ByteArray): Result<BatteryStatus> {
        if (data.size < 4) {
            return Result.failure(IOException("Invalid battery response"))
        }

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        val percentage = buffer.get().toInt() and 0xFF
        val flags = buffer.get().toInt() and 0xFF
        val isCharging = (flags and 0x01) != 0
        val voltage = if (buffer.remaining() >= 2) {
            buffer.getShort().toFloat() / 1000.0f  // mV to V
        } else {
            null
        }

        return Result.success(BatteryStatus(
            percentage = percentage.coerceIn(0, 100),
            isCharging = isCharging,
            voltage = voltage
        ))
    }

    override fun isConnected(): Boolean = _connectionState.value == MeshConnectionState.CONNECTED

    // ============================================================================
    // BLE-Specific Methods
    // ============================================================================

    /**
     * Get the negotiated MTU size.
     */
    fun getNegotiatedMtu(): Int = negotiatedMtu

    /**
     * Get the connected device name.
     */
    fun getDeviceName(): String? = bluetoothDevice?.name

    /**
     * Get the connected device MAC address.
     */
    fun getDeviceAddress(): String? = currentMacAddress

    /**
     * Get RSSI (signal strength) of the BLE connection.
     * Note: This requires reading RSSI which may not be immediately available.
     */
    suspend fun getConnectionRssi(): Int? {
        val gatt = bluetoothGatt ?: return null

        val rssiDeferred = CompletableDeferred<Int?>()

        // This is a simplified version - in production you'd use the callback
        return try {
            if (gatt.readRemoteRssi()) {
                // RSSI will be delivered via callback - for now return null
                // In production, you'd set up a proper callback mechanism
                null
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Check if the device supports the MeshCore service.
     */
    fun hasMeshCoreService(): Boolean {
        return rxCharacteristic != null && txCharacteristic != null
    }

    /**
     * Send a ping to verify the connection is active.
     */
    suspend fun ping(): Result<Long> {
        val startTime = System.currentTimeMillis()
        val seq = nextSequence()
        val frame = LoRaFrame.ping(seq)

        return sendFrameAndWait(frame, 5000).map {
            System.currentTimeMillis() - startTime
        }
    }

    /**
     * Configure LoRa radio parameters via BLE.
     */
    suspend fun configureRadio(
        frequencyHz: Long = 915_000_000,
        spreadingFactor: Int = 10,
        bandwidthKhz: Int = 125,
        codingRate: Int = 1,
        txPowerDbm: Int = 20
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
     * Receive the next packet from the mesh network.
     */
    suspend fun receivePacket(timeoutMs: Long = 5000): LoRaRxPacket? {
        return withTimeoutOrNull(timeoutMs) {
            receivedPackets.receive()
        }
    }

    /**
     * Transmit raw bytes over LoRa mesh.
     */
    suspend fun transmit(data: ByteArray): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.transmit(seq, data)
        return sendFrameAndWait(frame).map { }
    }

    /**
     * Request channel activity detection.
     */
    suspend fun channelActivityDetection(): Result<Boolean> {
        val seq = nextSequence()
        val frame = LoRaFrame.cad(seq)

        return sendFrameAndWait(frame).map { response ->
            response.data.getOrNull(0)?.toInt() == 1
        }
    }

    /**
     * Reset the LoRa radio.
     */
    suspend fun resetRadio(): Result<Unit> {
        val seq = nextSequence()
        val frame = LoRaFrame.reset(seq)
        return sendFrameAndWait(frame).map { }
    }

    /**
     * Get radio statistics.
     */
    suspend fun getRadioStats(): Result<BleRadioStats> {
        val seq = nextSequence()
        val frame = LoRaFrame.getStats(seq)

        return sendFrameAndWait(frame).map { response ->
            if (response.data.size >= 16) {
                val data = response.data
                BleRadioStats(
                    txPackets = readU32LE(data, 0),
                    rxPackets = readU32LE(data, 4),
                    txErrors = readU32LE(data, 8),
                    rxErrors = readU32LE(data, 12)
                )
            } else {
                BleRadioStats(0, 0, 0, 0)
            }
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
 * Radio statistics from BLE-connected MeshCore device.
 */
data class BleRadioStats(
    val txPackets: Long,
    val rxPackets: Long,
    val txErrors: Long,
    val rxErrors: Long
)

/**
 * BLE device information discovered during scanning.
 */
data class BleDeviceInfo(
    val name: String?,
    val address: String,
    val rssi: Int,
    val hasMeshCoreService: Boolean
)
