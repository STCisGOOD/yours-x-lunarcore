package com.yours.app.mesh

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlin.coroutines.CoroutineContext

/**
 * MeshCore Transport Layer
 *
 * Provides communication with MeshCore companion devices (Heltec V3, etc.)
 * over USB Serial, BLE, or TCP.
 *
 * This is the foundation for:
 * - Encrypted messaging over LoRa mesh
 * - File transfer over mesh DMs
 * - Contact discovery without internet
 *
 * Protocol reference: https://github.com/meshcore-dev/MeshCore
 */

// ============================================================================
// CONNECTION TYPES
// ============================================================================

sealed class MeshConnection {
    data class Serial(val devicePath: String, val baudRate: Int = 115200) : MeshConnection()
    data class Ble(val macAddress: String, val pin: String? = null) : MeshConnection()
    data class Tcp(val host: String, val port: Int = 4000) : MeshConnection()
}

// ============================================================================
// EVENTS
// ============================================================================

enum class MeshEventType {
    // Connection
    CONNECTED,
    DISCONNECTED,
    CONNECTION_ERROR,

    // Messages
    MESSAGE_RECEIVED,
    MESSAGE_SENT,
    MESSAGE_FAILED,
    MESSAGE_ACK,

    // Contacts
    CONTACT_DISCOVERED,
    CONTACT_UPDATED,

    // Network
    ADVERTISEMENT,
    PATH_UPDATE,

    // Device
    DEVICE_INFO,
    BATTERY_STATUS,

    // Errors
    ERROR
}

data class MeshEvent(
    val type: MeshEventType,
    val payload: Any? = null,
    val timestamp: Long = System.currentTimeMillis()
)

data class MeshContact(
    val publicKey: ByteArray,
    val displayName: String?,
    val lastSeen: Long,
    val signalStrength: Int? = null
) {
    val publicKeyHex: String get() = publicKey.joinToString("") { "%02x".format(it) }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MeshContact) return false
        return publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = publicKey.contentHashCode()
}

data class MeshMessage(
    val from: ByteArray,
    val to: ByteArray,
    val content: ByteArray,
    val timestamp: Long,
    val messageId: String,
    val isAcked: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MeshMessage) return false
        return messageId == other.messageId
    }

    override fun hashCode(): Int = messageId.hashCode()
}

// ============================================================================
// CONNECTION STATE
// ============================================================================

enum class MeshConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

// ============================================================================
// TRANSPORT INTERFACE
// ============================================================================

interface MeshCoreTransport {
    /**
     * Current connection state.
     */
    val connectionState: StateFlow<MeshConnectionState>

    /**
     * Stream of events from the mesh network.
     */
    val events: Flow<MeshEvent>

    /**
     * Connect to a MeshCore device.
     */
    suspend fun connect(connection: MeshConnection): Result<Unit>

    /**
     * Disconnect from the current device.
     */
    suspend fun disconnect()

    /**
     * Get device info (firmware version, node ID, etc.)
     */
    suspend fun getDeviceInfo(): Result<DeviceInfo>

    /**
     * Get list of known contacts on the mesh.
     */
    suspend fun getContacts(): Result<List<MeshContact>>

    /**
     * Send a direct message to a contact.
     *
     * @param recipient Contact's public key
     * @param content Message content (will be encrypted by BedrockCore before calling this)
     * @return Message ID for tracking ACKs
     */
    suspend fun sendMessage(recipient: ByteArray, content: ByteArray): Result<String>

    /**
     * Send a direct message with retry and ACK waiting.
     *
     * @param recipient Contact's public key
     * @param content Message content
     * @param maxRetries Maximum retry attempts
     * @param timeoutMs Timeout for ACK in milliseconds
     */
    suspend fun sendMessageWithRetry(
        recipient: ByteArray,
        content: ByteArray,
        maxRetries: Int = 3,
        timeoutMs: Long = 30000
    ): Result<String>

    /**
     * Get battery status of connected device.
     */
    suspend fun getBatteryStatus(): Result<BatteryStatus>

    /**
     * Check if connected to a MeshCore device.
     */
    fun isConnected(): Boolean
}

data class DeviceInfo(
    val nodeId: ByteArray,
    val firmwareVersion: String,
    val hardwareType: String,
    val meshName: String?
) {
    val nodeIdHex: String get() = nodeId.joinToString("") { "%02x".format(it) }
}

data class BatteryStatus(
    val percentage: Int,
    val isCharging: Boolean,
    val voltage: Float?
)

// ============================================================================
// TRANSPORT MANAGER
// ============================================================================

/**
 * Type of transport connection.
 */
enum class TransportType {
    SERIAL,
    BLE,
    TCP
}

/**
 * Discovery result for MeshCore devices.
 */
sealed class DiscoveredDevice {
    data class UsbDevice(
        val deviceName: String,
        val vendorId: Int,
        val productId: Int,
        val productName: String,
        val manufacturer: String,
        val hasPermission: Boolean
    ) : DiscoveredDevice()

    data class BleDevice(
        val name: String?,
        val address: String,
        val rssi: Int,
        val hasMeshCoreService: Boolean
    ) : DiscoveredDevice()

    data class TcpRelay(
        val host: String,
        val port: Int,
        val name: String
    ) : DiscoveredDevice()
}

/**
 * Transfer progress for file/artifact transfers over MeshCore.
 */
data class TransferProgress(
    val transferId: String,
    val totalBytes: Long,
    val sentBytes: Long,
    val status: TransferStatus,
    val error: String? = null
) {
    val progress: Float get() = if (totalBytes > 0) sentBytes.toFloat() / totalBytes else 0f
    val isComplete: Boolean get() = status == TransferStatus.COMPLETED
    val isFailed: Boolean get() = status == TransferStatus.FAILED
}

enum class TransferStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED
}

/**
 * Manages MeshCore transport and provides high-level messaging API.
 *
 * Supports three transport types:
 * - USB Serial: Direct connection to ESP32 LoRa devices via USB-C
 * - BLE: Wireless connection to MeshCore devices via Bluetooth LE
 * - TCP: Connection to relay servers or meshcore-pi instances
 *
 * Usage:
 * ```kotlin
 * val manager = MeshCoreManager(context)
 *
 * // Discover devices
 * val devices = manager.discoverDevices()
 *
 * // Connect to a device
 * manager.connect(MeshConnection.Serial(devicePath))
 *
 * // Send a message
 * manager.sendEncryptedMessage(recipientKey, encryptedContent)
 *
 * // Transfer a file with progress tracking
 * manager.transferFile(recipientKey, data, metadata) { progress ->
 *     updateUI(progress)
 * }
 * ```
 */
class MeshCoreManager(private val context: android.content.Context) {
    private var transport: MeshCoreTransport? = null
    private var currentTransportType: TransportType? = null

    private val _connectionState = MutableStateFlow(MeshConnectionState.DISCONNECTED)
    val connectionState: StateFlow<MeshConnectionState> = _connectionState

    private val _events = MutableSharedFlow<MeshEvent>(replay = 0, extraBufferCapacity = 64)
    val events: Flow<MeshEvent> = _events

    private val _transferProgress = MutableStateFlow<TransferProgress?>(null)
    val transferProgress: StateFlow<TransferProgress?> = _transferProgress

    // BLE scanner instance for device discovery
    private var bleScanner: MeshCoreBleScanner? = null

    // Coroutine scope for background operations
    private val scope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob()
    )

    // Event forwarding job
    private var eventForwardingJob: kotlinx.coroutines.Job? = null

    /**
     * Connect to a MeshCore device using the specified connection method.
     *
     * This automatically selects the appropriate transport based on the
     * connection type and establishes the connection.
     *
     * @param connection Connection parameters (Serial, BLE, or TCP)
     * @return Result indicating success or failure with details
     */
    suspend fun connect(connection: MeshConnection): Result<Unit> {
        // Disconnect existing transport if any
        if (transport != null) {
            disconnect()
        }

        _connectionState.value = MeshConnectionState.CONNECTING
        _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "Connecting to MeshCore device..."))

        val newTransport = when (connection) {
            is MeshConnection.Serial -> {
                currentTransportType = TransportType.SERIAL
                MeshCoreSerialTransport(context)
            }
            is MeshConnection.Ble -> {
                currentTransportType = TransportType.BLE
                MeshCoreBleTransport(context)
            }
            is MeshConnection.Tcp -> {
                currentTransportType = TransportType.TCP
                MeshCoreTcpTransport()
            }
        }

        return try {
            val result = newTransport.connect(connection)

            if (result.isSuccess) {
                transport = newTransport
                _connectionState.value = MeshConnectionState.CONNECTED

                // Start forwarding events from transport
                startEventForwarding(newTransport)

                _events.emit(MeshEvent(MeshEventType.CONNECTED, connection))

                // Query device info
                try {
                    val deviceInfo = newTransport.getDeviceInfo().getOrNull()
                    if (deviceInfo != null) {
                        _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, deviceInfo))
                    }
                } catch (e: Exception) {
                    // Device info query failed, but connection succeeded
                }

                Result.success(Unit)
            } else {
                _connectionState.value = MeshConnectionState.ERROR
                currentTransportType = null
                _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, result.exceptionOrNull()?.message))
                result
            }
        } catch (e: Exception) {
            _connectionState.value = MeshConnectionState.ERROR
            currentTransportType = null
            _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, e.message))
            Result.failure(e)
        }
    }

    /**
     * Connect to the first available USB Serial device.
     *
     * Convenience method that auto-discovers and connects to USB LoRa devices.
     *
     * @param baudRate Baud rate (default 115200)
     * @return Result indicating success or failure
     */
    suspend fun connectToFirstUsbDevice(baudRate: Int = 115200): Result<Unit> {
        val devices = getAvailableUsbDevices()

        if (devices.isEmpty()) {
            return Result.failure(java.io.IOException("No USB serial devices found. Connect an ESP32 LoRa device via USB-C."))
        }

        // Prefer devices with permission already granted
        val device = devices.firstOrNull { it.hasPermission } ?: devices.first()

        return connect(MeshConnection.Serial(device.deviceName, baudRate))
    }

    /**
     * Connect to the first available BLE MeshCore device.
     *
     * Scans for BLE devices advertising the MeshCore service and connects
     * to the first one found.
     *
     * @param scanTimeoutMs How long to scan for devices
     * @param pin Optional PIN for pairing
     * @return Result indicating success or failure
     */
    suspend fun connectToFirstBleDevice(
        scanTimeoutMs: Long = 10000,
        pin: String? = null
    ): Result<Unit> {
        _connectionState.value = MeshConnectionState.CONNECTING
        _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "Scanning for BLE MeshCore devices..."))

        return try {
            // Use the BLE scanner
            val scanner = getOrCreateBleScanner()
            val devices = scanner.scanForDevices(scanTimeoutMs)

            if (devices.isEmpty()) {
                _connectionState.value = MeshConnectionState.ERROR
                Result.failure(java.io.IOException("No BLE MeshCore devices found. Ensure your device is powered on and in range."))
            } else {
                // Prefer devices that advertise MeshCore service
                val device = devices.firstOrNull { it.hasMeshCoreService } ?: devices.first()
                _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, "Found device: ${device.name ?: device.address}"))

                connect(MeshConnection.Ble(device.address, pin))
            }
        } catch (e: Exception) {
            _connectionState.value = MeshConnectionState.ERROR
            Result.failure(e)
        }
    }

    /**
     * Connect to a TCP relay server.
     *
     * @param host Relay server hostname or IP
     * @param port Port number (default 4000)
     * @return Result indicating success or failure
     */
    suspend fun connectToRelay(host: String, port: Int = 4000): Result<Unit> {
        return connect(MeshConnection.Tcp(host, port))
    }

    /**
     * Start forwarding events from the transport to our event flow.
     */
    private fun startEventForwarding(transport: MeshCoreTransport) {
        eventForwardingJob?.cancel()
        eventForwardingJob = scope.launch {
            transport.events.collect { event ->
                _events.emit(event)
            }
        }
    }

    /**
     * Disconnect from the current device.
     */
    suspend fun disconnect() {
        eventForwardingJob?.cancel()
        eventForwardingJob = null

        transport?.disconnect()
        transport = null
        currentTransportType = null
        _connectionState.value = MeshConnectionState.DISCONNECTED
        _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
    }

    /**
     * Send an encrypted message to a contact.
     *
     * The content should already be encrypted by BedrockCore.
     *
     * @param recipientPublicKey Recipient's public key for addressing
     * @param encryptedContent Pre-encrypted message content
     * @return Message ID for tracking, or failure
     */
    suspend fun sendEncryptedMessage(recipientPublicKey: ByteArray, encryptedContent: ByteArray): Result<String> {
        val t = transport ?: return Result.failure(Exception("Not connected to MeshCore device"))
        return t.sendMessageWithRetry(recipientPublicKey, encryptedContent)
    }

    /**
     * Transfer a file or artifact to a recipient over the mesh network.
     *
     * This handles chunking large files, tracking progress, and retrying
     * failed chunks.
     *
     * @param recipientPublicKey Recipient's public key
     * @param data File data to transfer
     * @param metadata Optional metadata (filename, type, etc.)
     * @param onProgress Progress callback
     * @return Result with transfer ID on success
     */
    suspend fun transferFile(
        recipientPublicKey: ByteArray,
        data: ByteArray,
        metadata: Map<String, String> = emptyMap(),
        onProgress: ((TransferProgress) -> Unit)? = null
    ): Result<String> {
        val t = transport ?: return Result.failure(Exception("Not connected to MeshCore device"))

        val transferId = java.util.UUID.randomUUID().toString()
        val totalBytes = data.size.toLong()

        // Update initial progress
        val initialProgress = TransferProgress(
            transferId = transferId,
            totalBytes = totalBytes,
            sentBytes = 0,
            status = TransferStatus.PENDING
        )
        _transferProgress.value = initialProgress
        onProgress?.invoke(initialProgress)

        return try {
            // Chunk size based on transport type
            val chunkSize = when (currentTransportType) {
                TransportType.SERIAL -> 200  // Conservative for LoRa
                TransportType.BLE -> 500     // MTU-dependent
                TransportType.TCP -> 4096    // Larger chunks for TCP
                null -> 200
            }

            var sentBytes = 0L
            var chunkIndex = 0
            val totalChunks = (data.size + chunkSize - 1) / chunkSize

            // Send header with metadata
            val headerPayload = buildTransferHeader(transferId, totalBytes, totalChunks, metadata)
            val headerResult = t.sendMessageWithRetry(recipientPublicKey, headerPayload)
            if (headerResult.isFailure) {
                throw headerResult.exceptionOrNull() ?: Exception("Failed to send transfer header")
            }

            // Update progress to in-progress
            val inProgressStatus = TransferProgress(
                transferId = transferId,
                totalBytes = totalBytes,
                sentBytes = sentBytes,
                status = TransferStatus.IN_PROGRESS
            )
            _transferProgress.value = inProgressStatus
            onProgress?.invoke(inProgressStatus)

            // Send chunks
            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + chunkSize, data.size)
                val chunk = data.copyOfRange(offset, end)

                // Build chunk payload: [transferId:16][chunkIndex:4][chunk data]
                val chunkPayload = buildChunkPayload(transferId, chunkIndex, chunk)

                val result = t.sendMessageWithRetry(recipientPublicKey, chunkPayload)
                if (result.isFailure) {
                    throw result.exceptionOrNull() ?: Exception("Failed to send chunk $chunkIndex")
                }

                offset = end
                sentBytes = offset.toLong()
                chunkIndex++

                // Update progress
                val progress = TransferProgress(
                    transferId = transferId,
                    totalBytes = totalBytes,
                    sentBytes = sentBytes,
                    status = TransferStatus.IN_PROGRESS
                )
                _transferProgress.value = progress
                onProgress?.invoke(progress)

                // Small delay between chunks to avoid overwhelming the radio
                kotlinx.coroutines.delay(50)
            }

            // Send completion marker
            val completionPayload = buildCompletionPayload(transferId)
            t.sendMessageWithRetry(recipientPublicKey, completionPayload)

            // Final progress update
            val completedProgress = TransferProgress(
                transferId = transferId,
                totalBytes = totalBytes,
                sentBytes = totalBytes,
                status = TransferStatus.COMPLETED
            )
            _transferProgress.value = completedProgress
            onProgress?.invoke(completedProgress)

            Result.success(transferId)

        } catch (e: Exception) {
            val failedProgress = TransferProgress(
                transferId = transferId,
                totalBytes = totalBytes,
                sentBytes = _transferProgress.value?.sentBytes ?: 0,
                status = TransferStatus.FAILED,
                error = e.message
            )
            _transferProgress.value = failedProgress
            onProgress?.invoke(failedProgress)

            Result.failure(e)
        }
    }

    /**
     * Build transfer header payload.
     */
    private fun buildTransferHeader(
        transferId: String,
        totalBytes: Long,
        totalChunks: Int,
        metadata: Map<String, String>
    ): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(256)
        buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN)

        // Marker: 0x01 = header
        buffer.put(0x01)

        // Transfer ID (16 bytes)
        val idBytes = transferId.toByteArray(Charsets.UTF_8)
        buffer.put(idBytes.copyOf(16))

        // Total bytes (8 bytes)
        buffer.putLong(totalBytes)

        // Total chunks (4 bytes)
        buffer.putInt(totalChunks)

        // Metadata as JSON-like string
        val metaStr = metadata.entries.joinToString(",") { "${it.key}=${it.value}" }
        val metaBytes = metaStr.toByteArray(Charsets.UTF_8)
        buffer.putShort(metaBytes.size.toShort())
        buffer.put(metaBytes)

        return buffer.array().copyOf(buffer.position())
    }

    /**
     * Build chunk payload.
     */
    private fun buildChunkPayload(transferId: String, chunkIndex: Int, data: ByteArray): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(24 + data.size)
        buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN)

        // Marker: 0x02 = chunk
        buffer.put(0x02)

        // Transfer ID (16 bytes)
        val idBytes = transferId.toByteArray(Charsets.UTF_8)
        buffer.put(idBytes.copyOf(16))

        // Chunk index (4 bytes)
        buffer.putInt(chunkIndex)

        // Chunk size (2 bytes)
        buffer.putShort(data.size.toShort())

        // Chunk data
        buffer.put(data)

        return buffer.array().copyOf(buffer.position())
    }

    /**
     * Build completion marker payload.
     */
    private fun buildCompletionPayload(transferId: String): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(17)

        // Marker: 0x03 = completion
        buffer.put(0x03)

        // Transfer ID (16 bytes)
        val idBytes = transferId.toByteArray(Charsets.UTF_8)
        buffer.put(idBytes.copyOf(16))

        return buffer.array()
    }

    /**
     * Get the current transport (for advanced operations).
     */
    fun getTransport(): MeshCoreTransport? = transport

    /**
     * Get the current transport type.
     */
    fun getCurrentTransportType(): TransportType? = currentTransportType

    /**
     * Get the serial transport for LoRa-specific operations.
     */
    fun getSerialTransport(): MeshCoreSerialTransport? = transport as? MeshCoreSerialTransport

    /**
     * Get the BLE transport for BLE-specific operations.
     */
    fun getBleTransport(): MeshCoreBleTransport? = transport as? MeshCoreBleTransport

    /**
     * Get the TCP transport for relay-specific operations.
     */
    fun getTcpTransport(): MeshCoreTcpTransport? = transport as? MeshCoreTcpTransport

    /**
     * Configure LoRa radio parameters (serial or BLE transport).
     */
    suspend fun configureRadio(
        frequencyHz: Long = 915_000_000,
        spreadingFactor: Int = 10,
        bandwidthKhz: Int = 125,
        codingRate: Int = 1,
        txPowerDbm: Int = 20
    ): Result<Unit> {
        return when (val t = transport) {
            is MeshCoreSerialTransport -> t.configureRadio(
                frequencyHz, spreadingFactor, bandwidthKhz, codingRate, txPowerDbm
            )
            is MeshCoreBleTransport -> t.configureRadio(
                frequencyHz, spreadingFactor, bandwidthKhz, codingRate, txPowerDbm
            )
            else -> Result.failure(Exception("Radio configuration requires Serial or BLE transport"))
        }
    }

    /**
     * Transmit raw bytes over LoRa (serial or BLE transport).
     */
    suspend fun transmitRaw(data: ByteArray): Result<Unit> {
        return when (val t = transport) {
            is MeshCoreSerialTransport -> t.transmit(data)
            is MeshCoreBleTransport -> t.transmit(data)
            else -> Result.failure(Exception("Raw transmission requires Serial or BLE transport"))
        }
    }

    /**
     * Receive next packet from radio (serial or BLE transport).
     */
    suspend fun receivePacket(timeoutMs: Long = 5000): LoRaRxPacket? {
        return when (val t = transport) {
            is MeshCoreSerialTransport -> t.receivePacket(timeoutMs)
            is MeshCoreBleTransport -> t.receivePacket(timeoutMs)
            else -> null
        }
    }

    /**
     * Get list of available USB serial devices.
     */
    fun getAvailableUsbDevices(): List<UsbSerialDeviceInfo> {
        return MeshCoreSerialTransport(context).getAvailableDevices()
    }

    /**
     * Discover all available MeshCore devices across all transport types.
     *
     * @param scanBle Whether to scan for BLE devices (may require permissions)
     * @param bleScanTimeoutMs BLE scan duration
     * @param tcpRelays List of known TCP relay servers to check
     * @return List of discovered devices
     */
    suspend fun discoverDevices(
        scanBle: Boolean = true,
        bleScanTimeoutMs: Long = 5000,
        tcpRelays: List<Pair<String, Int>> = emptyList()
    ): List<DiscoveredDevice> {
        val devices = mutableListOf<DiscoveredDevice>()

        // USB Serial devices
        val usbDevices = getAvailableUsbDevices()
        devices.addAll(usbDevices.map {
            DiscoveredDevice.UsbDevice(
                deviceName = it.deviceName,
                vendorId = it.vendorId,
                productId = it.productId,
                productName = it.productName,
                manufacturer = it.manufacturer,
                hasPermission = it.hasPermission
            )
        })

        // BLE devices
        if (scanBle) {
            try {
                val scanner = getOrCreateBleScanner()
                val bleDevices = scanner.scanForDevices(bleScanTimeoutMs)
                devices.addAll(bleDevices.map {
                    DiscoveredDevice.BleDevice(
                        name = it.name,
                        address = it.address,
                        rssi = it.rssi,
                        hasMeshCoreService = it.hasMeshCoreService
                    )
                })
            } catch (e: Exception) {
                // BLE scan failed, continue with other transports
                _events.emit(MeshEvent(MeshEventType.ERROR, "BLE scan failed: ${e.message}"))
            }
        }

        // TCP relays
        for ((host, port) in tcpRelays) {
            try {
                // Quick connectivity check
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                socket.close()

                devices.add(DiscoveredDevice.TcpRelay(
                    host = host,
                    port = port,
                    name = "$host:$port"
                ))
            } catch (e: Exception) {
                // Relay not reachable
            }
        }

        return devices
    }

    /**
     * Get or create BLE scanner instance.
     */
    private fun getOrCreateBleScanner(): MeshCoreBleScanner {
        return bleScanner ?: MeshCoreBleScanner(context).also { bleScanner = it }
    }

    /**
     * Send a ping to verify connection is alive.
     *
     * @return Round-trip time in milliseconds, or failure
     */
    suspend fun ping(): Result<Long> {
        return when (val t = transport) {
            is MeshCoreSerialTransport -> t.ping().map { 0L } // Serial doesn't return RTT
            is MeshCoreBleTransport -> t.ping()
            is MeshCoreTcpTransport -> t.ping()
            null -> Result.failure(Exception("Not connected"))
            else -> Result.failure(Exception("Ping not supported"))
        }
    }

    /**
     * Get device info from connected transport.
     */
    suspend fun getDeviceInfo(): Result<DeviceInfo> {
        val t = transport ?: return Result.failure(Exception("Not connected"))
        return t.getDeviceInfo()
    }

    /**
     * Get battery status from connected device.
     */
    suspend fun getBatteryStatus(): Result<BatteryStatus> {
        val t = transport ?: return Result.failure(Exception("Not connected"))
        return t.getBatteryStatus()
    }

    /**
     * Get mesh contacts from connected device.
     */
    suspend fun getContacts(): Result<List<MeshContact>> {
        val t = transport ?: return Result.failure(Exception("Not connected"))
        return t.getContacts()
    }

    /**
     * Check if connected to a MeshCore device.
     */
    fun isConnected(): Boolean = transport?.isConnected() == true

    /**
     * Shutdown the manager and release resources.
     */
    suspend fun shutdown() {
        disconnect()
        bleScanner?.stopScan()
        scope.coroutineContext.cancelChildren()
    }

    private fun CoroutineContext.cancelChildren() {
        (this[kotlinx.coroutines.Job] as? kotlinx.coroutines.Job)?.cancel()
    }
}
