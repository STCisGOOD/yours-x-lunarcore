package com.yours.app.mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Meshtastic Adapter - Implements UniversalMeshTransport for Meshtastic protocol.
 *
 * Meshtastic is a popular open-source LoRa mesh network with a large community.
 * This adapter allows Yours app to communicate over Meshtastic networks.
 *
 * Protocol Details:
 * - BLE Service UUID: 6ba1b218-15a8-461f-9fa8-5dcae273eafd
 * - Serial framing: 0x94 0xC3 + LEN(2 bytes BE) + protobuf payload
 * - Encryption: AES-256-CTR with channel PSK
 * - Routing: Flooding with hop_limit
 *
 * Reference: https://meshtastic.org/docs/development/device/
 */
class MeshtasticAdapter(
    private val context: Context
) : UniversalMeshTransport {

    companion object {
        private const val TAG = "MeshtasticAdapter"

        // Meshtastic BLE UUIDs
        val SERVICE_UUID: UUID = UUID.fromString("6ba1b218-15a8-461f-9fa8-5dcae273eafd")
        val FROM_RADIO_UUID: UUID = UUID.fromString("2c55e69e-4993-11ed-b878-0242ac120002")
        val TO_RADIO_UUID: UUID = UUID.fromString("f75c76d2-129e-4dad-a1dd-7866124401e7")
        val FROM_NUM_UUID: UUID = UUID.fromString("ed9da18c-a800-4f66-a670-aa7547e34453")

        // Serial framing magic bytes
        const val MAGIC_BYTE_1: Byte = 0x94.toByte()
        const val MAGIC_BYTE_2: Byte = 0xC3.toByte()

        // MTU for BLE
        const val DEFAULT_MTU = 512
    }

    override val meshType: MeshType = MeshType.MESHTASTIC

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

    // BLE components
    private var bluetoothGatt: BluetoothGatt? = null
    private var fromRadioCharacteristic: BluetoothGattCharacteristic? = null
    private var toRadioCharacteristic: BluetoothGattCharacteristic? = null
    private var fromNumCharacteristic: BluetoothGattCharacteristic? = null

    // Local node info
    private var localNodeNum: Long? = null
    private var localAddress: UniversalAddress? = null

    // Receive buffer for accumulating fragmented messages
    private val receiveBuffer = ByteArrayOutputStream()

    // Write queue for BLE operations (BLE can only handle one write at a time)
    private val writeQueue = ConcurrentLinkedQueue<ByteArray>()
    private var isWriting = false

    // Coroutine scope
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // =========================================================================
    // UniversalMeshTransport Implementation
    // =========================================================================

    @SuppressLint("MissingPermission")
    override suspend fun connect(config: MeshConnectionConfig): Result<Unit> {
        return when (config) {
            is MeshConnectionConfig.Ble -> connectBle(config.macAddress)
            is MeshConnectionConfig.UsbSerial -> connectSerial(config.devicePath, config.baudRate)
            else -> Result.failure(UnsupportedOperationException(
                "Meshtastic adapter only supports BLE and USB Serial connections"
            ))
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun disconnect() {
        bluetoothGatt?.let { gatt ->
            gatt.disconnect()
            gatt.close()
        }
        bluetoothGatt = null
        fromRadioCharacteristic = null
        toRadioCharacteristic = null
        fromNumCharacteristic = null
        localNodeNum = null
        localAddress = null
        receiveBuffer.reset()
        writeQueue.clear()
        isWriting = false
        _connectionState.value = UniversalConnectionState.Disconnected
    }

    override suspend fun sendMessage(message: UniversalMessage): Result<String> {
        val toRadio = toRadioCharacteristic
            ?: return Result.failure(IllegalStateException("Not connected to Meshtastic device"))

        // Build Meshtastic packet
        // For now, we'll send as a text message through the TEXT_MESSAGE_APP port
        val packet = buildMeshtasticPacket(message)

        return try {
            writeToRadio(packet)
            Result.success(message.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    override suspend fun getDeviceInfo(): Result<MeshDeviceInfo> {
        return Result.success(MeshDeviceInfo(
            meshType = MeshType.MESHTASTIC,
            deviceName = "Meshtastic Device",
            firmwareVersion = "Unknown", // Would need to query MyNodeInfo
            hardwareModel = null,
            localAddress = localAddress
        ))
    }

    override suspend fun discoverPeers(timeout: Long): Result<List<UniversalAddress>> {
        // Meshtastic nodes are discovered via NodeInfo messages
        // For now, return empty - would need to implement NodeDB
        return Result.success(emptyList())
    }

    override suspend fun pingPeer(address: UniversalAddress): Result<Long> {
        // Meshtastic doesn't have a direct ping, but we could send a traceroute
        return Result.failure(UnsupportedOperationException("Ping not implemented for Meshtastic"))
    }

    // =========================================================================
    // BLE Connection
    // =========================================================================

    @SuppressLint("MissingPermission")
    private suspend fun connectBle(macAddress: String): Result<Unit> = suspendCancellableCoroutine { cont ->
        _connectionState.value = UniversalConnectionState.Connecting

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
            _connectionState.value = UniversalConnectionState.Error("Bluetooth not available")
            cont.resume(Result.failure(IllegalStateException("Bluetooth not available")))
            return@suspendCancellableCoroutine
        }

        val device = try {
            bluetoothAdapter.getRemoteDevice(macAddress)
        } catch (e: Exception) {
            _connectionState.value = UniversalConnectionState.Error("Invalid MAC address")
            cont.resume(Result.failure(e))
            return@suspendCancellableCoroutine
        }

        val gattCallback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        Log.i(TAG, "Connected to Meshtastic device")
                        bluetoothGatt = gatt
                        // Request higher MTU for larger packets
                        gatt.requestMtu(DEFAULT_MTU)
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        Log.i(TAG, "Disconnected from Meshtastic device")
                        _connectionState.value = UniversalConnectionState.Disconnected
                        scope.launch {
                            _meshEvents.emit(UniversalMeshEvent.DeviceStatusChanged(
                                MeshDeviceInfo(
                                    meshType = MeshType.MESHTASTIC,
                                    deviceName = "Disconnected",
                                    firmwareVersion = ""
                                )
                            ))
                        }
                        if (cont.isActive) {
                            cont.resume(Result.failure(Exception("Connection failed")))
                        }
                    }
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                Log.i(TAG, "MTU changed to $mtu, status=$status")
                // Now discover services
                gatt.discoverServices()
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Log.e(TAG, "Service discovery failed: $status")
                    _connectionState.value = UniversalConnectionState.Error("Service discovery failed")
                    if (cont.isActive) {
                        cont.resume(Result.failure(Exception("Service discovery failed")))
                    }
                    return
                }

                val service = gatt.getService(SERVICE_UUID)
                if (service == null) {
                    Log.e(TAG, "Meshtastic service not found")
                    _connectionState.value = UniversalConnectionState.Error("Not a Meshtastic device")
                    if (cont.isActive) {
                        cont.resume(Result.failure(Exception("Meshtastic service not found")))
                    }
                    return
                }

                // Get characteristics
                fromRadioCharacteristic = service.getCharacteristic(FROM_RADIO_UUID)
                toRadioCharacteristic = service.getCharacteristic(TO_RADIO_UUID)
                fromNumCharacteristic = service.getCharacteristic(FROM_NUM_UUID)

                if (fromRadioCharacteristic == null || toRadioCharacteristic == null) {
                    Log.e(TAG, "Required characteristics not found")
                    _connectionState.value = UniversalConnectionState.Error("Invalid Meshtastic device")
                    if (cont.isActive) {
                        cont.resume(Result.failure(Exception("Required characteristics not found")))
                    }
                    return
                }

                // Enable notifications on fromNum (message counter)
                fromNumCharacteristic?.let { char ->
                    gatt.setCharacteristicNotification(char, true)
                    val descriptor = char.getDescriptor(
                        UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                    )
                    descriptor?.let {
                        it.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        gatt.writeDescriptor(it)
                    }
                }

                Log.i(TAG, "Meshtastic service discovered, connection complete")
                _connectionState.value = UniversalConnectionState.Connected
                if (cont.isActive) {
                    cont.resume(Result.success(Unit))
                }

                // Start reading fromRadio to get initial state
                scope.launch {
                    delay(500) // Give time for descriptor write
                    // Request config to get node info and mesh state
                    requestConfig()
                    delay(200)
                    readFromRadio()
                }
            }

            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == FROM_RADIO_UUID) {
                    val data = characteristic.value
                    if (data != null && data.isNotEmpty()) {
                        handleFromRadioData(data)
                        // Continue reading if there's more data
                        scope.launch {
                            delay(100)
                            readFromRadio()
                        }
                    }
                }
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic
            ) {
                when (characteristic.uuid) {
                    FROM_NUM_UUID -> {
                        // New message available, read fromRadio
                        scope.launch { readFromRadio() }
                    }
                    FROM_RADIO_UUID -> {
                        characteristic.value?.let { handleFromRadioData(it) }
                    }
                }
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                isWriting = false
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Log.e(TAG, "Write failed: $status")
                }
                // Process next item in queue
                processWriteQueue()
            }
        }

        // Connect to device
        val gatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        } else {
            device.connectGatt(context, false, gattCallback)
        }

        cont.invokeOnCancellation {
            gatt.disconnect()
            gatt.close()
        }
    }

    @SuppressLint("MissingPermission")
    private fun readFromRadio() {
        val gatt = bluetoothGatt ?: return
        val char = fromRadioCharacteristic ?: return
        gatt.readCharacteristic(char)
    }

    @SuppressLint("MissingPermission")
    private fun processWriteQueue() {
        if (isWriting) return
        val data = writeQueue.poll() ?: return

        val gatt = bluetoothGatt ?: return
        val char = toRadioCharacteristic ?: return

        isWriting = true
        char.value = data
        char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        gatt.writeCharacteristic(char)
    }

    private fun writeToRadio(data: ByteArray) {
        // Frame the data with Meshtastic serial framing
        val framed = frameSerialData(data)
        writeQueue.add(framed)
        processWriteQueue()
    }

    // =========================================================================
    // Serial Connection (USB)
    // =========================================================================

    private suspend fun connectSerial(devicePath: String, baudRate: Int): Result<Unit> {
        // Similar to MeshCore but with Meshtastic framing
        return Result.failure(UnsupportedOperationException(
            "USB Serial not yet implemented for Meshtastic"
        ))
    }

    // =========================================================================
    // Protocol Handling
    // =========================================================================

    /**
     * Handle data received from the FromRadio characteristic.
     * This contains protobuf-encoded FromRadio messages.
     */
    private fun handleFromRadioData(data: ByteArray) {
        Log.d(TAG, "Received ${data.size} bytes from radio")

        try {
            val fromRadio = MeshtasticProtobuf.decodeFromRadio(data)
            Log.d(TAG, "Decoded FromRadio: $fromRadio")

            when (fromRadio) {
                is MeshtasticProtobuf.FromRadio.Packet -> {
                    val packet = fromRadio.packet
                    Log.d(TAG, "Received packet from=${packet.from}, to=${packet.to}, id=${packet.id}")

                    // Convert to UniversalMessage
                    val decoded = packet.decoded
                    if (decoded != null) {
                        val message = UniversalMessage(
                            id = packet.id.toString(),
                            sender = UniversalAddress(
                                did = "did:meshtastic:${packet.from.toString(16)}",
                                publicKey = ByteArray(0), // Meshtastic uses node numbers, not public keys
                                meshtasticId = packet.from
                            ),
                            recipient = UniversalAddress(
                                did = "did:meshtastic:${packet.to.toString(16)}",
                                publicKey = ByteArray(0),
                                meshtasticId = packet.to
                            ),
                            payload = decoded.payload,
                            timestamp = if (packet.rxTime > 0) packet.rxTime * 1000 else System.currentTimeMillis(),
                            meshType = MeshType.MESHTASTIC,
                            metadata = MessageMetadata(
                                rssi = packet.rxRssi,
                                snr = packet.rxSnr,
                                hopCount = 3 - packet.hopLimit // Estimate hops taken
                            )
                        )

                        scope.launch {
                            _incomingMessages.emit(message)
                        }
                    }
                }

                is MeshtasticProtobuf.FromRadio.MyInfo -> {
                    val info = fromRadio.info
                    Log.i(TAG, "Received MyNodeInfo: nodeNum=${info.myNodeNum}, fw=${info.firmwareVersion}")
                    localNodeNum = info.myNodeNum
                    localAddress = UniversalAddress(
                        did = "did:meshtastic:${info.myNodeNum.toString(16)}",
                        publicKey = ByteArray(0),
                        meshtasticId = info.myNodeNum
                    )

                    scope.launch {
                        _meshEvents.emit(UniversalMeshEvent.DeviceStatusChanged(
                            MeshDeviceInfo(
                                meshType = MeshType.MESHTASTIC,
                                deviceName = "Meshtastic Node",
                                firmwareVersion = info.firmwareVersion,
                                localAddress = localAddress
                            )
                        ))
                    }
                }

                is MeshtasticProtobuf.FromRadio.NodeInfoMsg -> {
                    val nodeInfo = fromRadio.info
                    Log.d(TAG, "Received NodeInfo: num=${nodeInfo.num}, user=${nodeInfo.user?.longName}")

                    val peerAddress = UniversalAddress(
                        did = "did:meshtastic:${nodeInfo.num.toString(16)}",
                        publicKey = ByteArray(0),
                        meshtasticId = nodeInfo.num
                    )

                    scope.launch {
                        _meshEvents.emit(UniversalMeshEvent.PeerDiscovered(peerAddress))
                    }
                }

                is MeshtasticProtobuf.FromRadio.ConfigComplete -> {
                    Log.i(TAG, "Config complete: id=${fromRadio.id}")
                }

                is MeshtasticProtobuf.FromRadio.Rebooted -> {
                    Log.w(TAG, "Device rebooted")
                }

                is MeshtasticProtobuf.FromRadio.Unknown -> {
                    Log.d(TAG, "Unknown FromRadio message type")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling fromRadio data", e)
        }
    }

    /**
     * Build a Meshtastic packet from a UniversalMessage.
     *
     * This creates a ToRadio protobuf message containing a MeshPacket.
     * Uses PRIVATE_APP port for our encrypted payloads to avoid interference
     * with regular Meshtastic text messages.
     */
    private fun buildMeshtasticPacket(message: UniversalMessage): ByteArray {
        val destinationNodeNum = message.recipient.meshtasticId ?: 0xFFFFFFFF // Broadcast if unknown

        // Create a ToRadio message with our encrypted payload
        val toRadio = MeshtasticProtobuf.createPrivateMessage(
            payload = message.payload,
            to = destinationNodeNum,
            channel = 0, // Primary channel
            wantAck = true
        )

        return MeshtasticProtobuf.encodeToRadio(toRadio)
    }

    /**
     * Send a text message over Meshtastic.
     * This is a convenience method for sending plaintext to Meshtastic users.
     */
    suspend fun sendTextMessage(text: String, to: Long = 0xFFFFFFFF): Result<String> {
        val toRadio = MeshtasticProtobuf.createTextMessage(
            text = text,
            to = to,
            channel = 0,
            wantAck = true
        )

        val encoded = MeshtasticProtobuf.encodeToRadio(toRadio)
        return try {
            writeToRadio(encoded)
            Result.success(System.currentTimeMillis().toString())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Request device configuration.
     * Call this after connecting to get node info and mesh state.
     */
    suspend fun requestConfig() {
        val toRadio = MeshtasticProtobuf.createWantConfig(
            configId = System.currentTimeMillis() and 0xFFFFFFFF
        )
        val encoded = MeshtasticProtobuf.encodeToRadio(toRadio)
        writeToRadio(encoded)
    }

    /**
     * Frame data with Meshtastic serial protocol.
     * Format: 0x94 0xC3 + LEN(2 bytes, big-endian) + payload
     */
    private fun frameSerialData(payload: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(4 + payload.size)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(MAGIC_BYTE_1)
        buffer.put(MAGIC_BYTE_2)
        buffer.putShort(payload.size.toShort())
        buffer.put(payload)
        return buffer.array()
    }

    /**
     * Parse Meshtastic serial framing.
     * Returns the payload if a complete frame is found, null otherwise.
     */
    private fun parseSerialFrame(buffer: ByteArray): Pair<ByteArray?, Int>? {
        if (buffer.size < 4) return null

        if (buffer[0] != MAGIC_BYTE_1 || buffer[1] != MAGIC_BYTE_2) {
            return null // Invalid magic
        }

        val length = ((buffer[2].toInt() and 0xFF) shl 8) or (buffer[3].toInt() and 0xFF)
        if (buffer.size < 4 + length) return null // Incomplete

        val payload = buffer.copyOfRange(4, 4 + length)
        return Pair(payload, 4 + length)
    }

    // =========================================================================
    // Device Discovery
    // =========================================================================

    /**
     * Scan for Meshtastic devices via BLE.
     */
    @SuppressLint("MissingPermission")
    suspend fun scanForDevices(timeoutMs: Long = 10000): List<MeshtasticDeviceInfo> =
        suspendCancellableCoroutine { cont ->
            val devices = mutableListOf<MeshtasticDeviceInfo>()
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val scanner = bluetoothManager.adapter?.bluetoothLeScanner

            if (scanner == null) {
                cont.resume(emptyList())
                return@suspendCancellableCoroutine
            }

            val callback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    val device = result.device
                    val name = device.name ?: "Unknown"
                    val address = device.address

                    // Check if it advertises the Meshtastic service
                    val hasMeshtasticService = result.scanRecord?.serviceUuids?.any {
                        it.uuid == SERVICE_UUID
                    } ?: false

                    if (hasMeshtasticService || name.contains("Meshtastic", ignoreCase = true)) {
                        val info = MeshtasticDeviceInfo(
                            name = name,
                            macAddress = address,
                            rssi = result.rssi
                        )
                        if (devices.none { it.macAddress == address }) {
                            devices.add(info)
                            Log.d(TAG, "Found Meshtastic device: $name ($address)")
                        }
                    }
                }

                override fun onScanFailed(errorCode: Int) {
                    Log.e(TAG, "Scan failed: $errorCode")
                }
            }

            val scanFilter = ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(SERVICE_UUID))
                .build()

            val scanSettings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()

            // Also scan without filter to catch devices that don't advertise the UUID
            scanner.startScan(listOf(scanFilter), scanSettings, callback)

            // Stop scan after timeout
            scope.launch {
                delay(timeoutMs)
                scanner.stopScan(callback)
                cont.resume(devices)
            }

            cont.invokeOnCancellation {
                scanner.stopScan(callback)
            }
        }
}

/**
 * Information about a discovered Meshtastic device.
 */
data class MeshtasticDeviceInfo(
    val name: String,
    val macAddress: String,
    val rssi: Int
)

/**
 * ByteArrayOutputStream for accumulating received data.
 */
private class ByteArrayOutputStream {
    private var buffer = ByteArray(1024)
    private var count = 0

    fun write(data: ByteArray) {
        ensureCapacity(count + data.size)
        System.arraycopy(data, 0, buffer, count, data.size)
        count += data.size
    }

    fun toByteArray(): ByteArray = buffer.copyOf(count)

    fun reset() {
        count = 0
    }

    private fun ensureCapacity(minCapacity: Int) {
        if (minCapacity > buffer.size) {
            val newSize = maxOf(buffer.size * 2, minCapacity)
            buffer = buffer.copyOf(newSize)
        }
    }
}
