package com.yours.app.mesh

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * MeshCore Adapter - Implements UniversalMeshTransport for MeshCore protocol.
 *
 * This adapter wraps the existing MeshCoreManager to provide a unified interface
 * that can be used interchangeably with Meshtastic and Reticulum adapters.
 *
 * MeshCore Protocol:
 * - 16-bit mesh addresses + Ed25519 public keys for identity
 * - Flood-then-direct routing (learns paths after first flood)
 * - AES-128 + HMAC encryption
 * - USB Serial, BLE, or TCP transport to companion devices
 *
 * Reference: https://github.com/meshcore-dev/MeshCore
 */
class MeshCoreAdapter(
    private val context: Context
) : UniversalMeshTransport {

    private val meshManager = MeshCoreManager(context)

    // Connection state mapped from MeshCore's state
    private val _connectionState = MutableStateFlow<UniversalConnectionState>(
        UniversalConnectionState.Disconnected
    )
    override val connectionState: StateFlow<UniversalConnectionState> = _connectionState

    // Incoming messages flow
    private val _incomingMessages = MutableSharedFlow<UniversalMessage>(
        replay = 0,
        extraBufferCapacity = 64
    )
    override val incomingMessages: Flow<UniversalMessage> = _incomingMessages

    // Mesh events flow
    private val _meshEvents = MutableSharedFlow<UniversalMeshEvent>(
        replay = 0,
        extraBufferCapacity = 64
    )
    override val meshEvents: Flow<UniversalMeshEvent> = _meshEvents

    // Our local address (set after connection)
    private var localAddress: UniversalAddress? = null

    override val meshType: MeshType = MeshType.MESHCORE

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    init {
        // Forward connection state changes
        scope.launch {
            meshManager.connectionState.collect { meshState ->
                _connectionState.value = when (meshState) {
                    MeshConnectionState.DISCONNECTED -> UniversalConnectionState.Disconnected
                    MeshConnectionState.CONNECTING -> UniversalConnectionState.Connecting
                    MeshConnectionState.CONNECTED -> UniversalConnectionState.Connected
                    MeshConnectionState.ERROR -> UniversalConnectionState.Error("Connection error")
                }
            }
        }

        // Forward mesh events
        scope.launch {
            meshManager.events.collect { event ->
                when (event.type) {
                    MeshEventType.MESSAGE_RECEIVED -> {
                        val meshMsg = event.payload as? MeshMessage
                        if (meshMsg != null) {
                            val universalMsg = meshMessageToUniversal(meshMsg)
                            _incomingMessages.emit(universalMsg)
                        }
                    }
                    MeshEventType.MESSAGE_SENT -> {
                        val msgId = event.payload as? String
                        if (msgId != null) {
                            _meshEvents.emit(UniversalMeshEvent.MessageDelivered(msgId))
                        }
                    }
                    MeshEventType.MESSAGE_FAILED -> {
                        val msgId = event.payload as? String
                        if (msgId != null) {
                            _meshEvents.emit(UniversalMeshEvent.MessageFailed(msgId, "Send failed"))
                        }
                    }
                    MeshEventType.CONTACT_DISCOVERED -> {
                        val contact = event.payload as? MeshContact
                        if (contact != null) {
                            val addr = meshContactToUniversalAddress(contact)
                            _meshEvents.emit(UniversalMeshEvent.PeerDiscovered(addr))
                        }
                    }
                    MeshEventType.DEVICE_INFO -> {
                        val info = event.payload as? DeviceInfo
                        if (info != null) {
                            val deviceInfo = meshDeviceInfoToUniversal(info)
                            _meshEvents.emit(UniversalMeshEvent.DeviceStatusChanged(deviceInfo))
                        }
                    }
                    else -> { /* Ignore other events */ }
                }
            }
        }
    }

    override suspend fun connect(config: MeshConnectionConfig): Result<Unit> {
        val meshConnection = when (config) {
            is MeshConnectionConfig.UsbSerial -> MeshConnection.Serial(config.devicePath, config.baudRate)
            is MeshConnectionConfig.Ble -> MeshConnection.Ble(config.macAddress, config.pin)
            is MeshConnectionConfig.Tcp -> MeshConnection.Tcp(config.host, config.port)
            is MeshConnectionConfig.WifiDirect -> {
                return Result.failure(UnsupportedOperationException("WiFi Direct not supported by MeshCore"))
            }
        }

        val result = meshManager.connect(meshConnection)

        if (result.isSuccess) {
            // Get device info to populate local address
            val deviceInfo = meshManager.getDeviceInfo().getOrNull()
            if (deviceInfo != null) {
                localAddress = UniversalAddress(
                    did = "did:mesh:${deviceInfo.nodeIdHex}",
                    publicKey = deviceInfo.nodeId,
                    meshcoreAddr = bytesToShort(deviceInfo.nodeId.take(2).toByteArray())
                )
            }
        }

        return result
    }

    override suspend fun disconnect() {
        meshManager.disconnect()
        localAddress = null
    }

    override suspend fun sendMessage(message: UniversalMessage): Result<String> {
        val recipientKey = message.recipient.publicKey

        return meshManager.sendEncryptedMessage(recipientKey, message.payload).map { messageId ->
            messageId
        }
    }

    override suspend fun getDeviceInfo(): Result<MeshDeviceInfo> {
        return meshManager.getDeviceInfo().map { info ->
            meshDeviceInfoToUniversal(info)
        }
    }

    override suspend fun discoverPeers(timeout: Long): Result<List<UniversalAddress>> {
        return meshManager.getContacts().map { contacts ->
            contacts.map { meshContactToUniversalAddress(it) }
        }
    }

    override suspend fun pingPeer(address: UniversalAddress): Result<Long> {
        // MeshCore doesn't have direct peer ping, use device ping as fallback
        return meshManager.ping()
    }

    // =========================================================================
    // CONVERSION HELPERS
    // =========================================================================

    private fun meshMessageToUniversal(msg: MeshMessage): UniversalMessage {
        return UniversalMessage(
            id = msg.messageId,
            sender = UniversalAddress(
                did = "did:mesh:${msg.from.toHex()}",
                publicKey = msg.from
            ),
            recipient = UniversalAddress(
                did = "did:mesh:${msg.to.toHex()}",
                publicKey = msg.to
            ),
            payload = msg.content,
            timestamp = msg.timestamp,
            meshType = MeshType.MESHCORE
        )
    }

    private fun meshContactToUniversalAddress(contact: MeshContact): UniversalAddress {
        return UniversalAddress(
            did = "did:mesh:${contact.publicKeyHex}",
            publicKey = contact.publicKey,
            meshcoreAddr = bytesToShort(contact.publicKey.take(2).toByteArray())
        )
    }

    private fun meshDeviceInfoToUniversal(info: DeviceInfo): MeshDeviceInfo {
        return MeshDeviceInfo(
            meshType = MeshType.MESHCORE,
            deviceName = info.meshName ?: "MeshCore Device",
            firmwareVersion = info.firmwareVersion,
            hardwareModel = info.hardwareType,
            localAddress = localAddress
        )
    }

    private fun bytesToShort(bytes: ByteArray): Short {
        if (bytes.size < 2) return 0
        return ((bytes[0].toInt() and 0xFF) shl 8 or (bytes[1].toInt() and 0xFF)).toShort()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    // =========================================================================
    // MESHCORE-SPECIFIC METHODS
    // =========================================================================

    /**
     * Get the underlying MeshCoreManager for MeshCore-specific operations.
     */
    fun getMeshCoreManager(): MeshCoreManager = meshManager

    /**
     * Configure LoRa radio parameters (MeshCore-specific).
     */
    suspend fun configureRadio(
        frequencyHz: Long = 915_000_000,
        spreadingFactor: Int = 10,
        bandwidthKhz: Int = 125,
        codingRate: Int = 1,
        txPowerDbm: Int = 20
    ): Result<Unit> {
        return meshManager.configureRadio(
            frequencyHz, spreadingFactor, bandwidthKhz, codingRate, txPowerDbm
        )
    }

    /**
     * Transfer a file over MeshCore mesh (MeshCore-specific chunked transfer).
     */
    suspend fun transferFile(
        recipient: UniversalAddress,
        data: ByteArray,
        metadata: Map<String, String> = emptyMap(),
        onProgress: ((TransferProgress) -> Unit)? = null
    ): Result<String> {
        return meshManager.transferFile(recipient.publicKey, data, metadata, onProgress)
    }

    /**
     * Discover MeshCore devices (USB, BLE, TCP).
     */
    suspend fun discoverDevices(
        scanBle: Boolean = true,
        bleScanTimeoutMs: Long = 5000,
        tcpRelays: List<Pair<String, Int>> = emptyList()
    ): List<DiscoveredDevice> {
        return meshManager.discoverDevices(scanBle, bleScanTimeoutMs, tcpRelays)
    }

    /**
     * Get battery status from connected device.
     */
    suspend fun getBatteryStatus(): Result<BatteryStatus> {
        return meshManager.getBatteryStatus()
    }
}

