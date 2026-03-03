package com.yours.app.mesh

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * Universal Mesh Abstraction Layer
 *
 * Allows the Yours app to communicate over any supported mesh network:
 * - MeshCore (current implementation)
 * - Meshtastic (Phase 2)
 * - Reticulum (Phase 3)
 *
 * The user selects which mesh network to use, and everything else works transparently.
 * Messages are encrypted at the application layer (Double Ratchet) regardless of
 * which mesh transport is used.
 */

// =============================================================================
// MESH TYPES
// =============================================================================

/**
 * Supported mesh network types.
 */
enum class MeshType {
    MESHCORE,       // MeshCore protocol (current)
    MESHTASTIC,     // Meshtastic protocol (Phase 2)
    RETICULUM;      // Reticulum/LXMF protocol (Phase 3)

    fun displayName(): String = when (this) {
        MESHCORE -> "MeshCore"
        MESHTASTIC -> "Meshtastic"
        RETICULUM -> "Reticulum"
    }

    fun description(): String = when (this) {
        MESHCORE -> "Lightweight mesh with flood-then-direct routing"
        MESHTASTIC -> "Popular LoRa mesh with large community"
        RETICULUM -> "Cryptography-based delay-tolerant networking"
    }
}

// =============================================================================
// CONNECTION STATE
// =============================================================================

/**
 * Universal connection state across all mesh types.
 */
sealed class UniversalConnectionState {
    object Disconnected : UniversalConnectionState()
    object Connecting : UniversalConnectionState()
    object Connected : UniversalConnectionState()
    data class Error(val message: String) : UniversalConnectionState()
}

// =============================================================================
// ADDRESSING
// =============================================================================

/**
 * Universal address that can represent identity across all mesh types.
 *
 * Each mesh has different addressing:
 * - MeshCore: 32-byte Ed25519 public key + 2-byte mesh address
 * - Meshtastic: 32-bit node number
 * - Reticulum: 16-byte destination hash
 *
 * Our DID serves as the canonical identity, with mesh-specific addresses derived.
 */
data class UniversalAddress(
    val did: String,                    // Our DID format (canonical identity)
    val publicKey: ByteArray,           // Ed25519 public key (32 bytes)
    val meshcoreAddr: Short? = null,    // MeshCore 16-bit mesh address
    val meshtasticId: Long? = null,     // Meshtastic 32-bit node number
    val reticulumHash: ByteArray? = null // Reticulum 16-byte destination hash
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UniversalAddress) return false
        return did == other.did
    }

    override fun hashCode(): Int = did.hashCode()

    /**
     * Get the mesh-specific address for a given mesh type.
     */
    fun getAddressFor(meshType: MeshType): ByteArray? = when (meshType) {
        MeshType.MESHCORE -> meshcoreAddr?.let {
            byteArrayOf((it.toInt() shr 8).toByte(), it.toByte())
        } ?: publicKey
        MeshType.MESHTASTIC -> meshtasticId?.let {
            byteArrayOf(
                (it shr 24).toByte(),
                (it shr 16).toByte(),
                (it shr 8).toByte(),
                it.toByte()
            )
        }
        MeshType.RETICULUM -> reticulumHash
    }
}

// =============================================================================
// MESSAGES
// =============================================================================

/**
 * Universal message format that works across all mesh types.
 *
 * Application-layer encryption (Double Ratchet) is applied before
 * the message reaches the mesh layer, ensuring E2E security
 * regardless of mesh transport.
 */
data class UniversalMessage(
    val id: String,                     // Unique message ID
    val sender: UniversalAddress,       // Sender's universal address
    val recipient: UniversalAddress,    // Recipient's universal address
    val payload: ByteArray,             // Encrypted payload (app-layer encryption)
    val timestamp: Long,                // Unix timestamp (millis)
    val meshType: MeshType,             // Which mesh this was sent/received on
    val metadata: MessageMetadata = MessageMetadata()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UniversalMessage) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * Additional metadata about a message.
 */
data class MessageMetadata(
    val hopCount: Int = 0,              // Number of hops traversed
    val rssi: Int? = null,              // Signal strength (if available)
    val snr: Float? = null,             // Signal-to-noise ratio (if available)
    val relayPath: List<String>? = null // Path through relays (if known)
)

// =============================================================================
// DEVICE INFO
// =============================================================================

/**
 * Information about a connected mesh device.
 */
data class MeshDeviceInfo(
    val meshType: MeshType,
    val deviceName: String,
    val firmwareVersion: String,
    val hardwareModel: String? = null,
    val batteryLevel: Int? = null,      // 0-100 percentage
    val isCharging: Boolean? = null,
    val localAddress: UniversalAddress? = null
)

// =============================================================================
// TRANSPORT INTERFACE
// =============================================================================

/**
 * Universal mesh transport interface.
 *
 * All mesh implementations (MeshCore, Meshtastic, Reticulum) implement this
 * interface, allowing the app to work transparently with any mesh type.
 */
interface UniversalMeshTransport {

    /**
     * The type of mesh this transport handles.
     */
    val meshType: MeshType

    /**
     * Current connection state.
     */
    val connectionState: StateFlow<UniversalConnectionState>

    /**
     * Flow of incoming messages from the mesh.
     */
    val incomingMessages: Flow<UniversalMessage>

    /**
     * Flow of mesh events (peer discovered, connection changes, etc.)
     */
    val meshEvents: Flow<UniversalMeshEvent>

    /**
     * Connect to the mesh device/network.
     *
     * @param config Connection configuration (device address, credentials, etc.)
     * @return Result indicating success or failure with error message
     */
    suspend fun connect(config: MeshConnectionConfig): Result<Unit>

    /**
     * Disconnect from the mesh.
     */
    suspend fun disconnect()

    /**
     * Send a message over the mesh.
     *
     * @param message The message to send (payload should already be encrypted)
     * @return Result with message ID on success, or error on failure
     */
    suspend fun sendMessage(message: UniversalMessage): Result<String>

    /**
     * Get information about the connected device.
     */
    suspend fun getDeviceInfo(): Result<MeshDeviceInfo>

    /**
     * Discover nearby mesh peers.
     *
     * @param timeout Discovery timeout in milliseconds
     * @return List of discovered peer addresses
     */
    suspend fun discoverPeers(timeout: Long = 30000): Result<List<UniversalAddress>>

    /**
     * Check if a specific peer is reachable.
     */
    suspend fun pingPeer(address: UniversalAddress): Result<Long> // Returns latency in ms
}

// =============================================================================
// CONNECTION CONFIG
// =============================================================================

/**
 * Configuration for connecting to a mesh device.
 */
sealed class MeshConnectionConfig {
    /**
     * USB Serial connection (MeshCore, Meshtastic, RNode)
     */
    data class UsbSerial(
        val devicePath: String,
        val baudRate: Int = 115200
    ) : MeshConnectionConfig()

    /**
     * Bluetooth Low Energy connection
     */
    data class Ble(
        val macAddress: String,
        val pin: String? = null
    ) : MeshConnectionConfig()

    /**
     * TCP connection (MeshCore relay, Reticulum)
     */
    data class Tcp(
        val host: String,
        val port: Int
    ) : MeshConnectionConfig()

    /**
     * WiFi Direct (future)
     */
    data class WifiDirect(
        val peerAddress: String
    ) : MeshConnectionConfig()
}

// =============================================================================
// MESH EVENTS
// =============================================================================

/**
 * Events from the mesh network.
 */
sealed class UniversalMeshEvent {
    data class PeerDiscovered(val address: UniversalAddress) : UniversalMeshEvent()
    data class PeerLost(val address: UniversalAddress) : UniversalMeshEvent()
    data class MessageDelivered(val messageId: String) : UniversalMeshEvent()
    data class MessageFailed(val messageId: String, val reason: String) : UniversalMeshEvent()
    data class DeviceStatusChanged(val info: MeshDeviceInfo) : UniversalMeshEvent()
    data class NetworkTopologyChanged(val peerCount: Int) : UniversalMeshEvent()
}

// =============================================================================
// ADDRESS TRANSLATOR
// =============================================================================

/**
 * Translates between DID and mesh-specific addresses.
 */
object AddressTranslator {

    /**
     * Create a UniversalAddress from a DID and public key.
     */
    fun fromDid(did: String, publicKey: ByteArray): UniversalAddress {
        return UniversalAddress(
            did = did,
            publicKey = publicKey,
            meshcoreAddr = deriveMeshcoreAddress(publicKey),
            meshtasticId = deriveMeshtasticId(publicKey),
            reticulumHash = deriveReticulumHash(publicKey, "yours.messaging")
        )
    }

    /**
     * Derive MeshCore 16-bit address from public key.
     * Uses first 2 bytes of SHA-256 hash.
     */
    private fun deriveMeshcoreAddress(publicKey: ByteArray): Short {
        val hash = sha256(publicKey)
        return ((hash[0].toInt() and 0xFF) shl 8 or (hash[1].toInt() and 0xFF)).toShort()
    }

    /**
     * Derive Meshtastic 32-bit node ID from public key.
     * Uses first 4 bytes of SHA-256 hash.
     */
    private fun deriveMeshtasticId(publicKey: ByteArray): Long {
        val hash = sha256(publicKey)
        return ((hash[0].toLong() and 0xFF) shl 24) or
               ((hash[1].toLong() and 0xFF) shl 16) or
               ((hash[2].toLong() and 0xFF) shl 8) or
               (hash[3].toLong() and 0xFF)
    }

    /**
     * Derive Reticulum destination hash.
     * SHA-256(appName || publicKey), truncated to 16 bytes.
     */
    private fun deriveReticulumHash(publicKey: ByteArray, appName: String): ByteArray {
        val nameHash = sha256(appName.toByteArray(Charsets.UTF_8))
        val combined = nameHash + publicKey
        return sha256(combined).copyOf(16)
    }

    private fun sha256(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }
}

// =============================================================================
// MESH MANAGER
// =============================================================================

/**
 * Manages multiple mesh transports and provides unified access.
 */
class UniversalMeshManager {

    private val transports = mutableMapOf<MeshType, UniversalMeshTransport>()
    private var activeTransport: UniversalMeshTransport? = null

    /**
     * Register a transport implementation.
     */
    fun registerTransport(transport: UniversalMeshTransport) {
        transports[transport.meshType] = transport
    }

    /**
     * Get available mesh types (registered transports).
     */
    fun getAvailableMeshTypes(): List<MeshType> = transports.keys.toList()

    /**
     * Set the active mesh type.
     */
    suspend fun setActiveMesh(meshType: MeshType, config: MeshConnectionConfig): Result<Unit> {
        val transport = transports[meshType]
            ?: return Result.failure(IllegalArgumentException("No transport for $meshType"))

        // Disconnect from current
        activeTransport?.disconnect()

        // Connect to new
        val result = transport.connect(config)
        if (result.isSuccess) {
            activeTransport = transport
        }
        return result
    }

    /**
     * Get the currently active transport.
     */
    fun getActiveTransport(): UniversalMeshTransport? = activeTransport

    /**
     * Get a specific transport by type.
     */
    fun getTransport(meshType: MeshType): UniversalMeshTransport? = transports[meshType]
}
