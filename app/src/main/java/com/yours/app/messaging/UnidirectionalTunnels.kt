package com.yours.app.messaging

import android.util.Log
import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.Contact
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom

/**
 * UnidirectionalTunnels - I2P-style separate inbound/outbound paths.
 *
 * INSPIRATION FROM I2P:
 * > "I2P uses unidirectional tunnels instead of bidirectional circuits,
 * >  doubling the number of nodes a peer has to compromise to get the
 * >  same information."
 *
 * WHY THIS MATTERS:
 *
 * BIDIRECTIONAL (Tor-style):
 * ```
 * Alice → R1 → R2 → R3 → Bob
 * Alice ← R1 ← R2 ← R3 ← Bob  (same path)
 *
 * Adversary at R2 sees BOTH directions
 * Can correlate request/response timing
 * ```
 *
 * UNIDIRECTIONAL (I2P-style):
 * ```
 * OUTBOUND: Alice → R1 → R2 → R3 → Bob
 * INBOUND:  Alice ← R4 ← R5 ← R6 ← Bob  (DIFFERENT path)
 *
 * Adversary must compromise nodes in BOTH tunnels
 * Doubles the attack cost
 * ```
 *
 * IMPLEMENTATION:
 * - Each contact relationship has TWO tunnel IDs
 * - Outbound tunnel: path we use to SEND to them
 * - Inbound tunnel: path they use to SEND to us
 * - Tunnels are rebuilt periodically for forward secrecy
 */
class UnidirectionalTunnels(
    private val getContacts: suspend () -> List<Contact>,
    private val getOurDid: () -> String
) {
    companion object {
        private const val TAG = "UnidirectionalTunnels"

        /**
         * Minimum relays per tunnel.
         */
        const val MIN_TUNNEL_LENGTH = 3

        /**
         * Maximum tunnel lifetime before rebuild.
         */
        const val TUNNEL_LIFETIME_MS = 30 * 60 * 1000L  // 30 minutes

        /**
         * Tunnel ID size in bytes.
         */
        const val TUNNEL_ID_SIZE = 8

        /**
         * Whether to prefer LunarRouter circuits over simple onion routing.
         */
        const val PREFER_LUNAR_CIRCUITS = true
    }

    /**
     * Optional LunarCircuitManager for AES-256-GCM circuits.
     * When set, tunnels will use persistent circuits instead of per-message onion.
     */
    private var circuitManager: LunarCircuitManager? = null

    /**
     * Set the circuit manager for LunarRouter integration.
     */
    fun setCircuitManager(manager: LunarCircuitManager) {
        this.circuitManager = manager
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()

    /**
     * Active tunnels keyed by contact DID.
     */
    private val tunnels = mutableMapOf<String, TunnelPair>()

    /**
     * Get or create tunnel pair for a contact.
     */
    suspend fun getTunnels(contactDid: String): TunnelPair = mutex.withLock {
        val existing = tunnels[contactDid]

        // Check if existing tunnels are still valid
        if (existing != null && !existing.isExpired()) {
            return@withLock existing
        }

        // Build new tunnel pair
        val newTunnels = buildTunnelPair(contactDid)
        tunnels[contactDid] = newTunnels
        newTunnels
    }

    /**
     * Build a new tunnel pair for a contact.
     */
    private suspend fun buildTunnelPair(contactDid: String): TunnelPair {
        val contacts = getContacts()
        val availableRelays = contacts.filter { it.did != contactDid && it.did != getOurDid() }

        // Generate unique tunnel IDs
        val outboundId = BedrockCore.randomBytes(TUNNEL_ID_SIZE)
        val inboundId = BedrockCore.randomBytes(TUNNEL_ID_SIZE)

        // Select relays for outbound tunnel
        val outboundRelays = selectRelays(availableRelays, MIN_TUNNEL_LENGTH)

        // Select DIFFERENT relays for inbound tunnel (if possible)
        val remainingRelays = availableRelays.filter { relay ->
            outboundRelays.none { it.did == relay.did }
        }

        val inboundRelays = if (remainingRelays.size >= MIN_TUNNEL_LENGTH) {
            // Ideal: completely separate paths
            selectRelays(remainingRelays, MIN_TUNNEL_LENGTH)
        } else if (availableRelays.size >= MIN_TUNNEL_LENGTH) {
            // Fallback: allow some overlap but shuffle differently
            selectRelays(availableRelays.shuffled(), MIN_TUNNEL_LENGTH)
        } else {
            // Not enough relays - use what we have
            selectRelays(availableRelays, availableRelays.size.coerceAtMost(MIN_TUNNEL_LENGTH))
        }

        return TunnelPair(
            contactDid = contactDid,
            outbound = Tunnel(
                id = outboundId,
                relays = outboundRelays,
                createdAt = System.currentTimeMillis(),
                direction = TunnelDirection.OUTBOUND
            ),
            inbound = Tunnel(
                id = inboundId,
                relays = inboundRelays,
                createdAt = System.currentTimeMillis(),
                direction = TunnelDirection.INBOUND
            )
        )
    }

    /**
     * Select relays for a tunnel.
     */
    private fun selectRelays(available: List<Contact>, count: Int): List<Contact> {
        if (available.size <= count) {
            return available.shuffled()
        }
        return available.shuffled().take(count)
    }

    /**
     * Build an outbound packet using the outbound tunnel.
     *
     * ROUTING STRATEGY (in priority order):
     * 1. LunarRouter circuits (AES-256-GCM) - persistent tunnels, better security
     * 2. Simple onion routing (ChaCha20-Poly1305) - per-message, fallback
     */
    suspend fun buildOutboundPacket(
        contactDid: String,
        recipientContact: Contact,
        payload: ByteArray
    ): ByteArray? {
        val tunnelPair = getTunnels(contactDid)

        // ====================================================================
        // STRATEGY 1: LunarRouter Circuits (AES-256-GCM) - PREFERRED
        // ====================================================================
        val manager = circuitManager
        if (PREFER_LUNAR_CIRCUITS && manager != null) {
            // Derive recipient hint for circuit destination
            val recipientHint = BedrockCore.lunarDeriveNodeHint(recipientContact.encryptionPublicKey)
                ?: ByteArray(LunarCircuitManager.NODE_HINT_SIZE)

            // Include return tunnel ID for I2P-style unidirectional response path
            val tunnelPayload = buildTunnelPayload(tunnelPair.inbound.id, payload)

            // Try to wrap via LunarRouter circuit
            val result = manager.wrapMessage(tunnelPayload, recipientHint)

            if (result != null) {
                Log.d(TAG, "Outbound packet wrapped via LunarRouter circuit (AES-256-GCM)")
                return result.wrappedPacket
            } else {
                Log.d(TAG, "No ready circuit, falling back to simple onion routing")
                // Fall through to simple onion routing
            }
        }

        // ====================================================================
        // STRATEGY 2: Simple Onion Routing (ChaCha20-Poly1305) - FALLBACK
        // ====================================================================
        val tunnel = tunnelPair.outbound

        if (tunnel.relays.isEmpty()) {
            // No relays - cannot build tunnel packet
            return null
        }

        // Build onion layers through outbound tunnel relays
        val routeNodeIds = tunnel.relays.map { deriveNodeId(it.encryptionPublicKey) }.toTypedArray()
        val routePublicKeys = tunnel.relays.map { it.encryptionPublicKey }.toTypedArray()

        // Include tunnel ID in the payload for the recipient
        val tunnelPayload = buildTunnelPayload(tunnelPair.inbound.id, payload)

        return BedrockCore.createOnionPacket(
            routeNodeIds = routeNodeIds,
            routePublicKeys = routePublicKeys,
            destNodeId = deriveNodeId(recipientContact.encryptionPublicKey),
            destPublicKey = recipientContact.encryptionPublicKey,
            payload = tunnelPayload
        )
    }

    /**
     * Process an inbound packet and extract the return tunnel ID.
     */
    fun extractTunnelInfo(payload: ByteArray): TunnelPayload? {
        return parseTunnelPayload(payload)
    }

    /**
     * Find which contact a tunnel ID belongs to.
     */
    suspend fun findContactByInboundTunnel(tunnelId: ByteArray): String? = mutex.withLock {
        for ((contactDid, pair) in tunnels) {
            if (pair.inbound.id.contentEquals(tunnelId)) {
                return@withLock contactDid
            }
        }
        null
    }

    /**
     * Rebuild all tunnels (call periodically or on security event).
     */
    suspend fun rebuildAllTunnels() = mutex.withLock {
        val contactDids = tunnels.keys.toList()
        tunnels.clear()

        for (did in contactDids) {
            tunnels[did] = buildTunnelPair(did)
        }
    }

    /**
     * Clear all tunnels (on lock/wipe).
     */
    suspend fun clearAll() = mutex.withLock {
        // Zeroize tunnel IDs
        for ((_, pair) in tunnels) {
            pair.outbound.id.fill(0)
            pair.inbound.id.fill(0)
        }
        tunnels.clear()
    }

    /**
     * Get tunnel statistics.
     */
    suspend fun getStats(): TunnelStats = mutex.withLock {
        val totalTunnels = tunnels.size * 2
        val expiredCount = tunnels.values.count { it.isExpired() }
        val avgOutboundLength = tunnels.values.map { it.outbound.relays.size }.average()
        val avgInboundLength = tunnels.values.map { it.inbound.relays.size }.average()

        TunnelStats(
            totalTunnelPairs = tunnels.size,
            expiredPairs = expiredCount,
            avgOutboundLength = avgOutboundLength,
            avgInboundLength = avgInboundLength
        )
    }

    private fun deriveNodeId(publicKey: ByteArray): ByteArray {
        val hash = BedrockCore.sha3_256(publicKey)
        return hash.copyOf(8)
    }

    /**
     * Build payload with tunnel ID prepended.
     */
    private fun buildTunnelPayload(returnTunnelId: ByteArray, payload: ByteArray): ByteArray {
        // Format: [return_tunnel_id:8][payload]
        val result = ByteArray(TUNNEL_ID_SIZE + payload.size)
        System.arraycopy(returnTunnelId, 0, result, 0, TUNNEL_ID_SIZE)
        System.arraycopy(payload, 0, result, TUNNEL_ID_SIZE, payload.size)
        return result
    }

    /**
     * Parse payload to extract tunnel ID and data.
     */
    private fun parseTunnelPayload(payload: ByteArray): TunnelPayload? {
        if (payload.size < TUNNEL_ID_SIZE) {
            return null
        }

        val tunnelId = payload.copyOfRange(0, TUNNEL_ID_SIZE)
        val data = payload.copyOfRange(TUNNEL_ID_SIZE, payload.size)

        return TunnelPayload(tunnelId, data)
    }
}

/**
 * A pair of tunnels for bidirectional communication.
 */
data class TunnelPair(
    val contactDid: String,
    val outbound: Tunnel,
    val inbound: Tunnel
) {
    fun isExpired(): Boolean {
        val now = System.currentTimeMillis()
        return outbound.isExpired(now) || inbound.isExpired(now)
    }
}

/**
 * A single unidirectional tunnel.
 */
data class Tunnel(
    val id: ByteArray,
    val relays: List<Contact>,
    val createdAt: Long,
    val direction: TunnelDirection
) {
    fun isExpired(now: Long = System.currentTimeMillis()): Boolean {
        return now - createdAt > UnidirectionalTunnels.TUNNEL_LIFETIME_MS
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tunnel) return false
        return id.contentEquals(other.id)
    }

    override fun hashCode(): Int {
        return id.contentHashCode()
    }
}

/**
 * Tunnel direction.
 */
enum class TunnelDirection {
    OUTBOUND,  // We send through this tunnel
    INBOUND    // We receive through this tunnel
}

/**
 * Parsed tunnel payload.
 */
data class TunnelPayload(
    val returnTunnelId: ByteArray,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TunnelPayload) return false
        return returnTunnelId.contentEquals(other.returnTunnelId) && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        return returnTunnelId.contentHashCode() * 31 + data.contentHashCode()
    }
}

/**
 * Tunnel statistics.
 */
data class TunnelStats(
    val totalTunnelPairs: Int,
    val expiredPairs: Int,
    val avgOutboundLength: Double,
    val avgInboundLength: Double
)

/**
 * Exception for tunnel-related errors.
 */
class TunnelException(message: String) : Exception(message)
