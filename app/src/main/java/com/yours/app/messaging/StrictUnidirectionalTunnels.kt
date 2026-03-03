package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.Contact
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom

/**
 * I2P-style unidirectional tunnels with guaranteed inbound/outbound relay separation.
 * Refuses to build tunnels if insufficient unique relays are available,
 * and adds per-hop timing jitter to resist traffic correlation.
 */
class StrictUnidirectionalTunnels(
    private val getContacts: suspend () -> List<Contact>,
    private val getOurDid: () -> String
) {
    companion object {
        /**
         * Minimum relays per tunnel direction.
         * 3 relays = 4 hops total (like Tor)
         */
        const val MIN_TUNNEL_LENGTH = 3

        /**
         * Minimum TOTAL relays needed = 2 × MIN_TUNNEL_LENGTH.
         * This ensures complete separation is possible.
         */
        const val MIN_TOTAL_RELAYS = MIN_TUNNEL_LENGTH * 2  // 6 relays minimum

        /**
         * Maximum tunnel lifetime before mandatory rebuild.
         */
        const val TUNNEL_LIFETIME_MS = 10 * 60 * 1000L  // 10 minutes (reduced from 30)

        /**
         * Tunnel ID size in bytes.
         */
        const val TUNNEL_ID_SIZE = 8

        /**
         * Timing jitter range for relay processing.
         * Each relay adds 50-200ms random delay.
         */
        const val MIN_RELAY_JITTER_MS = 50L
        const val MAX_RELAY_JITTER_MS = 200L
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()
    private val tunnels = mutableMapOf<String, StrictTunnelPair>()

    /**
     * Get or create tunnel pair for a contact.
     *
     * SECURITY: Will throw InsufficientRelaysException if separation is impossible.
     * Caller MUST handle this and inform user to add more contacts.
     */
    suspend fun getTunnels(contactDid: String): StrictTunnelPair = mutex.withLock {
        val existing = tunnels[contactDid]

        if (existing != null && !existing.isExpired()) {
            return@withLock existing
        }

        // Build new tunnel pair with STRICT separation
        val newTunnels = buildStrictTunnelPair(contactDid)
        tunnels[contactDid] = newTunnels
        newTunnels
    }

    /**
     * Build tunnel pair with MANDATORY separation.
     *
     * @throws InsufficientRelaysForSeparationException if separation impossible
     */
    private suspend fun buildStrictTunnelPair(contactDid: String): StrictTunnelPair {
        val contacts = getContacts()
        val ourDid = getOurDid()

        // Filter out self and target
        val availableRelays = contacts.filter {
            it.did != contactDid && it.did != ourDid
        }

        // STRICT CHECK: Must have enough for complete separation
        if (availableRelays.size < MIN_TOTAL_RELAYS) {
            throw InsufficientRelaysForSeparationException(
                available = availableRelays.size,
                required = MIN_TOTAL_RELAYS,
                message = "Need at least $MIN_TOTAL_RELAYS contacts for secure tunnels. " +
                         "Currently have ${availableRelays.size}. " +
                         "Add ${MIN_TOTAL_RELAYS - availableRelays.size} more contacts."
            )
        }

        // Shuffle with SecureRandom
        val shuffled = availableRelays.toMutableList()
        shuffleSecure(shuffled)

        // Split into two non-overlapping sets
        val outboundRelays = shuffled.take(MIN_TUNNEL_LENGTH)
        val inboundRelays = shuffled.drop(MIN_TUNNEL_LENGTH).take(MIN_TUNNEL_LENGTH)

        // VERIFY no overlap (defensive check)
        val outboundDids = outboundRelays.map { it.did }.toSet()
        val inboundDids = inboundRelays.map { it.did }.toSet()
        val overlap = outboundDids.intersect(inboundDids)

        if (overlap.isNotEmpty()) {
            // This should never happen with correct logic, but fail-safe
            throw IllegalStateException("SECURITY VIOLATION: Tunnel overlap detected")
        }

        // Generate unique tunnel IDs
        val outboundId = BedrockCore.randomBytes(TUNNEL_ID_SIZE)
        val inboundId = BedrockCore.randomBytes(TUNNEL_ID_SIZE)

        // Calculate timing jitter for each hop
        val outboundJitter = generateJitterSchedule(MIN_TUNNEL_LENGTH)
        val inboundJitter = generateJitterSchedule(MIN_TUNNEL_LENGTH)

        return StrictTunnelPair(
            contactDid = contactDid,
            outbound = StrictTunnel(
                id = outboundId,
                relays = outboundRelays,
                jitterSchedule = outboundJitter,
                createdAt = System.currentTimeMillis(),
                direction = TunnelDirection.OUTBOUND
            ),
            inbound = StrictTunnel(
                id = inboundId,
                relays = inboundRelays,
                jitterSchedule = inboundJitter,
                createdAt = System.currentTimeMillis(),
                direction = TunnelDirection.INBOUND
            )
        )
    }

    /**
     * Generate random jitter schedule for tunnel hops.
     */
    private fun generateJitterSchedule(hopCount: Int): List<Long> {
        return (0 until hopCount).map {
            MIN_RELAY_JITTER_MS + secureRandom.nextLong() %
                (MAX_RELAY_JITTER_MS - MIN_RELAY_JITTER_MS)
        }
    }

    /**
     * Secure shuffle using SecureRandom.
     */
    private fun shuffleSecure(list: MutableList<Contact>) {
        for (i in list.size - 1 downTo 1) {
            val j = secureRandom.nextInt(i + 1)
            val temp = list[i]
            list[i] = list[j]
            list[j] = temp
        }
    }

    /**
     * Build outbound packet using the outbound tunnel.
     *
     * @return Onion-encrypted packet, or null if tunnel unavailable
     */
    suspend fun buildOutboundPacket(
        contactDid: String,
        recipientContact: Contact,
        payload: ByteArray
    ): ByteArray? {
        val tunnelPair = try {
            getTunnels(contactDid)
        } catch (e: InsufficientRelaysForSeparationException) {
            return null
        }

        val tunnel = tunnelPair.outbound

        if (tunnel.relays.isEmpty()) {
            return null
        }

        // Build onion layers through outbound tunnel relays
        val routeNodeIds = tunnel.relays.map { deriveNodeId(it.encryptionPublicKey) }.toTypedArray()
        val routePublicKeys = tunnel.relays.map { it.encryptionPublicKey }.toTypedArray()

        // Include tunnel ID and jitter schedule in payload
        val tunnelPayload = buildTunnelPayload(
            returnTunnelId = tunnelPair.inbound.id,
            jitterSchedule = tunnel.jitterSchedule,
            payload = payload
        )

        return BedrockCore.createOnionPacket(
            routeNodeIds = routeNodeIds,
            routePublicKeys = routePublicKeys,
            destNodeId = deriveNodeId(recipientContact.encryptionPublicKey),
            destPublicKey = recipientContact.encryptionPublicKey,
            payload = tunnelPayload
        )
    }

    /**
     * Check if we have sufficient relays for secure tunneling.
     */
    suspend fun hasSufficientRelays(): Boolean {
        val contacts = getContacts()
        val availableRelays = contacts.filter { it.did != getOurDid() }
        return availableRelays.size >= MIN_TOTAL_RELAYS
    }

    /**
     * Get current relay count and requirement.
     */
    suspend fun getRelayStatus(): RelayStatus {
        val contacts = getContacts()
        val availableRelays = contacts.filter { it.did != getOurDid() }
        return RelayStatus(
            available = availableRelays.size,
            required = MIN_TOTAL_RELAYS,
            canOperate = availableRelays.size >= MIN_TOTAL_RELAYS
        )
    }

    /**
     * Rebuild all tunnels (call periodically or on security event).
     */
    suspend fun rebuildAllTunnels() = mutex.withLock {
        val contactDids = tunnels.keys.toList()
        tunnels.clear()

        for (did in contactDids) {
            try {
                tunnels[did] = buildStrictTunnelPair(did)
            } catch (e: InsufficientRelaysForSeparationException) {
                // Cannot rebuild - skip this tunnel
            }
        }
    }

    /**
     * Clear all tunnels securely.
     */
    suspend fun clearAll() = mutex.withLock {
        for ((_, pair) in tunnels) {
            pair.outbound.id.fill(0)
            pair.inbound.id.fill(0)
        }
        tunnels.clear()
    }

    private fun deriveNodeId(publicKey: ByteArray): ByteArray {
        val hash = BedrockCore.sha3_256(publicKey)
        return hash.copyOf(8)
    }

    /**
     * Build payload with tunnel ID and jitter schedule prepended.
     */
    private fun buildTunnelPayload(
        returnTunnelId: ByteArray,
        jitterSchedule: List<Long>,
        payload: ByteArray
    ): ByteArray {
        // Format: [return_tunnel_id:8][jitter_count:1][jitter_values:N*2][payload]
        val jitterBytes = jitterSchedule.size * 2
        val result = ByteArray(TUNNEL_ID_SIZE + 1 + jitterBytes + payload.size)

        System.arraycopy(returnTunnelId, 0, result, 0, TUNNEL_ID_SIZE)
        result[TUNNEL_ID_SIZE] = jitterSchedule.size.toByte()

        var offset = TUNNEL_ID_SIZE + 1
        for (jitter in jitterSchedule) {
            result[offset] = ((jitter shr 8) and 0xFF).toByte()
            result[offset + 1] = (jitter and 0xFF).toByte()
            offset += 2
        }

        System.arraycopy(payload, 0, result, offset, payload.size)
        return result
    }

    /**
     * Extract tunnel info from received payload.
     */
    fun extractTunnelInfo(payload: ByteArray): StrictTunnelPayload? {
        if (payload.size < TUNNEL_ID_SIZE + 1) {
            return null
        }

        val tunnelId = payload.copyOfRange(0, TUNNEL_ID_SIZE)
        val jitterCount = payload[TUNNEL_ID_SIZE].toInt() and 0xFF

        val jitterStart = TUNNEL_ID_SIZE + 1
        val jitterEnd = jitterStart + jitterCount * 2

        if (payload.size < jitterEnd) {
            return null
        }

        val jitterSchedule = mutableListOf<Long>()
        for (i in 0 until jitterCount) {
            val high = payload[jitterStart + i * 2].toInt() and 0xFF
            val low = payload[jitterStart + i * 2 + 1].toInt() and 0xFF
            jitterSchedule.add((high shl 8 or low).toLong())
        }

        val data = payload.copyOfRange(jitterEnd, payload.size)

        return StrictTunnelPayload(tunnelId, jitterSchedule, data)
    }

    /**
     * Find contact by inbound tunnel ID.
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
     * Get tunnel statistics.
     */
    suspend fun getStats(): StrictTunnelStats = mutex.withLock {
        val expiredCount = tunnels.values.count { it.isExpired() }
        val avgOutboundLength = if (tunnels.isNotEmpty()) {
            tunnels.values.map { it.outbound.relays.size }.average()
        } else 0.0
        val avgInboundLength = if (tunnels.isNotEmpty()) {
            tunnels.values.map { it.inbound.relays.size }.average()
        } else 0.0

        StrictTunnelStats(
            totalTunnelPairs = tunnels.size,
            expiredPairs = expiredCount,
            avgOutboundLength = avgOutboundLength,
            avgInboundLength = avgInboundLength,
            guaranteedSeparation = true
        )
    }
}

/**
 * A strict tunnel pair with guaranteed separation.
 */
data class StrictTunnelPair(
    val contactDid: String,
    val outbound: StrictTunnel,
    val inbound: StrictTunnel
) {
    fun isExpired(): Boolean {
        val now = System.currentTimeMillis()
        return outbound.isExpired(now) || inbound.isExpired(now)
    }

    /**
     * Verify no overlap between inbound and outbound relays.
     */
    fun verifySeparation(): Boolean {
        val outboundDids = outbound.relays.map { it.did }.toSet()
        val inboundDids = inbound.relays.map { it.did }.toSet()
        return outboundDids.intersect(inboundDids).isEmpty()
    }
}

/**
 * A single strict unidirectional tunnel.
 */
data class StrictTunnel(
    val id: ByteArray,
    val relays: List<Contact>,
    val jitterSchedule: List<Long>,  // Per-hop timing jitter
    val createdAt: Long,
    val direction: TunnelDirection
) {
    fun isExpired(now: Long = System.currentTimeMillis()): Boolean {
        return now - createdAt > StrictUnidirectionalTunnels.TUNNEL_LIFETIME_MS
    }

    /**
     * Get total expected jitter for this tunnel.
     */
    fun getTotalJitter(): Long = jitterSchedule.sum()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StrictTunnel) return false
        return id.contentEquals(other.id)
    }

    override fun hashCode(): Int = id.contentHashCode()
}

/**
 * Parsed tunnel payload.
 */
data class StrictTunnelPayload(
    val returnTunnelId: ByteArray,
    val jitterSchedule: List<Long>,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StrictTunnelPayload) return false
        return returnTunnelId.contentEquals(other.returnTunnelId) &&
               jitterSchedule == other.jitterSchedule &&
               data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = returnTunnelId.contentHashCode()
        result = 31 * result + jitterSchedule.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}

/**
 * Relay availability status.
 */
data class RelayStatus(
    val available: Int,
    val required: Int,
    val canOperate: Boolean
) {
    val deficit: Int get() = maxOf(0, required - available)
}

/**
 * Tunnel statistics.
 */
data class StrictTunnelStats(
    val totalTunnelPairs: Int,
    val expiredPairs: Int,
    val avgOutboundLength: Double,
    val avgInboundLength: Double,
    val guaranteedSeparation: Boolean
)

/**
 * Exception when insufficient relays for separation.
 */
class InsufficientRelaysForSeparationException(
    val available: Int,
    val required: Int,
    override val message: String
) : Exception(message)
