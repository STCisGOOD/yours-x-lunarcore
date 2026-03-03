package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.Contact
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * CoverTrafficScheduler - Generates chaff traffic to defeat traffic analysis.
 *
 * INSPIRATION FROM:
 * - Mullvad DAITA: Constant packet sizes + dummy injection
 * - Tornado Cash: Fixed denominations, anonymity pools
 * - I2P: Garlic routing with bundled messages
 *
 * PURPOSE:
 * Even when you're NOT sending messages, we generate fake traffic.
 * This means an adversary can't tell:
 * - When you're active vs idle
 * - When real messages are sent
 * - Who you're communicating with
 *
 * MODES:
 * 1. CONTINUOUS - Always generating traffic (maximum bandwidth, maximum anonymity)
 * 2. BURST - Generate traffic when real messages are sent (moderate bandwidth)
 * 3. PROBABILISTIC - Random chance of generating traffic each interval
 *
 * INTEGRATION:
 * Works with MessagePool to ensure pools are always filled,
 * even during idle periods.
 */
class CoverTrafficScheduler(
    private val messagePool: MessagePool,
    private val getRandomContact: suspend () -> Contact?,  // For realistic routing
    private val buildOnionPacket: suspend (Contact, ByteArray) -> ByteArray?,
    private val wrapInGarlic: suspend (Contact, ByteArray) -> ByteArray  // Wrap in garlic for pool padding safety
) {
    companion object {
        /**
         * Interval for checking if cover traffic needed.
         */
        const val CHECK_INTERVAL_MS = 5_000L  // 5 seconds

        /**
         * Base probability of generating cover traffic per check.
         * Actual probability varies by mode.
         */
        const val BASE_COVER_PROBABILITY = 0.3  // 30%

        /**
         * Maximum cover packets per check (prevent flooding).
         */
        const val MAX_COVER_PER_CHECK = 3

        /**
         * Inner payload size for cover traffic (before onion wrapping).
         *
         * MUST match real message hintedPayload size for indistinguishability:
         * - MessageWireFormat.PADDED_SIZE (73 bytes) = wire payload
         * - + 36 bytes = session encryption overhead
         * - + 4 bytes = blinded hint
         * = 113 bytes total
         *
         * After onion wrapping (+62 bytes) = 175 bytes
         * After garlic (+9 bytes) = 184 bytes = MAX_PACKET_SIZE ✓
         */
        const val COVER_INNER_PAYLOAD_SIZE = 113  // Same as real hintedPayload
    }

    private val secureRandom = SecureRandom()
    private var coverJob: Job? = null
    private var scope: CoroutineScope? = null

    /**
     * Current operating mode.
     */
    private var mode: CoverTrafficMode = CoverTrafficMode.PROBABILISTIC

    /**
     * Statistics.
     */
    private var coverPacketsGenerated = 0L
    private var coverPacketsFailed = 0L

    /**
     * Events for monitoring.
     */
    private val _events = MutableSharedFlow<CoverEvent>(replay = 0, extraBufferCapacity = 16)
    val events: Flow<CoverEvent> = _events.asSharedFlow()

    /**
     * Start generating cover traffic.
     */
    fun start(scope: CoroutineScope, mode: CoverTrafficMode = CoverTrafficMode.PROBABILISTIC) {
        this.scope = scope
        this.mode = mode

        coverJob = scope.launch {
            while (isActive) {
                try {
                    generateCoverIfNeeded()
                } catch (e: Exception) {
                    // Don't let cover traffic errors crash the scheduler
                    _events.emit(CoverEvent.Error(e.message ?: "Unknown error"))
                }

                // Random jitter on check interval
                val jitter = (secureRandom.nextDouble() * CHECK_INTERVAL_MS * 0.5).toLong()
                delay(CHECK_INTERVAL_MS + jitter)
            }
        }
    }

    /**
     * Stop generating cover traffic.
     */
    fun stop() {
        coverJob?.cancel()
        coverJob = null
    }

    /**
     * Set the cover traffic mode.
     */
    fun setMode(mode: CoverTrafficMode) {
        this.mode = mode
        scope?.launch {
            _events.emit(CoverEvent.ModeChanged(mode))
        }
    }

    /**
     * Get current mode.
     */
    fun getMode(): CoverTrafficMode = mode

    /**
     * Get statistics.
     */
    fun getStats(): CoverStats = CoverStats(
        packetsGenerated = coverPacketsGenerated,
        packetsFailed = coverPacketsFailed,
        currentMode = mode
    )

    /**
     * Generate cover traffic if needed based on current mode.
     */
    private suspend fun generateCoverIfNeeded() {
        val currentPoolSize = messagePool.getPoolSize()

        when (mode) {
            CoverTrafficMode.OFF -> {
                // No cover traffic
                return
            }

            CoverTrafficMode.PROBABILISTIC -> {
                // Random chance of generating cover
                if (secureRandom.nextDouble() < BASE_COVER_PROBABILITY) {
                    generateCoverPackets(1)
                }
            }

            CoverTrafficMode.BURST -> {
                // Previous implementation only generated cover when real messages existed,
                // which created a perfect oracle: cover traffic = real activity
                //
                // New behavior: Always generate probabilistic cover, with MORE cover
                // when real messages are present (but adversary can't distinguish)
                val baseCover = if (secureRandom.nextDouble() < 0.4) 1 else 0
                val burstCover = if (currentPoolSize > 0) 1 + secureRandom.nextInt(2) else 0
                val coverCount = baseCover + burstCover
                if (coverCount > 0) {
                    generateCoverPackets(coverCount.coerceAtMost(MAX_COVER_PER_CHECK))
                }
            }

            CoverTrafficMode.CONTINUOUS -> {
                // Always maintain minimum pool size
                val needed = MessagePool.MIN_POOL_SIZE - currentPoolSize
                if (needed > 0) {
                    generateCoverPackets(needed.coerceAtMost(MAX_COVER_PER_CHECK))
                }
            }

            CoverTrafficMode.PARANOID -> {
                // Maximum cover traffic
                // Generate traffic every check regardless of pool state
                val count = 2 + secureRandom.nextInt(2)  // 2-3 packets
                generateCoverPackets(count)
            }
        }
    }

    /**
     * Generate the specified number of cover packets.
     */
    private suspend fun generateCoverPackets(count: Int) {
        repeat(count) {
            try {
                val coverPacket = generateRealisticCover()
                if (coverPacket != null) {
                    messagePool.addMessage(
                        packet = coverPacket,
                        priority = -1,  // Lowest priority
                        metadata = PacketMetadata(
                            messageId = null,
                            contactDid = null,
                            isHandshake = false
                        )
                    )
                    coverPacketsGenerated++
                    _events.emit(CoverEvent.PacketGenerated)
                }
            } catch (e: Exception) {
                coverPacketsFailed++
            }
        }
    }

    /**
     * Generate a realistic-looking cover packet.
     *
     * For maximum effectiveness, cover packets should:
     * 1. Be routed through real contacts (onion layers)
     * 2. Be indistinguishable from real traffic
     * 3. Terminate at a random contact (who discards it)
     *
     * SECURITY: Inner payload MUST match real hintedPayload size (113 bytes)
     * so that final packets are indistinguishable from real messages.
     *
     * CRITICAL: All packets MUST be garlic-wrapped before going to pool.
     * The pool pads packets to MAX_PACKET_SIZE with random bytes, which
     * corrupts raw onion packets (auth tag at end gets garbage appended).
     * Garlic format includes length fields so receiver knows real data size.
     */
    private suspend fun generateRealisticCover(): ByteArray? {
        // If we have contacts, route through them for realism
        val contact = getRandomContact()

        return if (contact != null) {
            // Generate cover that looks like real onion-routed traffic
            // MAX_PACKET_SIZE (184 bytes) - the payload must match real hintedPayload
            // size so that after onion wrapping (+62) it fits within 184-byte limit
            val innerPayload = BedrockCore.randomBytes(COVER_INNER_PAYLOAD_SIZE)
            val onionPacket = buildOnionPacket(contact, innerPayload) ?: return null

            wrapInGarlic(contact, onionPacket)
        } else {
            // No contacts - generate pure random cover that looks like garlic
            // Use garlic format with random clove so it's indistinguishable
            // from real garlic packets after pool padding
            generateRandomGarlicCover()
        }
    }

    /**
     * Generate random cover in garlic format (when no contacts available).
     *
     * This creates a fake garlic packet that:
     * 1. Has valid garlic structure (version, count, clove headers)
     * 2. Contains random encrypted-looking data
     * 3. Is indistinguishable from real garlic after pool padding
     */
    private fun generateRandomGarlicCover(): ByteArray {
        // Create a garlic-formatted packet manually
        // Format: [version:1][count:1][clove: type:1, hint:4, len:2, payload:variable][padding]
        val buffer = java.nio.ByteBuffer.allocate(MessagePool.MAX_PACKET_SIZE)

        // Garlic header
        // Version MUST be 0x04 for Rust packet type compatibility (0x04 & 0b11 = Data)
        buffer.put(0x04.toByte())  // Version
        buffer.put(0x01)  // 1 clove

        // Clove header
        buffer.put(GarlicBundler.CLOVE_TYPE_CHAFF)  // Chaff type
        buffer.put(BedrockCore.randomBytes(4))      // Random hint

        // Payload length - fill remaining space minus 2 bytes for length field
        val payloadSize = MessagePool.MAX_PACKET_SIZE - 2 - 1 - 4 - 2
        buffer.putShort(payloadSize.toShort())

        // Random payload
        buffer.put(BedrockCore.randomBytes(payloadSize))

        return buffer.array()
    }

    /**
     * Trigger burst of cover traffic (call when sending real message).
     */
    suspend fun triggerBurst() {
        if (mode == CoverTrafficMode.BURST || mode == CoverTrafficMode.PARANOID) {
            val burstCount = 2 + secureRandom.nextInt(3)  // 2-4 packets
            generateCoverPackets(burstCount)
        }
    }
}

/**
 * Cover traffic operating modes.
 */
enum class CoverTrafficMode(val description: String) {
    /**
     * No cover traffic (not recommended).
     * Only real messages are transmitted.
     */
    OFF("Off - No cover traffic (vulnerable to traffic analysis)"),

    /**
     * Random probability of generating cover each interval.
     * Low bandwidth impact, moderate anonymity.
     */
    PROBABILISTIC("Probabilistic - 30% chance per interval"),

    /**
     * Generate cover when sending real messages.
     * Moderate bandwidth, good anonymity for active periods.
     */
    BURST("Burst - Cover accompanies real messages"),

    /**
     * Always maintain minimum pool size with cover.
     * Higher bandwidth, strong anonymity.
     */
    CONTINUOUS("Continuous - Maintain constant traffic"),

    /**
     * Maximum cover traffic generation.
     * Highest bandwidth, maximum anonymity.
     */
    PARANOID("Paranoid - Maximum cover traffic")
}

/**
 * Cover traffic statistics.
 */
data class CoverStats(
    val packetsGenerated: Long,
    val packetsFailed: Long,
    val currentMode: CoverTrafficMode
)

/**
 * Events from cover traffic scheduler.
 */
sealed class CoverEvent {
    data object PacketGenerated : CoverEvent()
    data class ModeChanged(val mode: CoverTrafficMode) : CoverEvent()
    data class Error(val message: String) : CoverEvent()
}

/**
 * Bandwidth estimation for each mode.
 *
 * Assuming:
 * - Packet size: 184 bytes (MeshCore MAX_PACKET_PAYLOAD)
 * - Epoch: 30 seconds
 * - Check interval: 5 seconds
 */
object CoverBandwidthEstimate {
    const val PACKET_SIZE_BYTES = MessagePool.MAX_PACKET_SIZE

    /**
     * Estimate bytes per hour for each mode.
     */
    fun estimateBytesPerHour(mode: CoverTrafficMode): Long {
        val checksPerHour = 3600 / 5  // 720 checks per hour
        val epochsPerHour = 3600 / 30  // 120 epochs per hour

        return when (mode) {
            CoverTrafficMode.OFF -> 0L

            CoverTrafficMode.PROBABILISTIC -> {
                // 30% chance * 1 packet * 720 checks
                (0.3 * 1 * checksPerHour * PACKET_SIZE_BYTES).toLong()
            }

            CoverTrafficMode.BURST -> {
                // Depends on real message volume
                // Assume 10 real messages/hour, 2 cover each
                (10 * 2 * PACKET_SIZE_BYTES).toLong()
            }

            CoverTrafficMode.CONTINUOUS -> {
                // MIN_POOL_SIZE packets per epoch
                (MessagePool.MIN_POOL_SIZE * epochsPerHour * PACKET_SIZE_BYTES).toLong()
            }

            CoverTrafficMode.PARANOID -> {
                // 2-3 packets per check
                (2.5 * checksPerHour * PACKET_SIZE_BYTES).toLong()
            }
        }
    }

    /**
     * Human-readable bandwidth estimate.
     */
    fun formatEstimate(mode: CoverTrafficMode): String {
        val bytesPerHour = estimateBytesPerHour(mode)
        return when {
            bytesPerHour == 0L -> "0 bytes/hour"
            bytesPerHour < 1024 -> "$bytesPerHour bytes/hour"
            bytesPerHour < 1024 * 1024 -> "${bytesPerHour / 1024} KB/hour"
            else -> "${bytesPerHour / (1024 * 1024)} MB/hour"
        }
    }
}
