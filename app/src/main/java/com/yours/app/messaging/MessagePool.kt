package com.yours.app.messaging

import android.util.Log
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom

private const val TAG = "MessagePool"

/**
 * MessagePool - Tornado Cash-style anonymity pooling for LoRa mesh.
 *
 * CONCEPT (from Tornado Cash):
 * - Fixed denominations = Fixed packet size (200 bytes)
 * - Anonymity set = All messages in current epoch
 * - Time mixing = Queue messages, release at epoch boundary
 * - Pool size = Real messages + chaff packets
 *
 * HOW IT WORKS:
 * 1. Messages aren't sent immediately - they're added to a pool
 * 2. Chaff (fake) packets are generated to fill the pool
 * 3. At epoch boundary (every EPOCH_DURATION_MS), entire pool is released
 * 4. Release order is randomized
 * 5. All packets are same size (200 bytes) - indistinguishable
 *
 * ANONYMITY GUARANTEE:
 * - Adversary sees N packets released at epoch boundary
 * - Can't tell which are real vs chaff
 * - Can't correlate sender timing to receiver timing
 * - Larger pool = stronger anonymity (like Tornado Cash denomination pools)
 *
 * BANDWIDTH COST:
 * - Minimum MIN_POOL_SIZE packets per epoch
 * - If you send 1 real message, we add (MIN_POOL_SIZE - 1) chaff
 * - Configurable based on paranoia level
 */
class MessagePool(
    private val onTransmit: suspend (PooledPacket) -> Boolean
) {
    companion object {
        /**
         * Epoch duration in milliseconds.
         * All messages within an epoch are pooled together.
         * Shorter = lower latency, weaker anonymity
         * Longer = higher latency, stronger anonymity
         *
         * NOTE: Reduced from 30s to 2s for practical usability.
         */
        const val EPOCH_DURATION_MS = 2_000L  // 2 seconds

        /**
         * Minimum pool size before release.
         * Even if only 1 real message, we pad to this size with chaff.
         * Larger = more bandwidth, stronger anonymity
         */
        const val MIN_POOL_SIZE = 5

        /**
         * Maximum pool size (prevent memory exhaustion).
         */
        const val MAX_POOL_SIZE = 20

        /**
         * Random jitter on epoch boundary (0-500ms).
         * Prevents predictable release timing.
         *
         * NOTE: Reduced from 5s to 500ms to match shorter epoch.
         */
        const val EPOCH_JITTER_MS = 500L

        /**
         * Maximum packet size (LoRa MTU).
         * All packets are padded to this size for anonymity.
         *
         * FIXED: Changed from 237 to 184 to match MeshCore MAX_PACKET_PAYLOAD.
         * The old value of 237 caused packets to be padded beyond the LoRa limit,
         * leading to truncation and message corruption.
         */
        const val MAX_PACKET_SIZE = 184

        /**
         * Packet types in pool.
         */
        const val PACKET_TYPE_REAL: Byte = 0x01
        const val PACKET_TYPE_CHAFF: Byte = 0x02
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()

    /**
     * Current epoch's message pool.
     */
    private val currentPool = mutableListOf<PooledPacket>()

    /**
     * Epoch counter for debugging/metrics.
     */
    private var epochCounter = 0L

    /**
     * Coroutine scope for epoch timer.
     */
    private var scope: CoroutineScope? = null
    private var epochJob: Job? = null

    /**
     * Flow of pool events for monitoring.
     */
    private val _events = MutableSharedFlow<PoolEvent>(replay = 0, extraBufferCapacity = 16)
    val events: Flow<PoolEvent> = _events.asSharedFlow()

    /**
     * Statistics.
     */
    private var totalRealPackets = 0L
    private var totalChaffPackets = 0L
    private var totalEpochs = 0L

    /**
     * Start the epoch timer.
     */
    fun start(scope: CoroutineScope) {
        // If start() is called multiple times without this guard, each call creates
        // a NEW epoch job while the OLD one keeps running, causing duplicate transmissions
        // and different epoch counters running simultaneously.
        if (epochJob?.isActive == true) {
            Log.w(TAG, "start() called but epoch timer already running - ignoring")
            return
        }

        this.scope = scope
        epochJob = scope.launch {
            while (isActive) {
                // Wait for epoch duration + random jitter
                val jitter = (secureRandom.nextDouble() * EPOCH_JITTER_MS).toLong()
                delay(EPOCH_DURATION_MS + jitter)

                // Release the pool
                releasePool()
            }
        }
    }

    /**
     * Stop the epoch timer.
     */
    fun stop() {
        epochJob?.cancel()
        epochJob = null
    }

    /**
     * Add a real message to the pool.
     * Will be released at next epoch boundary, unless immediate=true.
     *
     * @param packet The encrypted packet data (will be padded to MAX_PACKET_SIZE)
     * @param priority Higher priority = released first within epoch (for handshakes)
     * @param metadata Optional metadata for tracking
     * @param immediate If true, bypass pool and transmit immediately (P2P mode)
     * @return Epoch number this message will be released in (or -1 if immediate)
     */
    suspend fun addMessage(
        packet: ByteArray,
        priority: Int = 0,
        metadata: PacketMetadata? = null,
        immediate: Boolean = false
    ): Long = mutex.withLock {
        Log.d(TAG, "=== ADD MESSAGE TO POOL ===")
        Log.d(TAG, "packet.size=${packet.size}, priority=$priority, messageId=${metadata?.messageId}, immediate=$immediate")

        // Validate packet size
        require(packet.size <= MAX_PACKET_SIZE) {
            "Packet exceeds maximum size: ${packet.size} > $MAX_PACKET_SIZE"
        }

        // Pad to MAX_PACKET_SIZE for anonymity (all packets same size)
        val paddedPacket = if (packet.size < MAX_PACKET_SIZE) {
            val padded = ByteArray(MAX_PACKET_SIZE)
            System.arraycopy(packet, 0, padded, 0, packet.size)
            // Fill remainder with random padding
            val padding = BedrockCore.randomBytes(MAX_PACKET_SIZE - packet.size)
            System.arraycopy(padding, 0, padded, packet.size, padding.size)
            padded
        } else {
            packet
        }

        // P2P IMMEDIATE MODE: Bypass pool and transmit directly
        // This is used when there's only 1 contact (no anonymity benefit from pooling)
        if (immediate) {
            Log.d(TAG, "P2P IMMEDIATE MODE: Bypassing pool, transmitting directly")
            val immediatePacket = PooledPacket(
                data = paddedPacket,
                type = PACKET_TYPE_REAL,
                priority = priority,
                addedAt = System.currentTimeMillis(),
                metadata = metadata
            )
            try {
                val success = onTransmit(immediatePacket)
                if (success) {
                    Log.d(TAG, "P2P immediate transmit SUCCESS")
                    totalRealPackets++
                } else {
                    Log.w(TAG, "P2P immediate transmit FAILED")
                }
            } catch (e: Exception) {
                Log.e(TAG, "P2P immediate transmit ERROR: ${e.message}")
            }
            return@withLock -1L  // Special epoch value for immediate mode
        }

        // Check pool capacity
        if (currentPool.size >= MAX_POOL_SIZE) {
            // Pool full - force early release
            releasePoolInternal()
        }

        val pooledPacket = PooledPacket(
            data = paddedPacket,
            type = PACKET_TYPE_REAL,
            priority = priority,
            addedAt = System.currentTimeMillis(),
            metadata = metadata
        )

        currentPool.add(pooledPacket)
        totalRealPackets++

        _events.emit(PoolEvent.MessageAdded(currentPool.size, epochCounter))

        epochCounter
    }

    /**
     * Force immediate release of pool (e.g., for shutdown).
     */
    suspend fun flush() = mutex.withLock {
        if (currentPool.isNotEmpty()) {
            releasePoolInternal()
        }
    }

    /**
     * Get current pool size (for UI/debugging).
     */
    suspend fun getPoolSize(): Int = mutex.withLock {
        currentPool.size
    }

    /**
     * Get statistics.
     */
    fun getStats(): PoolStats = PoolStats(
        totalRealPackets = totalRealPackets,
        totalChaffPackets = totalChaffPackets,
        totalEpochs = totalEpochs,
        currentPoolSize = currentPool.size,
        currentEpoch = epochCounter
    )

    /**
     * Release the current pool.
     */
    private suspend fun releasePool() = mutex.withLock {
        releasePoolInternal()
    }

    /**
     * Internal pool release (must hold mutex).
     */
    private suspend fun releasePoolInternal() {
        epochCounter++
        totalEpochs++

        val realCount = currentPool.size
        Log.d(TAG, "=== EPOCH RELEASE #$epochCounter ===")
        Log.d(TAG, "realCount=$realCount, MIN_POOL_SIZE=$MIN_POOL_SIZE")

        // Pad with chaff to minimum pool size
        val chaffNeeded = (MIN_POOL_SIZE - currentPool.size).coerceAtLeast(0)
        repeat(chaffNeeded) {
            currentPool.add(generateChaff())
            totalChaffPackets++
        }

        // Shuffle the pool (random release order)
        // Use Fisher-Yates shuffle with SecureRandom
        // Priority sorting was leaking information (handshakes always first)
        for (i in currentPool.size - 1 downTo 1) {
            val j = secureRandom.nextInt(i + 1)
            val temp = currentPool[i]
            currentPool[i] = currentPool[j]
            currentPool[j] = temp
        }

        // Adversary monitoring events cannot distinguish real from chaff
        _events.emit(PoolEvent.EpochReleasing(
            epoch = epochCounter,
            totalPackets = currentPool.size
        ))

        // Transmit all packets with small random delays between them
        Log.d(TAG, "Transmitting ${currentPool.size} packets...")
        var transmitted = 0
        for (packet in currentPool) {
            try {
                Log.d(TAG, "Transmitting packet ${transmitted + 1}/${currentPool.size}, type=${packet.type}, messageId=${packet.metadata?.messageId}")
                onTransmit(packet)
                transmitted++

                // Small random delay between packets (10-100ms)
                // Prevents burst fingerprinting
                val interPacketDelay = 10L + secureRandom.nextInt(90)
                delay(interPacketDelay)
            } catch (e: Exception) {
                // Log but continue with other packets
                Log.e(TAG, "Transmit error: ${e.message}")
                _events.emit(PoolEvent.TransmitError(packet, e.message ?: "Unknown error"))
            }
        }
        Log.d(TAG, "Epoch release complete: transmitted $transmitted packets")

        // Clear pool for next epoch
        currentPool.clear()

        _events.emit(PoolEvent.EpochComplete(epochCounter))
    }

    /**
     * Generate a chaff (fake) packet.
     * Indistinguishable from real packets (same size).
     */
    private fun generateChaff(): PooledPacket {
        // Generate random data of exact MAX_PACKET_SIZE for anonymity
        val chaffData = BedrockCore.randomBytes(MAX_PACKET_SIZE)
        chaffData[0] = 0x04  // Garlic version (0x04 & 0b11 = Data type for Rust)

        return PooledPacket(
            data = chaffData,
            type = PACKET_TYPE_CHAFF,
            priority = -1,  // Lowest priority
            addedAt = System.currentTimeMillis(),
            metadata = null
        )
    }

    /**
     * Clear pool without sending (for panic wipe).
     */
    suspend fun clear() = mutex.withLock {
        // Zeroize all packet data
        for (packet in currentPool) {
            packet.data.fill(0)
        }
        currentPool.clear()
    }
}

/**
 * A packet in the anonymity pool.
 */
data class PooledPacket(
    val data: ByteArray,
    val type: Byte,
    val priority: Int,
    val addedAt: Long,
    val metadata: PacketMetadata?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PooledPacket) return false
        return data.contentEquals(other.data) && type == other.type
    }

    override fun hashCode(): Int {
        return data.contentHashCode() * 31 + type.toInt()
    }
}

/**
 * Optional metadata for tracking (not transmitted).
 */
data class PacketMetadata(
    val messageId: String?,
    val contactDid: String?,
    val isHandshake: Boolean = false
)

/**
 * Pool statistics.
 */
data class PoolStats(
    val totalRealPackets: Long,
    val totalChaffPackets: Long,
    val totalEpochs: Long,
    val currentPoolSize: Int,
    val currentEpoch: Long
) {
    val chaffRatio: Double
        get() = if (totalRealPackets > 0) {
            totalChaffPackets.toDouble() / totalRealPackets
        } else 0.0

    val avgPoolSize: Double
        get() = if (totalEpochs > 0) {
            (totalRealPackets + totalChaffPackets).toDouble() / totalEpochs
        } else 0.0
}

/**
 * Events emitted by the pool for monitoring.
 *
 * SECURITY: Events intentionally do NOT reveal:
 * - Real vs chaff packet counts (defeats traffic analysis)
 * - Packet priorities or types (all packets are equal)
 * - Any information that could correlate sender activity
 */
sealed class PoolEvent {
    data class MessageAdded(val poolSize: Int, val epoch: Long) : PoolEvent()

    /**
     * Epoch releasing event.
     * SECURITY FIX: Only total count exposed - no real/chaff breakdown.
     * An adversary observing these events learns nothing about actual activity.
     */
    data class EpochReleasing(
        val epoch: Long,
        val totalPackets: Int
        // REMOVED: realPackets, chaffPackets - these were leaking anonymity
    ) : PoolEvent()

    data class EpochComplete(val epoch: Long) : PoolEvent()
    data class TransmitError(val packet: PooledPacket, val error: String) : PoolEvent()
}

/**
 * Configuration for different paranoia levels.
 */
enum class PoolParanoiaLevel(
    val epochDurationMs: Long,
    val minPoolSize: Int,
    val description: String
) {
    /**
     * Low latency, weaker anonymity.
     * Good for casual use.
     */
    NORMAL(
        epochDurationMs = 15_000L,   // 15 seconds
        minPoolSize = 3,
        description = "Normal: 15s epochs, 3 packet minimum"
    ),

    /**
     * Balanced latency and anonymity.
     * Recommended for most users.
     */
    ENHANCED(
        epochDurationMs = 30_000L,   // 30 seconds
        minPoolSize = 5,
        description = "Enhanced: 30s epochs, 5 packet minimum"
    ),

    /**
     * Maximum anonymity, higher latency.
     * For high-risk situations.
     */
    PARANOID(
        epochDurationMs = 60_000L,   // 60 seconds
        minPoolSize = 10,
        description = "Paranoid: 60s epochs, 10 packet minimum"
    )
}
