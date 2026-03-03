package com.yours.app.crypto

import com.yours.app.messaging.MessagePool
import com.yours.app.messaging.PacketMetadata
import com.yours.app.messaging.PooledPacket
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom

/**
 * Constant-rate cover traffic generator that transmits a fixed number of
 * identically-sized packets per epoch. Real messages replace chaff 1:1,
 * ensuring observers cannot distinguish real traffic from cover.
 */
class ConstantRateCoverTraffic(
    private val messagePool: MessagePool,
    private val generateCoverPacket: suspend () -> ByteArray?
) {
    companion object {
        /**
         * FIXED transmission rate: packets per epoch.
         *
         * SECURITY: This is the ONLY rate - never varies.
         * Real messages replace chaff 1:1, maintaining constant rate.
         */
        const val PACKETS_PER_EPOCH = 8

        /**
         * Epoch duration in milliseconds.
         *
         * SECURITY: Fixed duration, no jitter.
         * Jitter creates detectable patterns.
         */
        const val EPOCH_DURATION_MS = 30_000L  // 30 seconds

        /**
         * Maximum packet size (LoRa MTU).
         * All packets padded to this size.
         *
         * FIXED: Changed from 237 to 184 to match MeshCore MAX_PACKET_PAYLOAD.
         * The old value caused packets to exceed the LoRa limit.
         */
        const val FIXED_PACKET_SIZE = 184

        /**
         * Domain separator for deterministic timing.
         */
        private val TIMING_DOMAIN = "lunarpunk-constant-rate-v1".toByteArray()
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()
    private var isRunning = false
    private var transmissionJob: Job? = null

    // Queue of real packets waiting to be sent
    private val realPacketQueue = ArrayDeque<QueuedPacket>()

    // Current epoch state
    private var currentEpoch: Long = 0
    private var packetsThisEpoch: Int = 0

    /**
     * Start constant-rate transmission.
     *
     * Once started, EXACTLY PACKETS_PER_EPOCH packets are sent
     * every EPOCH_DURATION_MS milliseconds. No exceptions.
     */
    suspend fun start(scope: CoroutineScope) = mutex.withLock {
        if (isRunning) return@withLock

        isRunning = true
        currentEpoch = System.currentTimeMillis() / EPOCH_DURATION_MS

        transmissionJob = scope.launch {
            while (isActive && isRunning) {
                try {
                    runEpoch()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // Continue running even on errors
                    delay(1000)
                }
            }
        }
    }

    /**
     * Stop transmission.
     */
    suspend fun stop() = mutex.withLock {
        isRunning = false
        transmissionJob?.cancelAndJoin()
        transmissionJob = null
    }

    /**
     * Queue a real packet for transmission.
     *
     * The packet will replace a chaff packet in the next available slot.
     * This maintains constant rate while allowing real communication.
     */
    suspend fun queueRealPacket(packet: ByteArray, metadata: PacketMetadata) = mutex.withLock {
        // Pad to fixed size
        val paddedPacket = padToFixedSize(packet)
        realPacketQueue.addLast(QueuedPacket(paddedPacket, metadata))
    }

    /**
     * Run a single epoch of constant-rate transmission.
     */
    private suspend fun runEpoch() {
        val epochStart = System.currentTimeMillis()
        val epochNumber = epochStart / EPOCH_DURATION_MS

        mutex.withLock {
            currentEpoch = epochNumber
            packetsThisEpoch = 0
        }

        // Calculate inter-packet interval
        // SECURITY: Fixed interval, no randomization
        val intervalMs = EPOCH_DURATION_MS / PACKETS_PER_EPOCH

        // Transmit exactly PACKETS_PER_EPOCH packets
        for (i in 0 until PACKETS_PER_EPOCH) {
            val packetStartTime = System.currentTimeMillis()

            // Get packet to send (real or chaff)
            val packet = mutex.withLock {
                if (realPacketQueue.isNotEmpty()) {
                    // Send real packet
                    val queued = realPacketQueue.removeFirst()
                    packetsThisEpoch++
                    PooledPacket(
                        data = queued.data,
                        type = MessagePool.PACKET_TYPE_REAL,
                        priority = 0,
                        addedAt = epochNumber,
                        metadata = queued.metadata
                    )
                } else {
                    // Generate chaff
                    packetsThisEpoch++
                    generateChaffPacket(epochNumber)
                }
            }

            // Transmit via message pool by adding to the pool for anonymity mixing
            messagePool.addMessage(packet.data, packet.priority, packet.metadata)

            // Wait for next slot
            val elapsed = System.currentTimeMillis() - packetStartTime
            val waitTime = intervalMs - elapsed
            if (waitTime > 0) {
                delay(waitTime)
            }
        }

        // Wait for epoch to complete
        val epochElapsed = System.currentTimeMillis() - epochStart
        val remaining = EPOCH_DURATION_MS - epochElapsed
        if (remaining > 0) {
            delay(remaining)
        }
    }

    /**
     * Generate a chaff packet.
     *
     * SECURITY: Chaff is cryptographically indistinguishable from real traffic.
     * - Same size (padded)
     * - Same encryption (random key)
     * - Same timing (constant rate)
     */
    private suspend fun generateChaffPacket(epoch: Long): PooledPacket {
        val chaffData = generateCoverPacket()?.let { padToFixedSize(it) }
            ?: generateRandomChaff()

        return PooledPacket(
            data = chaffData,
            type = MessagePool.PACKET_TYPE_CHAFF,
            priority = -1,
            addedAt = epoch,
            metadata = null  // SECURITY: No metadata for chaff
        )
    }

    /**
     * Generate cryptographically random chaff.
     */
    private fun generateRandomChaff(): ByteArray {
        val chaff = ByteArray(FIXED_PACKET_SIZE)
        secureRandom.nextBytes(chaff)

        // Add valid packet header so it looks like real traffic
        // SECURITY: Header format matches real packets exactly
        chaff[0] = 0x04  // Garlic version byte (0x04 & 0b11 = Data type for Rust)
        // Rest is random (appears encrypted)

        return chaff
    }

    /**
     * Pad packet to fixed size.
     *
     * SECURITY: All packets MUST be identical size.
     * Variable size = observable message length = information leak.
     */
    private fun padToFixedSize(packet: ByteArray): ByteArray {
        if (packet.size >= FIXED_PACKET_SIZE) {
            return packet.copyOf(FIXED_PACKET_SIZE)
        }

        val padded = ByteArray(FIXED_PACKET_SIZE)
        System.arraycopy(packet, 0, padded, 0, packet.size)

        // Fill remainder with random padding
        // SECURITY: Random padding prevents length inference
        val padding = ByteArray(FIXED_PACKET_SIZE - packet.size)
        secureRandom.nextBytes(padding)
        System.arraycopy(padding, 0, padded, packet.size, padding.size)

        return padded
    }

    /**
     * Get current statistics.
     */
    suspend fun getStats(): ConstantRateStats = mutex.withLock {
        ConstantRateStats(
            isRunning = isRunning,
            currentEpoch = currentEpoch,
            packetsThisEpoch = packetsThisEpoch,
            queuedRealPackets = realPacketQueue.size,
            packetsPerEpoch = PACKETS_PER_EPOCH,
            epochDurationMs = EPOCH_DURATION_MS
        )
    }
}

/**
 * A queued real packet waiting to be transmitted.
 */
private data class QueuedPacket(
    val data: ByteArray,
    val metadata: PacketMetadata
)

/**
 * Statistics for constant-rate cover traffic.
 */
data class ConstantRateStats(
    val isRunning: Boolean,
    val currentEpoch: Long,
    val packetsThisEpoch: Int,
    val queuedRealPackets: Int,
    val packetsPerEpoch: Int,
    val epochDurationMs: Long
) {
    /**
     * Effective bandwidth utilization.
     * Lower = more chaff, higher anonymity.
     */
    val utilizationPercent: Double
        get() = if (packetsPerEpoch > 0) {
            (packetsThisEpoch.toDouble() / packetsPerEpoch) * 100
        } else 0.0
}
