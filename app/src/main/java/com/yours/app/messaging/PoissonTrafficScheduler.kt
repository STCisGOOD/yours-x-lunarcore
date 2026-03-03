package com.yours.app.messaging

import android.util.Log
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import kotlin.math.ln

private const val TAG = "PoissonTraffic"

/**
 * Loopix-style Poisson-distributed packet transmission.
 * Memoryless inter-arrival times make real messages indistinguishable from cover traffic.
 *
 * Rates (λ = packets/second):
 * - STEALTH:  1/60  → ~15s avg latency
 * - NORMAL:   1/30  → ~7.5s avg latency
 * - FAST:     1/15  → ~3.75s avg latency
 * - REALTIME: 1/5   → ~1.25s avg latency
 */
class PoissonTrafficScheduler(
    private val onTransmit: suspend (PoissonPacket) -> Boolean,
    private val generateCoverPacket: suspend () -> ByteArray
) {
    companion object {
        /**
         * Transmission rates (packets per second).
         *
         * LoRa constraints:
         * - TX time ≈ 300ms for 184-byte packet at SF7/125kHz
         * - Many regions: 1% duty cycle → max 1 packet per 30 seconds
         * - Some regions: 10% duty cycle → max 1 packet per 3 seconds
         */
        const val LAMBDA_STEALTH = 1.0 / 60.0    // 1 packet per minute
        const val LAMBDA_NORMAL = 1.0 / 30.0     // 2 packets per minute
        const val LAMBDA_FAST = 1.0 / 15.0       // 4 packets per minute
        const val LAMBDA_REALTIME = 1.0 / 5.0    // 12 packets per minute

        /**
         * Minimum inter-arrival time (prevents burst flooding).
         * Must be > LoRa TX time to avoid queue buildup.
         */
        const val MIN_INTER_ARRIVAL_MS = 500L

        /**
         * Post-TX receive window (half-duplex collision prevention).
         *
         * CRITICAL FIX: After transmitting, we MUST wait before TX again.
         * This gives the remote device time to send responses.
         *
         * Without this, the pattern is:
         *   Device A TX → Device A TX → Device A TX → ...
         *   Device B tries to respond but A is always transmitting!
         *
         * With this window:
         *   Device A TX → [RECEIVE WINDOW] → Device A TX → ...
         *   Device B can send during the receive window.
         *
         * Value chosen: 3 seconds
         * - Allows remote device ~2 Poisson intervals to respond
         * - Accounts for LoRa propagation + TX time (~700ms)
         * - Not so long that it hurts real-time performance
         */
        const val POST_TX_RECEIVE_WINDOW_MS = 3000L

        /**
         * Maximum inter-arrival time (ensures liveness).
         */
        const val MAX_INTER_ARRIVAL_MS = 120_000L  // 2 minutes

        /**
         * Standard packet size (LoRa MTU).
         */
        const val PACKET_SIZE = 184
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()

    /**
     * Last transmission completion time (for receive window enforcement).
     */
    @Volatile
    private var lastTxCompleteTimeMs: Long = 0L

    /**
     * Current transmission rate.
     */
    @Volatile
    private var lambda: Double = LAMBDA_NORMAL

    /**
     * Queue of pending real packets (priority over cover traffic).
     */
    private val packetQueue = ArrayDeque<QueuedPacket>()

    /**
     * Maximum queue size (prevents memory exhaustion).
     */
    private val maxQueueSize = 50

    /**
     * Scheduler state.
     */
    private var scope: CoroutineScope? = null
    private var schedulerJob: Job? = null
    @Volatile
    private var isRunning = false

    /**
     * Statistics for monitoring.
     */
    private var totalPacketsSent = 0L
    private var realPacketsSent = 0L
    private var coverPacketsSent = 0L
    private var totalCollisions = 0L  // Detected via failed TX

    /**
     * Events for monitoring.
     */
    private val _events = MutableSharedFlow<PoissonEvent>(replay = 0, extraBufferCapacity = 16)
    val events: Flow<PoissonEvent> = _events.asSharedFlow()

    /**
     * Start the Poisson scheduler.
     *
     * @param scope Coroutine scope for the scheduler
     * @param initialLambda Initial transmission rate (packets/second)
     */
    fun start(scope: CoroutineScope, initialLambda: Double = LAMBDA_NORMAL) {
        if (isRunning) {
            Log.w(TAG, "start() called but scheduler already running - ignoring")
            return
        }

        this.scope = scope
        this.lambda = initialLambda
        this.isRunning = true

        Log.i(TAG, "Starting Poisson scheduler with λ=$lambda (${1.0/lambda}s mean interval)")

        schedulerJob = scope.launch {
            runSchedulerLoop()
        }
    }

    /**
     * Stop the scheduler.
     */
    fun stop() {
        isRunning = false
        schedulerJob?.cancel()
        schedulerJob = null
        Log.i(TAG, "Poisson scheduler stopped")
    }

    /**
     * Queue a real packet for transmission.
     *
     * The packet will be transmitted at the next Poisson tick.
     * Average latency = 1/(2λ) seconds.
     *
     * @param packet The garlic-wrapped packet (must be PACKET_SIZE bytes)
     * @param metadata Optional metadata for tracking
     * @param priority Higher priority packets are sent first
     * @return Position in queue, or -1 if queue full
     */
    suspend fun queuePacket(
        packet: ByteArray,
        metadata: PacketMetadata? = null,
        priority: Int = 0
    ): Int = mutex.withLock {
        require(packet.size == PACKET_SIZE) {
            "Packet must be exactly $PACKET_SIZE bytes, got ${packet.size}"
        }

        if (packetQueue.size >= maxQueueSize) {
            Log.w(TAG, "Queue full ($maxQueueSize packets) - dropping oldest")
            packetQueue.removeFirst()
        }

        val queued = QueuedPacket(
            data = packet,
            metadata = metadata,
            priority = priority,
            queuedAt = System.currentTimeMillis()
        )

        // Insert in priority order (higher priority first)
        val insertIndex = packetQueue.indexOfFirst { it.priority < priority }
        if (insertIndex == -1) {
            packetQueue.addLast(queued)
        } else {
            packetQueue.add(insertIndex, queued)
        }

        val position = packetQueue.indexOf(queued)
        Log.d(TAG, "Queued packet at position $position (queue size: ${packetQueue.size})")

        _events.emit(PoissonEvent.PacketQueued(position, packetQueue.size))

        position
    }

    /**
     * Set the transmission rate.
     *
     * @param newLambda New rate in packets per second
     */
    fun setRate(newLambda: Double) {
        require(newLambda > 0) { "Lambda must be positive" }
        val oldLambda = lambda
        lambda = newLambda
        Log.i(TAG, "Rate changed: λ=$oldLambda → λ=$newLambda (${1.0/newLambda}s mean interval)")
    }

    /**
     * Get current queue size.
     */
    suspend fun getQueueSize(): Int = mutex.withLock {
        packetQueue.size
    }

    /**
     * Get statistics.
     */
    fun getStats(): PoissonStats = PoissonStats(
        totalPacketsSent = totalPacketsSent,
        realPacketsSent = realPacketsSent,
        coverPacketsSent = coverPacketsSent,
        currentQueueSize = packetQueue.size,
        currentLambda = lambda,
        meanInterArrivalMs = (1000.0 / lambda).toLong()
    )

    /**
     * Clear the queue (for panic wipe).
     */
    suspend fun clear() = mutex.withLock {
        for (packet in packetQueue) {
            packet.data.fill(0)
        }
        packetQueue.clear()
    }

    /**
     * Main scheduler loop - the heart of Poisson transmission.
     */
    private suspend fun runSchedulerLoop() {
        Log.d(TAG, "Scheduler loop started")

        while (isRunning && scope?.isActive == true) {
            try {
                // Generate next inter-arrival time from Exponential(λ)
                val interArrivalMs = generateExponentialDelay()

                Log.v(TAG, "Next TX in ${interArrivalMs}ms")
                delay(interArrivalMs)

                if (!isRunning) break

                // HALF-DUPLEX FIX: Enforce post-TX receive window
                // This prevents "TX hogging" where one device transmits so frequently
                // that the remote device never gets a chance to send its responses.
                val now = System.currentTimeMillis()
                val timeSinceLastTx = now - lastTxCompleteTimeMs
                if (timeSinceLastTx < POST_TX_RECEIVE_WINDOW_MS) {
                    val remainingWindow = POST_TX_RECEIVE_WINDOW_MS - timeSinceLastTx
                    Log.d(TAG, "In receive window - waiting ${remainingWindow}ms before next TX")
                    delay(remainingWindow)
                }

                if (!isRunning) break

                // Transmit one packet
                val txStartTime = System.currentTimeMillis()
                Log.d(TAG, "TX START at $txStartTime")

                transmitNext()

                // Record TX completion time for receive window calculation
                lastTxCompleteTimeMs = System.currentTimeMillis()
                val txDuration = lastTxCompleteTimeMs - txStartTime
                Log.d(TAG, "TX END at $lastTxCompleteTimeMs (duration: ${txDuration}ms)")

            } catch (e: CancellationException) {
                Log.d(TAG, "Scheduler loop cancelled")
                break
            } catch (e: Exception) {
                Log.e(TAG, "Scheduler loop error: ${e.message}", e)
                // Continue running despite errors
                delay(1000)
            }
        }

        Log.d(TAG, "Scheduler loop ended")
    }

    /**
     * Generate exponentially-distributed delay.
     *
     * For Poisson process with rate λ:
     * Inter-arrival time T ~ Exponential(λ)
     * T = -ln(U) / λ, where U ~ Uniform(0,1)
     */
    private fun generateExponentialDelay(): Long {
        // Avoid ln(0) by using nextDouble() which returns [0,1)
        // Add small epsilon to avoid edge case
        val u = secureRandom.nextDouble().coerceIn(0.0001, 0.9999)

        // Exponential distribution: T = -ln(U) / λ
        val delaySeconds = -ln(u) / lambda
        val delayMs = (delaySeconds * 1000).toLong()

        // Clamp to reasonable bounds
        return delayMs.coerceIn(MIN_INTER_ARRIVAL_MS, MAX_INTER_ARRIVAL_MS)
    }

    /**
     * Transmit the next packet (real or cover).
     */
    private suspend fun transmitNext() {
        val packet = mutex.withLock {
            if (packetQueue.isNotEmpty()) {
                // Real packet available
                packetQueue.removeFirst()
            } else {
                null
            }
        }

        val poissonPacket = if (packet != null) {
            // Transmit real packet
            val latencyMs = System.currentTimeMillis() - packet.queuedAt
            Log.d(TAG, "TX real packet (latency: ${latencyMs}ms, messageId: ${packet.metadata?.messageId})")

            PoissonPacket(
                data = packet.data,
                isReal = true,
                metadata = packet.metadata
            )
        } else {
            // Generate and transmit cover traffic
            val coverData = try {
                generateCoverPacket()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to generate cover packet: ${e.message}")
                return
            }

            Log.v(TAG, "TX cover packet")

            PoissonPacket(
                data = coverData,
                isReal = false,
                metadata = null
            )
        }

        // Transmit
        val success = try {
            onTransmit(poissonPacket)
        } catch (e: Exception) {
            Log.e(TAG, "Transmit error: ${e.message}", e)
            false
        }

        // Update statistics
        totalPacketsSent++
        if (poissonPacket.isReal) {
            realPacketsSent++
        } else {
            coverPacketsSent++
        }

        if (!success) {
            totalCollisions++
            _events.emit(PoissonEvent.TransmitFailed(poissonPacket.isReal))
        } else {
            _events.emit(PoissonEvent.PacketSent(poissonPacket.isReal))
        }
    }
}

/**
 * A packet in the Poisson queue.
 */
private data class QueuedPacket(
    val data: ByteArray,
    val metadata: PacketMetadata?,
    val priority: Int,
    val queuedAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is QueuedPacket) return false
        return data.contentEquals(other.data) && queuedAt == other.queuedAt
    }

    override fun hashCode(): Int {
        return data.contentHashCode() * 31 + queuedAt.hashCode()
    }
}

/**
 * A packet ready for transmission.
 */
data class PoissonPacket(
    val data: ByteArray,
    val isReal: Boolean,
    val metadata: PacketMetadata?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PoissonPacket) return false
        return data.contentEquals(other.data) && isReal == other.isReal
    }

    override fun hashCode(): Int {
        return data.contentHashCode() * 31 + isReal.hashCode()
    }
}

/**
 * Poisson scheduler statistics.
 */
data class PoissonStats(
    val totalPacketsSent: Long,
    val realPacketsSent: Long,
    val coverPacketsSent: Long,
    val currentQueueSize: Int,
    val currentLambda: Double,
    val meanInterArrivalMs: Long
) {
    val coverRatio: Double
        get() = if (totalPacketsSent > 0) {
            coverPacketsSent.toDouble() / totalPacketsSent
        } else 0.0
}

/**
 * Events from the Poisson scheduler.
 */
sealed class PoissonEvent {
    data class PacketQueued(val position: Int, val queueSize: Int) : PoissonEvent()
    data class PacketSent(val wasReal: Boolean) : PoissonEvent()
    data class TransmitFailed(val wasReal: Boolean) : PoissonEvent()
    data class RateChanged(val oldLambda: Double, val newLambda: Double) : PoissonEvent()
}

/**
 * Preset rate configurations.
 */
enum class PoissonRate(
    val lambda: Double,
    val description: String
) {
    /**
     * Minimal bandwidth usage, highest latency.
     * Good for: Battery saving, low-activity periods.
     */
    STEALTH(
        lambda = PoissonTrafficScheduler.LAMBDA_STEALTH,
        description = "Stealth: 1 pkt/min, ~30s avg latency"
    ),

    /**
     * Balanced bandwidth and latency.
     * Good for: Normal usage, most scenarios.
     */
    NORMAL(
        lambda = PoissonTrafficScheduler.LAMBDA_NORMAL,
        description = "Normal: 2 pkt/min, ~15s avg latency"
    ),

    /**
     * Higher bandwidth, lower latency.
     * Good for: Active conversations.
     */
    FAST(
        lambda = PoissonTrafficScheduler.LAMBDA_FAST,
        description = "Fast: 4 pkt/min, ~7.5s avg latency"
    ),

    /**
     * Maximum responsiveness.
     * Good for: Real-time coordination, emergencies.
     * Warning: High battery and bandwidth usage.
     */
    REALTIME(
        lambda = PoissonTrafficScheduler.LAMBDA_REALTIME,
        description = "Realtime: 12 pkt/min, ~2.5s avg latency"
    )
}
