package com.yours.app.messaging

import android.content.Context
import android.util.Log
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * LunarCircuitManager - Manages anonymous onion circuits with AES-256-GCM encryption.
 *
 * This provides Tor-like circuit-based routing where:
 * - Circuits are persistent tunnels through 3+ relay nodes
 * - Each hop uses AES-256-GCM with session keys established via X25519
 * - Path selection prioritizes diversity (different regions/operators)
 * - Circuits rotate based on time (10 min) or message count (100)
 *
 * ## Architecture
 *
 * ```
 * You -> [Entry Relay] -> [Middle Relay] -> [Exit Relay] -> Recipient
 *          AES layer 1      AES layer 2       AES layer 3
 * ```
 *
 * Each relay only knows previous and next hop (like Tor).
 *
 * ## Security Properties
 * - Forward secrecy: Per-circuit session keys
 * - Anti-correlation: Entry/exit not reused together
 * - Path diversity: Different operators/regions when possible
 * - Traffic analysis resistance: Fixed packet sizes
 *
 * ## Usage
 * ```kotlin
 * val manager = LunarCircuitManager(context)
 * manager.start()
 *
 * // Learn about nodes from announcements
 * manager.processAnnouncement(announcementBytes)
 *
 * // Send a message through the circuit
 * val wrapped = manager.wrapMessage(payload, recipientHint)
 * meshTransport.send(wrapped, entryHint)
 * ```
 */
class LunarCircuitManager(
    private val context: Context,
    private val entropyCollector: EntropyCollector? = null
) {
    companion object {
        private const val TAG = "LunarCircuitManager"

        // Circuit configuration
        const val MIN_CIRCUIT_HOPS = 3
        const val MAX_CIRCUIT_HOPS = 5
        const val DEFAULT_HOPS = 3

        // Rotation thresholds
        const val CIRCUIT_ROTATION_TIME_MS = 10 * 60 * 1000L  // 10 minutes
        const val CIRCUIT_ROTATION_MESSAGE_COUNT = 100
        const val CLEANUP_INTERVAL_MS = 60 * 1000L  // 1 minute

        // Circuit states
        const val STATE_BUILDING = 0
        const val STATE_READY = 1
        const val STATE_CLOSING = 2
        const val STATE_CLOSED = 3

        // Circuit ID size
        const val CIRCUIT_ID_SIZE = 8
        // MUST MATCH bedrock-core/src/lunar/packet.rs NODE_HINT_SIZE
        const val NODE_HINT_SIZE = 4
        // MUST MATCH bedrock-core/src/lunar/packet.rs SESSION_HINT_SIZE
        const val SESSION_HINT_SIZE = 8
    }

    // Router handle (stores node table and circuits in Rust)
    private var routerHandle: Long = -1
    private val routerMutex = Mutex()

    // Active circuits
    private val circuits = ConcurrentHashMap<ByteArrayKey, CircuitInfo>()

    // Currently preferred circuit for sending
    @Volatile
    private var preferredCircuitId: ByteArray? = null

    // Coroutine scope for background tasks
    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var cleanupJob: Job? = null

    // Events
    private val _events = MutableSharedFlow<CircuitEvent>(extraBufferCapacity = 16)
    val events: Flow<CircuitEvent> = _events

    /**
     * Circuit information stored on Kotlin side.
     * The actual circuit data is in Rust (accessed via handle).
     */
    data class CircuitInfo(
        val circuitId: ByteArray,
        val createdAt: Long,
        var state: Int,
        var hopCount: Int,
        var messageCount: Int,
        var needsRotation: Boolean,
        var entryHint: ByteArray? = null
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitInfo) return false
            return circuitId.contentEquals(other.circuitId)
        }

        override fun hashCode(): Int = circuitId.contentHashCode()
    }

    /**
     * Events emitted by the circuit manager.
     */
    sealed class CircuitEvent {
        data class CircuitBuilding(val circuitId: ByteArray, val hopCount: Int) : CircuitEvent()
        data class CircuitReady(val circuitId: ByteArray) : CircuitEvent()
        data class CircuitClosed(val circuitId: ByteArray, val reason: String) : CircuitEvent()
        data class HandshakesReady(val circuitId: ByteArray, val handshakes: List<ByteArray>) : CircuitEvent()
        data class NodeDiscovered(val hint: ByteArray) : CircuitEvent()
        data class Error(val message: String) : CircuitEvent()
    }

    /**
     * Wrapper for ByteArray to use as HashMap key.
     */
    private data class ByteArrayKey(val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ByteArrayKey) return false
            return bytes.contentEquals(other.bytes)
        }

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /**
     * Start the circuit manager.
     *
     * Creates the underlying router and starts background cleanup.
     */
    suspend fun start() = routerMutex.withLock {
        if (routerHandle >= 0) {
            Log.w(TAG, "Already started")
            return@withLock
        }

        routerHandle = BedrockCore.lunarRouterCreate()
        if (routerHandle < 0) {
            Log.e(TAG, "Failed to create router")
            throw CircuitException("Failed to create Lunar router")
        }

        Log.i(TAG, "Router created with handle $routerHandle")

        // Start background cleanup
        cleanupJob = scope.launch {
            while (isActive) {
                delay(CLEANUP_INTERVAL_MS)
                cleanup()
            }
        }
    }

    /**
     * Stop the circuit manager.
     *
     * Closes all circuits and releases resources.
     */
    suspend fun stop() = routerMutex.withLock {
        cleanupJob?.cancel()
        cleanupJob = null

        if (routerHandle >= 0) {
            // Close all circuits
            for ((_, info) in circuits) {
                BedrockCore.lunarRouterCloseCircuit(routerHandle, info.circuitId)
            }
            circuits.clear()
            preferredCircuitId = null

            // Close router
            BedrockCore.lunarRouterClose(routerHandle)
            routerHandle = -1
        }

        Log.i(TAG, "Router stopped")
    }

    /**
     * Process a node announcement.
     *
     * Announcements are broadcast by relay nodes to advertise their presence.
     * The router builds a routing table from these.
     *
     * @param announcementBytes Encoded announcement from a relay
     * @return true if the announcement was valid and added
     */
    suspend fun processAnnouncement(announcementBytes: ByteArray): Boolean = routerMutex.withLock {
        if (routerHandle < 0) {
            Log.w(TAG, "Router not started")
            return@withLock false
        }

        val result = BedrockCore.lunarRouterProcessAnnouncement(routerHandle, announcementBytes)
        if (result) {
            // Extract hint from announcement for event (first 2 bytes after header)
            if (announcementBytes.size >= 4) {
                val hint = announcementBytes.copyOfRange(2, 4)
                _events.tryEmit(CircuitEvent.NodeDiscovered(hint))
            }
            Log.d(TAG, "Processed announcement successfully")
        }
        result
    }

    /**
     * Create our own node announcement for broadcasting.
     *
     * @param region Optional region identifier (0 = none)
     * @param operator Optional operator identifier (0 = none)
     * @return Encoded announcement bytes
     */
    suspend fun createAnnouncement(region: Int = 0, operator: Int = 0): ByteArray? = routerMutex.withLock {
        if (routerHandle < 0) return@withLock null
        BedrockCore.lunarRouterCreateAnnouncement(routerHandle, region, operator)
    }

    /**
     * Get our node hint.
     */
    suspend fun getOurHint(): ByteArray? = routerMutex.withLock {
        if (routerHandle < 0) return@withLock null
        BedrockCore.lunarRouterGetOurHint(routerHandle)
    }

    /**
     * Get router statistics.
     *
     * @return RouterStats or null if router not started
     */
    suspend fun getStats(): RouterStats? = routerMutex.withLock {
        if (routerHandle < 0) return@withLock null

        val bytes = BedrockCore.lunarRouterGetStats(routerHandle) ?: return@withLock null
        if (bytes.size < 20) return@withLock null

        val buf = ByteBuffer.wrap(bytes)
        RouterStats(
            knownNodes = buf.int,
            activeNodes = buf.int,
            totalCircuits = buf.int,
            readyCircuits = buf.int,
            pendingBuilds = buf.int
        )
    }

    /**
     * Build a new circuit.
     *
     * This creates the circuit and returns handshakes that must be sent
     * to each relay in the path.
     *
     * @param minHops Minimum relay hops (default: 3)
     * @param diverseRegions Require different regions for each hop
     * @param diverseOperators Require different operators for each hop
     * @return CircuitBuildResult with circuit ID and handshakes, or null on error
     */
    suspend fun buildCircuit(
        minHops: Int = DEFAULT_HOPS,
        diverseRegions: Boolean = true,
        diverseOperators: Boolean = true
    ): CircuitBuildResult? = routerMutex.withLock {
        if (routerHandle < 0) {
            Log.e(TAG, "Router not started")
            return@withLock null
        }

        // Build circuit
        val circuitId = BedrockCore.lunarRouterBuildCircuit(
            routerHandle,
            minHops,
            0, // maxHops = default
            diverseRegions,
            diverseOperators,
            0  // minReliability = default
        )

        if (circuitId == null) {
            Log.e(TAG, "Failed to build circuit - not enough nodes?")
            _events.tryEmit(CircuitEvent.Error("Failed to build circuit - need more relay nodes"))
            return@withLock null
        }

        // Collect entropy for handshakes
        val entropy = entropyCollector?.collectEntropy()
            ?: BedrockCore.randomBytes(32)

        // Create handshakes for each hop
        val handshakesEncoded = BedrockCore.lunarRouterEstablishCircuit(
            routerHandle,
            circuitId,
            entropy
        )

        BedrockCore.zeroize(entropy)

        if (handshakesEncoded == null) {
            Log.e(TAG, "Failed to create handshakes")
            BedrockCore.lunarRouterCloseCircuit(routerHandle, circuitId)
            return@withLock null
        }

        // Parse handshakes: [numHops(1), hop0Len(2), hop0Data, ...]
        val handshakes = parseHandshakes(handshakesEncoded)
        if (handshakes.isEmpty()) {
            Log.e(TAG, "No handshakes created")
            BedrockCore.lunarRouterCloseCircuit(routerHandle, circuitId)
            return@withLock null
        }

        // Store circuit info
        val info = CircuitInfo(
            circuitId = circuitId,
            createdAt = System.currentTimeMillis(),
            state = STATE_BUILDING,
            hopCount = handshakes.size,
            messageCount = 0,
            needsRotation = false
        )
        circuits[ByteArrayKey(circuitId)] = info

        Log.i(TAG, "Built circuit with ${handshakes.size} hops")
        _events.tryEmit(CircuitEvent.CircuitBuilding(circuitId, handshakes.size))
        _events.tryEmit(CircuitEvent.HandshakesReady(circuitId, handshakes))

        CircuitBuildResult(circuitId, handshakes)
    }

    /**
     * Confirm that a circuit hop has been established.
     *
     * Call this after the handshake with a relay succeeds.
     * When all hops are confirmed, the circuit becomes ready.
     *
     * @param circuitId Circuit ID
     * @param hopIndex Which hop was confirmed (0 = entry)
     * @return true if all hops now confirmed (circuit ready)
     */
    suspend fun confirmHop(circuitId: ByteArray, hopIndex: Int): Boolean = routerMutex.withLock {
        if (routerHandle < 0) return@withLock false

        val success = BedrockCore.lunarRouterConfirmHop(routerHandle, circuitId, hopIndex)
        if (!success) {
            Log.e(TAG, "Failed to confirm hop $hopIndex")
            return@withLock false
        }

        // Check if circuit is now ready
        val info = circuits[ByteArrayKey(circuitId)] ?: return@withLock false
        val circuitInfo = BedrockCore.lunarRouterGetCircuitInfo(routerHandle, circuitId)
            ?: return@withLock false

        val state = circuitInfo[0].toInt()
        info.state = state

        if (state == STATE_READY) {
            // Get entry hint for routing
            info.entryHint = BedrockCore.lunarRouterGetEntryHint(routerHandle, circuitId)

            // Make this the preferred circuit if we don't have one
            if (preferredCircuitId == null) {
                preferredCircuitId = circuitId
            }

            Log.i(TAG, "Circuit ready!")
            _events.tryEmit(CircuitEvent.CircuitReady(circuitId))
            return@withLock true
        }

        false
    }

    /**
     * Wrap a message through a circuit for anonymous transmission.
     *
     * @param payload Message to send
     * @param recipientHint 2-byte hint of final recipient
     * @param circuitId Specific circuit to use (null = use preferred)
     * @return WrapResult with wrapped packet and entry hint, or null on error
     */
    suspend fun wrapMessage(
        payload: ByteArray,
        recipientHint: ByteArray,
        circuitId: ByteArray? = null
    ): WrapResult? = routerMutex.withLock {
        if (routerHandle < 0) return@withLock null

        val cid = circuitId ?: preferredCircuitId
        if (cid == null) {
            Log.w(TAG, "No circuit available")
            return@withLock null
        }

        val info = circuits[ByteArrayKey(cid)]
        if (info == null || info.state != STATE_READY) {
            Log.w(TAG, "Circuit not ready")
            return@withLock null
        }

        val wrapped = BedrockCore.lunarRouterWrapMessage(
            routerHandle,
            cid,
            payload,
            recipientHint
        )

        if (wrapped == null) {
            Log.e(TAG, "Failed to wrap message")
            return@withLock null
        }

        // Update message count
        info.messageCount++

        // Check if needs rotation
        refreshCircuitInfo(cid, info)

        WrapResult(
            wrappedPacket = wrapped,
            entryHint = info.entryHint ?: return@withLock null,
            circuitId = cid
        )
    }

    /**
     * Check if we have a ready circuit.
     */
    fun hasReadyCircuit(): Boolean {
        val cid = preferredCircuitId ?: return false
        val info = circuits[ByteArrayKey(cid)] ?: return false
        return info.state == STATE_READY && !info.needsRotation
    }

    /**
     * Get or build a ready circuit.
     *
     * If a ready circuit exists, returns it. Otherwise builds a new one.
     * Note: Building requires handshake exchange before ready.
     *
     * @return Circuit ID, or null if not enough nodes
     */
    suspend fun getOrBuildCircuit(): ByteArray? = routerMutex.withLock {
        if (routerHandle < 0) return@withLock null

        // Check for existing ready circuit
        preferredCircuitId?.let { cid ->
            val info = circuits[ByteArrayKey(cid)]
            if (info != null && info.state == STATE_READY && !info.needsRotation) {
                return@withLock cid
            }
        }

        // Try to get or build via Rust
        BedrockCore.lunarRouterGetOrBuildCircuit(routerHandle, DEFAULT_HOPS)
    }

    /**
     * Close a specific circuit.
     */
    suspend fun closeCircuit(circuitId: ByteArray, reason: String = "manual") = routerMutex.withLock {
        if (routerHandle < 0) return@withLock

        BedrockCore.lunarRouterCloseCircuit(routerHandle, circuitId)
        circuits.remove(ByteArrayKey(circuitId))

        if (preferredCircuitId?.contentEquals(circuitId) == true) {
            preferredCircuitId = null
            // Find another ready circuit
            for ((_, info) in circuits) {
                if (info.state == STATE_READY && !info.needsRotation) {
                    preferredCircuitId = info.circuitId
                    break
                }
            }
        }

        Log.i(TAG, "Closed circuit: $reason")
        _events.tryEmit(CircuitEvent.CircuitClosed(circuitId, reason))
    }

    /**
     * Cleanup stale circuits.
     */
    private suspend fun cleanup() = routerMutex.withLock {
        if (routerHandle < 0) return@withLock

        BedrockCore.lunarRouterCleanup(routerHandle)

        // Refresh all circuit states
        val toRemove = mutableListOf<ByteArrayKey>()
        for ((key, info) in circuits) {
            refreshCircuitInfo(info.circuitId, info)
            if (info.state == STATE_CLOSED) {
                toRemove.add(key)
            }
        }

        for (key in toRemove) {
            circuits.remove(key)
            if (preferredCircuitId?.contentEquals(key.bytes) == true) {
                preferredCircuitId = null
            }
            _events.tryEmit(CircuitEvent.CircuitClosed(key.bytes, "rotation"))
        }

        // Find new preferred circuit if needed
        if (preferredCircuitId == null) {
            for ((_, info) in circuits) {
                if (info.state == STATE_READY && !info.needsRotation) {
                    preferredCircuitId = info.circuitId
                    break
                }
            }
        }
    }

    /**
     * Refresh circuit info from Rust.
     */
    private fun refreshCircuitInfo(circuitId: ByteArray, info: CircuitInfo) {
        val bytes = BedrockCore.lunarRouterGetCircuitInfo(routerHandle, circuitId) ?: return
        if (bytes.size < 7) return

        info.state = bytes[0].toInt()
        info.hopCount = bytes[1].toInt()
        info.messageCount = ByteBuffer.wrap(bytes, 2, 4).int
        info.needsRotation = bytes[6] != 0.toByte()
    }

    /**
     * Parse handshakes from encoded format.
     */
    private fun parseHandshakes(encoded: ByteArray): List<ByteArray> {
        if (encoded.isEmpty()) return emptyList()

        val result = mutableListOf<ByteArray>()
        val numHops = encoded[0].toInt() and 0xFF
        var offset = 1

        for (i in 0 until numHops) {
            if (offset + 2 > encoded.size) break
            val len = ((encoded[offset].toInt() and 0xFF) shl 8) or
                      (encoded[offset + 1].toInt() and 0xFF)
            offset += 2

            if (offset + len > encoded.size) break
            result.add(encoded.copyOfRange(offset, offset + len))
            offset += len
        }

        return result
    }
}

/**
 * Router statistics.
 */
data class RouterStats(
    val knownNodes: Int,
    val activeNodes: Int,
    val totalCircuits: Int,
    val readyCircuits: Int,
    val pendingBuilds: Int
)

/**
 * Result of building a circuit.
 */
data class CircuitBuildResult(
    val circuitId: ByteArray,
    val handshakes: List<ByteArray>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CircuitBuildResult) return false
        return circuitId.contentEquals(other.circuitId)
    }

    override fun hashCode(): Int = circuitId.contentHashCode()
}

/**
 * Result of wrapping a message.
 */
data class WrapResult(
    val wrappedPacket: ByteArray,
    val entryHint: ByteArray,
    val circuitId: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WrapResult) return false
        return wrappedPacket.contentEquals(other.wrappedPacket)
    }

    override fun hashCode(): Int = wrappedPacket.contentHashCode()
}

/**
 * Exception for circuit-related errors.
 */
class CircuitException(message: String) : Exception(message)
