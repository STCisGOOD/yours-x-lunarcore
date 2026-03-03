package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * ReplayProtection - Prevents replay attacks on handshakes and messages.
 *
 * ATTACK SCENARIO (without protection):
 * 1. Adversary captures handshake packet from Alice
 * 2. Adversary replays it hours/days later
 * 3. Bob's app reprocesses, potentially disrupting session
 * 4. Or: adversary confirms "Bob is a target" by observing response
 *
 * PROTECTION MECHANISMS:
 *
 * 1. MONOTONIC COUNTERS
 *    - Each sender maintains an incrementing counter
 *    - Receiver rejects if counter <= last seen
 *    - No clock synchronization needed
 *
 * 2. SLIDING WINDOW
 *    - Accept counters within a window of last seen
 *    - Handles out-of-order delivery (common in mesh)
 *    - Bitmap tracks which counters in window were used
 *
 * 3. NONCE CACHE
 *    - Store seen message nonces for replay detection
 *    - Bounded size with LRU eviction
 *    - Alternative to counter-based approach
 */
class ReplayProtection {

    companion object {
        /**
         * Sliding window size (in counter values).
         * Handles out-of-order delivery within this range.
         */
        const val WINDOW_SIZE = 64

        /**
         * Maximum nonce cache size per contact.
         */
        const val MAX_NONCE_CACHE_SIZE = 1000

        /**
         * Nonce size in bytes.
         */
        const val NONCE_SIZE = 16
    }

    private val mutex = Mutex()

    /**
     * Counter state per contact (by DID).
     * Stores: (lastSeenCounter, windowBitmap)
     */
    private val counterState = ConcurrentHashMap<String, CounterState>()

    /**
     * Nonce cache per contact (for message-level replay protection).
     */
    private val nonceCache = ConcurrentHashMap<String, MutableSet<NonceWrapper>>()

    /**
     * Generate a new counter value for outgoing messages.
     *
     * @param contactDid The recipient's DID
     * @return Counter value to include in message
     */
    suspend fun generateCounter(contactDid: String): Long = mutex.withLock {
        val state = counterState.getOrPut(contactDid) { CounterState() }
        state.outgoingCounter++
        state.outgoingCounter
    }

    /**
     * Validate an incoming counter value.
     *
     * @param contactDid The sender's DID
     * @param counter The counter from the message
     * @return true if valid (not a replay), false if replay detected
     */
    suspend fun validateCounter(contactDid: String, counter: Long): Boolean = mutex.withLock {
        val state = counterState.getOrPut(contactDid) { CounterState() }

        // Check if counter is too old (before window)
        if (counter <= state.lastSeenCounter - WINDOW_SIZE) {
            return@withLock false  // Definitely a replay or very old
        }

        // Check if counter is ahead of window (new high-water mark)
        if (counter > state.lastSeenCounter) {
            // Shift window to new position
            val shift = (counter - state.lastSeenCounter).toInt().coerceAtMost(WINDOW_SIZE)

            // Shift bitmap left, losing old entries
            state.windowBitmap = state.windowBitmap shl shift

            // Mark this counter as seen (bit 0)
            state.windowBitmap = state.windowBitmap or 1L

            // Update high-water mark
            state.lastSeenCounter = counter

            return@withLock true  // Valid new counter
        }

        // Counter is within window - check bitmap
        val offset = (state.lastSeenCounter - counter).toInt()
        if (offset < WINDOW_SIZE) {
            val bit = 1L shl offset
            if ((state.windowBitmap and bit) != 0L) {
                return@withLock false  // Already seen (replay)
            }
            // Mark as seen
            state.windowBitmap = state.windowBitmap or bit
            return@withLock true  // Valid (out-of-order but new)
        }

        false  // Should not reach here
    }

    /**
     * Generate a random nonce for a message.
     */
    fun generateNonce(): ByteArray {
        return BedrockCore.randomBytes(NONCE_SIZE)
    }

    /**
     * Validate a message nonce (not seen before).
     *
     * @param contactDid The sender's DID
     * @param nonce The nonce from the message
     * @return true if valid (not a replay), false if nonce was seen before
     */
    suspend fun validateNonce(contactDid: String, nonce: ByteArray): Boolean = mutex.withLock {
        val cache = nonceCache.getOrPut(contactDid) { mutableSetOf() }

        val wrapper = NonceWrapper(nonce)

        // Check if already seen
        if (cache.contains(wrapper)) {
            return@withLock false  // Replay detected
        }

        // Add to cache
        cache.add(wrapper)

        // Evict oldest if cache is full
        // Note: MutableSet doesn't preserve order, so this is approximate LRU
        // For proper LRU, would need LinkedHashSet or custom structure
        if (cache.size > MAX_NONCE_CACHE_SIZE) {
            cache.remove(cache.first())
        }

        true  // Valid new nonce
    }

    /**
     * Clear all replay protection state for a contact.
     * Call when session is reset.
     */
    suspend fun clearContact(contactDid: String): Unit = mutex.withLock {
        counterState.remove(contactDid)
        nonceCache.remove(contactDid)
        Unit
    }

    /**
     * Clear all replay protection state.
     * Call on lock/wipe.
     */
    suspend fun clearAll() = mutex.withLock {
        counterState.clear()
        nonceCache.clear()
    }

    /**
     * Get current state for debugging.
     */
    fun getState(contactDid: String): CounterState? {
        return counterState[contactDid]
    }
}

/**
 * Counter state for a single contact.
 */
data class CounterState(
    var outgoingCounter: Long = 0,
    var lastSeenCounter: Long = 0,
    var windowBitmap: Long = 0  // Bit i = 1 means (lastSeenCounter - i) was seen
)

/**
 * Wrapper for nonce bytes to enable proper Set membership checking.
 */
private class NonceWrapper(private val nonce: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NonceWrapper) return false
        return nonce.contentEquals(other.nonce)
    }

    override fun hashCode(): Int {
        return nonce.contentHashCode()
    }
}

/**
 * Extension to encode counter into a message.
 */
fun ByteArray.withReplayProtection(counter: Long, nonce: ByteArray): ByteArray {
    require(nonce.size == ReplayProtection.NONCE_SIZE) {
        "Nonce must be ${ReplayProtection.NONCE_SIZE} bytes"
    }

    // Format: [counter:8][nonce:16][original_data]
    val buffer = ByteBuffer.allocate(8 + ReplayProtection.NONCE_SIZE + this.size)
    buffer.putLong(counter)
    buffer.put(nonce)
    buffer.put(this)
    return buffer.array()
}

/**
 * Extension to extract counter and nonce from a message.
 */
fun ByteArray.extractReplayProtection(): Triple<Long, ByteArray, ByteArray>? {
    if (this.size < 8 + ReplayProtection.NONCE_SIZE) {
        return null
    }

    val buffer = ByteBuffer.wrap(this)
    val counter = buffer.getLong()
    val nonce = ByteArray(ReplayProtection.NONCE_SIZE)
    buffer.get(nonce)

    val data = ByteArray(this.size - 8 - ReplayProtection.NONCE_SIZE)
    buffer.get(data)

    return Triple(counter, nonce, data)
}

/**
 * Handshake replay protection with timestamp validation.
 *
 * Handshakes include a timestamp that must be within acceptable range.
 * This prevents replay of very old handshakes without requiring
 * synchronized clocks (generous tolerance).
 */
object HandshakeReplayProtection {
    /**
     * Maximum age of a valid handshake (24 hours).
     * Generous to handle timezone/clock drift issues.
     */
    const val MAX_HANDSHAKE_AGE_MS = 24 * 60 * 60 * 1000L

    /**
     * Maximum future tolerance (5 minutes).
     * Handles minor clock skew.
     */
    const val MAX_FUTURE_TOLERANCE_MS = 5 * 60 * 1000L

    /**
     * Validate handshake timestamp.
     *
     * @param handshakeTimestamp Timestamp from handshake
     * @return true if within acceptable range
     */
    fun validateTimestamp(handshakeTimestamp: Long): Boolean {
        val now = System.currentTimeMillis()
        val age = now - handshakeTimestamp

        // Reject if too old
        if (age > MAX_HANDSHAKE_AGE_MS) {
            return false
        }

        // Reject if too far in future
        if (age < -MAX_FUTURE_TOLERANCE_MS) {
            return false
        }

        return true
    }

    /**
     * Generate current timestamp for handshake.
     */
    fun generateTimestamp(): Long {
        return System.currentTimeMillis()
    }
}
