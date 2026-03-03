package com.yours.app.messaging

import android.util.Log
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * I2P-style garlic bundling — multiple encrypted cloves in a single packet.
 * Obscures message count and adds chaff for traffic analysis resistance.
 */
class GarlicBundler {

    companion object {
        /** Maximum garlic payload size (within LoRa MTU). */
        const val MAX_GARLIC_SIZE = 184

        /**
         * Garlic header overhead: version(1) + count(1) = 2 bytes
         */
        const val GARLIC_HEADER_SIZE = 2

        /**
         * Clove header size: [type:1][dest_hint:4][length:2] = 7 bytes
         */
        const val CLOVE_HEADER_SIZE = 7

        /**
         * Minimum clove payload (must be useful).
         */
        const val MIN_CLOVE_PAYLOAD = 20

        /**
         * Maximum cloves per garlic (practical limit).
         */
        const val MAX_CLOVES_PER_GARLIC = 4

        /**
         * Clove types.
         */
        const val CLOVE_TYPE_DATA: Byte = 0x01      // Real message data
        const val CLOVE_TYPE_ACK: Byte = 0x02       // Acknowledgment
        const val CLOVE_TYPE_CHAFF: Byte = 0x03    // Fake/padding clove
        const val CLOVE_TYPE_DELIVERY: Byte = 0x04 // Delivery instruction
        const val CLOVE_TYPE_HANDSHAKE: Byte = 0x05 // Session handshake (no hint prefix in payload)
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()

    /**
     * Pending cloves waiting to be bundled.
     */
    private val pendingCloves = mutableListOf<Clove>()

    /**
     * Add a clove to the pending bundle.
     *
     * @return BundleStatus indicating next action:
     *   - SKIP: Clove too large for garlic, send raw packet instead
     *   - READY: Bundle full, call buildGarlic()
     *   - PENDING: More room, wait for more cloves or timeout
     */
    suspend fun addClove(clove: Clove): BundleStatus = mutex.withLock {
        // Check if this single clove would exceed garlic limit
        // Garlic overhead = GARLIC_HEADER_SIZE (2) + CLOVE_HEADER_SIZE (7) = 9 bytes
        val singleCloveSize = GARLIC_HEADER_SIZE + CLOVE_HEADER_SIZE + clove.payload.size
        if (singleCloveSize > MAX_GARLIC_SIZE) {
            // Clove too large for garlic bundling - caller should send raw packet
            return@withLock BundleStatus.SKIP
        }

        pendingCloves.add(clove)

        // Check if we should bundle now
        val totalSize = calculateBundleSize(pendingCloves)

        when {
            pendingCloves.size >= MAX_CLOVES_PER_GARLIC -> BundleStatus.READY
            totalSize >= MAX_GARLIC_SIZE - CLOVE_HEADER_SIZE - MIN_CLOVE_PAYLOAD -> BundleStatus.READY
            else -> BundleStatus.PENDING
        }
    }

    /**
     * Build a garlic from pending cloves.
     *
     * @param addChaff Whether to add chaff cloves for padding
     * @return Serialized garlic ready for transmission
     */
    suspend fun buildGarlic(addChaff: Boolean = true): ByteArray? = mutex.withLock {
        if (pendingCloves.isEmpty()) {
            return@withLock null
        }

        val cloves = pendingCloves.toMutableList()
        pendingCloves.clear()

        // Add chaff to fill remaining space
        if (addChaff) {
            val currentSize = calculateBundleSize(cloves)
            val remainingSpace = MAX_GARLIC_SIZE - currentSize

            if (remainingSpace >= CLOVE_HEADER_SIZE + MIN_CLOVE_PAYLOAD) {
                // Add chaff clove(s)
                val chaffSize = remainingSpace - CLOVE_HEADER_SIZE
                cloves.add(generateChaffClove(chaffSize))
            }
        }

        // Shuffle cloves to randomize order
        cloves.shuffle(secureRandom)

        // Serialize garlic
        serializeGarlic(cloves)
    }

    /**
     * Build a garlic immediately with the given cloves (don't wait for more).
     *
     * @param cloves The cloves to bundle
     * @param addChaff Whether to add chaff padding for traffic analysis resistance
     * @param preserveOrder If true, cloves are serialized in the order provided.
     *                      CRITICAL for session establishment: handshake MUST come
     *                      before the message clove so receiver establishes session
     *                      before attempting decryption.
     *                      Default is false (shuffle for anonymity).
     */
    fun buildImmediateGarlic(
        cloves: List<Clove>,
        addChaff: Boolean = true,
        preserveOrder: Boolean = false
    ): ByteArray {
        val workingCloves = cloves.toMutableList()

        if (addChaff) {
            val currentSize = calculateBundleSize(workingCloves)
            val remainingSpace = MAX_GARLIC_SIZE - currentSize

            if (remainingSpace >= CLOVE_HEADER_SIZE + MIN_CLOVE_PAYLOAD) {
                val chaffSize = remainingSpace - CLOVE_HEADER_SIZE
                workingCloves.add(generateChaffClove(chaffSize))
            }
        }

        // Only shuffle if order doesn't matter.
        // For session establishment, handshake MUST precede message clove.
        if (!preserveOrder) {
            workingCloves.shuffle(secureRandom)
        }
        return serializeGarlic(workingCloves)
    }

    /**
     * Parse a received garlic into cloves.
     *
     * Version byte must be 0x04 (not 0x01) to avoid Rust packet type conflict:
     * - Rust uses lower 2 bits of first byte for packet type
     * - 0x01 & 0b11 = 0b01 = Handshake (wrong!)
     * - 0x04 & 0b11 = 0b00 = Data (correct!)
     */
    fun parseGarlic(data: ByteArray): List<Clove> {
        val cloves = mutableListOf<Clove>()
        var offset = 0

        // Version byte - MUST be 0x04 for Rust packet type compatibility
        if (data.isEmpty() || data[0] != 0x04.toByte()) {
            Log.w("GarlicBundler", "parseGarlic: INVALID version byte 0x${String.format("%02X", data.getOrNull(0) ?: 0)}")
            return emptyList()
        }
        offset++

        // Clove count
        if (offset >= data.size) return emptyList()
        val cloveCount = data[offset].toInt() and 0xFF
        offset++

        Log.d("GarlicBundler", "parseGarlic: version=0x04, cloveCount=$cloveCount")

        // !! DIAGNOSTIC: Track if we find handshake cloves !!
        var foundHandshake = false

        // Parse each clove
        repeat(cloveCount) { cloveIndex ->
            if (offset + CLOVE_HEADER_SIZE > data.size) return cloves

            val type = data[offset]
            offset++

            val destHint = data.copyOfRange(offset, offset + 4)
            offset += 4

            val length = ((data[offset].toInt() and 0xFF) shl 8) or
                        (data[offset + 1].toInt() and 0xFF)
            offset += 2

            // !! DIAGNOSTIC: Log each clove type !!
            val typeStr = when (type) {
                CLOVE_TYPE_DATA -> "DATA"
                CLOVE_TYPE_ACK -> "ACK"
                CLOVE_TYPE_CHAFF -> "CHAFF"
                CLOVE_TYPE_DELIVERY -> "DELIVERY"
                CLOVE_TYPE_HANDSHAKE -> "HANDSHAKE"
                else -> "UNKNOWN(0x${String.format("%02X", type)})"
            }
            Log.d("GarlicBundler", "parseGarlic: clove[$cloveIndex] type=$typeStr, length=$length")

            if (type == CLOVE_TYPE_HANDSHAKE) {
                foundHandshake = true
                Log.d("GarlicBundler", "Found handshake clove in garlic (clove[$cloveIndex], $length bytes)")
            }

            if (length < 0 || length > MAX_GARLIC_SIZE || offset + length > data.size) {
                Log.e("GarlicBundler", "parseGarlic: INVALID length $length at clove[$cloveIndex]")
                return cloves
            }

            val payload = data.copyOfRange(offset, offset + length)
            offset += length

            // Skip chaff cloves
            if (type != CLOVE_TYPE_CHAFF) {
                cloves.add(Clove(
                    type = type,
                    destinationHint = destHint,
                    payload = payload
                ))
            }
        }

        // !! DIAGNOSTIC: Summary of parse result !!
        Log.d("GarlicBundler", "parseGarlic: returning ${cloves.size} cloves (foundHandshake=$foundHandshake)")
        if (cloveCount == 2 && !foundHandshake) {
            Log.d("GarlicBundler", "2-clove garlic with no handshake (message+chaff)")
        }

        return cloves
    }

    /**
     * Check if there are pending cloves.
     */
    suspend fun hasPending(): Boolean = mutex.withLock {
        pendingCloves.isNotEmpty()
    }

    /**
     * Get pending clove count.
     */
    suspend fun getPendingCount(): Int = mutex.withLock {
        pendingCloves.size
    }

    /**
     * Clear pending cloves (on lock/wipe).
     */
    suspend fun clear() = mutex.withLock {
        for (clove in pendingCloves) {
            clove.payload.fill(0)
        }
        pendingCloves.clear()
    }

    /**
     * Calculate total size of a bundle.
     */
    private fun calculateBundleSize(cloves: List<Clove>): Int {
        // Version (1) + count (1) + cloves
        return 2 + cloves.sumOf { CLOVE_HEADER_SIZE + it.payload.size }
    }

    /**
     * Generate a chaff clove.
     */
    private fun generateChaffClove(payloadSize: Int): Clove {
        return Clove(
            type = CLOVE_TYPE_CHAFF,
            destinationHint = BedrockCore.randomBytes(4),
            payload = BedrockCore.randomBytes(payloadSize.coerceIn(MIN_CLOVE_PAYLOAD, MAX_GARLIC_SIZE))
        )
    }

    /**
     * Serialize cloves into a garlic packet.
     *
     * CRITICAL: Always outputs exactly MAX_GARLIC_SIZE (184) bytes!
     * This ensures that MessagePool padding won't add any extra bytes,
     * preserving the garlic structure with its length fields.
     *
     * Version byte is 0x04 (not 0x01) to avoid conflict with Rust packet type detection:
     * - Rust uses lower 2 bits of first byte for packet type
     * - 0x01 & 0b11 = 0b01 = Handshake (wrong!)
     * - 0x04 & 0b11 = 0b00 = Data (correct!)
     *
     * BUG FIX: Now writes ACTUAL count after serialization, not cloves.size before.
     * Previously, if a clove didn't fit, it was silently dropped but the count
     * still reflected the original cloves.size, causing parse errors on receiver.
     */
    private fun serializeGarlic(cloves: List<Clove>): ByteArray {
        // ALWAYS allocate full MAX_GARLIC_SIZE - this is the key fix!
        val buffer = ByteBuffer.allocate(MAX_GARLIC_SIZE)

        // Version - MUST be 0x04 for Rust packet type compatibility
        buffer.put(0x04.toByte())

        // Reserve position for count, write placeholder (will update after serialization)
        val countPosition = buffer.position()
        buffer.put(0.toByte())

        // Serialize cloves that fit, tracking actual count
        var actualCount = 0
        for (clove in cloves) {
            if (buffer.remaining() < CLOVE_HEADER_SIZE + clove.payload.size) {
                android.util.Log.w("GarlicBundler",
                    "Clove dropped: ${clove.payload.size} bytes won't fit in ${buffer.remaining()} remaining")
                break  // No more space
            }

            buffer.put(clove.type)
            buffer.put(clove.destinationHint)
            buffer.putShort(clove.payload.size.toShort())
            buffer.put(clove.payload)
            actualCount++
        }

        buffer.put(countPosition, actualCount.toByte())

        // Pad remaining space with random data (internal padding)
        if (buffer.remaining() > 0) {
            buffer.put(BedrockCore.randomBytes(buffer.remaining()))
        }

        return buffer.array()
    }

    /**
     * Check if the given cloves will all fit in a single garlic.
     *
     * Use this BEFORE calling buildImmediateGarlic() to determine if
     * you need to split into multiple garlics.
     *
     * @param cloves The cloves to check
     * @return true if all cloves fit, false if any would be dropped
     */
    fun willClovesFit(cloves: List<Clove>): Boolean {
        val totalSize = calculateBundleSize(cloves)
        return totalSize <= MAX_GARLIC_SIZE
    }

    /**
     * Get the maximum payload size that can fit in a single garlic.
     *
     * Useful for determining if a message needs to be split.
     * Accounts for: garlic header (2) + clove header (7) = 9 bytes overhead
     *
     * @return Maximum payload bytes for a single-clove garlic
     */
    fun getMaxSingleClovePayload(): Int {
        return MAX_GARLIC_SIZE - GARLIC_HEADER_SIZE - CLOVE_HEADER_SIZE
    }

    /**
     * Wrap a single clove in garlic format - GUARANTEED to succeed.
     *
     * This is the safe method to use when you need garlic wrapping and
     * cannot tolerate null results. Unlike buildGarlic() which may return
     * null if the pending queue was emptied by another thread, this method
     * takes the clove directly and always returns a valid garlic packet.
     *
     * @param clove The clove to wrap
     * @param addChaff Whether to add chaff cloves for padding
     * @return Garlic packet of exactly MAX_GARLIC_SIZE (184) bytes
     */
    fun wrapSingleClove(clove: Clove, addChaff: Boolean = true): ByteArray {
        val cloves = mutableListOf(clove)

        if (addChaff) {
            val currentSize = calculateBundleSize(cloves)
            val remainingSpace = MAX_GARLIC_SIZE - currentSize

            if (remainingSpace >= CLOVE_HEADER_SIZE + MIN_CLOVE_PAYLOAD) {
                val chaffSize = remainingSpace - CLOVE_HEADER_SIZE
                cloves.add(generateChaffClove(chaffSize))
            }
        }

        cloves.shuffle(secureRandom)
        return serializeGarlic(cloves)
    }
}

/**
 * A single clove within a garlic.
 */
data class Clove(
    val type: Byte,
    val destinationHint: ByteArray,  // 4 bytes - blinded hint for recipient
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Clove) return false
        return type == other.type &&
               destinationHint.contentEquals(other.destinationHint) &&
               payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = type.toInt()
        result = 31 * result + destinationHint.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        /**
         * Create a data clove for a message.
         */
        fun data(destinationHint: ByteArray, encryptedMessage: ByteArray): Clove {
            return Clove(
                type = GarlicBundler.CLOVE_TYPE_DATA,
                destinationHint = destinationHint,
                payload = encryptedMessage
            )
        }

        /**
         * Create an ACK clove.
         */
        fun ack(destinationHint: ByteArray, ackPayload: ByteArray): Clove {
            return Clove(
                type = GarlicBundler.CLOVE_TYPE_ACK,
                destinationHint = destinationHint,
                payload = ackPayload
            )
        }

        /**
         * Create a handshake clove for session establishment.
         *
         * IMPORTANT: Unlike data cloves, handshake payloads do NOT have a
         * blinded hint prefix. The payload is the raw handshake packet
         * (starting with flags byte 0x01). The destinationHint is only
         * in the clove header for routing purposes.
         */
        fun handshake(destinationHint: ByteArray, handshakePacket: ByteArray): Clove {
            return Clove(
                type = GarlicBundler.CLOVE_TYPE_HANDSHAKE,
                destinationHint = destinationHint,
                payload = handshakePacket
            )
        }
    }
}

/**
 * Bundle status after adding a clove.
 */
enum class BundleStatus {
    PENDING,  // More room in bundle
    READY,    // Bundle should be sent
    SKIP      // Clove too large for garlic - send raw packet instead
}

/**
 * Garlic routing instructions for relay nodes.
 *
 * Each relay receives a garlic, peels its layer, and:
 * - Forwards cloves meant for other destinations
 * - Processes cloves meant for itself
 */
data class GarlicRoutingInstructions(
    val forwardCloves: List<ForwardInstruction>,
    val localCloves: List<Clove>
)

/**
 * Instruction for forwarding a clove.
 */
data class ForwardInstruction(
    val nextHopHint: ByteArray,
    val encryptedClove: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ForwardInstruction) return false
        return nextHopHint.contentEquals(other.nextHopHint) &&
               encryptedClove.contentEquals(other.encryptedClove)
    }

    override fun hashCode(): Int {
        return nextHopHint.contentHashCode() * 31 + encryptedClove.contentHashCode()
    }
}

/**
 * Statistics for garlic bundling.
 */
data class GarlicStats(
    val totalGarlicsSent: Long,
    val totalClovesSent: Long,
    val totalChaffCloves: Long,
    val avgClovesPerGarlic: Double
) {
    val chaffRatio: Double
        get() = if (totalClovesSent > 0) {
            totalChaffCloves.toDouble() / totalClovesSent
        } else 0.0
}

/**
 * Multi-destination garlic builder.
 *
 * Allows building a single garlic with cloves for multiple recipients,
 * maximizing the anonymity benefit of garlic routing.
 */
class MultiDestinationGarlic {

    private val cloves = mutableListOf<DestinedClove>()

    /**
     * Add a clove destined for a specific contact.
     */
    fun addClove(contactDid: String, destinationHint: ByteArray, payload: ByteArray) {
        cloves.add(DestinedClove(
            contactDid = contactDid,
            clove = Clove.data(destinationHint, payload)
        ))
    }

    /**
     * Get cloves grouped by first-hop relay.
     *
     * This enables efficient routing where cloves going through
     * the same first relay are bundled together.
     */
    fun groupByFirstHop(getFirstHop: (String) -> String?): Map<String?, List<DestinedClove>> {
        return cloves.groupBy { getFirstHop(it.contactDid) }
    }

    /**
     * Get all cloves.
     */
    fun getAllCloves(): List<DestinedClove> = cloves.toList()

    /**
     * Clear all cloves.
     */
    fun clear() {
        for (dc in cloves) {
            dc.clove.payload.fill(0)
        }
        cloves.clear()
    }
}

/**
 * A clove with its intended destination.
 */
data class DestinedClove(
    val contactDid: String,
    val clove: Clove
)
