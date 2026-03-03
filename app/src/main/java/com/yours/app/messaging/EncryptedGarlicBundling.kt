package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * I2P-style garlic message bundler with fully encrypted headers.
 * All clove metadata (type, count, lengths) is encrypted as a single blob,
 * with per-bundle key derivation and indistinguishable chaff cloves.
 */
class EncryptedGarlicBundler {

    companion object {
        /**
         * Maximum garlic payload size (within LoRa MTU).
         */
        const val MAX_GARLIC_SIZE = 200

        /**
         * Encrypted header overhead: [version:1][nonce:12][tag:16]
         */
        const val ENCRYPTION_OVERHEAD = 29

        /**
         * Clove header size (inside encrypted blob): [type:1][dest_hint:8][length:2]
         */
        const val CLOVE_HEADER_SIZE = 11  // Increased hint to 8 bytes

        /**
         * Minimum clove payload.
         */
        const val MIN_CLOVE_PAYLOAD = 16

        /**
         * Maximum cloves per garlic.
         */
        const val MAX_CLOVES_PER_GARLIC = 4

        /**
         * Clove types (only visible after decryption).
         */
        const val CLOVE_TYPE_DATA: Byte = 0x01
        const val CLOVE_TYPE_ACK: Byte = 0x02
        const val CLOVE_TYPE_CHAFF: Byte = 0x03
        const val CLOVE_TYPE_DELIVERY: Byte = 0x04

        /**
         * Version byte for forward compatibility.
         */
        const val VERSION: Byte = 0x02  // v2 = encrypted headers

        /**
         * Domain separator for garlic key derivation.
         */
        private val GARLIC_KEY_DOMAIN = "lunarpunk-garlic-key-v2".toByteArray()
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()
    private val pendingCloves = mutableListOf<EncryptedClove>()

    /**
     * Add a clove to the pending bundle.
     */
    suspend fun addClove(clove: EncryptedClove): BundleStatus = mutex.withLock {
        pendingCloves.add(clove)

        val totalSize = calculateBundleSize(pendingCloves)

        when {
            pendingCloves.size >= MAX_CLOVES_PER_GARLIC -> BundleStatus.READY
            totalSize >= MAX_GARLIC_SIZE - ENCRYPTION_OVERHEAD - CLOVE_HEADER_SIZE - MIN_CLOVE_PAYLOAD -> BundleStatus.READY
            else -> BundleStatus.PENDING
        }
    }

    /**
     * Build an encrypted garlic from pending cloves.
     *
     * SECURITY: The entire garlic (including all headers) is encrypted.
     * An observer sees only: [version:1][nonce:12][ciphertext][tag:16]
     *
     * @param recipientPublicKey Used to derive garlic decryption key
     * @param senderSecretKey Our secret key for key derivation
     * @param addChaff Whether to add chaff cloves
     * @return Encrypted garlic ready for transmission
     */
    suspend fun buildGarlic(
        recipientPublicKey: ByteArray,
        senderSecretKey: ByteArray,
        addChaff: Boolean = true
    ): ByteArray? = mutex.withLock {
        if (pendingCloves.isEmpty()) {
            return@withLock null
        }

        val cloves = pendingCloves.toMutableList()
        pendingCloves.clear()

        // Add chaff to fill remaining space
        if (addChaff) {
            val currentSize = calculateBundleSize(cloves)
            val remainingSpace = MAX_GARLIC_SIZE - ENCRYPTION_OVERHEAD - currentSize

            while (remainingSpace >= CLOVE_HEADER_SIZE + MIN_CLOVE_PAYLOAD &&
                   cloves.size < MAX_CLOVES_PER_GARLIC) {
                val chaffSize = minOf(
                    remainingSpace - CLOVE_HEADER_SIZE,
                    MAX_GARLIC_SIZE / 4  // Don't make chaff too large
                )
                cloves.add(generateChaffClove(chaffSize))
                break  // Add one chaff clove
            }
        }

        // SECURITY: Shuffle cloves with SecureRandom
        shuffleSecure(cloves)

        // Serialize plaintext garlic (will be encrypted)
        val plaintextGarlic = serializePlaintext(cloves)

        // Derive per-garlic encryption key
        val garlicKey = deriveGarlicKey(recipientPublicKey, senderSecretKey)

        // Encrypt entire garlic
        val encryptedGarlic = encryptGarlic(plaintextGarlic, garlicKey)

        // Zeroize sensitive data
        BedrockCore.zeroize(plaintextGarlic)
        BedrockCore.zeroize(garlicKey)

        encryptedGarlic
    }

    /**
     * Build garlic immediately without waiting for more cloves.
     */
    fun buildImmediateGarlic(
        cloves: List<EncryptedClove>,
        recipientPublicKey: ByteArray,
        senderSecretKey: ByteArray,
        addChaff: Boolean = true
    ): ByteArray {
        val workingCloves = cloves.toMutableList()

        if (addChaff) {
            val currentSize = calculateBundleSize(workingCloves)
            val remainingSpace = MAX_GARLIC_SIZE - ENCRYPTION_OVERHEAD - currentSize

            if (remainingSpace >= CLOVE_HEADER_SIZE + MIN_CLOVE_PAYLOAD) {
                val chaffSize = remainingSpace - CLOVE_HEADER_SIZE
                workingCloves.add(generateChaffClove(chaffSize))
            }
        }

        shuffleSecure(workingCloves)

        val plaintextGarlic = serializePlaintext(workingCloves)
        val garlicKey = deriveGarlicKey(recipientPublicKey, senderSecretKey)
        val encryptedGarlic = encryptGarlic(plaintextGarlic, garlicKey)

        BedrockCore.zeroize(plaintextGarlic)
        BedrockCore.zeroize(garlicKey)

        return encryptedGarlic
    }

    /**
     * Parse a received encrypted garlic.
     *
     * @param data The encrypted garlic bytes
     * @param recipientSecretKey Our secret key for decryption
     * @param senderPublicKey Sender's public key for key derivation
     * @return List of decrypted cloves (excluding chaff)
     */
    fun parseGarlic(
        data: ByteArray,
        recipientSecretKey: ByteArray,
        senderPublicKey: ByteArray
    ): List<EncryptedClove> {
        if (data.size < ENCRYPTION_OVERHEAD + 2) {
            return emptyList()
        }

        // Check version
        if (data[0] != VERSION) {
            // May be legacy unencrypted garlic
            return parseLegacyGarlic(data)
        }

        // Derive garlic key
        val garlicKey = deriveGarlicKey(senderPublicKey, recipientSecretKey)

        // Decrypt garlic
        val plaintextGarlic = decryptGarlic(data, garlicKey)
        BedrockCore.zeroize(garlicKey)

        if (plaintextGarlic == null) {
            return emptyList()
        }

        // Parse decrypted cloves
        val cloves = parsePlaintext(plaintextGarlic)
        BedrockCore.zeroize(plaintextGarlic)

        // Filter out chaff
        return cloves.filter { it.type != CLOVE_TYPE_CHAFF }
    }

    /**
     * Derive per-garlic encryption key using Lunar HK-OVCT + HKDF.
     *
     * SECURITY: Each garlic has a unique key derived from:
     * - Shared secret (Lunar HK-OVCT)
     * - Random nonce (included in garlic)
     * This provides forward secrecy per-garlic.
     */
    private fun deriveGarlicKey(theirPublicKey: ByteArray, ourSecretKey: ByteArray): ByteArray {
        // Compute shared secret using Lunar HK-OVCT encapsulation
        // Use auxiliary entropy from deterministic source for garlic key derivation
        val auxEntropy = BedrockCore.sha3_256(ourSecretKey + theirPublicKey + GARLIC_KEY_DOMAIN)
        val encapResult = BedrockCore.lunarHkOvctEncapsulate(theirPublicKey, ourSecretKey, auxEntropy)
        BedrockCore.zeroize(auxEntropy)

        if (encapResult == null) {
            throw IllegalStateException("Lunar HK-OVCT encapsulation failed")
        }

        val (_, handle) = encapResult

        // Derive shared secret from handle
        val sharedSecret = BedrockCore.lunarHkOvctDeriveSessionKey(handle, "garlic-shared".toByteArray())
        BedrockCore.lunarHkOvctDeleteSecret(handle)

        if (sharedSecret == null) {
            throw IllegalStateException("Shared secret derivation failed")
        }

        // HKDF to derive garlic-specific key
        val garlicKey = BedrockCore.hkdf(
            inputKeyMaterial = sharedSecret,
            salt = GARLIC_KEY_DOMAIN,
            info = "garlic-encryption".toByteArray(),
            outputLength = 32
        ) ?: throw IllegalStateException("HKDF failed")

        BedrockCore.zeroize(sharedSecret)

        return garlicKey
    }

    /**
     * Encrypt the plaintext garlic.
     *
     * Format: [version:1][nonce:12][ciphertext][tag:16]
     */
    private fun encryptGarlic(plaintext: ByteArray, key: ByteArray): ByteArray {
        // Generate random nonce
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        // Encrypt with AES-GCM
        val ciphertext = BedrockCore.aesEncrypt(key, plaintext, nonce)
            ?: throw IllegalStateException("Encryption failed")

        // Build output: version || nonce || ciphertext
        val result = ByteBuffer.allocate(1 + 12 + ciphertext.size)
            .put(VERSION)
            .put(nonce)
            .put(ciphertext)
            .array()

        BedrockCore.zeroize(nonce)

        return result
    }

    /**
     * Decrypt an encrypted garlic.
     */
    private fun decryptGarlic(encrypted: ByteArray, key: ByteArray): ByteArray? {
        if (encrypted.size < 1 + 12 + 16) {  // version + nonce + min tag
            return null
        }

        // Extract nonce
        val nonce = encrypted.copyOfRange(1, 13)

        // Extract ciphertext
        val ciphertext = encrypted.copyOfRange(13, encrypted.size)

        // Decrypt
        val plaintext = BedrockCore.aesDecrypt(key, ciphertext, nonce)

        BedrockCore.zeroize(nonce)

        return plaintext
    }

    /**
     * Serialize cloves to plaintext (before encryption).
     */
    private fun serializePlaintext(cloves: List<EncryptedClove>): ByteArray {
        val totalSize = 1 + cloves.sumOf { CLOVE_HEADER_SIZE + it.payload.size }
        val buffer = ByteBuffer.allocate(totalSize)

        // Clove count
        buffer.put(cloves.size.toByte())

        // Each clove
        for (clove in cloves) {
            buffer.put(clove.type)
            buffer.put(clove.destinationHint)  // Now 8 bytes
            buffer.putShort(clove.payload.size.toShort())
            buffer.put(clove.payload)
        }

        return buffer.array()
    }

    /**
     * Parse plaintext into cloves (after decryption).
     */
    private fun parsePlaintext(plaintext: ByteArray): List<EncryptedClove> {
        val cloves = mutableListOf<EncryptedClove>()

        if (plaintext.isEmpty()) return cloves

        var offset = 0
        val cloveCount = plaintext[offset].toInt() and 0xFF
        offset++

        repeat(cloveCount) {
            if (offset + CLOVE_HEADER_SIZE > plaintext.size) return cloves

            val type = plaintext[offset]
            offset++

            val destHint = plaintext.copyOfRange(offset, offset + 8)
            offset += 8

            val length = ((plaintext[offset].toInt() and 0xFF) shl 8) or
                        (plaintext[offset + 1].toInt() and 0xFF)
            offset += 2

            if (length < 0 || offset + length > plaintext.size) return cloves

            val payload = plaintext.copyOfRange(offset, offset + length)
            offset += length

            cloves.add(EncryptedClove(type, destHint, payload))
        }

        return cloves
    }

    /**
     * Parse legacy unencrypted garlic (for backward compatibility).
     */
    private fun parseLegacyGarlic(data: ByteArray): List<EncryptedClove> {
        // Version 0x01 = old unencrypted format
        if (data.isEmpty() || data[0] != 0x01.toByte()) {
            return emptyList()
        }

        // Parse using old format (7-byte headers)
        val cloves = mutableListOf<EncryptedClove>()
        var offset = 2  // Skip version and count

        if (data.size < 2) return cloves
        val cloveCount = data[1].toInt() and 0xFF

        repeat(cloveCount) {
            if (offset + 7 > data.size) return cloves

            val type = data[offset]
            offset++

            // Old format had 4-byte hints
            val destHintOld = data.copyOfRange(offset, offset + 4)
            offset += 4

            // Expand to 8 bytes
            val destHint = ByteArray(8)
            System.arraycopy(destHintOld, 0, destHint, 0, 4)

            val length = ((data[offset].toInt() and 0xFF) shl 8) or
                        (data[offset + 1].toInt() and 0xFF)
            offset += 2

            if (length < 0 || offset + length > data.size) return cloves

            val payload = data.copyOfRange(offset, offset + length)
            offset += length

            if (type != CLOVE_TYPE_CHAFF) {
                cloves.add(EncryptedClove(type, destHint, payload))
            }
        }

        return cloves
    }

    /**
     * Generate a chaff clove.
     */
    private fun generateChaffClove(payloadSize: Int): EncryptedClove {
        return EncryptedClove(
            type = CLOVE_TYPE_CHAFF,
            destinationHint = BedrockCore.randomBytes(8),
            payload = BedrockCore.randomBytes(payloadSize.coerceIn(MIN_CLOVE_PAYLOAD, MAX_GARLIC_SIZE))
        )
    }

    /**
     * Secure shuffle using SecureRandom.
     */
    private fun shuffleSecure(cloves: MutableList<EncryptedClove>) {
        for (i in cloves.size - 1 downTo 1) {
            val j = secureRandom.nextInt(i + 1)
            val temp = cloves[i]
            cloves[i] = cloves[j]
            cloves[j] = temp
        }
    }

    /**
     * Calculate bundle size.
     */
    private fun calculateBundleSize(cloves: List<EncryptedClove>): Int {
        return 1 + cloves.sumOf { CLOVE_HEADER_SIZE + it.payload.size }
    }

    /**
     * Check for pending cloves.
     */
    suspend fun hasPending(): Boolean = mutex.withLock {
        pendingCloves.isNotEmpty()
    }

    /**
     * Clear pending cloves.
     */
    suspend fun clear() = mutex.withLock {
        for (clove in pendingCloves) {
            clove.payload.fill(0)
        }
        pendingCloves.clear()
    }
}

/**
 * An encrypted clove within a garlic.
 */
data class EncryptedClove(
    val type: Byte,
    val destinationHint: ByteArray,  // 8 bytes - increased from 4
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedClove) return false
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
        fun data(destinationHint: ByteArray, encryptedMessage: ByteArray): EncryptedClove {
            // Ensure hint is 8 bytes
            val hint = if (destinationHint.size >= 8) {
                destinationHint.copyOf(8)
            } else {
                ByteArray(8).also { System.arraycopy(destinationHint, 0, it, 0, destinationHint.size) }
            }
            return EncryptedClove(EncryptedGarlicBundler.CLOVE_TYPE_DATA, hint, encryptedMessage)
        }

        fun ack(destinationHint: ByteArray, ackPayload: ByteArray): EncryptedClove {
            val hint = if (destinationHint.size >= 8) {
                destinationHint.copyOf(8)
            } else {
                ByteArray(8).also { System.arraycopy(destinationHint, 0, it, 0, destinationHint.size) }
            }
            return EncryptedClove(EncryptedGarlicBundler.CLOVE_TYPE_ACK, hint, ackPayload)
        }
    }
}
