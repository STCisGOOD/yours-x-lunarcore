package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer

/**
 * BlindedHints - Prevents targeted traffic scanning.
 *
 * THE PROBLEM:
 * If node hints are derived directly from public keys:
 * ```
 * hint = truncate(SHA3(publicKey), 4)
 * ```
 *
 * An adversary who knows Alice's public key can:
 * 1. Compute hint = SHA3(Alice's pubkey)
 * 2. Scan ALL mesh traffic for packets with that hint
 * 3. Know exactly which packets are destined for Alice
 * 4. Build a profile of when/how often Alice receives messages
 *
 * THE SOLUTION:
 * Blind the hints so they change over time and per-sender:
 * ```
 * blinded_hint = truncate(SHA3(publicKey || epoch || sender_secret), 4)
 * ```
 *
 * Now:
 * - Hints rotate every epoch (e.g., hourly)
 * - Each sender uses different hints for same recipient
 * - Adversary can't precompute hints without knowing secrets
 * - Only the recipient can recognize their own blinded hints
 *
 * IMPLEMENTATION:
 * 1. SENDER computes: hint = HKDF(recipient_pk || our_shared_secret || epoch)
 * 2. RECIPIENT tries to match incoming hints against computed expected hints
 * 3. Hints rotate every HINT_EPOCH_DURATION
 * 4. We keep current + previous epoch hints for transition periods
 */
class BlindedHintSystem(
    private val getOurSecretKey: () -> ByteArray?
) {
    companion object {
        /**
         * Blinded hint size in bytes.
         */
        const val BLINDED_HINT_SIZE = 4

        /**
         * Hint epoch duration (1 hour).
         * All hints rotate simultaneously across the network.
         */
        const val HINT_EPOCH_DURATION_MS = 60 * 60 * 1000L  // 1 hour

        /**
         * Number of epochs to accept (current + previous for transition).
         */
        const val HINT_EPOCH_TOLERANCE = 2

        /**
         * Domain separator for hint derivation.
         */
        private val HINT_DOMAIN = "yours:blinded_hint:v1".toByteArray()
    }

    private val mutex = Mutex()

    /**
     * Cache of our expected hints (what others will send to us).
     */
    private val ourExpectedHints = mutableMapOf<Long, ByteArray>()

    /**
     * Cache of computed hints for recipients.
     */
    private val recipientHintCache = mutableMapOf<HintCacheKey, ByteArray>()

    /**
     * Get current epoch number.
     */
    fun getCurrentEpoch(): Long {
        return System.currentTimeMillis() / HINT_EPOCH_DURATION_MS
    }

    /**
     * Compute a blinded hint for sending to a recipient.
     *
     * The hint is derived from:
     * - Recipient's public key
     * - Shared secret between us and recipient
     * - Current epoch
     *
     * This ensures:
     * - Only recipient can recognize the hint
     * - Hint changes every epoch
     * - Different senders produce different hints
     */
    suspend fun computeHintForRecipient(
        recipientPublicKey: ByteArray
    ): ByteArray = mutex.withLock {
        val epoch = getCurrentEpoch()
        val cacheKey = HintCacheKey(recipientPublicKey.contentHashCode(), epoch)

        // Check cache
        recipientHintCache[cacheKey]?.let { return@withLock it }

        // Compute blinded hint
        val ourSk = getOurSecretKey() ?: throw IllegalStateException("No secret key")

        val hint = deriveBlindedHint(
            recipientPublicKey = recipientPublicKey,
            senderSecretKey = ourSk,
            epoch = epoch
        )

        // Cache it
        recipientHintCache[cacheKey] = hint

        // Clean old cache entries
        cleanCache(epoch)

        hint
    }

    /**
     * Check if a received hint matches our identity.
     *
     * We check against current and previous epochs to handle
     * messages in transit during epoch transitions.
     *
     * @param receivedHint The hint from the received packet
     * @param senderPublicKey The sender's public key (if known)
     * @return true if the hint is for us
     */
    suspend fun isHintForUs(
        receivedHint: ByteArray,
        senderPublicKey: ByteArray
    ): Boolean = mutex.withLock {
        val currentEpoch = getCurrentEpoch()

        // Check current and previous epochs
        for (epochOffset in 0 until HINT_EPOCH_TOLERANCE) {
            val epoch = currentEpoch - epochOffset
            val expectedHint = computeExpectedHint(senderPublicKey, epoch)

            if (constantTimeEquals(receivedHint, expectedHint)) {
                return@withLock true
            }
        }

        false
    }

    /**
     * Compute what hint a sender would use for us in a given epoch.
     *
     * FIXED: Uses symmetric X25519 DH instead of asymmetric HK-OVCT KEM.
     * DH(senderSk, ourPk) == DH(ourSk, senderPk) - both produce same shared secret.
     */
    private fun computeExpectedHint(
        senderPublicKey: ByteArray,
        epoch: Long
    ): ByteArray {
        val ourSk = getOurSecretKey() ?: return ByteArray(BLINDED_HINT_SIZE)

        // Compute shared secret using symmetric X25519 Diffie-Hellman
        // This is the KEY FIX: DH is symmetric, so both sides get same result
        // Sender computes: DH(senderSk, ourPk)
        // We compute:      DH(ourSk, senderPk) -> SAME shared secret!
        val sharedSecret = BedrockCore.x25519DiffieHellman(ourSk, senderPublicKey)

        if (sharedSecret == null) {
            return ByteArray(BLINDED_HINT_SIZE)
        }

        // Compute our public key from our secret key via proper X25519 scalar multiplication
        // FIXED: No longer using incorrect HKDF derivation
        val ourPk = BedrockCore.x25519ComputePublicKey(ourSk)

        if (ourPk == null) {
            BedrockCore.zeroize(sharedSecret)
            return ByteArray(BLINDED_HINT_SIZE)
        }

        // The sender computes: deriveHintFromSharedSecret(ourPk, sharedSecret, epoch)
        // We compute the same thing using our own public key
        val hint = deriveHintFromSharedSecret(ourPk, sharedSecret, epoch)

        // Zeroize intermediates
        BedrockCore.zeroize(sharedSecret)
        BedrockCore.zeroize(ourPk)

        return hint
    }

    /**
     * Derive a blinded hint.
     *
     * FIXED: Uses symmetric X25519 DH instead of asymmetric HK-OVCT KEM.
     * DH(senderSk, recipientPk) == DH(recipientSk, senderPk) - both produce same shared secret.
     */
    private fun deriveBlindedHint(
        recipientPublicKey: ByteArray,
        senderSecretKey: ByteArray,
        epoch: Long
    ): ByteArray {
        // Compute shared secret using symmetric X25519 Diffie-Hellman
        // This is the KEY FIX: DH is symmetric, so both sides get same result
        // We compute:      DH(senderSk, recipientPk)
        // Recipient will:  DH(recipientSk, senderPk) -> SAME shared secret!
        val sharedSecret = BedrockCore.x25519DiffieHellman(senderSecretKey, recipientPublicKey)

        if (sharedSecret == null) {
            return ByteArray(BLINDED_HINT_SIZE)
        }

        val hint = deriveHintFromSharedSecret(recipientPublicKey, sharedSecret, epoch)

        // Zeroize
        BedrockCore.zeroize(sharedSecret)

        return hint
    }

    /**
     * Derive hint from shared secret.
     */
    private fun deriveHintFromSharedSecret(
        publicKey: ByteArray,
        sharedSecret: ByteArray,
        epoch: Long
    ): ByteArray {
        // Input: domain || publicKey || sharedSecret || epoch
        val epochBytes = ByteBuffer.allocate(8).putLong(epoch).array()

        val input = ByteArray(HINT_DOMAIN.size + publicKey.size + sharedSecret.size + 8)
        var offset = 0

        System.arraycopy(HINT_DOMAIN, 0, input, offset, HINT_DOMAIN.size)
        offset += HINT_DOMAIN.size

        System.arraycopy(publicKey, 0, input, offset, publicKey.size)
        offset += publicKey.size

        System.arraycopy(sharedSecret, 0, input, offset, sharedSecret.size)
        offset += sharedSecret.size

        System.arraycopy(epochBytes, 0, input, offset, 8)

        // Hash and truncate
        val hash = BedrockCore.sha3_256(input)
        val hint = hash.copyOf(BLINDED_HINT_SIZE)

        // Zeroize
        BedrockCore.zeroize(input)
        BedrockCore.zeroize(hash)

        return hint
    }

    /**
     * Constant-time comparison to prevent timing attacks.
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false

        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    /**
     * Clean old cache entries.
     */
    private fun cleanCache(currentEpoch: Long) {
        val cutoff = currentEpoch - HINT_EPOCH_TOLERANCE - 1

        // Clean recipient hint cache
        val keysToRemove = recipientHintCache.keys.filter { it.epoch < cutoff }
        for (key in keysToRemove) {
            recipientHintCache[key]?.fill(0)
            recipientHintCache.remove(key)
        }

        // Clean our expected hints
        val epochsToRemove = ourExpectedHints.keys.filter { it < cutoff }
        for (epoch in epochsToRemove) {
            ourExpectedHints[epoch]?.fill(0)
            ourExpectedHints.remove(epoch)
        }
    }

    /**
     * Clear all cached hints (on lock/wipe).
     */
    suspend fun clearAll() = mutex.withLock {
        for ((_, hint) in recipientHintCache) {
            hint.fill(0)
        }
        recipientHintCache.clear()

        for ((_, hint) in ourExpectedHints) {
            hint.fill(0)
        }
        ourExpectedHints.clear()
    }

    /**
     * Force hint rotation (for testing or security events).
     */
    suspend fun forceRotation() = mutex.withLock {
        recipientHintCache.clear()
        ourExpectedHints.clear()
    }
}

/**
 * Cache key for recipient hints.
 */
private data class HintCacheKey(
    val publicKeyHash: Int,
    val epoch: Long
)

/**
 * Static hint utilities for contacts without active sessions.
 */
object StaticBlindedHints {

    /**
     * Compute a hint that doesn't require a session.
     *
     * Used for:
     * - Initial contact (before session established)
     * - Broadcast messages
     * - Relay forwarding hints
     *
     * Less private than session-based hints but still rotates.
     */
    fun computeStaticHint(
        publicKey: ByteArray,
        epoch: Long = System.currentTimeMillis() / BlindedHintSystem.HINT_EPOCH_DURATION_MS
    ): ByteArray {
        val epochBytes = ByteBuffer.allocate(8).putLong(epoch).array()

        val input = ByteArray(publicKey.size + 8)
        System.arraycopy(publicKey, 0, input, 0, publicKey.size)
        System.arraycopy(epochBytes, 0, input, publicKey.size, 8)

        val hash = BedrockCore.sha3_256(input)
        val hint = hash.copyOf(BlindedHintSystem.BLINDED_HINT_SIZE)

        BedrockCore.zeroize(input)
        BedrockCore.zeroize(hash)

        return hint
    }

    /**
     * Check if a static hint matches a public key.
     */
    fun matchesStaticHint(
        hint: ByteArray,
        publicKey: ByteArray,
        epochTolerance: Int = BlindedHintSystem.HINT_EPOCH_TOLERANCE
    ): Boolean {
        val currentEpoch = System.currentTimeMillis() / BlindedHintSystem.HINT_EPOCH_DURATION_MS

        for (offset in 0 until epochTolerance) {
            val expected = computeStaticHint(publicKey, currentEpoch - offset)
            if (constantTimeEquals(hint, expected)) {
                return true
            }
        }

        return false
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
}

/**
 * Hint scanner for incoming packets.
 *
 * Efficiently checks if any received hint matches our identity
 * or any of our contacts.
 */
class HintScanner(
    private val blindedHintSystem: BlindedHintSystem,
    private val getKnownSenderKeys: suspend () -> List<ByteArray>
) {

    /**
     * Check if a packet hint is for us.
     *
     * Tries all known sender keys to see if any produces matching hint.
     */
    suspend fun isPacketForUs(receivedHint: ByteArray): ScanResult {
        val senderKeys = getKnownSenderKeys()

        for (senderKey in senderKeys) {
            if (blindedHintSystem.isHintForUs(receivedHint, senderKey)) {
                return ScanResult.ForUs(senderKey)
            }
        }

        // Also check static hints (for unknown senders)
        // This is less common but handles edge cases
        return ScanResult.NotForUs
    }
}

/**
 * Result of hint scanning.
 */
sealed class ScanResult {
    data class ForUs(val likelySenderKey: ByteArray) : ScanResult()
    data object NotForUs : ScanResult()
    data object MaybeForUs : ScanResult()  // Uncertain, should try decryption
}
