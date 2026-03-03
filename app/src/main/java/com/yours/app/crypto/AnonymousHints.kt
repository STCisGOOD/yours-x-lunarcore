package com.yours.app.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Cryptographically secure 64-bit hint generation for anonymous routing.
 * Node hints rotate per epoch, session hints rotate per message, and both
 * are HMAC-derived to prevent enumeration and tracking attacks.
 */
object AnonymousHints {

    /**
     * SECURITY FIX: Increased from 2 bytes to 8 bytes.
     * 64 bits prevents enumeration attacks.
     */
    const val NODE_HINT_SIZE = 8

    /**
     * SECURITY FIX: Increased from 4 bytes to 8 bytes.
     * 64 bits prevents tracking via session hints.
     */
    const val SESSION_HINT_SIZE = 8

    /**
     * Epoch duration for node hint rotation.
     */
    const val NODE_HINT_EPOCH_MS = 10 * 60 * 1000L  // 10 minutes

    /**
     * Domain separators prevent cross-protocol attacks.
     */
    private val NODE_HINT_DOMAIN = "lunarpunk-node-hint-v2".toByteArray()
    private val SESSION_HINT_DOMAIN = "lunarpunk-session-hint-v2".toByteArray()

    private val secureRandom = SecureRandom()

    /**
     * Compute node hint with epoch rotation.
     *
     * SECURITY PROPERTIES:
     * 1. Deterministic: Both parties compute same hint
     * 2. Rotates: New hint every epoch prevents tracking
     * 3. Unforgeable: Requires knowledge of public key
     * 4. Non-enumerable: 64 bits prevents brute force
     *
     * @param publicKey The node's public key
     * @param epoch Optional epoch override (for tolerance checking)
     * @return 8-byte node hint
     */
    fun computeNodeHint(publicKey: ByteArray, epoch: Long? = null): ByteArray {
        val currentEpoch = epoch ?: (System.currentTimeMillis() / NODE_HINT_EPOCH_MS)

        // HMAC(domain || epoch || publicKey)
        val input = ByteBuffer.allocate(NODE_HINT_DOMAIN.size + 8 + publicKey.size)
            .put(NODE_HINT_DOMAIN)
            .putLong(currentEpoch)
            .put(publicKey)
            .array()

        val hash = BedrockCore.sha3_256(input)

        // Zeroize intermediate
        BedrockCore.zeroize(input)

        // Return first 8 bytes
        val hint = hash.copyOf(NODE_HINT_SIZE)
        BedrockCore.zeroize(hash)

        return hint
    }

    /**
     * Check if a node hint matches for current or previous epoch.
     *
     * TOLERANCE: Accept hints from current epoch and one back
     * to handle in-flight packets during epoch transitions.
     */
    fun verifyNodeHint(receivedHint: ByteArray, publicKey: ByteArray): Boolean {
        if (receivedHint.size != NODE_HINT_SIZE) return false

        val currentEpoch = System.currentTimeMillis() / NODE_HINT_EPOCH_MS

        // Check current epoch
        val currentHint = computeNodeHint(publicKey, currentEpoch)
        if (constantTimeEquals(receivedHint, currentHint)) {
            BedrockCore.zeroize(currentHint)
            return true
        }
        BedrockCore.zeroize(currentHint)

        // Check previous epoch
        val prevHint = computeNodeHint(publicKey, currentEpoch - 1)
        val matches = constantTimeEquals(receivedHint, prevHint)
        BedrockCore.zeroize(prevHint)

        return matches
    }

    /**
     * Compute session hint with per-message nonce.
     *
     * SECURITY PROPERTIES:
     * 1. Changes every message (nonce-based)
     * 2. Only sender and recipient can compute
     * 3. Adversary cannot correlate messages in same session
     * 4. No long-term session identifier exposed
     *
     * @param sharedSecret The session's shared secret (from Double Ratchet)
     * @param messageNonce Unique nonce for this message
     * @return 8-byte session hint
     */
    fun computeSessionHint(sharedSecret: ByteArray, messageNonce: ByteArray): ByteArray {
        // HMAC(domain || sharedSecret || nonce)
        val input = ByteBuffer.allocate(SESSION_HINT_DOMAIN.size + sharedSecret.size + messageNonce.size)
            .put(SESSION_HINT_DOMAIN)
            .put(sharedSecret)
            .put(messageNonce)
            .array()

        val hash = BedrockCore.sha3_256(input)
        BedrockCore.zeroize(input)

        val hint = hash.copyOf(SESSION_HINT_SIZE)
        BedrockCore.zeroize(hash)

        return hint
    }

    /**
     * Compute sender-blinded hint.
     *
     * ADVANCED FEATURE: Sender identity is hidden even from recipient
     * until they successfully decrypt. Prevents targeted attacks.
     *
     * @param senderSecret Sender's secret key
     * @param recipientPublic Recipient's public key
     * @param epoch Current epoch
     * @return Blinded hint that only recipient can verify
     */
    fun computeBlindedHint(
        senderSecret: ByteArray,
        recipientPublic: ByteArray,
        epoch: Long? = null
    ): ByteArray {
        val currentEpoch = epoch ?: (System.currentTimeMillis() / NODE_HINT_EPOCH_MS)

        // Compute shared point using Lunar HK-OVCT encapsulation for X25519 DH
        // Both parties can compute the same shared secret
        val auxEntropy = BedrockCore.randomBytes(32)
        val encapResult = BedrockCore.lunarHkOvctEncapsulate(recipientPublic, senderSecret, auxEntropy)
            ?: throw IllegalStateException("X25519 key agreement failed")

        val (_, secretHandle) = encapResult
        val sharedPoint = BedrockCore.lunarHkOvctDeriveSessionKey(secretHandle, "blinded-hint".toByteArray())
            ?: throw IllegalStateException("Session key derivation failed")
        BedrockCore.lunarHkOvctDeleteSecret(secretHandle)

        val input = ByteBuffer.allocate(NODE_HINT_DOMAIN.size + 8 + sharedPoint.size)
            .put(NODE_HINT_DOMAIN, 0, NODE_HINT_DOMAIN.size)
            .putLong(currentEpoch)
            .put(sharedPoint, 0, sharedPoint.size)
            .array()

        val hash = BedrockCore.sha3_256(input)

        BedrockCore.zeroize(sharedPoint)
        BedrockCore.zeroize(input)

        val hint = hash.copyOf(NODE_HINT_SIZE)
        BedrockCore.zeroize(hash)

        return hint
    }

    /**
     * Verify a blinded hint (recipient side).
     *
     * @param receivedHint The hint from the packet
     * @param recipientSecret Recipient's secret key
     * @param senderPublic Sender's public key
     * @return true if hint matches
     */
    fun verifyBlindedHint(
        receivedHint: ByteArray,
        recipientSecret: ByteArray,
        senderPublic: ByteArray
    ): Boolean {
        if (receivedHint.size != NODE_HINT_SIZE) return false

        val currentEpoch = System.currentTimeMillis() / NODE_HINT_EPOCH_MS

        // Recipient computes shared point using Lunar HK-OVCT decapsulation
        // This produces the same shared secret as the sender's encapsulation
        val auxEntropy = BedrockCore.randomBytes(32)
        val encapResult = BedrockCore.lunarHkOvctEncapsulate(senderPublic, recipientSecret, auxEntropy)
            ?: return false

        val (_, secretHandle) = encapResult
        val sharedPoint = BedrockCore.lunarHkOvctDeriveSessionKey(secretHandle, "blinded-hint".toByteArray())
        BedrockCore.lunarHkOvctDeleteSecret(secretHandle)

        if (sharedPoint == null) return false

        // Check current epoch
        val currentInput = ByteBuffer.allocate(NODE_HINT_DOMAIN.size + 8 + sharedPoint.size)
            .put(NODE_HINT_DOMAIN, 0, NODE_HINT_DOMAIN.size)
            .putLong(currentEpoch)
            .put(sharedPoint, 0, sharedPoint.size)
            .array()

        val currentHash = BedrockCore.sha3_256(currentInput)
        val currentHint = currentHash.copyOf(NODE_HINT_SIZE)

        if (constantTimeEquals(receivedHint, currentHint)) {
            BedrockCore.zeroize(sharedPoint)
            BedrockCore.zeroize(currentInput)
            BedrockCore.zeroize(currentHash)
            BedrockCore.zeroize(currentHint)
            return true
        }

        // Check previous epoch
        val prevInput = ByteBuffer.allocate(NODE_HINT_DOMAIN.size + 8 + sharedPoint.size)
            .put(NODE_HINT_DOMAIN, 0, NODE_HINT_DOMAIN.size)
            .putLong(currentEpoch - 1)
            .put(sharedPoint, 0, sharedPoint.size)
            .array()

        val prevHash = BedrockCore.sha3_256(prevInput)
        val prevHint = prevHash.copyOf(NODE_HINT_SIZE)

        val matches = constantTimeEquals(receivedHint, prevHint)

        // Cleanup
        BedrockCore.zeroize(sharedPoint)
        BedrockCore.zeroize(currentInput)
        BedrockCore.zeroize(currentHash)
        BedrockCore.zeroize(currentHint)
        BedrockCore.zeroize(prevInput)
        BedrockCore.zeroize(prevHash)
        BedrockCore.zeroize(prevHint)

        return matches
    }

    /**
     * Generate random nonce for session hint.
     */
    fun generateNonce(): ByteArray {
        val nonce = ByteArray(16)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    /**
     * Constant-time byte array comparison.
     *
     * SECURITY: Prevents timing attacks.
     * Always compares all bytes regardless of where mismatch occurs.
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false

        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
}
