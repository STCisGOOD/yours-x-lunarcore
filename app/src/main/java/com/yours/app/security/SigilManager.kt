package com.yours.app.security

import android.content.Context
import com.yours.app.crypto.BedrockCore
import com.yours.app.ui.components.Pattern
import com.yours.app.ui.components.MIN_PATTERN_LENGTH
import java.io.File

/**
 * Manages the Pattern Sigil - a grid-based authentication pattern.
 *
 * The Pattern provides:
 * - ~61 bits of entropy (12 points from 36-point grid)
 * - Combined with device-bound key for full security
 * - Easy to trace with muscle memory
 *
 * Security model:
 * - Pattern encrypted with device-bound key (Android Keystore)
 * - Passphrase encrypted with key derived from pattern + device key
 * - Rate limiting on failed attempts
 * - Pattern can be reset only with full passphrase
 */
class SigilManager(private val context: Context) {

    private val sigilFile: File
        get() = File(context.filesDir, "sigil.sealed")

    private val sigilPassphraseFile: File
        get() = File(context.filesDir, "sigil_passphrase.sealed")

    private val secureDeviceKey = SecureDeviceKey.getInstance(context)

    /**
     * Check if a sigil has been set up.
     */
    fun hasSigil(): Boolean = sigilFile.exists() && sigilPassphraseFile.exists()

    /**
     * Set up a new pattern.
     *
     * @param pattern The grid pattern (12+ points)
     * @param passphraseBytes The passphrase to encrypt (for pattern-based unlock)
     */
    fun setupSigil(pattern: Pattern, passphraseBytes: ByteArray) {
        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            // 1. Store the pattern encrypted with device key
            val patternBytes = pattern.toBytes()
            val encryptedPattern = BedrockCore.aesEncrypt(
                key = deviceKey,
                plaintext = patternBytes,
                associatedData = "sigil".toByteArray()
            )
            sigilFile.writeBytes(encryptedPattern)
            BedrockCore.zeroize(patternBytes)

            // 2. Derive a key from the pattern
            val patternKey = derivePatternKey(pattern, deviceKey)

            // 3. Encrypt the passphrase with the pattern-derived key
            val encryptedPassphrase = BedrockCore.aesEncrypt(
                key = patternKey,
                plaintext = passphraseBytes,
                associatedData = "vow".toByteArray()
            )
            sigilPassphraseFile.writeBytes(encryptedPassphrase)
            BedrockCore.zeroize(patternKey)
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }

    /**
     * Verify a pattern and return the passphrase if correct.
     *
     * @param inputPattern The pattern to verify
     * @return The decrypted passphrase bytes, or null if verification failed
     */
    fun verifySigil(inputPattern: Pattern): ByteArray? {
        if (!hasSigil()) return null

        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            // 1. Load and decrypt stored pattern
            val encryptedPattern = sigilFile.readBytes()
            val storedPatternBytes = BedrockCore.aesDecrypt(
                key = deviceKey,
                ciphertext = encryptedPattern,
                associatedData = "sigil".toByteArray()
            ) ?: return null

            val storedPattern = Pattern.fromBytes(storedPatternBytes)
            BedrockCore.zeroize(storedPatternBytes)

            if (storedPattern == null) return null

            // 2. Compare patterns - SECURITY AUDIT FIX #10: Constant-time comparison
            // Using XOR accumulation to prevent timing attacks
            val inputPoints = inputPattern.points
            val storedPoints = storedPattern.points

            // First check lengths (this leaks length info but that's acceptable)
            if (inputPoints.size != storedPoints.size) {
                return null
            }

            // Constant-time comparison of all points
            var diff = 0
            for (i in inputPoints.indices) {
                diff = diff or (inputPoints[i] xor storedPoints[i])
            }
            if (diff != 0) {
                return null
            }

            // 3. Pattern matches - derive key and decrypt passphrase
            val patternKey = derivePatternKey(inputPattern, deviceKey)

            val encryptedPassphrase = sigilPassphraseFile.readBytes()
            val passphrase = BedrockCore.aesDecrypt(
                key = patternKey,
                ciphertext = encryptedPassphrase,
                associatedData = "vow".toByteArray()
            )
            BedrockCore.zeroize(patternKey)

            return passphrase
        } catch (e: Exception) {
            return null
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }

    /**
     * Check if a pattern matches without returning the passphrase.
     */
    fun checkSigil(inputPattern: Pattern): Boolean {
        val passphrase = verifySigil(inputPattern)
        return if (passphrase != null) {
            BedrockCore.zeroize(passphrase)
            true
        } else {
            false
        }
    }

    /**
     * Clear the sigil (requires re-setup).
     * Used when user wants to change their sigil.
     */
    fun clearSigil() {
        if (sigilFile.exists()) {
            // Secure delete - overwrite with random data
            val random = BedrockCore.randomBytes(sigilFile.length().toInt())
            sigilFile.writeBytes(random)
            sigilFile.delete()
        }
        if (sigilPassphraseFile.exists()) {
            val random = BedrockCore.randomBytes(sigilPassphraseFile.length().toInt())
            sigilPassphraseFile.writeBytes(random)
            sigilPassphraseFile.delete()
        }
    }

    /**
     * Derive a key from the pattern and device key.
     * Uses HKDF with both pattern bytes and device key as inputs.
     */
    private fun derivePatternKey(pattern: Pattern, deviceKey: ByteArray): ByteArray {
        val patternBytes = pattern.toBytes()
        try {
            // Combine pattern with device key for key derivation
            // This ensures both knowledge of the pattern AND device possession are required
            val combinedInput = ByteArray(patternBytes.size + deviceKey.size)
            System.arraycopy(patternBytes, 0, combinedInput, 0, patternBytes.size)
            System.arraycopy(deviceKey, 0, combinedInput, patternBytes.size, deviceKey.size)

            // Use Argon2id for key derivation (same as passphrase)
            // Salt is derived from pattern to make it unique per pattern
            val salt = BedrockCore.sha3_256(patternBytes)
            val key = BedrockCore.deriveKey(combinedInput, salt)

            BedrockCore.zeroize(combinedInput)
            BedrockCore.zeroize(salt)

            return key
        } finally {
            BedrockCore.zeroize(patternBytes)
        }
    }

    /**
     * Get a hint about the stored pattern (for display purposes).
     * Only returns first and last points, not the full pattern.
     */
    fun getStoredPatternHint(): List<Int>? {
        if (!hasSigil()) return null

        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            val encryptedPattern = sigilFile.readBytes()
            val storedPatternBytes = BedrockCore.aesDecrypt(
                key = deviceKey,
                ciphertext = encryptedPattern,
                associatedData = "sigil".toByteArray()
            ) ?: return null

            val pattern = Pattern.fromBytes(storedPatternBytes)
            BedrockCore.zeroize(storedPatternBytes)

            // Only return first and last points as hint
            return pattern?.let { listOf(it.points.first(), it.points.last()) }
        } catch (e: Exception) {
            return null
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }
}
