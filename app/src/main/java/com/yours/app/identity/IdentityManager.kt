package com.yours.app.identity

import android.content.Context
import com.yours.app.crypto.BedrockCore
import com.yours.app.crypto.BedrockCore.useAndZeroize
import com.yours.app.security.SecureDeviceKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import android.util.Log
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Self-sovereign identity.
 * 
 * An Identity is:
 * - Self-certifying (derived from cryptographic keys)
 * - Recoverable (through guardian threshold)
 * - Never uploaded anywhere
 * - Controlled entirely by the user
 */
data class Identity(
    val name: String,                    // User's chosen name (local only)
    val did: String,                     // did:key:z6Mk... (derived from signing key)
    val signingPublicKey: ByteArray,     // Ed25519 public key
    val encryptionPublicKey: ByteArray,  // ML-KEM-768 public key (Hk-OVCT artifact encryption)
    val sessionPublicKey: ByteArray,     // X25519 public key (32 bytes, for Double Ratchet sessions)
    val createdAt: Long                  // Unix timestamp
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Identity) return false
        return did == other.did
    }
    
    override fun hashCode(): Int = did.hashCode()
}

/**
 * Encrypted identity storage.
 * Contains all keys, encrypted with master key derived from passphrase.
 */
data class EncryptedIdentity(
    val salt: ByteArray,                 // Salt for Argon2id
    val encryptedPayload: ByteArray,     // AES-GCM encrypted keys
    val publicIdentity: Identity         // Public portion (for display without unlocking)
)

/**
 * Manages identity creation, storage, and unlocking.
 *
 * Security features:
 * - Rate limiting on failed unlock attempts (exponential backoff)
 * - Auto-lock timeout when app is backgrounded
 * - Secure key zeroization on lock
 */
class IdentityManager(private val context: Context) {

    private val identityFile: File
        get() = File(context.filesDir, "identity.yours")

    // Store passphrase encrypted with device key for sigil unlock
    private val passphraseFile: File
        get() = File(context.filesDir, "passphrase.enc")

    @Volatile
    private var unlockedKeys: UnlockedKeys? = null

    // Mutex for thread-safe unlock/lock operations (Fix #5: Race condition)
    private val keysMutex = Mutex()

    // Secure device key manager (Fix #1: Device key was plaintext)
    private val secureDeviceKey = SecureDeviceKey.getInstance(context)

    // ========================================================================
    // RATE LIMITING (Fix #7: Persistent rate limiting)
    // ========================================================================

    private val rateLimitFile: File
        get() = File(context.filesDir, "rate_limit.enc")

    private var failedAttempts: Int = 0
    private var lockoutUntil: Long = 0

    // ========================================================================
    // AUTO-LOCK TIMEOUT (Fix #18)
    // ========================================================================

    @Volatile
    private var lastActivityTime: Long = 0

    @Volatile
    private var backgroundedAt: Long = 0

    /**
     * Record that the app is going to background.
     * The lock timer starts from this moment.
     */
    fun onAppBackgrounded() {
        backgroundedAt = System.currentTimeMillis()
    }

    /**
     * Check if auto-lock should trigger when app resumes.
     * Returns true if the vault should be locked.
     */
    fun shouldAutoLock(timeoutMs: Long = DEFAULT_AUTO_LOCK_TIMEOUT_MS): Boolean {
        if (backgroundedAt == 0L) return false
        if (unlockedKeys == null) return false

        val elapsed = System.currentTimeMillis() - backgroundedAt
        return elapsed >= timeoutMs
    }

    /**
     * Called when app resumes. Locks if timeout expired.
     */
    suspend fun onAppResumed(timeoutMs: Long = DEFAULT_AUTO_LOCK_TIMEOUT_MS) {
        if (shouldAutoLock(timeoutMs)) {
            lock()
        }
        backgroundedAt = 0L
        lastActivityTime = System.currentTimeMillis()
    }

    /**
     * Update last activity time (call on user interaction).
     */
    fun recordActivity() {
        lastActivityTime = System.currentTimeMillis()
    }

    init {
        loadRateLimitState()
    }

    private fun loadRateLimitState() {
        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            if (rateLimitFile.exists()) {
                val encrypted = rateLimitFile.readBytes()
                val decrypted = BedrockCore.aesDecrypt(deviceKey, encrypted, byteArrayOf())
                if (decrypted != null && decrypted.size >= 12) {
                    failedAttempts = bytesToInt(decrypted, 0)
                    lockoutUntil = bytesToLong(decrypted, 4)
                }
            }
        } catch (e: Exception) {
            // Reset on error
            failedAttempts = 0
            lockoutUntil = 0
        } finally {
            BedrockCore.zeroize(deviceKey) // Zeroize after use
        }
    }

    private fun saveRateLimitState() {
        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            val data = ByteArray(12)
            System.arraycopy(intToBytes(failedAttempts), 0, data, 0, 4)
            System.arraycopy(longToBytes(lockoutUntil), 0, data, 4, 8)
            val encrypted = BedrockCore.aesEncrypt(deviceKey, data, byteArrayOf())
            rateLimitFile.writeBytes(encrypted)
        } catch (e: Exception) {
            // Best effort
        } finally {
            BedrockCore.zeroize(deviceKey) // Zeroize after use
        }
    }

    companion object {
        private const val MAX_ATTEMPTS_BEFORE_LOCKOUT = 3
        private const val MAX_ATTEMPTS_BEFORE_WIPE = 10 // Wipe identity after 10 failed attempts
        private const val BASE_LOCKOUT_MS = 2000L // 2 seconds base
        private const val MAX_LOCKOUT_MS = 300000L // 5 minutes max

        // Auto-lock timeout (2 minutes default)
        const val DEFAULT_AUTO_LOCK_TIMEOUT_MS = 120000L

        // Base58 encoding for did:key
        private const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        fun base58Encode(input: ByteArray): String {
            if (input.isEmpty()) return ""

            // Count leading zeros
            var zeros = 0
            while (zeros < input.size && input[zeros] == 0.toByte()) {
                zeros++
            }

            // Convert to base58
            val encoded = CharArray(input.size * 2)
            var outputStart = encoded.size
            var inputStart = zeros
            val tempInput = input.copyOf() // Work on copy

            while (inputStart < tempInput.size) {
                outputStart--
                encoded[outputStart] = BASE58_ALPHABET[divmod(tempInput, inputStart, 256, 58)]
                if (tempInput[inputStart] == 0.toByte()) {
                    inputStart++
                }
            }

            while (outputStart < encoded.size && encoded[outputStart] == BASE58_ALPHABET[0]) {
                outputStart++
            }

            while (--zeros >= 0) {
                outputStart--
                encoded[outputStart] = BASE58_ALPHABET[0]
            }

            return String(encoded, outputStart, encoded.size - outputStart)
        }

        private fun divmod(number: ByteArray, firstDigit: Int, base: Int, divisor: Int): Int {
            var remainder = 0
            for (i in firstDigit until number.size) {
                val digit = number[i].toInt() and 0xFF
                val temp = remainder * base + digit
                number[i] = (temp / divisor).toByte()
                remainder = temp % divisor
            }
            return remainder
        }
    }

    /**
     * Get remaining lockout time in milliseconds.
     * Returns 0 if not locked out.
     */
    fun getRemainingLockoutMs(): Long {
        val remaining = lockoutUntil - System.currentTimeMillis()
        return if (remaining > 0) remaining else 0
    }

    /**
     * Check if currently locked out from unlock attempts.
     */
    fun isLockedOut(): Boolean = getRemainingLockoutMs() > 0

    /**
     * Get the number of failed attempts.
     */
    fun getFailedAttempts(): Int = failedAttempts

    /**
     * Reset failed attempts (call after successful unlock or user-initiated reset).
     */
    fun resetFailedAttempts() {
        failedAttempts = 0
        lockoutUntil = 0
    }
    
    /**
     * Holds decrypted keys during an unlocked session.
     * Cleared on lock.
     */
    data class UnlockedKeys(
        val signingPrivateKey: ByteArray,           // Ed25519 private key
        val encryptionPrivateKey: ByteArray,        // ML-KEM-768 secret key (Hk-OVCT artifact encryption)
        val sessionPrivateKey: ByteArray,           // X25519 secret key (32 bytes, for Double Ratchet sessions)
        val masterKey: ByteArray
    ) {
        fun zeroize() {
            BedrockCore.zeroize(signingPrivateKey)
            BedrockCore.zeroize(encryptionPrivateKey)
            BedrockCore.zeroize(sessionPrivateKey)
            BedrockCore.zeroize(masterKey)
        }
    }
    
    /**
     * Check if an identity exists on this device.
     */
    fun hasIdentity(): Boolean = identityFile.exists()
    
    /**
     * Check if the vault is currently unlocked.
     */
    fun isUnlocked(): Boolean = unlockedKeys != null
    
    /**
     * Get the current identity (public info only).
     * Returns null if no identity exists.
     */
    suspend fun getIdentity(): Identity? = withContext(Dispatchers.IO) {
        if (!hasIdentity()) return@withContext null
        val identity = loadEncryptedIdentity()?.publicIdentity
        if (identity != null) {
            Log.d("IdentityManager", "=== GET IDENTITY ===")
            Log.d("IdentityManager", "identity.sessionPublicKey.size=${identity.sessionPublicKey.size} (expected 32)")
            Log.d("IdentityManager", "identity.encryptionPublicKey.size=${identity.encryptionPublicKey.size} (expected 1184)")
        }
        identity
    }
    
    /**
     * Create a new identity.
     *
     * SECURITY FIX: Now accepts ByteArray instead of String to prevent
     * immutable String objects lingering in memory. Caller must zeroize
     * the ByteArray after this call returns.
     *
     * @param name User's chosen display name
     * @param passphraseBytes Eight+ words as UTF-8 bytes - for recovery
     * @return The new identity
     */
    suspend fun createIdentity(
        name: String,
        passphraseBytes: ByteArray
    ): Identity = withContext(Dispatchers.IO) {
        require(!hasIdentity()) { "Identity already exists" }
        // Count spaces to estimate word count without creating a String
        val spaceCount = passphraseBytes.count { it == ' '.code.toByte() }
        require(spaceCount >= 7) { "Passphrase must be at least 8 words" }

        // Generate all keypairs
        val (signingPrivate, signingPublic) = BedrockCore.generateSigningKeypair()
        val (encryptionPrivate, encryptionPublic) = BedrockCore.hkovctKeygen()
        val (sessionPrivate, sessionPublic) = BedrockCore.lunarHkOvctKeygen()

        Log.d("IdentityManager", "=== CREATE IDENTITY ===")
        Log.d("IdentityManager", "sessionPublic.size=${sessionPublic.size} (expected 32)")
        Log.d("IdentityManager", "sessionPrivate.size=${sessionPrivate.size} (expected 32)")
        Log.d("IdentityManager", "encryptionPublic.size=${encryptionPublic.size} (expected 1184)")

        // Derive DID from signing public key
        val did = deriveDid(signingPublic)

        // Create identity
        val identity = Identity(
            name = name,
            did = did,
            signingPublicKey = signingPublic,
            encryptionPublicKey = encryptionPublic,
            sessionPublicKey = sessionPublic,
            createdAt = System.currentTimeMillis()
        )

        Log.d("IdentityManager", "Identity created: did=${did.take(30)}..., sessionPublicKey.size=${identity.sessionPublicKey.size}")

        // Derive master key from passphrase (passphraseBytes used directly)
        val salt = BedrockCore.randomBytes(32)
        val masterKey = BedrockCore.deriveKey(passphraseBytes, salt)
        // Note: Caller is responsible for zeroizing passphraseBytes

        // Serialize private keys
        val privatePayload = serializePrivateKeysV3(
            signingPrivate,
            encryptionPrivate,
            sessionPrivate,
            null,
            null
        )

        // Encrypt private keys
        val encryptedPayload = BedrockCore.aesEncrypt(
            key = masterKey,
            plaintext = privatePayload,
            associatedData = did.toByteArray(StandardCharsets.UTF_8)
        )
        BedrockCore.zeroize(privatePayload)

        // Save encrypted identity
        val encryptedIdentity = EncryptedIdentity(
            salt = salt,
            encryptedPayload = encryptedPayload,
            publicIdentity = identity
        )
        saveEncryptedIdentity(encryptedIdentity)

        // Save encrypted passphrase for sigil-based unlock
        saveEncryptedPassphrase(passphraseBytes)

        // Keep unlocked
        unlockedKeys = UnlockedKeys(
            signingPrivateKey = signingPrivate,
            encryptionPrivateKey = encryptionPrivate,
            sessionPrivateKey = sessionPrivate,
            masterKey = masterKey
        )

        identity
    }

    /**
     * Unlock using the stored encrypted passphrase.
     * Call this after sigil has been verified by the UI.
     */
    suspend fun unlockWithStoredPassphrase(): UnlockResult = withContext(Dispatchers.IO) {
        val passphraseBytes = loadEncryptedPassphrase()
            ?: return@withContext UnlockResult.Failed("Recovery required - use your 8 words")

        try {
            unlock(passphraseBytes)
        } finally {
            BedrockCore.zeroize(passphraseBytes)
        }
    }

    /**
     * Save passphrase encrypted with device-bound key (Fix #1: Now uses Android Keystore).
     * SECURITY FIX: Now accepts ByteArray instead of String.
     * CRITICAL FIX: Device key now zeroized after use.
     */
    private fun saveEncryptedPassphrase(passphraseBytes: ByteArray) {
        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            val encrypted = BedrockCore.aesEncrypt(deviceKey, passphraseBytes, byteArrayOf())
            passphraseFile.writeBytes(encrypted)
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }

    /**
     * Load passphrase decrypted with device-bound key (Fix #1: Now uses Android Keystore).
     * SECURITY FIX: Now returns ByteArray instead of String.
     * CRITICAL FIX: Device key now zeroized after use. Caller must zeroize returned ByteArray.
     */
    private fun loadEncryptedPassphrase(): ByteArray? {
        if (!passphraseFile.exists()) return null
        val deviceKey = secureDeviceKey.getDeviceKey()
        return try {
            val encrypted = passphraseFile.readBytes()
            BedrockCore.aesDecrypt(deviceKey, encrypted, byteArrayOf())
        } catch (e: Exception) {
            null
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }
    
    /**
     * Unlock the identity with passphrase.
     *
     * SECURITY FIX: Now accepts ByteArray instead of String to prevent
     * immutable String objects lingering in memory. Caller must zeroize
     * the ByteArray after this call returns.
     *
     * Implements rate limiting with exponential backoff:
     * - After 3 failed attempts: 2 second lockout
     * - Each subsequent failure doubles the lockout (up to 5 minutes)
     *
     * Fix #5: Uses mutex for thread-safe key access
     * Fix #7: Persists rate limiting state
     *
     * @param passphraseBytes Eight+ words as UTF-8 bytes
     * @return UnlockResult indicating success, failure, or lockout
     */
    suspend fun unlock(passphraseBytes: ByteArray): UnlockResult = withContext(Dispatchers.IO) {
        // Check rate limiting
        if (isLockedOut()) {
            return@withContext UnlockResult.LockedOut(getRemainingLockoutMs())
        }

        require(hasIdentity()) { "No identity exists" }

        val encrypted = loadEncryptedIdentity()
            ?: return@withContext UnlockResult.Failed("No identity found")

        // Derive master key (passphraseBytes used directly)
        val masterKey = BedrockCore.deriveKey(passphraseBytes, encrypted.salt)
        // Note: Caller is responsible for zeroizing passphraseBytes

        // Try to decrypt
        val decrypted = BedrockCore.aesDecrypt(
            key = masterKey,
            ciphertext = encrypted.encryptedPayload,
            associatedData = encrypted.publicIdentity.did.toByteArray(StandardCharsets.UTF_8)
        )

        if (decrypted == null) {
            BedrockCore.zeroize(masterKey)

            // Track failed attempt and persist (Fix #7)
            failedAttempts++

            // SECURITY: Wipe identity after too many failed attempts
            if (failedAttempts >= MAX_ATTEMPTS_BEFORE_WIPE) {
                android.util.Log.w("IdentityManager",
                    "MAX FAILED ATTEMPTS REACHED ($failedAttempts) - TRIGGERING WIPE")
                // Reset state before wipe
                failedAttempts = 0
                lockoutUntil = 0
                saveRateLimitState()
                // Wipe identity - securely overwrite then delete
                try {
                    identityFile.takeIf { it.exists() }?.let { file ->
                        val size = file.length().toInt().coerceAtLeast(32)
                        val random = java.security.SecureRandom()
                        val junk = ByteArray(size)
                        random.nextBytes(junk)
                        file.writeBytes(junk)
                        file.delete()
                    }
                    // Also clear keystore
                    secureDeviceKey.clearDeviceKey()
                } catch (e: Exception) {
                    identityFile.delete()
                }
                return@withContext UnlockResult.WipedDueToFailedAttempts
            }

            if (failedAttempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT) {
                // Exponential backoff: 2s, 4s, 8s, 16s, ... up to 5 minutes
                val lockoutMs = minOf(
                    BASE_LOCKOUT_MS * (1L shl (failedAttempts - MAX_ATTEMPTS_BEFORE_LOCKOUT)),
                    MAX_LOCKOUT_MS
                )
                lockoutUntil = System.currentTimeMillis() + lockoutMs
                saveRateLimitState() // Persist lockout state
                return@withContext UnlockResult.LockedOut(lockoutMs)
            }
            saveRateLimitState() // Persist failed attempts

            return@withContext UnlockResult.Failed(
                "Incorrect passphrase",
                attemptsRemaining = MAX_ATTEMPTS_BEFORE_WIPE - failedAttempts
            )
        }

        // Success - reset rate limiting and persist
        resetFailedAttempts()
        saveRateLimitState()

        // Deserialize keys (supports both v1 and v2 formats)
        val keys = deserializePrivateKeysV2(decrypted)
        BedrockCore.zeroize(decrypted)

        // Migration: Generate X25519 session keys if missing (for pre-V3 identities)
        val existingEncrypted = loadEncryptedIdentity()
        val existingIdentity = existingEncrypted?.publicIdentity

        val (sessionPrivate, sessionPublic) = if (keys.sessionPrivate == null || keys.sessionPrivate.isEmpty() || keys.sessionPrivate.all { it == 0.toByte() }) {
            // Generate new X25519 session keys for legacy identities
            val (newPrivate, newPublic) = BedrockCore.lunarHkOvctKeygen()

            // Re-save the encrypted identity with new session keys
            if (existingIdentity != null && existingEncrypted != null) {
                val updatedIdentity = existingIdentity.copy(sessionPublicKey = newPublic)

                val newPrivatePayload = serializePrivateKeysV3(
                    keys.signingPrivate,
                    keys.encryptionPrivate,
                    newPrivate,
                    keys.dilithiumPrivate,
                    keys.dilithiumPublic
                )
                val newEncryptedPayload = BedrockCore.aesEncrypt(
                    key = masterKey,
                    plaintext = newPrivatePayload,
                    associatedData = updatedIdentity.did.toByteArray(StandardCharsets.UTF_8)
                )
                BedrockCore.zeroize(newPrivatePayload)

                val updatedEncryptedIdentity = EncryptedIdentity(
                    salt = existingEncrypted.salt,
                    encryptedPayload = newEncryptedPayload,
                    publicIdentity = updatedIdentity
                )
                saveEncryptedIdentity(updatedEncryptedIdentity)
            }

            Pair(newPrivate, newPublic)
        } else {
            Pair(keys.sessionPrivate, existingIdentity?.sessionPublicKey ?: ByteArray(32))
        }

        // Thread-safe key assignment (Fix #5)
        keysMutex.withLock {
            unlockedKeys = UnlockedKeys(
                signingPrivateKey = keys.signingPrivate,
                encryptionPrivateKey = keys.encryptionPrivate,
                sessionPrivateKey = sessionPrivate,
                masterKey = masterKey
            )
        }

        UnlockResult.Success
    }

    /**
     * Result of an unlock attempt.
     */
    sealed class UnlockResult {
        object Success : UnlockResult()
        data class Failed(
            val reason: String,
            val attemptsRemaining: Int = 0
        ) : UnlockResult()
        data class LockedOut(val remainingMs: Long) : UnlockResult()
        object WipedDueToFailedAttempts : UnlockResult() // Identity wiped after too many failed attempts
    }

    /**
     * Legacy unlock method for compatibility.
     * SECURITY FIX: Now accepts ByteArray instead of String.
     * @deprecated Use unlock() which returns UnlockResult
     */
    @Deprecated("Use unlock() with UnlockResult", ReplaceWith("unlock(passphraseBytes)"))
    suspend fun unlockLegacy(passphraseBytes: ByteArray): Boolean {
        return when (unlock(passphraseBytes)) {
            is UnlockResult.Success -> true
            else -> false
        }
    }
    
    /**
     * Lock the vault, clearing all keys from memory.
     * Fix #5: Uses mutex for thread-safe key access to prevent race conditions.
     */
    suspend fun lock() = keysMutex.withLock {
        unlockedKeys?.zeroize()
        unlockedKeys = null
    }

    /**
     * Lock the vault synchronously (for non-suspend contexts).
     * Prefer using suspend lock() when possible.
     */
    fun lockSync() {
        // Best-effort synchronization for non-coroutine contexts
        synchronized(this) {
            unlockedKeys?.zeroize()
            unlockedKeys = null
        }
    }
    
    /**
     * Get encryption key for creating owned artifacts.
     * Requires unlocked state.
     */
    fun getEncryptionKey(): ByteArray {
        return unlockedKeys?.encryptionPrivateKey 
            ?: throw IllegalStateException("Identity not unlocked")
    }
    
    /**
     * Get signing key for authorizations.
     * Requires unlocked state.
     */
    fun getSigningKey(): ByteArray {
        return unlockedKeys?.signingPrivateKey
            ?: throw IllegalStateException("Identity not unlocked")
    }

    /**
     * Get unlocked keys (for artifact decryption, contact saving, etc.)
     * Returns null if not unlocked.
     */
    fun getUnlockedKeys(): UnlockedKeys? = unlockedKeys

    /**
     * Get master key for encrypting contacts, vault index, etc.
     * Requires unlocked state.
     */
    fun getMasterKey(): ByteArray {
        return unlockedKeys?.masterKey
            ?: throw IllegalStateException("Identity not unlocked")
    }

    /**
     * Verify passphrase is correct (for confirming dangerous operations).
     * SECURITY FIX: Now accepts ByteArray instead of String.
     * Caller must zeroize the ByteArray after this call returns.
     */
    suspend fun verifyPassphrase(passphraseBytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        val encrypted = loadEncryptedIdentity() ?: return@withContext false

        val testKey = BedrockCore.deriveKey(passphraseBytes, encrypted.salt)
        // Note: Caller is responsible for zeroizing passphraseBytes

        val result = BedrockCore.aesDecrypt(
            key = testKey,
            ciphertext = encrypted.encryptedPayload,
            associatedData = encrypted.publicIdentity.did.toByteArray(StandardCharsets.UTF_8)
        )

        BedrockCore.zeroize(testKey)

        if (result != null) {
            BedrockCore.zeroize(result)
            true
        } else {
            false
        }
    }
    
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================
    
    private fun deriveDid(signingPublicKey: ByteArray): String {
        // Multibase + Multicodec encoding for did:offgrid
        // 0xed = Ed25519 public key
        val multicodec = byteArrayOf(0xed.toByte(), 0x01) + signingPublicKey
        val multibase = "z" + Companion.base58Encode(multicodec)
        return "did:offgrid:$multibase"
    }
    
    /**
     * V1 serialization - legacy format without Dilithium keys.
     */
    @Deprecated("Use serializePrivateKeysV2 for post-quantum support")
    private fun serializePrivateKeys(signing: ByteArray, encryption: ByteArray): ByteArray {
        // Simple length-prefixed serialization
        val result = ByteArray(4 + signing.size + 4 + encryption.size)
        var offset = 0

        // Signing key
        result[offset++] = (signing.size shr 24).toByte()
        result[offset++] = (signing.size shr 16).toByte()
        result[offset++] = (signing.size shr 8).toByte()
        result[offset++] = signing.size.toByte()
        System.arraycopy(signing, 0, result, offset, signing.size)
        offset += signing.size

        // Encryption key (ML-KEM-768)
        result[offset++] = (encryption.size shr 24).toByte()
        result[offset++] = (encryption.size shr 16).toByte()
        result[offset++] = (encryption.size shr 8).toByte()
        result[offset++] = encryption.size.toByte()
        System.arraycopy(encryption, 0, result, offset, encryption.size)

        return result
    }

    /**
     * V3 serialization - includes X25519 session keys for Double Ratchet.
     *
     * Format:
     * [version:1][signingLen:4][signing:N][encryptionLen:4][encryption:N]
     * [sessionPrivLen:4][sessionPriv:N][dilithiumPrivLen:4][dilithiumPriv:N][dilithiumPubLen:4][dilithiumPub:N]
     */
    private fun serializePrivateKeysV3(
        signing: ByteArray,
        encryption: ByteArray,
        sessionPrivate: ByteArray,
        dilithiumPrivate: ByteArray?,
        dilithiumPublic: ByteArray?
    ): ByteArray {
        val dilithiumPrivLen = dilithiumPrivate?.size ?: 0
        val dilithiumPubLen = dilithiumPublic?.size ?: 0

        val totalSize = 1 +  // version
                4 + signing.size +
                4 + encryption.size +
                4 + sessionPrivate.size +
                4 + dilithiumPrivLen +
                4 + dilithiumPubLen

        val result = ByteArray(totalSize)
        var offset = 0

        // Version 0x03 = X25519 session keys support
        result[offset++] = 0x03

        // Signing key (Ed25519)
        result[offset++] = (signing.size shr 24).toByte()
        result[offset++] = (signing.size shr 16).toByte()
        result[offset++] = (signing.size shr 8).toByte()
        result[offset++] = signing.size.toByte()
        System.arraycopy(signing, 0, result, offset, signing.size)
        offset += signing.size

        // Encryption key (ML-KEM-768)
        result[offset++] = (encryption.size shr 24).toByte()
        result[offset++] = (encryption.size shr 16).toByte()
        result[offset++] = (encryption.size shr 8).toByte()
        result[offset++] = encryption.size.toByte()
        System.arraycopy(encryption, 0, result, offset, encryption.size)
        offset += encryption.size

        // Session private key (X25519 - 32 bytes)
        result[offset++] = (sessionPrivate.size shr 24).toByte()
        result[offset++] = (sessionPrivate.size shr 16).toByte()
        result[offset++] = (sessionPrivate.size shr 8).toByte()
        result[offset++] = sessionPrivate.size.toByte()
        System.arraycopy(sessionPrivate, 0, result, offset, sessionPrivate.size)
        offset += sessionPrivate.size

        // Dilithium private key (optional)
        result[offset++] = (dilithiumPrivLen shr 24).toByte()
        result[offset++] = (dilithiumPrivLen shr 16).toByte()
        result[offset++] = (dilithiumPrivLen shr 8).toByte()
        result[offset++] = dilithiumPrivLen.toByte()
        if (dilithiumPrivate != null && dilithiumPrivLen > 0) {
            System.arraycopy(dilithiumPrivate, 0, result, offset, dilithiumPrivLen)
            offset += dilithiumPrivLen
        }

        // Dilithium public key (optional)
        result[offset++] = (dilithiumPubLen shr 24).toByte()
        result[offset++] = (dilithiumPubLen shr 16).toByte()
        result[offset++] = (dilithiumPubLen shr 8).toByte()
        result[offset++] = dilithiumPubLen.toByte()
        if (dilithiumPublic != null && dilithiumPubLen > 0) {
            System.arraycopy(dilithiumPublic, 0, result, offset, dilithiumPubLen)
        }

        return result
    }

    /**
     * Result of deserializing private keys.
     */
    private data class DeserializedKeys(
        val signingPrivate: ByteArray,
        val encryptionPrivate: ByteArray,
        val sessionPrivate: ByteArray?,      // X25519 session key (V3+)
        val dilithiumPrivate: ByteArray?,
        val dilithiumPublic: ByteArray?
    )

    /**
     * V2/V3 deserialization - supports v1, v2, and v3 formats.
     *
     * V3 format includes X25519 session private key for Double Ratchet.
     */
    private fun deserializePrivateKeysV2(data: ByteArray): DeserializedKeys {
        var offset = 0

        // Check version byte to determine format
        // v1 format starts with the length of the signing key (typically 64 bytes = 0x00000040)
        // v2 format starts with version byte 0x02
        // v3 format starts with version byte 0x03
        val version = if (data.isNotEmpty()) data[0].toInt() and 0xFF else 0
        val isV2 = version == 0x02
        val isV3 = version == 0x03

        if (isV2 || isV3) {
            // Skip version byte
            offset++
        }

        // Signing key
        val signingLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                        ((data[offset++].toInt() and 0xFF) shl 16) or
                        ((data[offset++].toInt() and 0xFF) shl 8) or
                        (data[offset++].toInt() and 0xFF)
        val signing = data.copyOfRange(offset, offset + signingLen)
        offset += signingLen

        // Encryption key (ML-KEM-768)
        val encryptionLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                           ((data[offset++].toInt() and 0xFF) shl 16) or
                           ((data[offset++].toInt() and 0xFF) shl 8) or
                           (data[offset++].toInt() and 0xFF)
        val encryption = data.copyOfRange(offset, offset + encryptionLen)
        offset += encryptionLen

        // Session private key (V3 only - X25519 for Double Ratchet)
        val sessionPrivate: ByteArray? = if (isV3 && offset + 4 <= data.size) {
            val sessionPrivLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                                ((data[offset++].toInt() and 0xFF) shl 16) or
                                ((data[offset++].toInt() and 0xFF) shl 8) or
                                (data[offset++].toInt() and 0xFF)
            if (sessionPrivLen > 0 && offset + sessionPrivLen <= data.size) {
                data.copyOfRange(offset, offset + sessionPrivLen).also { offset += sessionPrivLen }
            } else null
        } else null

        // Dilithium keys (v2 and v3)
        val dilithiumPrivate: ByteArray?
        val dilithiumPublic: ByteArray?

        if ((isV2 || isV3) && offset + 4 <= data.size) {
            // Dilithium private key
            val dilithiumPrivLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                                   ((data[offset++].toInt() and 0xFF) shl 16) or
                                   ((data[offset++].toInt() and 0xFF) shl 8) or
                                   (data[offset++].toInt() and 0xFF)
            dilithiumPrivate = if (dilithiumPrivLen > 0 && offset + dilithiumPrivLen <= data.size) {
                data.copyOfRange(offset, offset + dilithiumPrivLen).also { offset += dilithiumPrivLen }
            } else null

            // Dilithium public key
            val dilithiumPubLen = if (offset + 4 <= data.size) {
                ((data[offset++].toInt() and 0xFF) shl 24) or
                ((data[offset++].toInt() and 0xFF) shl 16) or
                ((data[offset++].toInt() and 0xFF) shl 8) or
                (data[offset++].toInt() and 0xFF)
            } else 0
            dilithiumPublic = if (dilithiumPubLen > 0 && offset + dilithiumPubLen <= data.size) {
                data.copyOfRange(offset, offset + dilithiumPubLen)
            } else null
        } else {
            dilithiumPrivate = null
            dilithiumPublic = null
        }

        return DeserializedKeys(
            signingPrivate = signing,
            encryptionPrivate = encryption,
            sessionPrivate = sessionPrivate,  // Populated for V3, null for V1/V2
            dilithiumPrivate = dilithiumPrivate,
            dilithiumPublic = dilithiumPublic
        )
    }

    /**
     * Legacy deserialization for v1 format.
     */
    @Deprecated("Use deserializePrivateKeysV2 for unified deserialization")
    private fun deserializePrivateKeys(data: ByteArray): Pair<ByteArray, ByteArray> {
        var offset = 0

        // Signing key
        val signingLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                        ((data[offset++].toInt() and 0xFF) shl 16) or
                        ((data[offset++].toInt() and 0xFF) shl 8) or
                        (data[offset++].toInt() and 0xFF)
        val signing = data.copyOfRange(offset, offset + signingLen)
        offset += signingLen

        // Encryption key (ML-KEM-768)
        val encryptionLen = ((data[offset++].toInt() and 0xFF) shl 24) or
                           ((data[offset++].toInt() and 0xFF) shl 16) or
                           ((data[offset++].toInt() and 0xFF) shl 8) or
                           (data[offset++].toInt() and 0xFF)
        val encryption = data.copyOfRange(offset, offset + encryptionLen)

        return signing to encryption
    }
    
    private fun saveEncryptedIdentity(encrypted: EncryptedIdentity) {
        identityFile.writeBytes(serializeEncryptedIdentity(encrypted))
    }

    private fun loadEncryptedIdentity(): EncryptedIdentity? {
        if (!identityFile.exists()) return null
        return deserializeEncryptedIdentity(identityFile.readBytes())
    }

    // ========================================================================
    // CBOR ENCODER - RFC 8949 Compliant Implementation
    // ========================================================================

    /**
     * CBOR Encoder implementing RFC 8949 (Concise Binary Object Representation).
     * Supports major types 0-5 needed for identity serialization.
     */
    private class CborEncoder {
        private val buffer = mutableListOf<Byte>()

        /**
         * Encode an unsigned integer (major type 0).
         * CBOR format: major type 0 (bits 7-5) + argument (bits 4-0 or following bytes)
         */
        fun encodeUnsignedInt(value: Long): CborEncoder {
            encodeTypeAndValue(MAJOR_TYPE_UNSIGNED_INT, value)
            return this
        }

        /**
         * Encode a byte string (major type 2).
         * CBOR format: major type 2 + length + raw bytes
         */
        fun encodeByteString(bytes: ByteArray): CborEncoder {
            encodeTypeAndValue(MAJOR_TYPE_BYTE_STRING, bytes.size.toLong())
            buffer.addAll(bytes.toList())
            return this
        }

        /**
         * Encode a text string (major type 3).
         * CBOR format: major type 3 + length + UTF-8 bytes
         */
        fun encodeTextString(text: String): CborEncoder {
            val utf8Bytes = text.toByteArray(StandardCharsets.UTF_8)
            encodeTypeAndValue(MAJOR_TYPE_TEXT_STRING, utf8Bytes.size.toLong())
            buffer.addAll(utf8Bytes.toList())
            return this
        }

        /**
         * Begin encoding an array (major type 4).
         * CBOR format: major type 4 + count
         */
        fun encodeArrayStart(count: Int): CborEncoder {
            encodeTypeAndValue(MAJOR_TYPE_ARRAY, count.toLong())
            return this
        }

        /**
         * Begin encoding a map (major type 5).
         * CBOR format: major type 5 + pair count
         */
        fun encodeMapStart(pairCount: Int): CborEncoder {
            encodeTypeAndValue(MAJOR_TYPE_MAP, pairCount.toLong())
            return this
        }

        /**
         * Encode type and argument value per RFC 8949 Section 3.
         * - Values 0-23: encoded in additional info bits
         * - Values 24-255: 1 additional byte (marker 24)
         * - Values 256-65535: 2 additional bytes (marker 25)
         * - Values 65536-4294967295: 4 additional bytes (marker 26)
         * - Larger values: 8 additional bytes (marker 27)
         */
        private fun encodeTypeAndValue(majorType: Int, value: Long) {
            val type = (majorType shl 5)
            when {
                value < 24 -> {
                    buffer.add((type or value.toInt()).toByte())
                }
                value < 256 -> {
                    buffer.add((type or 24).toByte())
                    buffer.add(value.toByte())
                }
                value < 65536 -> {
                    buffer.add((type or 25).toByte())
                    buffer.add((value shr 8).toByte())
                    buffer.add(value.toByte())
                }
                value < 4294967296L -> {
                    buffer.add((type or 26).toByte())
                    buffer.add((value shr 24).toByte())
                    buffer.add((value shr 16).toByte())
                    buffer.add((value shr 8).toByte())
                    buffer.add(value.toByte())
                }
                else -> {
                    buffer.add((type or 27).toByte())
                    buffer.add((value shr 56).toByte())
                    buffer.add((value shr 48).toByte())
                    buffer.add((value shr 40).toByte())
                    buffer.add((value shr 32).toByte())
                    buffer.add((value shr 24).toByte())
                    buffer.add((value shr 16).toByte())
                    buffer.add((value shr 8).toByte())
                    buffer.add(value.toByte())
                }
            }
        }

        fun toByteArray(): ByteArray = buffer.toByteArray()

        companion object {
            const val MAJOR_TYPE_UNSIGNED_INT = 0
            const val MAJOR_TYPE_BYTE_STRING = 2
            const val MAJOR_TYPE_TEXT_STRING = 3
            const val MAJOR_TYPE_ARRAY = 4
            const val MAJOR_TYPE_MAP = 5
        }
    }

    // ========================================================================
    // CBOR DECODER - RFC 8949 Compliant Implementation
    // ========================================================================

    /**
     * CBOR Decoder implementing RFC 8949 (Concise Binary Object Representation).
     * Supports major types 0-5 needed for identity deserialization.
     */
    private class CborDecoder(private val data: ByteArray) {
        private var offset = 0

        /**
         * Decode an unsigned integer (major type 0).
         * @throws CborDecodeException if not a valid unsigned int
         */
        fun decodeUnsignedInt(): Long {
            val (majorType, value) = decodeTypeAndValue()
            if (majorType != CborEncoder.MAJOR_TYPE_UNSIGNED_INT) {
                throw CborDecodeException("Expected unsigned int (type 0), got type $majorType")
            }
            return value
        }

        /**
         * Decode a byte string (major type 2).
         * @throws CborDecodeException if not a valid byte string
         */
        fun decodeByteString(): ByteArray {
            val (majorType, length) = decodeTypeAndValue()
            if (majorType != CborEncoder.MAJOR_TYPE_BYTE_STRING) {
                throw CborDecodeException("Expected byte string (type 2), got type $majorType")
            }
            val len = length.toInt()
            if (offset + len > data.size) {
                throw CborDecodeException("Byte string length $len exceeds available data")
            }
            val result = data.copyOfRange(offset, offset + len)
            offset += len
            return result
        }

        /**
         * Decode a text string (major type 3).
         * @throws CborDecodeException if not a valid text string
         */
        fun decodeTextString(): String {
            val (majorType, length) = decodeTypeAndValue()
            if (majorType != CborEncoder.MAJOR_TYPE_TEXT_STRING) {
                throw CborDecodeException("Expected text string (type 3), got type $majorType")
            }
            val len = length.toInt()
            if (offset + len > data.size) {
                throw CborDecodeException("Text string length $len exceeds available data")
            }
            val result = String(data, offset, len, StandardCharsets.UTF_8)
            offset += len
            return result
        }

        /**
         * Decode array start (major type 4) and return element count.
         * @throws CborDecodeException if not a valid array
         */
        fun decodeArrayStart(): Int {
            val (majorType, count) = decodeTypeAndValue()
            if (majorType != CborEncoder.MAJOR_TYPE_ARRAY) {
                throw CborDecodeException("Expected array (type 4), got type $majorType")
            }
            return count.toInt()
        }

        /**
         * Decode map start (major type 5) and return pair count.
         * @throws CborDecodeException if not a valid map
         */
        fun decodeMapStart(): Int {
            val (majorType, pairCount) = decodeTypeAndValue()
            if (majorType != CborEncoder.MAJOR_TYPE_MAP) {
                throw CborDecodeException("Expected map (type 5), got type $majorType")
            }
            return pairCount.toInt()
        }

        /**
         * Decode the major type and argument value per RFC 8949 Section 3.
         * @return Pair of (majorType, value)
         */
        private fun decodeTypeAndValue(): Pair<Int, Long> {
            if (offset >= data.size) {
                throw CborDecodeException("Unexpected end of data")
            }
            val initial = data[offset++].toInt() and 0xFF
            val majorType = initial shr 5
            val additionalInfo = initial and 0x1F

            val value: Long = when {
                additionalInfo < 24 -> additionalInfo.toLong()
                additionalInfo == 24 -> {
                    if (offset >= data.size) throw CborDecodeException("Unexpected end of data")
                    (data[offset++].toInt() and 0xFF).toLong()
                }
                additionalInfo == 25 -> {
                    if (offset + 2 > data.size) throw CborDecodeException("Unexpected end of data")
                    val b1 = (data[offset++].toInt() and 0xFF)
                    val b2 = (data[offset++].toInt() and 0xFF)
                    ((b1 shl 8) or b2).toLong()
                }
                additionalInfo == 26 -> {
                    if (offset + 4 > data.size) throw CborDecodeException("Unexpected end of data")
                    val b1 = (data[offset++].toLong() and 0xFF)
                    val b2 = (data[offset++].toLong() and 0xFF)
                    val b3 = (data[offset++].toLong() and 0xFF)
                    val b4 = (data[offset++].toLong() and 0xFF)
                    (b1 shl 24) or (b2 shl 16) or (b3 shl 8) or b4
                }
                additionalInfo == 27 -> {
                    if (offset + 8 > data.size) throw CborDecodeException("Unexpected end of data")
                    val b1 = (data[offset++].toLong() and 0xFF)
                    val b2 = (data[offset++].toLong() and 0xFF)
                    val b3 = (data[offset++].toLong() and 0xFF)
                    val b4 = (data[offset++].toLong() and 0xFF)
                    val b5 = (data[offset++].toLong() and 0xFF)
                    val b6 = (data[offset++].toLong() and 0xFF)
                    val b7 = (data[offset++].toLong() and 0xFF)
                    val b8 = (data[offset++].toLong() and 0xFF)
                    (b1 shl 56) or (b2 shl 48) or (b3 shl 40) or (b4 shl 32) or
                        (b5 shl 24) or (b6 shl 16) or (b7 shl 8) or b8
                }
                else -> throw CborDecodeException("Invalid additional info: $additionalInfo")
            }
            return majorType to value
        }

        /**
         * Peek at the major type of the next item without consuming it.
         */
        fun peekMajorType(): Int {
            if (offset >= data.size) {
                throw CborDecodeException("Unexpected end of data")
            }
            return (data[offset].toInt() and 0xFF) shr 5
        }

        /**
         * Check if we've consumed all data.
         */
        fun isComplete(): Boolean = offset >= data.size
    }

    /**
     * Exception thrown during CBOR decoding.
     */
    private class CborDecodeException(message: String) : Exception(message)

    // ========================================================================
    // ENCRYPTED IDENTITY CBOR SERIALIZATION
    // ========================================================================

    /**
     * CBOR serialization format version. Increment when format changes.
     */
    private val CBOR_FORMAT_VERSION = 2L

    /**
     * Map keys for CBOR serialization (using integers for compactness).
     */
    private object CborKeys {
        const val VERSION = 0L
        const val SALT = 1L
        const val ENCRYPTED_PAYLOAD = 2L
        const val PUBLIC_IDENTITY = 3L
        const val NAME = 4L
        const val DID = 5L
        const val SIGNING_PUBLIC_KEY = 6L
        const val ENCRYPTION_PUBLIC_KEY = 7L
        const val CREATED_AT = 8L
        const val SESSION_PUBLIC_KEY = 9L
    }

    /**
     * Serialize EncryptedIdentity to CBOR bytes.
     *
     * CBOR Structure (map with integer keys for compactness):
     * {
     *   0: version (unsigned int),
     *   1: salt (byte string),
     *   2: encryptedPayload (byte string),
     *   3: publicIdentity (map) {
     *     4: name (text string),
     *     5: did (text string),
     *     6: signingPublicKey (byte string),
     *     7: encryptionPublicKey (byte string),
     *     8: createdAt (unsigned int)
     *   }
     * }
     */
    private fun serializeEncryptedIdentity(encrypted: EncryptedIdentity): ByteArray {
        val encoder = CborEncoder()

        // Root map with 4 entries: version, salt, encryptedPayload, publicIdentity
        encoder.encodeMapStart(4)

        // Version (key 0)
        encoder.encodeUnsignedInt(CborKeys.VERSION)
        encoder.encodeUnsignedInt(CBOR_FORMAT_VERSION)

        // Salt (key 1)
        encoder.encodeUnsignedInt(CborKeys.SALT)
        encoder.encodeByteString(encrypted.salt)

        // Encrypted payload (key 2)
        encoder.encodeUnsignedInt(CborKeys.ENCRYPTED_PAYLOAD)
        encoder.encodeByteString(encrypted.encryptedPayload)

        // Public identity (key 3) - nested map with 6 entries
        encoder.encodeUnsignedInt(CborKeys.PUBLIC_IDENTITY)
        encoder.encodeMapStart(6)

        // Name (key 4)
        encoder.encodeUnsignedInt(CborKeys.NAME)
        encoder.encodeTextString(encrypted.publicIdentity.name)

        // DID (key 5)
        encoder.encodeUnsignedInt(CborKeys.DID)
        encoder.encodeTextString(encrypted.publicIdentity.did)

        // Signing public key (key 6)
        encoder.encodeUnsignedInt(CborKeys.SIGNING_PUBLIC_KEY)
        encoder.encodeByteString(encrypted.publicIdentity.signingPublicKey)

        // Encryption public key (key 7)
        encoder.encodeUnsignedInt(CborKeys.ENCRYPTION_PUBLIC_KEY)
        encoder.encodeByteString(encrypted.publicIdentity.encryptionPublicKey)

        // Session public key (key 9) - X25519 for Double Ratchet
        encoder.encodeUnsignedInt(CborKeys.SESSION_PUBLIC_KEY)
        encoder.encodeByteString(encrypted.publicIdentity.sessionPublicKey)

        // Created at timestamp (key 8)
        encoder.encodeUnsignedInt(CborKeys.CREATED_AT)
        encoder.encodeUnsignedInt(encrypted.publicIdentity.createdAt)

        return encoder.toByteArray()
    }

    /**
     * Deserialize CBOR bytes to EncryptedIdentity.
     * Supports both legacy format (version 1) and CBOR format (version 2+).
     *
     * @param data The serialized bytes
     * @return EncryptedIdentity or null if deserialization fails
     */
    private fun deserializeEncryptedIdentity(data: ByteArray): EncryptedIdentity? {
        if (data.isEmpty()) return null

        // Check if this is legacy format (version byte 0x01 at start)
        // Legacy format starts with 0x01, CBOR map starts with 0xA4 (map of 4 items)
        if (data[0] == 0x01.toByte()) {
            return deserializeEncryptedIdentityLegacy(data)
        }

        return try {
            deserializeEncryptedIdentityCbor(data)
        } catch (e: CborDecodeException) {
            null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Deserialize EncryptedIdentity from CBOR format.
     */
    private fun deserializeEncryptedIdentityCbor(data: ByteArray): EncryptedIdentity {
        val decoder = CborDecoder(data)

        // Read root map
        val rootMapSize = decoder.decodeMapStart()
        if (rootMapSize < 4) {
            throw CborDecodeException("Root map too small: expected at least 4 entries, got $rootMapSize")
        }

        var version: Long? = null
        var salt: ByteArray? = null
        var encryptedPayload: ByteArray? = null
        var name: String? = null
        var did: String? = null
        var signingPublicKey: ByteArray? = null
        var encryptionPublicKey: ByteArray? = null
        var sessionPublicKey: ByteArray? = null
        var createdAt: Long? = null

        // Parse root map entries
        repeat(rootMapSize) {
            val key = decoder.decodeUnsignedInt()
            when (key) {
                CborKeys.VERSION -> version = decoder.decodeUnsignedInt()
                CborKeys.SALT -> salt = decoder.decodeByteString()
                CborKeys.ENCRYPTED_PAYLOAD -> encryptedPayload = decoder.decodeByteString()
                CborKeys.PUBLIC_IDENTITY -> {
                    // Parse nested public identity map
                    val identityMapSize = decoder.decodeMapStart()
                    repeat(identityMapSize) {
                        val identityKey = decoder.decodeUnsignedInt()
                        when (identityKey) {
                            CborKeys.NAME -> name = decoder.decodeTextString()
                            CborKeys.DID -> did = decoder.decodeTextString()
                            CborKeys.SIGNING_PUBLIC_KEY -> signingPublicKey = decoder.decodeByteString()
                            CborKeys.ENCRYPTION_PUBLIC_KEY -> encryptionPublicKey = decoder.decodeByteString()
                            CborKeys.SESSION_PUBLIC_KEY -> sessionPublicKey = decoder.decodeByteString()
                            CborKeys.CREATED_AT -> createdAt = decoder.decodeUnsignedInt()
                            else -> skipCborValue(decoder)
                        }
                    }
                }
                else -> skipCborValue(decoder)
            }
        }

        // Validate version
        if (version == null || version!! < CBOR_FORMAT_VERSION) {
            throw CborDecodeException("Unsupported CBOR format version: $version")
        }

        // Validate required fields
        if (salt == null) throw CborDecodeException("Missing salt")
        if (encryptedPayload == null) throw CborDecodeException("Missing encryptedPayload")
        if (name == null) throw CborDecodeException("Missing name")
        if (did == null) throw CborDecodeException("Missing did")
        if (signingPublicKey == null) throw CborDecodeException("Missing signingPublicKey")
        if (encryptionPublicKey == null) throw CborDecodeException("Missing encryptionPublicKey")
        if (createdAt == null) throw CborDecodeException("Missing createdAt")

        return EncryptedIdentity(
            salt = salt!!,
            encryptedPayload = encryptedPayload!!,
            publicIdentity = Identity(
                name = name!!,
                did = did!!,
                signingPublicKey = signingPublicKey!!,
                encryptionPublicKey = encryptionPublicKey!!,
                sessionPublicKey = sessionPublicKey ?: ByteArray(0),  // May be null for older formats
                createdAt = createdAt!!
            )
        )
    }

    /**
     * Skip over a CBOR value (for forward compatibility with unknown keys).
     */
    private fun skipCborValue(decoder: CborDecoder) {
        when (decoder.peekMajorType()) {
            CborEncoder.MAJOR_TYPE_UNSIGNED_INT -> decoder.decodeUnsignedInt()
            CborEncoder.MAJOR_TYPE_BYTE_STRING -> decoder.decodeByteString()
            CborEncoder.MAJOR_TYPE_TEXT_STRING -> decoder.decodeTextString()
            CborEncoder.MAJOR_TYPE_ARRAY -> {
                val count = decoder.decodeArrayStart()
                repeat(count) { skipCborValue(decoder) }
            }
            CborEncoder.MAJOR_TYPE_MAP -> {
                val count = decoder.decodeMapStart()
                repeat(count) {
                    skipCborValue(decoder) // key
                    skipCborValue(decoder) // value
                }
            }
            else -> throw CborDecodeException("Cannot skip unknown major type")
        }
    }

    /**
     * Deserialize EncryptedIdentity from legacy format (version 1).
     * Provides backward compatibility for existing identity files.
     */
    private fun deserializeEncryptedIdentityLegacy(data: ByteArray): EncryptedIdentity? {
        try {
            var offset = 0

            // Version
            val version = data[offset++]
            if (version != 0x01.toByte()) return null

            // Salt
            val salt = data.copyOfRange(offset, offset + 32)
            offset += 32

            // Name
            val nameLen = bytesToInt(data, offset)
            offset += 4
            val name = String(data.copyOfRange(offset, offset + nameLen), StandardCharsets.UTF_8)
            offset += nameLen

            // DID
            val didLen = bytesToInt(data, offset)
            offset += 4
            val did = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
            offset += didLen

            // Signing public key
            val signingPublic = data.copyOfRange(offset, offset + 32)
            offset += 32

            // Encryption public key
            val encryptionLen = bytesToInt(data, offset)
            offset += 4
            val encryptionPublic = data.copyOfRange(offset, offset + encryptionLen)
            offset += encryptionLen

            // Created at
            val createdAt = bytesToLong(data, offset)
            offset += 8

            // Encrypted payload
            val payloadLen = bytesToInt(data, offset)
            offset += 4
            val payload = data.copyOfRange(offset, offset + payloadLen)

            return EncryptedIdentity(
                salt = salt,
                encryptedPayload = payload,
                publicIdentity = Identity(
                    name = name,
                    did = did,
                    signingPublicKey = signingPublic,
                    encryptionPublicKey = encryptionPublic,
                    sessionPublicKey = ByteArray(0),  // Legacy format doesn't have session key
                    createdAt = createdAt
                )
            )
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun intToBytes(value: Int): ByteArray {
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }
    
    private fun bytesToInt(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
               ((data[offset + 1].toInt() and 0xFF) shl 16) or
               ((data[offset + 2].toInt() and 0xFF) shl 8) or
               (data[offset + 3].toInt() and 0xFF)
    }
    
    private fun longToBytes(value: Long): ByteArray {
        return byteArrayOf(
            (value shr 56).toByte(),
            (value shr 48).toByte(),
            (value shr 40).toByte(),
            (value shr 32).toByte(),
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }
    
    private fun bytesToLong(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 56) or
               ((data[offset + 1].toLong() and 0xFF) shl 48) or
               ((data[offset + 2].toLong() and 0xFF) shl 40) or
               ((data[offset + 3].toLong() and 0xFF) shl 32) or
               ((data[offset + 4].toLong() and 0xFF) shl 24) or
               ((data[offset + 5].toLong() and 0xFF) shl 16) or
               ((data[offset + 6].toLong() and 0xFF) shl 8) or
               (data[offset + 7].toLong() and 0xFF)
    }
    
    // Base58 encoding helper (moved to top-level companion object)
}
