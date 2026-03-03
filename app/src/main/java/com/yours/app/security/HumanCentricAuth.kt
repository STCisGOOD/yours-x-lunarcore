package com.yours.app.security

import android.content.Context
import java.io.File
import java.nio.ByteBuffer
import java.security.SecureRandom
import com.yours.app.crypto.BedrockCore
import com.yours.app.security.Bip39Wordlist
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * HumanCentricAuth - Authentication that works WITH human psychology, not against it.
 *
 * CORE INSIGHT:
 * A 12-word passphrase has 128+ bits of entropy but ZERO usability.
 * A constellation pattern has ~40 bits but 100% usability.
 * Combined with device-bound secrets, we can have BOTH.
 *
 * THE ARCHITECTURE:
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  RECOVERY LAYER (12 words) - Used ONCE at setup or recovery    │
 * │  ├─ 128-bit entropy                                            │
 * │  ├─ Stored encrypted with device key                           │
 * │  └─ Never entered again unless recovering on new device        │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  DAILY LAYER (Constellation + Rhythm) - Used every unlock      │
 * │  ├─ 60-80 bits from gesture (spatial + timing)                 │
 * │  ├─ Combined with 256-bit device secret                        │
 * │  ├─ Feels like "drawing a shape"                               │
 * │  └─ Takes 1-2 seconds                                          │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  DEVICE LAYER (Hardware) - Transparent to user                 │
 * │  ├─ 256-bit key in Android Keystore / StrongBox                │
 * │  ├─ Biometric-gated access (optional)                          │
 * │  └─ Destroyed on factory reset                                 │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * HUMAN PSYCHOLOGY PRINCIPLES APPLIED:
 *
 * 1. SPATIAL MEMORY: Humans remember WHERE things are effortlessly.
 *    The constellation pattern exploits hippocampal spatial processing.
 *
 * 2. MOTOR MEMORY: Once you learn to draw a shape, it's automatic.
 *    Like signing your name - unique but feels effortless.
 *
 * 3. CHUNKING: Brain sees "arrow pointing up-right" not "9 coordinate pairs".
 *    The pattern is ONE memory, not N memories.
 *
 * 4. RHYTHM: Adding timing makes patterns unique but natural.
 *    Like a musical phrase - tap-tap-TAP-tap feels different than tap-tap-tap-TAP.
 *
 * 5. EMOTIONAL ANCHORING: Personal patterns have meaning.
 *    "My grandmother's house shape" is unforgettable.
 *
 * ENTROPY CALCULATION:
 *
 * Constellation with rhythm:
 * - Grid: 5x7 = 35 points
 * - Pattern length: 6-12 points
 * - Order matters
 * - Timing: 3 speed levels per segment (fast/medium/slow)
 * - Pressure: 2 levels if available (light/firm)
 *
 * For 8-point pattern:
 * - Positions: 35 * 34 * 33 * 32 * 31 * 30 * 29 * 28 = 3.3 * 10^12 (~42 bits)
 * - Timing: 3^7 = 2187 additional combinations (~11 bits)
 * - Pressure: 2^8 = 256 additional combinations (~8 bits)
 * - Total: ~61 bits from user input alone
 *
 * Combined with device secret:
 * - User pattern: ~61 bits
 * - Device secret: 256 bits
 * - HKDF combination: Effective 256-bit security
 *
 * Even if device is cloned, attacker still needs the pattern.
 * Even if pattern is shoulder-surfed, attacker needs the device.
 */
class HumanCentricAuth(private val context: Context) {

    companion object {
        // Grid dimensions for constellation
        const val GRID_COLS = 7
        const val GRID_ROWS = 5
        const val TOTAL_POINTS = GRID_COLS * GRID_ROWS  // 35 points

        // Pattern constraints
        const val MIN_PATTERN_LENGTH = 6
        const val MAX_PATTERN_LENGTH = 15
        const val RECOMMENDED_LENGTH = 8

        // Timing thresholds (milliseconds between points)
        const val TIMING_FAST = 150L      // < 150ms = fast
        const val TIMING_MEDIUM = 400L    // 150-400ms = medium
        // > 400ms = slow

        // Pressure thresholds (if available)
        const val PRESSURE_LIGHT = 0.3f
        const val PRESSURE_FIRM = 0.7f

        // Domain separators
        private val DOMAIN_PATTERN = "yours-pattern-auth-v1".toByteArray()
        private val DOMAIN_COMBINED = "yours-combined-auth-v1".toByteArray()
        private val DOMAIN_RECOVERY = "yours-recovery-binding-v1".toByteArray()

        // Rate limiting
        const val MAX_ATTEMPTS = 5
        const val LOCKOUT_MS = 30_000L  // 30 seconds
        const val LOCKOUT_MULTIPLIER = 2  // Doubles each time

        // Minimum entropy requirements
        const val MIN_PATTERN_ENTROPY_BITS = 40
    }

    private val secureRandom = SecureRandom()
    private val mutex = Mutex()

    // Secure device key provider (singleton)
    private val secureDeviceKey = SecureDeviceKey.getInstance(context)

    // Directory for encrypted storage files
    private val storageDir: File = context.filesDir

    // Rate limiting state
    private var failedAttempts = 0
    private var lockoutUntil = 0L
    private var consecutiveLockouts = 0

    /**
     * A point in the constellation grid.
     */
    data class ConstellationPoint(
        val x: Int,  // 0 to GRID_COLS-1
        val y: Int,  // 0 to GRID_ROWS-1
        val timestamp: Long,  // When this point was touched
        val pressure: Float = 0.5f  // 0.0 to 1.0
    ) {
        init {
            require(x in 0 until GRID_COLS) { "x out of bounds" }
            require(y in 0 until GRID_ROWS) { "y out of bounds" }
        }

        val index: Int get() = y * GRID_COLS + x
    }

    /**
     * A complete constellation pattern with timing and pressure.
     */
    data class ConstellationPattern(
        val points: List<ConstellationPoint>
    ) {
        init {
            require(points.size >= MIN_PATTERN_LENGTH) {
                "Pattern too short: ${points.size} < $MIN_PATTERN_LENGTH"
            }
            require(points.size <= MAX_PATTERN_LENGTH) {
                "Pattern too long: ${points.size} > $MAX_PATTERN_LENGTH"
            }
        }

        /**
         * Calculate entropy of this pattern.
         */
        fun calculateEntropyBits(): Double {
            // Position entropy
            var positionEntropy = 0.0
            var availablePoints = TOTAL_POINTS
            for (i in points.indices) {
                positionEntropy += Math.log(availablePoints.toDouble()) / Math.log(2.0)
                availablePoints--
            }

            // Timing entropy (3 levels per segment)
            val timingEntropy = (points.size - 1) * Math.log(3.0) / Math.log(2.0)

            // Pressure entropy (2 levels per point, if varied)
            val pressureVariance = points.map { it.pressure }.distinct().size
            val pressureEntropy = if (pressureVariance > 1) {
                points.size * Math.log(2.0) / Math.log(2.0)
            } else {
                0.0
            }

            return positionEntropy + timingEntropy + pressureEntropy
        }

        /**
         * Extract timing pattern (relative speeds between points).
         */
        fun extractTimingPattern(): List<Int> {
            if (points.size < 2) return emptyList()

            return (1 until points.size).map { i ->
                val delta = points[i].timestamp - points[i-1].timestamp
                when {
                    delta < TIMING_FAST -> 0   // Fast
                    delta < TIMING_MEDIUM -> 1 // Medium
                    else -> 2                   // Slow
                }
            }
        }

        /**
         * Extract pressure pattern.
         */
        fun extractPressurePattern(): List<Int> {
            return points.map { p ->
                when {
                    p.pressure < PRESSURE_LIGHT -> 0  // Light
                    p.pressure > PRESSURE_FIRM -> 2   // Firm
                    else -> 1                          // Medium
                }
            }
        }

        /**
         * Serialize pattern for key derivation.
         * Includes position, timing, and pressure data.
         */
        fun serialize(): ByteArray {
            val buffer = ByteBuffer.allocate(
                4 +                          // Point count
                points.size * 2 +            // Position indices
                (points.size - 1) +          // Timing pattern
                points.size                  // Pressure pattern
            )

            buffer.putInt(points.size)

            // Positions
            for (point in points) {
                buffer.put(point.index.toByte())
                buffer.put(point.y.toByte())
            }

            // Timing (between points)
            for (timing in extractTimingPattern()) {
                buffer.put(timing.toByte())
            }

            // Pressure
            for (pressure in extractPressurePattern()) {
                buffer.put(pressure.toByte())
            }

            return buffer.array()
        }
    }

    /**
     * Setup result containing all generated secrets.
     */
    data class SetupResult(
        val recoveryPhrase: List<String>,  // 12 words for backup
        val patternHash: ByteArray,         // For verification
        val deviceSecretCreated: Boolean
    )

    /**
     * Initial setup - called once when user first creates identity.
     *
     * @param pattern The constellation pattern user drew
     * @return SetupResult with recovery phrase (show to user ONCE)
     */
    suspend fun setup(pattern: ConstellationPattern): SetupResult = mutex.withLock {
        // Validate pattern entropy
        val entropy = pattern.calculateEntropyBits()
        require(entropy >= MIN_PATTERN_ENTROPY_BITS) {
            "Pattern too simple: $entropy bits < $MIN_PATTERN_ENTROPY_BITS required"
        }

        // Generate recovery phrase (12 words = 128 bits)
        val recoveryPhrase = generateRecoveryPhrase()

        // Generate device secret (256 bits, stored encrypted)
        val deviceSecret = BedrockCore.randomBytes(32)
        storeEncryptedFile("device_secret", deviceSecret)

        // Derive pattern key from constellation
        val patternKey = derivePatternKey(pattern)

        // Encrypt recovery phrase with combined key
        val combinedKey = combineKeys(patternKey, deviceSecret)
        val recoveryBytes = serializeRecoveryPhrase(recoveryPhrase)
        val encryptedRecovery = BedrockCore.aesEncrypt(
            combinedKey,
            recoveryBytes,
            DOMAIN_RECOVERY
        ) ?: throw IllegalStateException("Failed to encrypt recovery phrase")

        // Store encrypted recovery
        storeEncryptedFile("encrypted_recovery", encryptedRecovery)

        // Store pattern hash for verification (NOT the pattern itself)
        val patternHash = BedrockCore.sha3_256(pattern.serialize())
        storeEncryptedFile("pattern_hash", patternHash)

        // Zeroize sensitive data
        BedrockCore.zeroize(deviceSecret)
        BedrockCore.zeroize(patternKey)
        BedrockCore.zeroize(combinedKey)
        BedrockCore.zeroize(recoveryBytes)

        return@withLock SetupResult(
            recoveryPhrase = recoveryPhrase,
            patternHash = patternHash,
            deviceSecretCreated = true
        )
    }

    /**
     * Daily unlock - fast, uses constellation pattern.
     *
     * @param pattern The constellation pattern user drew
     * @return Master key if successful, null if failed
     */
    suspend fun unlock(pattern: ConstellationPattern): ByteArray? = mutex.withLock {
        // Check rate limiting
        if (isLockedOut()) {
            val remaining = (lockoutUntil - System.currentTimeMillis()) / 1000
            throw RateLimitException("Locked out. Try again in $remaining seconds.")
        }

        // Get stored secrets
        val deviceSecret = loadEncryptedFile("device_secret")
            ?: throw IllegalStateException("Device secret not found - need recovery")

        val storedPatternHash = loadEncryptedFile("pattern_hash")
            ?: throw IllegalStateException("Pattern hash not found")

        val encryptedRecovery = loadEncryptedFile("encrypted_recovery")
            ?: throw IllegalStateException("Encrypted recovery not found")

        // Derive pattern key
        val patternKey = derivePatternKey(pattern)

        // Verify pattern hash (constant-time comparison)
        val inputPatternHash = BedrockCore.sha3_256(pattern.serialize())
        val patternValid = constantTimeEquals(inputPatternHash, storedPatternHash)

        if (!patternValid) {
            BedrockCore.zeroize(deviceSecret)
            BedrockCore.zeroize(patternKey)
            recordFailedAttempt()
            return@withLock null
        }

        // Pattern valid - combine keys
        val combinedKey = combineKeys(patternKey, deviceSecret)

        // Decrypt recovery phrase
        val recoveryBytes = BedrockCore.aesDecrypt(
            combinedKey,
            encryptedRecovery,
            DOMAIN_RECOVERY
        )

        if (recoveryBytes == null) {
            // This shouldn't happen if pattern hash matched
            BedrockCore.zeroize(deviceSecret)
            BedrockCore.zeroize(patternKey)
            BedrockCore.zeroize(combinedKey)
            recordFailedAttempt()
            return@withLock null
        }

        // Derive master key from recovery phrase
        val recoveryPhrase = deserializeRecoveryPhrase(recoveryBytes)
        val masterKey = deriveMasterKeyFromPhrase(recoveryPhrase)

        // Success - reset rate limiting
        failedAttempts = 0
        consecutiveLockouts = 0

        // Zeroize intermediates
        BedrockCore.zeroize(deviceSecret)
        BedrockCore.zeroize(patternKey)
        BedrockCore.zeroize(combinedKey)
        BedrockCore.zeroize(recoveryBytes)

        return@withLock masterKey
    }

    /**
     * Recover on new device using 12-word phrase.
     * This is the ONLY time user needs to enter the full phrase.
     *
     * @param recoveryPhrase The 12-word recovery phrase
     * @param newPattern New constellation pattern for this device
     * @return Master key if successful
     */
    suspend fun recover(
        recoveryPhrase: List<String>,
        newPattern: ConstellationPattern
    ): ByteArray = mutex.withLock {
        // Validate phrase
        require(recoveryPhrase.size == 12) { "Recovery phrase must be 12 words" }

        // Validate pattern entropy
        val entropy = newPattern.calculateEntropyBits()
        require(entropy >= MIN_PATTERN_ENTROPY_BITS) {
            "Pattern too simple: $entropy bits < $MIN_PATTERN_ENTROPY_BITS required"
        }

        // Derive master key from recovery phrase
        val masterKey = deriveMasterKeyFromPhrase(recoveryPhrase)

        // Generate new device secret
        val deviceSecret = BedrockCore.randomBytes(32)
        storeEncryptedFile("device_secret", deviceSecret)

        // Derive new pattern key
        val patternKey = derivePatternKey(newPattern)

        // Encrypt recovery phrase with new combined key
        val combinedKey = combineKeys(patternKey, deviceSecret)
        val recoveryBytes = serializeRecoveryPhrase(recoveryPhrase)
        val encryptedRecovery = BedrockCore.aesEncrypt(
            combinedKey,
            recoveryBytes,
            DOMAIN_RECOVERY
        ) ?: throw IllegalStateException("Failed to encrypt recovery phrase")

        // Store new encrypted recovery
        storeEncryptedFile("encrypted_recovery", encryptedRecovery)

        // Store new pattern hash
        val patternHash = BedrockCore.sha3_256(newPattern.serialize())
        storeEncryptedFile("pattern_hash", patternHash)

        // Zeroize
        BedrockCore.zeroize(deviceSecret)
        BedrockCore.zeroize(patternKey)
        BedrockCore.zeroize(combinedKey)
        BedrockCore.zeroize(recoveryBytes)

        return@withLock masterKey
    }

    /**
     * Change constellation pattern without needing recovery phrase.
     *
     * @param currentPattern Current pattern for verification
     * @param newPattern New pattern to use
     * @return true if changed successfully
     */
    suspend fun changePattern(
        currentPattern: ConstellationPattern,
        newPattern: ConstellationPattern
    ): Boolean = mutex.withLock {
        // Validate new pattern
        val newEntropy = newPattern.calculateEntropyBits()
        require(newEntropy >= MIN_PATTERN_ENTROPY_BITS) {
            "New pattern too simple"
        }

        // Unlock with current pattern to verify
        val masterKey = unlock(currentPattern) ?: return@withLock false

        // Get device secret
        val deviceSecret = loadEncryptedFile("device_secret")
            ?: return@withLock false

        val encryptedRecovery = loadEncryptedFile("encrypted_recovery")
            ?: return@withLock false

        // Decrypt recovery with old pattern
        val oldPatternKey = derivePatternKey(currentPattern)
        val oldCombinedKey = combineKeys(oldPatternKey, deviceSecret)
        val recoveryBytes = BedrockCore.aesDecrypt(
            oldCombinedKey,
            encryptedRecovery,
            DOMAIN_RECOVERY
        ) ?: return@withLock false

        // Re-encrypt with new pattern
        val newPatternKey = derivePatternKey(newPattern)
        val newCombinedKey = combineKeys(newPatternKey, deviceSecret)
        val newEncryptedRecovery = BedrockCore.aesEncrypt(
            newCombinedKey,
            recoveryBytes,
            DOMAIN_RECOVERY
        ) ?: return@withLock false

        // Store new encrypted recovery and pattern hash
        storeEncryptedFile("encrypted_recovery", newEncryptedRecovery)
        val newPatternHash = BedrockCore.sha3_256(newPattern.serialize())
        storeEncryptedFile("pattern_hash", newPatternHash)

        // Zeroize
        BedrockCore.zeroize(masterKey)
        BedrockCore.zeroize(deviceSecret)
        BedrockCore.zeroize(oldPatternKey)
        BedrockCore.zeroize(oldCombinedKey)
        BedrockCore.zeroize(recoveryBytes)
        BedrockCore.zeroize(newPatternKey)
        BedrockCore.zeroize(newCombinedKey)

        return@withLock true
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    /**
     * Store encrypted data to a file using the device key.
     *
     * @param name The name of the file (will be stored in context.filesDir)
     * @param data The data to encrypt and store
     */
    private fun storeEncryptedFile(name: String, data: ByteArray) {
        val deviceKey = secureDeviceKey.getDeviceKey()
        try {
            val encrypted = BedrockCore.aesEncrypt(deviceKey, data, name.toByteArray())
            File(storageDir, name).writeBytes(encrypted)
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }

    /**
     * Load and decrypt data from a file using the device key.
     *
     * @param name The name of the file to read
     * @return The decrypted data, or null if file doesn't exist or decryption fails
     */
    private fun loadEncryptedFile(name: String): ByteArray? {
        val file = File(storageDir, name)
        if (!file.exists()) return null

        val deviceKey = secureDeviceKey.getDeviceKey()
        return try {
            val encrypted = file.readBytes()
            BedrockCore.aesDecrypt(deviceKey, encrypted, name.toByteArray())
        } finally {
            BedrockCore.zeroize(deviceKey)
        }
    }

    /**
     * Delete an encrypted file.
     *
     * @param name The name of the file to delete
     */
    private fun deleteEncryptedFile(name: String) {
        val file = File(storageDir, name)
        if (file.exists()) {
            // Overwrite with random data before deletion for secure delete
            try {
                file.writeBytes(BedrockCore.randomBytes(file.length().toInt().coerceAtLeast(32)))
            } catch (_: Exception) {
                // Best effort
            }
            file.delete()
        }
    }

    /**
     * Derive key from constellation pattern.
     * Uses HKDF with pattern data as IKM.
     */
    private fun derivePatternKey(pattern: ConstellationPattern): ByteArray {
        val patternData = pattern.serialize()

        // Add salt based on pattern characteristics
        val salt = ByteBuffer.allocate(DOMAIN_PATTERN.size + 8)
            .put(DOMAIN_PATTERN)
            .putInt(pattern.points.size)
            .putInt(pattern.calculateEntropyBits().toInt())
            .array()

        val key = BedrockCore.hkdf(
            inputKeyMaterial = patternData,
            salt = salt,
            info = "pattern-key".toByteArray(),
            outputLength = 32
        )

        BedrockCore.zeroize(patternData)
        return key
    }

    /**
     * Combine pattern key with device secret.
     */
    private fun combineKeys(patternKey: ByteArray, deviceSecret: ByteArray): ByteArray {
        val combined = ByteBuffer.allocate(DOMAIN_COMBINED.size + patternKey.size + deviceSecret.size)
            .put(DOMAIN_COMBINED)
            .put(patternKey)
            .put(deviceSecret)
            .array()

        val result = BedrockCore.sha3_256(combined)
        BedrockCore.zeroize(combined)
        return result
    }

    /**
     * Generate 12-word recovery phrase (BIP-39 style).
     */
    private fun generateRecoveryPhrase(): List<String> {
        // Generate 128 bits of entropy
        val entropy = ByteArray(16)
        secureRandom.nextBytes(entropy)

        // Convert to word indices (11 bits each = 12 words from 2048 word list)
        val words = mutableListOf<String>()
        val bits = entropy.toBitString()

        // Add checksum (4 bits for 128-bit entropy)
        val checksum = BedrockCore.sha3_256(entropy)
        val checksumBits = checksum[0].toInt() and 0xF0 shr 4

        val fullBits = bits + checksumBits.toString(2).padStart(4, '0')

        for (i in 0 until 12) {
            val start = i * 11
            val end = start + 11
            val index = fullBits.substring(start, end).toInt(2)
            words.add(Bip39Wordlist.getWord(index))
        }

        BedrockCore.zeroize(entropy)
        return words
    }

    /**
     * Derive master key from recovery phrase.
     * Uses HKDF for key derivation since Argon2id is not available in BedrockCore.
     * The recovery phrase already has 128 bits of entropy, so HKDF provides
     * adequate security for key derivation.
     */
    private fun deriveMasterKeyFromPhrase(phrase: List<String>): ByteArray {
        val phraseBytes = phrase.joinToString(" ").toByteArray()

        // Use HKDF with domain separation salt
        val salt = BedrockCore.sha3_256(DOMAIN_RECOVERY)

        val masterKey = BedrockCore.hkdf(
            inputKeyMaterial = phraseBytes,
            salt = salt,
            info = "master-key-derivation".toByteArray(),
            outputLength = 32
        )

        BedrockCore.zeroize(phraseBytes)
        return masterKey
    }

    private fun serializeRecoveryPhrase(phrase: List<String>): ByteArray {
        return phrase.joinToString(" ").toByteArray(Charsets.UTF_8)
    }

    private fun deserializeRecoveryPhrase(data: ByteArray): List<String> {
        return String(data, Charsets.UTF_8).split(" ")
    }

    private fun ByteArray.toBitString(): String {
        return this.joinToString("") { byte ->
            (byte.toInt() and 0xFF).toString(2).padStart(8, '0')
        }
    }

    /**
     * Constant-time byte array comparison.
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    private fun isLockedOut(): Boolean {
        return System.currentTimeMillis() < lockoutUntil
    }

    private fun recordFailedAttempt() {
        failedAttempts++
        if (failedAttempts >= MAX_ATTEMPTS) {
            consecutiveLockouts++
            val lockoutDuration = LOCKOUT_MS * Math.pow(
                LOCKOUT_MULTIPLIER.toDouble(),
                (consecutiveLockouts - 1).toDouble()
            ).toLong()
            lockoutUntil = System.currentTimeMillis() + lockoutDuration
            failedAttempts = 0
        }
    }
}

/**
 * Exception for rate limiting.
 */
class RateLimitException(message: String) : Exception(message)

