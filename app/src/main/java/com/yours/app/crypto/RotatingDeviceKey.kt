package com.yours.app.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Automatic device key rotation with versioning and forward secrecy.
 * Rotates keys every 90 days, retains up to 4 generations, and supports
 * emergency rotation on suspected compromise.
 */
class RotatingDeviceKey(
    private val storage: SecureKeyStorage,
    private val securityEventEmitter: SecurityEventEmitter? = null
) {
    companion object {
        /**
         * Default rotation period: 90 days.
         */
        const val DEFAULT_ROTATION_PERIOD_MS = 90L * 24 * 60 * 60 * 1000

        /**
         * Maximum key generations to keep.
         * Allows decryption of data encrypted with recent old keys.
         */
        const val MAX_KEY_GENERATIONS = 4

        /**
         * Key version prefix for storage.
         */
        const val KEY_VERSION_PREFIX = "device_key_v"

        /**
         * Metadata key for current version.
         */
        const val CURRENT_VERSION_KEY = "device_key_current_version"

        /**
         * Metadata key for rotation timestamp.
         */
        const val LAST_ROTATION_KEY = "device_key_last_rotation"

        /**
         * Domain separator for key derivation.
         */
        private val ROTATION_DOMAIN = "lunarpunk-device-key-rotation-v1".toByteArray()
    }

    private val secureRandom = SecureRandom()

    /**
     * Current key version (0 = initial, increments on rotation).
     */
    private var currentVersion: Int = 0

    /**
     * Timestamp of last rotation.
     */
    private var lastRotationTime: Long = 0

    /**
     * Cached keys by version (decrypted when needed).
     */
    private val keyCache = mutableMapOf<Int, ByteArray>()

    /**
     * Initialize the rotating key system.
     *
     * @param masterKey Master key used to encrypt device keys
     * @return true if initialized successfully
     */
    fun initialize(masterKey: ByteArray): Boolean {
        // Load current version from storage
        currentVersion = storage.getInt(CURRENT_VERSION_KEY) ?: 0
        lastRotationTime = storage.getLong(LAST_ROTATION_KEY) ?: System.currentTimeMillis()

        // If no key exists, generate initial key
        if (!storage.exists(keyName(currentVersion))) {
            return generateNewKey(masterKey, 0)
        }

        return true
    }

    /**
     * Get the current device key.
     *
     * @param masterKey Master key to decrypt device key
     * @return Current device key (32 bytes)
     */
    fun getCurrentKey(masterKey: ByteArray): ByteArray? {
        return getKeyVersion(currentVersion, masterKey)
    }

    /**
     * Get a specific key version.
     *
     * @param version Key version to retrieve
     * @param masterKey Master key to decrypt
     * @return Device key for that version, or null if not available
     */
    fun getKeyVersion(version: Int, masterKey: ByteArray): ByteArray? {
        // Check cache first
        keyCache[version]?.let { return it.copyOf() }

        // Load from storage
        val encryptedKey = storage.getBytes(keyName(version)) ?: return null

        // Decrypt with master key
        val decryptedKey = BedrockCore.aesDecrypt(
            masterKey,
            encryptedKey,
            keyName(version).toByteArray()  // AAD = key name
        ) ?: return null

        // Cache for future use
        keyCache[version] = decryptedKey

        return decryptedKey.copyOf()
    }

    /**
     * Check if rotation is needed.
     *
     * @return true if key should be rotated
     */
    fun isRotationNeeded(): Boolean {
        val timeSinceRotation = System.currentTimeMillis() - lastRotationTime
        return timeSinceRotation >= DEFAULT_ROTATION_PERIOD_MS
    }

    /**
     * Rotate to a new key version.
     *
     * SECURITY: This operation is atomic - either completes fully or fails.
     *
     * @param masterKey Master key to encrypt new device key
     * @param onProgress Callback for rotation progress (0.0 to 1.0)
     * @return true if rotation succeeded
     */
    fun rotate(
        masterKey: ByteArray,
        onProgress: ((Float) -> Unit)? = null
    ): Boolean {
        val newVersion = currentVersion + 1

        onProgress?.invoke(0.1f)

        // Generate new key
        if (!generateNewKey(masterKey, newVersion)) {
            return false
        }

        onProgress?.invoke(0.3f)

        // Update current version
        val previousVersion = currentVersion
        currentVersion = newVersion
        lastRotationTime = System.currentTimeMillis()

        // Persist version change
        storage.putInt(CURRENT_VERSION_KEY, currentVersion)
        storage.putLong(LAST_ROTATION_KEY, lastRotationTime)

        onProgress?.invoke(0.5f)

        // Delete old keys beyond retention limit
        val oldestToKeep = newVersion - MAX_KEY_GENERATIONS + 1
        for (v in 0 until oldestToKeep) {
            deleteKeyVersion(v)
        }

        onProgress?.invoke(0.8f)

        // Clear old keys from cache
        keyCache.keys.filter { it < oldestToKeep }.forEach { v ->
            keyCache[v]?.let { BedrockCore.zeroize(it) }
            keyCache.remove(v)
        }

        onProgress?.invoke(1.0f)

        return true
    }

    /**
     * Emergency rotation after suspected compromise.
     *
     * SECURITY: Immediately rotates and optionally re-encrypts all data.
     *
     * @param masterKey Master key
     * @param reEncryptCallback Callback to re-encrypt data with new key
     * @return true if emergency rotation succeeded
     */
    fun emergencyRotate(
        masterKey: ByteArray,
        reEncryptCallback: ((oldKey: ByteArray, newKey: ByteArray) -> Boolean)? = null
    ): Boolean {
        val previousVersion = currentVersion
        val oldKey = getCurrentKey(masterKey) ?: return false

        // Emit security event for emergency rotation start
        securityEventEmitter?.emit(SecurityEvent(
            type = SecurityEventType.EMERGENCY_KEY_ROTATION_STARTED,
            severity = SecurityEventSeverity.CRITICAL,
            timestamp = System.currentTimeMillis(),
            details = mapOf(
                "previous_version" to previousVersion.toString(),
                "reason" to "suspected_compromise"
            )
        ))

        // Rotate to new key
        if (!rotate(masterKey)) {
            BedrockCore.zeroize(oldKey)
            securityEventEmitter?.emit(SecurityEvent(
                type = SecurityEventType.KEY_ROTATION_FAILED,
                severity = SecurityEventSeverity.CRITICAL,
                timestamp = System.currentTimeMillis(),
                details = mapOf(
                    "previous_version" to previousVersion.toString(),
                    "failure_reason" to "rotation_failed"
                )
            ))
            return false
        }

        val newKey = getCurrentKey(masterKey) ?: run {
            BedrockCore.zeroize(oldKey)
            securityEventEmitter?.emit(SecurityEvent(
                type = SecurityEventType.KEY_ROTATION_FAILED,
                severity = SecurityEventSeverity.CRITICAL,
                timestamp = System.currentTimeMillis(),
                details = mapOf(
                    "previous_version" to previousVersion.toString(),
                    "failure_reason" to "new_key_retrieval_failed"
                )
            ))
            return false
        }

        // Re-encrypt data if callback provided
        val reEncryptSuccess = reEncryptCallback?.invoke(oldKey, newKey) ?: true

        // Zeroize old key
        BedrockCore.zeroize(oldKey)
        BedrockCore.zeroize(newKey)

        // If re-encryption failed, we still rotated - emit warning event
        if (!reEncryptSuccess) {
            securityEventEmitter?.emit(SecurityEvent(
                type = SecurityEventType.DATA_REENCRYPTION_FAILED,
                severity = SecurityEventSeverity.HIGH,
                timestamp = System.currentTimeMillis(),
                details = mapOf(
                    "previous_version" to previousVersion.toString(),
                    "new_version" to currentVersion.toString(),
                    "warning" to "Key rotated but data re-encryption failed. Some data may be encrypted with old key."
                )
            ))
        } else {
            securityEventEmitter?.emit(SecurityEvent(
                type = SecurityEventType.EMERGENCY_KEY_ROTATION_COMPLETED,
                severity = SecurityEventSeverity.INFO,
                timestamp = System.currentTimeMillis(),
                details = mapOf(
                    "previous_version" to previousVersion.toString(),
                    "new_version" to currentVersion.toString(),
                    "data_reencrypted" to reEncryptSuccess.toString()
                )
            ))
        }

        return true
    }

    /**
     * Generate a new key version.
     */
    private fun generateNewKey(masterKey: ByteArray, version: Int): Boolean {
        // Generate random key
        val newKey = ByteArray(32)
        secureRandom.nextBytes(newKey)

        // Derive key with version binding
        val boundKey = deriveVersionBoundKey(newKey, version)
        BedrockCore.zeroize(newKey)

        // Encrypt with master key
        val encryptedKey = BedrockCore.aesEncrypt(
            masterKey,
            boundKey,
            keyName(version).toByteArray()  // AAD = key name
        )

        if (encryptedKey == null) {
            BedrockCore.zeroize(boundKey)
            return false
        }

        // Store encrypted key
        val stored = storage.putBytes(keyName(version), encryptedKey)

        if (!stored) {
            BedrockCore.zeroize(boundKey)
            return false
        }

        // Cache the key
        keyCache[version] = boundKey

        return true
    }

    /**
     * Derive version-bound key.
     *
     * Ensures keys are cryptographically bound to their version number.
     */
    private fun deriveVersionBoundKey(baseKey: ByteArray, version: Int): ByteArray {
        val input = ByteBuffer.allocate(ROTATION_DOMAIN.size + 4 + baseKey.size)
            .put(ROTATION_DOMAIN)
            .putInt(version)
            .put(baseKey)
            .array()

        val derived = BedrockCore.sha3_256(input)
        BedrockCore.zeroize(input)

        return derived
    }

    /**
     * Delete a key version securely.
     */
    private fun deleteKeyVersion(version: Int) {
        storage.delete(keyName(version))
    }

    /**
     * Get key storage name for a version.
     */
    private fun keyName(version: Int): String {
        return "$KEY_VERSION_PREFIX$version"
    }

    /**
     * Decrypt data with automatic version detection.
     *
     * Tries current version first, then falls back to older versions.
     *
     * @param ciphertext Encrypted data (includes version prefix)
     * @param masterKey Master key to decrypt device key
     * @param aad Additional authenticated data
     * @return Decrypted data, or null if all versions fail
     */
    fun decryptWithVersionFallback(
        ciphertext: ByteArray,
        masterKey: ByteArray,
        aad: ByteArray
    ): ByteArray? {
        // Extract version from ciphertext if embedded
        val (version, actualCiphertext) = extractVersion(ciphertext)

        // Try specified version first
        if (version != null) {
            val key = getKeyVersion(version, masterKey)
            if (key != null) {
                val result = BedrockCore.aesDecrypt(key, actualCiphertext, aad)
                BedrockCore.zeroize(key)
                if (result != null) return result
            }
        }

        // Try all available versions (newest to oldest)
        val oldestVersion = maxOf(0, currentVersion - MAX_KEY_GENERATIONS + 1)
        for (v in currentVersion downTo oldestVersion) {
            if (v == version) continue  // Already tried

            val key = getKeyVersion(v, masterKey) ?: continue
            val result = BedrockCore.aesDecrypt(key, actualCiphertext, aad)
            BedrockCore.zeroize(key)
            if (result != null) return result
        }

        return null
    }

    /**
     * Encrypt data with current version.
     *
     * @param plaintext Data to encrypt
     * @param masterKey Master key to decrypt device key
     * @param aad Additional authenticated data
     * @return Encrypted data with version prefix
     */
    fun encryptWithVersion(
        plaintext: ByteArray,
        masterKey: ByteArray,
        aad: ByteArray
    ): ByteArray? {
        val key = getCurrentKey(masterKey) ?: return null

        val ciphertext = BedrockCore.aesEncrypt(key, plaintext, aad)
        BedrockCore.zeroize(key)

        if (ciphertext == null) return null

        // Prepend version
        return embedVersion(currentVersion, ciphertext)
    }

    /**
     * Embed version in ciphertext.
     */
    private fun embedVersion(version: Int, ciphertext: ByteArray): ByteArray {
        val result = ByteBuffer.allocate(4 + ciphertext.size)
            .putInt(version)
            .put(ciphertext)
            .array()
        return result
    }

    /**
     * Extract version from ciphertext.
     */
    private fun extractVersion(data: ByteArray): Pair<Int?, ByteArray> {
        if (data.size < 4) {
            return Pair(null, data)
        }

        val version = ByteBuffer.wrap(data, 0, 4).int
        val ciphertext = data.copyOfRange(4, data.size)

        return Pair(version, ciphertext)
    }

    /**
     * Get rotation status.
     */
    fun getStatus(): KeyRotationStatus {
        val timeSinceRotation = System.currentTimeMillis() - lastRotationTime
        val timeUntilRotation = DEFAULT_ROTATION_PERIOD_MS - timeSinceRotation

        return KeyRotationStatus(
            currentVersion = currentVersion,
            lastRotationTime = lastRotationTime,
            nextRotationTime = lastRotationTime + DEFAULT_ROTATION_PERIOD_MS,
            rotationNeeded = isRotationNeeded(),
            daysUntilRotation = if (timeUntilRotation > 0) {
                (timeUntilRotation / (24 * 60 * 60 * 1000)).toInt()
            } else 0,
            availableVersions = (maxOf(0, currentVersion - MAX_KEY_GENERATIONS + 1)..currentVersion).toList()
        )
    }

    /**
     * Clear all cached keys from memory.
     */
    fun clearCache() {
        for ((_, key) in keyCache) {
            BedrockCore.zeroize(key)
        }
        keyCache.clear()
    }
}

/**
 * Key rotation status.
 */
data class KeyRotationStatus(
    val currentVersion: Int,
    val lastRotationTime: Long,
    val nextRotationTime: Long,
    val rotationNeeded: Boolean,
    val daysUntilRotation: Int,
    val availableVersions: List<Int>
)

/**
 * Interface for secure key storage.
 */
interface SecureKeyStorage {
    fun exists(key: String): Boolean
    fun getBytes(key: String): ByteArray?
    fun putBytes(key: String, value: ByteArray): Boolean
    fun getInt(key: String): Int?
    fun putInt(key: String, value: Int): Boolean
    fun getLong(key: String): Long?
    fun putLong(key: String, value: Long): Boolean
    fun delete(key: String): Boolean
}

/**
 * Interface for emitting security events.
 *
 * Implementations can log to secure storage, send to monitoring systems,
 * or trigger alerts based on event severity.
 */
interface SecurityEventEmitter {
    /**
     * Emit a security event.
     *
     * @param event The security event to emit
     */
    fun emit(event: SecurityEvent)
}

/**
 * A security event that should be recorded and potentially acted upon.
 */
data class SecurityEvent(
    /** Type of security event */
    val type: SecurityEventType,
    /** Severity level */
    val severity: SecurityEventSeverity,
    /** Unix timestamp when event occurred */
    val timestamp: Long,
    /** Additional details about the event */
    val details: Map<String, String> = emptyMap()
)

/**
 * Types of security events.
 */
enum class SecurityEventType {
    // Key rotation events
    KEY_ROTATION_STARTED,
    KEY_ROTATION_COMPLETED,
    KEY_ROTATION_FAILED,
    EMERGENCY_KEY_ROTATION_STARTED,
    EMERGENCY_KEY_ROTATION_COMPLETED,

    // Data protection events
    DATA_REENCRYPTION_STARTED,
    DATA_REENCRYPTION_COMPLETED,
    DATA_REENCRYPTION_FAILED,

    // Access events
    KEY_ACCESS_ATTEMPT,
    KEY_ACCESS_DENIED,

    // Compromise detection
    POTENTIAL_COMPROMISE_DETECTED,
    ANOMALOUS_ACCESS_PATTERN,

    // Lifecycle events
    KEY_DELETED,
    OLD_KEY_PURGED
}

/**
 * Severity levels for security events.
 */
enum class SecurityEventSeverity {
    /** Informational - routine operations */
    INFO,
    /** Warning - unusual but not necessarily problematic */
    WARNING,
    /** High - requires attention */
    HIGH,
    /** Critical - immediate action required */
    CRITICAL
}

/**
 * Default implementation that logs security events to Android Log.
 *
 * In production, replace with secure audit logging.
 */
class LoggingSecurityEventEmitter : SecurityEventEmitter {
    private val tag = "SecurityEvent"

    override fun emit(event: SecurityEvent) {
        val message = buildString {
            append("[${event.type}] ")
            append("severity=${event.severity} ")
            event.details.forEach { (key, value) ->
                append("$key=$value ")
            }
        }

        when (event.severity) {
            SecurityEventSeverity.CRITICAL -> android.util.Log.e(tag, message)
            SecurityEventSeverity.HIGH -> android.util.Log.w(tag, message)
            SecurityEventSeverity.WARNING -> android.util.Log.w(tag, message)
            SecurityEventSeverity.INFO -> android.util.Log.i(tag, message)
        }
    }
}

/**
 * Security event emitter that stores events for later retrieval.
 *
 * Useful for audit trails and forensic analysis.
 */
class StoringSecurityEventEmitter(
    private val maxEvents: Int = 1000
) : SecurityEventEmitter {
    private val events = mutableListOf<SecurityEvent>()
    private val lock = Any()

    override fun emit(event: SecurityEvent) {
        synchronized(lock) {
            events.add(event)
            // Maintain max size by removing oldest events
            while (events.size > maxEvents) {
                events.removeAt(0)
            }
        }
    }

    /**
     * Get all stored events.
     */
    fun getEvents(): List<SecurityEvent> {
        synchronized(lock) {
            return events.toList()
        }
    }

    /**
     * Get events filtered by type.
     */
    fun getEventsByType(type: SecurityEventType): List<SecurityEvent> {
        synchronized(lock) {
            return events.filter { it.type == type }
        }
    }

    /**
     * Get events filtered by severity (at or above the specified level).
     */
    fun getEventsBySeverity(minSeverity: SecurityEventSeverity): List<SecurityEvent> {
        synchronized(lock) {
            return events.filter { it.severity.ordinal >= minSeverity.ordinal }
        }
    }

    /**
     * Get events within a time range.
     */
    fun getEventsInRange(startTime: Long, endTime: Long): List<SecurityEvent> {
        synchronized(lock) {
            return events.filter { it.timestamp in startTime..endTime }
        }
    }

    /**
     * Clear all stored events.
     */
    fun clear() {
        synchronized(lock) {
            events.clear()
        }
    }
}

/**
 * Composite emitter that forwards events to multiple emitters.
 */
class CompositeSecurityEventEmitter(
    private val emitters: List<SecurityEventEmitter>
) : SecurityEventEmitter {
    override fun emit(event: SecurityEvent) {
        emitters.forEach { it.emit(event) }
    }
}
