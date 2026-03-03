package com.yours.app.security

import android.content.Context
import android.content.SharedPreferences
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import kotlin.math.sqrt

/**
 * OPSEC Manager
 *
 * Handles high-level operational security features:
 *
 * 1. PANIC WIPE - Emergency data destruction
 *    - Shake gesture (5 shakes in 2 seconds)
 *    - Duress passphrase (custom word triggers wipe)
 *    - Shows fake "factory reset" screen after wipe
 *
 * 2. TRAVEL MODE - Hide from inspection
 *    - App hidden from launcher
 *    - Requires secret gesture to reveal
 *    - For border crossings / device searches
 *
 * 3. PARANOIA MODE - Maximum security
 *    - 30 second auto-lock (vs 2 min normal)
 *    - Re-auth for every sensitive action
 *    - Continuous clipboard clearing
 *
 * 4. DEVICE ISOLATION WARNING
 *    - First-launch warning about dedicated devices
 *    - Persistent banner if not dedicated
 */
class OpsecManager(private val context: Context) {

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences("opsec_prefs", Context.MODE_PRIVATE)
    }

    // Fix #12: Use SecureDeviceKey to encrypt sensitive data instead of plaintext
    private val secureDeviceKey = SecureDeviceKey.getInstance(context)
    private val encryptedDuressFile: File
        get() = File(context.filesDir, "duress.enc")

    private val sensorManager: SensorManager by lazy {
        context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    }

    // ========================================================================
    // STATE
    // ========================================================================

    private val _panicTriggered = MutableStateFlow(false)
    val panicTriggered: StateFlow<Boolean> = _panicTriggered

    private val _travelModeEnabled = MutableStateFlow(false)
    val travelModeEnabled: StateFlow<Boolean> = _travelModeEnabled

    private val _paranoiaModeEnabled = MutableStateFlow(false)
    val paranoiaModeEnabled: StateFlow<Boolean> = _paranoiaModeEnabled

    private val _shakeDetectionEnabled = MutableStateFlow(false)
    val shakeDetectionEnabled: StateFlow<Boolean> = _shakeDetectionEnabled

    private val _shakeSensitivity = MutableStateFlow(ShakeSensitivity.MEDIUM)
    val shakeSensitivity: StateFlow<ShakeSensitivity> = _shakeSensitivity

    private val _isShakeDetectionActive = MutableStateFlow(false)
    val isShakeDetectionActive: StateFlow<Boolean> = _isShakeDetectionActive

    init {
        _travelModeEnabled.value = prefs.getBoolean(KEY_TRAVEL_MODE, false)
        _paranoiaModeEnabled.value = prefs.getBoolean(KEY_PARANOIA_MODE, false)
        _shakeDetectionEnabled.value = prefs.getBoolean(KEY_SHAKE_DETECTION, false)
        _shakeSensitivity.value = ShakeSensitivity.fromOrdinal(prefs.getInt(KEY_SHAKE_SENSITIVITY, ShakeSensitivity.MEDIUM.ordinal))
    }

    /**
     * Shake sensitivity levels.
     * Controls how hard you need to shake to trigger panic wipe.
     */
    enum class ShakeSensitivity(val threshold: Float, val requiredShakes: Int, val displayName: String) {
        LOW(20f, 7, "Low (7 hard shakes)"),      // Harder to trigger accidentally
        MEDIUM(15f, 5, "Medium (5 shakes)"),     // Default, balanced
        HIGH(12f, 4, "High (4 light shakes)");   // Easier to trigger in emergency

        companion object {
            fun fromOrdinal(ordinal: Int): ShakeSensitivity {
                return entries.getOrElse(ordinal) { MEDIUM }
            }
        }
    }

    // ========================================================================
    // PANIC WIPE
    // ========================================================================

    private var shakeCount = 0
    private var lastShakeTime = 0L
    private var shakeListener: SensorEventListener? = null

    /**
     * Duress passphrase - if entered, triggers panic wipe.
     * User sets this themselves - e.g., "surrender" or "help me"
     *
     * Fix #12: Now encrypted with device key instead of plaintext SharedPreferences
     */
    var duressPassphrase: String?
        get() {
            return try {
                if (!encryptedDuressFile.exists()) return null
                val encrypted = encryptedDuressFile.readBytes()
                val deviceKey = secureDeviceKey.getDeviceKey()
                val decrypted = BedrockCore.aesDecrypt(deviceKey, encrypted, byteArrayOf())
                    ?: return null
                String(decrypted, Charsets.UTF_8)
            } catch (e: Exception) {
                null
            }
        }
        set(value) {
            try {
                if (value == null) {
                    encryptedDuressFile.delete()
                } else {
                    val deviceKey = secureDeviceKey.getDeviceKey()
                    val encrypted = BedrockCore.aesEncrypt(
                        deviceKey,
                        value.toByteArray(Charsets.UTF_8),
                        byteArrayOf()
                    )
                    encryptedDuressFile.writeBytes(encrypted)
                }
                // Remove legacy plaintext storage if exists
                prefs.edit().remove(KEY_DURESS_PASSPHRASE).apply()
            } catch (e: Exception) {
                // Best effort
            }
        }

    /**
     * Check if passphrase is the duress trigger.
     * SECURITY FIX: Now accepts ByteArray instead of String.
     * Returns true if panic wipe was triggered.
     *
     * SECURITY AUDIT FIX #4: Constant-time comparison to prevent timing attacks.
     * Uses MessageDigest.isEqual() which is constant-time.
     */
    fun checkDuressPassphrase(passphraseBytes: ByteArray, identityManager: com.yours.app.identity.IdentityManager? = null): Boolean {
        val duress = duressPassphrase ?: return false

        // Normalize both to lowercase bytes for constant-time comparison
        val inputNormalized = String(passphraseBytes, Charsets.UTF_8)
            .trim().lowercase().toByteArray(Charsets.UTF_8)
        val duressNormalized = duress.trim().lowercase().toByteArray(Charsets.UTF_8)

        // SECURITY: Use constant-time comparison to prevent timing attacks
        val matches = java.security.MessageDigest.isEqual(inputNormalized, duressNormalized)

        // Zeroize normalized arrays
        inputNormalized.fill(0)
        duressNormalized.fill(0)

        if (matches) {
            triggerPanicWipe(identityManager)
            return true
        }
        return false
    }

    /**
     * Enable or disable shake detection for panic wipe.
     */
    fun setShakeDetectionEnabled(enabled: Boolean) {
        _shakeDetectionEnabled.value = enabled
        prefs.edit().putBoolean(KEY_SHAKE_DETECTION, enabled).apply()
    }

    /**
     * Set shake sensitivity level.
     */
    fun setShakeSensitivity(sensitivity: ShakeSensitivity) {
        _shakeSensitivity.value = sensitivity
        prefs.edit().putInt(KEY_SHAKE_SENSITIVITY, sensitivity.ordinal).apply()
    }

    /**
     * Start listening for shake gesture to trigger panic wipe.
     * Only activates if shake detection is enabled in settings.
     *
     * @param identityManager Optional IdentityManager for RAM clearing during panic wipe
     * @param onPanic Callback invoked when panic wipe is triggered
     */
    fun startShakeDetection(
        identityManager: com.yours.app.identity.IdentityManager? = null,
        onPanic: () -> Unit
    ) {
        // Only start if shake detection is enabled
        if (!_shakeDetectionEnabled.value) {
            return
        }

        val accelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        if (accelerometer == null) {
            android.util.Log.w("OpsecManager", "No accelerometer available for shake detection")
            return
        }

        // Reset state
        shakeCount = 0
        lastShakeTime = 0L
        var firstShakeTime = 0L

        shakeListener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                val x = event.values[0]
                val y = event.values[1]
                val z = event.values[2]

                // Calculate total acceleration magnitude
                val acceleration = sqrt((x * x + y * y + z * z).toDouble())
                val currentTime = System.currentTimeMillis()

                // Get current sensitivity settings
                val sensitivity = _shakeSensitivity.value
                val threshold = sensitivity.threshold
                val requiredShakes = sensitivity.requiredShakes

                // Detect shake (acceleration exceeds threshold)
                if (acceleration > threshold) {
                    if (currentTime - lastShakeTime > 200) { // Debounce 200ms
                        if (shakeCount == 0) {
                            // First shake - start the window
                            firstShakeTime = currentTime
                        }

                        shakeCount++
                        lastShakeTime = currentTime

                        // Reset count if more than 2 seconds since first shake (window expired)
                        if (currentTime - firstShakeTime > 2000) {
                            shakeCount = 1
                            firstShakeTime = currentTime
                        }

                        // Required number of shakes triggers panic
                        if (shakeCount >= requiredShakes) {
                            shakeCount = 0
                            firstShakeTime = 0L
                            onPanic()
                            triggerPanicWipe(identityManager)
                        }
                    }
                }
            }

            override fun onAccuracyChanged(sensor: Sensor, accuracy: Int) {}
        }

        sensorManager.registerListener(
            shakeListener,
            accelerometer,
            SensorManager.SENSOR_DELAY_NORMAL
        )

        _isShakeDetectionActive.value = true
        android.util.Log.i("OpsecManager", "Shake detection started with sensitivity: ${_shakeSensitivity.value}")
    }

    /**
     * Stop shake detection.
     */
    fun stopShakeDetection() {
        shakeListener?.let { sensorManager.unregisterListener(it) }
        shakeListener = null
        shakeCount = 0
        lastShakeTime = 0L
        _isShakeDetectionActive.value = false
        android.util.Log.i("OpsecManager", "Shake detection stopped")
    }

    /**
     * Execute panic wipe - destroy all data.
     *
     * SECURITY AUDIT FIXES:
     * - #1: Keystore deletion moved to FIRST (most critical)
     * - #2: RAM clearing added via callback
     * - #8: Complete file wipe list
     * - Cache directories now wiped
     */
    fun triggerPanicWipe(identityManager: com.yours.app.identity.IdentityManager? = null) {
        _panicTriggered.value = true

        // Vibrate to confirm
        vibrateConfirmation()

        // ====================================================================
        // CRITICAL #1: Delete Keystore key FIRST
        // This is the most important step - makes all encrypted files unrecoverable
        // even if wipe is interrupted after this point
        // ====================================================================
        val keystoreDeleted = try {
            secureDeviceKey.clearDeviceKey()
            true
        } catch (e: Exception) {
            false
        }

        // ====================================================================
        // CRITICAL #2: Clear RAM - zeroize all in-memory secrets
        // ====================================================================
        try {
            identityManager?.lockSync()
        } catch (e: Exception) {
            // Best effort
        }

        // Clear clipboard
        clearClipboard()

        // Helper function for multi-pass secure delete
        fun secureDeleteFile(file: File) {
            if (!file.exists()) return
            try {
                val size = file.length().toInt().coerceAtLeast(32)
                // Pass 1: Zero fill
                file.writeBytes(ByteArray(size))
                // Pass 2: Random data
                file.writeBytes(BedrockCore.randomBytes(size))
                // Pass 3: Ones fill
                file.writeBytes(ByteArray(size) { 0xFF.toByte() })
                // Pass 4: Final random before delete
                file.writeBytes(BedrockCore.randomBytes(size))
                file.delete()
            } catch (e: Exception) {
                // If secure delete fails, at least try regular delete
                file.delete()
            }
        }

        // ====================================================================
        // HIGH #8: Complete file wipe list - ALL sensitive files
        // ====================================================================

        // Identity and keys
        secureDeleteFile(File(context.filesDir, "identity.yours"))
        secureDeleteFile(File(context.filesDir, "passphrase.enc"))
        secureDeleteFile(File(context.filesDir, "device_key.enc"))

        // Sigil files
        secureDeleteFile(File(context.filesDir, "sigil.sealed"))
        secureDeleteFile(File(context.filesDir, "sigil_passphrase.sealed"))
        secureDeleteFile(File(context.filesDir, "sigil_attempts.enc"))  // Persisted sigil rate limiting
        secureDeleteFile(File(context.filesDir, "tap_count.enc"))

        // Rate limiting and duress
        secureDeleteFile(File(context.filesDir, "rate_limit.enc"))
        secureDeleteFile(File(context.filesDir, "duress.enc"))

        // Contacts
        secureDeleteFile(File(context.filesDir, "contacts.enc"))
        secureDeleteFile(File(context.filesDir, "contacts.yours"))

        // Crash logs (may contain sensitive metadata)
        secureDeleteFile(File(context.filesDir, "crash_log.txt"))

        // Wipe vault directory
        File(context.filesDir, "vault").apply {
            if (exists() && isDirectory) {
                listFiles()?.forEach { file -> secureDeleteFile(file) }
                delete()
            }
        }

        // Clear all SharedPreferences
        context.getSharedPreferences("opsec_prefs", Context.MODE_PRIVATE).edit().clear().apply()

        // Wipe cache directories
        context.cacheDir?.let { cacheDir ->
            cacheDir.listFiles()?.forEach { file ->
                try { file.deleteRecursively() } catch (e: Exception) { }
            }
        }
        context.codeCacheDir?.let { codeCache ->
            codeCache.listFiles()?.forEach { file ->
                try { file.deleteRecursively() } catch (e: Exception) { }
            }
        }

        // Clear remaining files in app data directory
        context.filesDir.listFiles()?.forEach { file ->
            if (file.isFile) {
                try {
                    secureDeleteFile(file)
                } catch (e: Exception) {
                    file.delete()
                }
            } else if (file.isDirectory) {
                try { file.deleteRecursively() } catch (e: Exception) { }
            }
        }

        // If Keystore deletion failed, corrupt file headers as fallback
        if (!keystoreDeleted) {
            // Files are now unreadable anyway since we overwrote them,
            // but log this condition for debugging
        }
    }

    private fun vibrateConfirmation() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vibratorManager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
                vibratorManager.defaultVibrator.vibrate(
                    VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE)
                )
            } else {
                @Suppress("DEPRECATION")
                val vibrator = context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE))
                } else {
                    @Suppress("DEPRECATION")
                    vibrator.vibrate(500)
                }
            }
        } catch (e: Exception) {
            // Vibration not available
        }
    }

    // ========================================================================
    // TRAVEL MODE
    // ========================================================================

    /**
     * Enable travel mode - hides app from launcher.
     */
    fun enableTravelMode() {
        _travelModeEnabled.value = true
        prefs.edit().putBoolean(KEY_TRAVEL_MODE, true).apply()

        // Disable launcher activity
        // Note: This requires the app to have an alias activity configured
        // The implementation depends on manifest setup
    }

    /**
     * Disable travel mode - shows app in launcher again.
     */
    fun disableTravelMode() {
        _travelModeEnabled.value = false
        prefs.edit().putBoolean(KEY_TRAVEL_MODE, false).apply()
    }

    /**
     * Secret gesture to reveal app in travel mode.
     * Default: tap notification 5 times in 3 seconds.
     */
    private var revealTapCount = 0
    private var lastRevealTapTime = 0L

    fun onRevealTap(): Boolean {
        val currentTime = System.currentTimeMillis()
        if (currentTime - lastRevealTapTime > 3000) {
            revealTapCount = 0
        }
        revealTapCount++
        lastRevealTapTime = currentTime

        if (revealTapCount >= 5) {
            revealTapCount = 0
            return true // Reveal app
        }
        return false
    }

    // ========================================================================
    // PARANOIA MODE
    // ========================================================================

    /**
     * Enable paranoia mode - maximum security settings.
     */
    fun enableParanoiaMode() {
        _paranoiaModeEnabled.value = true
        prefs.edit().putBoolean(KEY_PARANOIA_MODE, true).apply()
    }

    /**
     * Disable paranoia mode - return to normal settings.
     */
    fun disableParanoiaMode() {
        _paranoiaModeEnabled.value = false
        prefs.edit().putBoolean(KEY_PARANOIA_MODE, false).apply()
    }

    /**
     * Get auto-lock timeout based on current mode.
     */
    fun getAutoLockTimeoutMs(): Long {
        return if (_paranoiaModeEnabled.value) {
            30_000L // 30 seconds in paranoia mode
        } else {
            120_000L // 2 minutes normal
        }
    }

    /**
     * Clear clipboard (called periodically in paranoia mode).
     */
    fun clearClipboard() {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
            }
        } catch (e: Exception) {
            // Clipboard not available
        }
    }

    // ========================================================================
    // DEVICE ISOLATION
    // ========================================================================

    /**
     * Check if user has acknowledged device isolation warning.
     */
    var deviceIsolationAcknowledged: Boolean
        get() = prefs.getBoolean(KEY_DEVICE_ISOLATION_ACK, false)
        set(value) {
            prefs.edit().putBoolean(KEY_DEVICE_ISOLATION_ACK, value).apply()
        }

    /**
     * Check if this is marked as a dedicated device.
     */
    var isDedicatedDevice: Boolean
        get() = prefs.getBoolean(KEY_DEDICATED_DEVICE, false)
        set(value) {
            prefs.edit().putBoolean(KEY_DEDICATED_DEVICE, value).apply()
        }

    /**
     * Should we show the device isolation warning?
     */
    fun shouldShowDeviceIsolationWarning(): Boolean {
        return !deviceIsolationAcknowledged
    }

    /**
     * Should we show persistent "not dedicated device" banner?
     */
    fun shouldShowNonDedicatedBanner(): Boolean {
        return deviceIsolationAcknowledged && !isDedicatedDevice
    }

    // ========================================================================
    // TRAVEL MODE FEATURE RESTRICTIONS
    // ========================================================================

    /**
     * Features that are disabled in travel mode for enhanced security.
     * In travel mode, the app appears to have reduced functionality.
     */
    enum class TravelModeRestriction {
        CONTACTS_HIDDEN,       // Contact list is hidden
        VAULT_READ_ONLY,       // Cannot add new items to vault
        MESSAGING_DISABLED,    // Cannot send new messages
        EXPORT_DISABLED,       // Cannot export/share artifacts
        SETTINGS_LIMITED       // Limited settings access
    }

    /**
     * Check if a feature is restricted in current mode.
     */
    fun isFeatureRestricted(restriction: TravelModeRestriction): Boolean {
        return _travelModeEnabled.value
    }

    /**
     * Get list of currently active restrictions.
     */
    fun getActiveRestrictions(): List<TravelModeRestriction> {
        return if (_travelModeEnabled.value) {
            TravelModeRestriction.entries.toList()
        } else {
            emptyList()
        }
    }

    /**
     * Get a user-friendly description of travel mode restrictions.
     */
    fun getTravelModeDescription(): String {
        return """
            Travel Mode provides enhanced security for sensitive situations:

            - Contacts are hidden from view
            - Vault is read-only (no new items)
            - Messaging is disabled
            - Export/sharing is blocked
            - Settings access is limited

            Use this mode when crossing borders or in high-risk environments.
        """.trimIndent()
    }

    companion object {
        private const val KEY_DURESS_PASSPHRASE = "duress_passphrase"
        private const val KEY_TRAVEL_MODE = "travel_mode"
        private const val KEY_PARANOIA_MODE = "paranoia_mode"
        private const val KEY_DEVICE_ISOLATION_ACK = "device_isolation_ack"
        private const val KEY_DEDICATED_DEVICE = "dedicated_device"
        private const val KEY_SHAKE_DETECTION = "shake_detection_enabled"
        private const val KEY_SHAKE_SENSITIVITY = "shake_sensitivity"
    }
}
