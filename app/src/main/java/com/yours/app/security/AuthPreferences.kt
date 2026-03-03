package com.yours.app.security

import android.content.Context
import android.content.SharedPreferences

/**
 * Authentication method preferences manager.
 *
 * Stores user's chosen authentication method:
 * - SIGIL: Traditional 6x6 grid pattern (SigilManager)
 * - CONSTELLATION: Enhanced 7x5 constellation with timing/pressure (HumanCentricAuth)
 *
 * Uses standard SharedPreferences with MODE_PRIVATE for storage.
 * App-level encryption is handled by the Rust crypto layer (BedrockCore).
 */
class AuthPreferences private constructor(context: Context) {

    companion object {
        private const val PREFS_NAME = "auth_preferences"
        private const val KEY_AUTH_METHOD = "auth_method"
        private const val KEY_CONSTELLATION_SETUP = "constellation_setup_complete"
        private const val KEY_SIGIL_SETUP = "sigil_setup_complete"

        @Volatile
        private var instance: AuthPreferences? = null
        private val lock = Any()

        /**
         * Get singleton instance (thread-safe).
         */
        fun getInstance(context: Context): AuthPreferences {
            return instance ?: synchronized(lock) {
                instance ?: AuthPreferences(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Available authentication methods.
     */
    enum class AuthMethod {
        /** Traditional 6x6 grid pattern - simpler, faster */
        SIGIL,
        /** Enhanced 7x5 constellation with timing/pressure - more secure */
        CONSTELLATION
    }

    private val prefs: SharedPreferences by lazy {
        // Using standard SharedPreferences with MODE_PRIVATE
        // App-level encryption handled by Rust crypto layer (BedrockCore)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Get the currently configured authentication method.
     * Defaults to SIGIL for backwards compatibility.
     */
    var authMethod: AuthMethod
        get() {
            val methodStr = prefs.getString(KEY_AUTH_METHOD, AuthMethod.SIGIL.name)
            return try {
                AuthMethod.valueOf(methodStr ?: AuthMethod.SIGIL.name)
            } catch (e: IllegalArgumentException) {
                AuthMethod.SIGIL
            }
        }
        set(value) {
            prefs.edit().putString(KEY_AUTH_METHOD, value.name).apply()
        }

    /**
     * Check if constellation auth has been set up.
     */
    var isConstellationSetup: Boolean
        get() = prefs.getBoolean(KEY_CONSTELLATION_SETUP, false)
        set(value) = prefs.edit().putBoolean(KEY_CONSTELLATION_SETUP, value).apply()

    /**
     * Check if sigil auth has been set up.
     */
    var isSigilSetup: Boolean
        get() = prefs.getBoolean(KEY_SIGIL_SETUP, false)
        set(value) = prefs.edit().putBoolean(KEY_SIGIL_SETUP, value).apply()

    /**
     * Check if the current auth method is set up and ready to use.
     */
    fun isCurrentMethodSetup(): Boolean {
        return when (authMethod) {
            AuthMethod.SIGIL -> isSigilSetup
            AuthMethod.CONSTELLATION -> isConstellationSetup
        }
    }

    /**
     * Check if any auth method is set up.
     */
    fun hasAnyAuthSetup(): Boolean = isSigilSetup || isConstellationSetup

    /**
     * Get display name for an auth method.
     */
    fun getDisplayName(method: AuthMethod): String {
        return when (method) {
            AuthMethod.SIGIL -> "Pattern Sigil"
            AuthMethod.CONSTELLATION -> "Enhanced Security"
        }
    }

    /**
     * Get description for an auth method.
     */
    fun getDescription(method: AuthMethod): String {
        return when (method) {
            AuthMethod.SIGIL -> "Traditional 6x6 grid pattern. Fast and familiar."
            AuthMethod.CONSTELLATION -> "7x5 constellation with timing & pressure. Enhanced security using spatial, motor, and temporal memory."
        }
    }

    /**
     * Get security info for an auth method.
     */
    fun getSecurityInfo(method: AuthMethod): String {
        return when (method) {
            AuthMethod.SIGIL -> "~61 bits entropy from pattern"
            AuthMethod.CONSTELLATION -> "~61-80 bits entropy from pattern + timing + pressure"
        }
    }

    /**
     * Clear all auth preferences (used during identity reset).
     */
    fun clearAll() {
        prefs.edit().clear().apply()
    }
}
