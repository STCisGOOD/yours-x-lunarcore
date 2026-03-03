package com.yours.app.security

import android.content.Context
import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.IdentityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Unified Authentication Manager
 *
 * Coordinates between SigilManager (simple pattern) and HumanCentricAuth (constellation)
 * to ensure both methods can unlock the vault using the same underlying master key.
 *
 * SECURITY MODEL:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  User authenticates with EITHER:                                        │
 * │  ├─ Pattern Sigil (6x6 grid) -> retrieves encrypted passphrase          │
 * │  ├─ Constellation (7x5 grid) -> retrieves master key directly           │
 * │  └─ Passphrase (8 words) -> derives master key via Argon2id             │
 * │                                                                         │
 * │  All paths lead to the SAME master key for vault decryption             │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * When setting up constellation auth:
 * 1. User enters their passphrase to verify identity
 * 2. Master key is derived from passphrase (same as SigilManager)
 * 3. Constellation pattern is set up with HumanCentricAuth
 * 4. Master key (not passphrase) is encrypted with constellation-derived key
 *
 * This allows constellation auth to return the master key directly,
 * which is compatible with the existing vault unlock flow.
 */
class UnifiedAuthManager(private val context: Context) {

    private val sigilManager = SigilManager(context)
    private val humanCentricAuth = HumanCentricAuth(context)
    private val authPreferences = AuthPreferences.getInstance(context)
    private val secureDeviceKey = SecureDeviceKey.getInstance(context)

    // File for storing master key encrypted with constellation
    private val constellationMasterKeyFile: java.io.File
        get() = java.io.File(context.filesDir, "constellation_master.enc")

    /**
     * Get the currently active authentication method.
     */
    val activeMethod: AuthPreferences.AuthMethod
        get() = authPreferences.authMethod

    /**
     * Check if the active auth method is set up.
     */
    fun isActiveMethodSetup(): Boolean {
        return when (authPreferences.authMethod) {
            AuthPreferences.AuthMethod.SIGIL -> sigilManager.hasSigil()
            AuthPreferences.AuthMethod.CONSTELLATION -> authPreferences.isConstellationSetup
        }
    }

    /**
     * Check if sigil auth is available.
     */
    fun hasSigil(): Boolean = sigilManager.hasSigil()

    /**
     * Check if constellation auth is available.
     */
    fun hasConstellation(): Boolean = authPreferences.isConstellationSetup

    /**
     * Get the SigilManager for direct access.
     */
    fun getSigilManager(): SigilManager = sigilManager

    /**
     * Get the HumanCentricAuth for direct access.
     */
    fun getHumanCentricAuth(): HumanCentricAuth = humanCentricAuth

    /**
     * Set up constellation auth using the existing passphrase.
     *
     * This requires:
     * 1. The passphrase to derive the master key
     * 2. A constellation pattern from the user
     *
     * The master key is then encrypted with the constellation-derived key,
     * allowing future unlocks with just the constellation pattern.
     *
     * @param passphraseBytes The passphrase as bytes (for master key derivation)
     * @param pattern The constellation pattern to use
     * @param identityManager The identity manager to derive the master key
     * @return true if setup was successful
     */
    suspend fun setupConstellationAuth(
        passphraseBytes: ByteArray,
        pattern: HumanCentricAuth.ConstellationPattern,
        identityManager: IdentityManager
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // Verify the passphrase is correct by attempting unlock
            val unlockResult = identityManager.unlock(passphraseBytes.copyOf())
            if (unlockResult !is IdentityManager.UnlockResult.Success) {
                return@withContext false
            }

            // Get the master key from identity manager
            val masterKey = identityManager.getMasterKey()

            // Set up constellation auth (this creates its own recovery phrase internally)
            val setupResult = humanCentricAuth.setup(pattern)

            // Store the vault master key encrypted with constellation-derived key
            // This allows constellation unlock to return the vault master key
            val constellationMasterKey = humanCentricAuth.unlock(pattern)
                ?: return@withContext false

            // Encrypt the vault master key with the constellation's derived key
            val encryptedVaultKey = BedrockCore.aesEncrypt(
                key = constellationMasterKey,
                plaintext = masterKey,
                associatedData = "vault-master-key".toByteArray()
            )

            // Store the encrypted vault master key
            constellationMasterKeyFile.writeBytes(encryptedVaultKey)

            // Zeroize sensitive data
            BedrockCore.zeroize(constellationMasterKey)

            // Mark constellation as set up
            authPreferences.isConstellationSetup = true

            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Unlock using constellation pattern.
     *
     * Returns the vault master key for use with IdentityManager.
     *
     * @param pattern The constellation pattern
     * @return The vault master key, or null if unlock failed
     */
    suspend fun unlockWithConstellation(
        pattern: HumanCentricAuth.ConstellationPattern
    ): ByteArray? = withContext(Dispatchers.IO) {
        try {
            if (!constellationMasterKeyFile.exists()) {
                return@withContext null
            }

            // Unlock constellation auth to get its master key
            val constellationMasterKey = humanCentricAuth.unlock(pattern)
                ?: return@withContext null

            // Decrypt the vault master key
            val encryptedVaultKey = constellationMasterKeyFile.readBytes()
            val vaultMasterKey = BedrockCore.aesDecrypt(
                key = constellationMasterKey,
                ciphertext = encryptedVaultKey,
                associatedData = "vault-master-key".toByteArray()
            )

            // Zeroize the constellation key
            BedrockCore.zeroize(constellationMasterKey)

            vaultMasterKey
        } catch (e: RateLimitException) {
            throw e
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Unlock using sigil pattern.
     *
     * Returns the passphrase bytes for use with IdentityManager.
     *
     * @param pattern The sigil pattern
     * @return The passphrase bytes, or null if unlock failed
     */
    fun unlockWithSigil(pattern: com.yours.app.ui.components.Pattern): ByteArray? {
        return sigilManager.verifySigil(pattern)
    }

    /**
     * Change the constellation pattern.
     *
     * @param currentPattern The current constellation pattern
     * @param newPattern The new constellation pattern
     * @return true if change was successful
     */
    suspend fun changeConstellationPattern(
        currentPattern: HumanCentricAuth.ConstellationPattern,
        newPattern: HumanCentricAuth.ConstellationPattern
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // First, get the current vault master key
            val vaultMasterKey = unlockWithConstellation(currentPattern)
                ?: return@withContext false

            // Change the constellation pattern
            val success = humanCentricAuth.changePattern(currentPattern, newPattern)
            if (!success) {
                BedrockCore.zeroize(vaultMasterKey)
                return@withContext false
            }

            // Get the new constellation master key
            val newConstellationMasterKey = humanCentricAuth.unlock(newPattern)
            if (newConstellationMasterKey == null) {
                BedrockCore.zeroize(vaultMasterKey)
                return@withContext false
            }

            // Re-encrypt the vault master key with the new constellation key
            val encryptedVaultKey = BedrockCore.aesEncrypt(
                key = newConstellationMasterKey,
                plaintext = vaultMasterKey,
                associatedData = "vault-master-key".toByteArray()
            )

            // Store the updated encrypted vault master key
            constellationMasterKeyFile.writeBytes(encryptedVaultKey)

            // Zeroize sensitive data
            BedrockCore.zeroize(vaultMasterKey)
            BedrockCore.zeroize(newConstellationMasterKey)

            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Clear constellation auth (e.g., when switching to sigil only).
     */
    fun clearConstellationAuth() {
        try {
            // Securely delete the encrypted master key
            if (constellationMasterKeyFile.exists()) {
                val random = BedrockCore.randomBytes(constellationMasterKeyFile.length().toInt().coerceAtLeast(32))
                constellationMasterKeyFile.writeBytes(random)
                constellationMasterKeyFile.delete()
            }
            authPreferences.isConstellationSetup = false
        } catch (e: Exception) {
            // Best effort cleanup
            constellationMasterKeyFile.delete()
            authPreferences.isConstellationSetup = false
        }
    }

    /**
     * Switch the active authentication method.
     *
     * @param method The method to switch to
     * @return true if the switch was successful (method is set up)
     */
    fun switchAuthMethod(method: AuthPreferences.AuthMethod): Boolean {
        return when (method) {
            AuthPreferences.AuthMethod.SIGIL -> {
                if (sigilManager.hasSigil()) {
                    authPreferences.authMethod = method
                    true
                } else {
                    false
                }
            }
            AuthPreferences.AuthMethod.CONSTELLATION -> {
                if (authPreferences.isConstellationSetup) {
                    authPreferences.authMethod = method
                    true
                } else {
                    false
                }
            }
        }
    }
}
