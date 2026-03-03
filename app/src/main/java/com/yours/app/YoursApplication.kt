package com.yours.app

import android.app.Application
import com.yours.app.crypto.HardwareSecurityModule
import com.yours.app.identity.ContactManager
import com.yours.app.identity.IdentityManager
import com.yours.app.mesh.MeshCoreManager
import com.yours.app.messaging.LunarSessionManager
import com.yours.app.messaging.MessageManager
import com.yours.app.security.OpsecManager
import com.yours.app.vault.ArtifactSharingManager
import com.yours.app.vault.VaultStorage

/**
 * Yours Application.
 *
 * Initializes core components that live for the app's lifetime.
 * No analytics. No tracking. No cloud sync.
 *
 * Component Initialization Order (respects dependencies):
 * 1. Core managers (no dependencies): IdentityManager, VaultStorage, ContactManager
 * 2. Security/Hardware: HardwareSecurityModule, OpsecManager
 * 3. Transport: MeshCoreManager
 * 4. Session: LunarSessionManager
 * 5. High-level (with dependencies): ArtifactSharingManager, MessageManager
 */
class YoursApplication : Application() {

    // ========================================================================
    // CORE MANAGERS (No inter-dependencies)
    // ========================================================================

    lateinit var identityManager: IdentityManager
        private set

    lateinit var vaultStorage: VaultStorage
        private set

    lateinit var contactManager: ContactManager
        private set

    // ========================================================================
    // SECURITY & HARDWARE
    // ========================================================================

    /**
     * Hardware Security Module - Abstracts hardware-backed cryptographic operations.
     * Detects and uses StrongBox, TEE, or software fallback.
     */
    lateinit var hardwareSecurityModule: HardwareSecurityModule
        private set

    /**
     * OPSEC Manager - Handles operational security features:
     * - Panic wipe (shake gesture, duress passphrase)
     * - Travel mode (hide app from launcher)
     * - Paranoia mode (aggressive auto-lock, clipboard clearing)
     */
    lateinit var opsecManager: OpsecManager
        private set

    // ========================================================================
    // TRANSPORT & COMMUNICATION
    // ========================================================================

    /**
     * MeshCore Manager - Manages connection to MeshCore companion devices.
     * Provides LoRa mesh communication via USB Serial, BLE, or TCP.
     */
    lateinit var meshCoreManager: MeshCoreManager
        private set

    /**
     * Lunar Session Manager - Manages Double Ratchet sessions for secure messaging.
     * Provides forward secrecy and post-compromise security.
     */
    lateinit var lunarSessionManager: LunarSessionManager
        private set

    // ========================================================================
    // HIGH-LEVEL MANAGERS (Have dependencies on above)
    // ========================================================================

    /**
     * Artifact Sharing Manager - Secure artifact sharing via multiple channels:
     * - MeshCore transport (direct P2P over LoRa)
     * - External apps (encrypted via share sheet)
     * - QR codes (small artifacts < 2KB)
     * - NFC (tap-to-share)
     */
    lateinit var artifactSharingManager: ArtifactSharingManager
        private set

    /**
     * Message Manager - High-level P2P messaging over LunarCore mesh.
     * Coordinates session management, encryption, onion routing, and storage.
     */
    lateinit var messageManager: MessageManager
        private set

    override fun onCreate() {
        super.onCreate()

        // ====================================================================
        // PHASE 1: Core managers (no dependencies)
        // ====================================================================

        // Initialize identity manager
        identityManager = IdentityManager(this)

        // Initialize vault storage
        vaultStorage = VaultStorage(this)

        // Initialize contact manager
        contactManager = ContactManager(this)

        // ====================================================================
        // PHASE 2: Security and hardware managers
        // ====================================================================

        // Initialize hardware security module and detect capabilities
        hardwareSecurityModule = HardwareSecurityModule(this)
        hardwareSecurityModule.initialize()

        // Initialize OPSEC manager for panic wipe, travel mode, etc.
        opsecManager = OpsecManager(this)

        // ====================================================================
        // PHASE 3: Transport layer
        // ====================================================================

        // Initialize MeshCore manager for LoRa mesh communication
        meshCoreManager = MeshCoreManager(this)

        // ====================================================================
        // PHASE 4: Session management
        // ====================================================================

        // Initialize Lunar session manager for Double Ratchet sessions
        lunarSessionManager = LunarSessionManager(this)

        // ====================================================================
        // PHASE 5: High-level managers (depend on above components)
        // ====================================================================

        // Initialize artifact sharing manager
        // Dependencies: meshCoreManager (optional), lunarSessionManager (optional)
        artifactSharingManager = ArtifactSharingManager(
            context = this,
            meshManager = meshCoreManager,
            sessionManager = lunarSessionManager
        )

        // Initialize message manager
        // Dependencies: contactManager, meshCoreManager
        messageManager = MessageManager(
            context = this,
            contactManager = contactManager,
            meshManager = meshCoreManager
        )
    }

    // ========================================================================
    // LIFECYCLE CALLBACKS
    // ========================================================================

    /**
     * Called when the app is going to background.
     * Triggers auto-lock timer and other OPSEC measures.
     */
    fun onAppBackgrounded() {
        identityManager.onAppBackgrounded()
    }

    /**
     * Called when the app returns to foreground.
     * Checks if auto-lock should trigger based on time elapsed.
     */
    suspend fun onAppResumed() {
        val timeout = opsecManager.getAutoLockTimeoutMs()
        identityManager.onAppResumed(timeout)
    }
}
