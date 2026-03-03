package com.yours.app.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.yours.app.YoursApplication
import com.yours.app.camera.SovereignCamera
import com.yours.app.identity.ContactManager
import com.yours.app.identity.Identity
import com.yours.app.identity.IdentityManager
import com.yours.app.security.OpsecManager
import com.yours.app.security.SigilManager
import com.yours.app.ui.camera.CameraScreen
import com.yours.app.ui.contact.AddContactScreen
import com.yours.app.identity.ContactHello
import com.yours.app.ui.onboarding.GenesisScreen
import com.yours.app.ui.theme.YoursColors
import com.yours.app.ui.theme.YoursTheme
import com.yours.app.ui.unlock.UnlockScreen
import com.yours.app.ui.recovery.RecoveryScreen
import com.yours.app.ui.settings.SettingsScreen
import com.yours.app.ui.vault.ArtifactItem
import com.yours.app.ui.vault.ArtifactViewerScreen
import com.yours.app.ui.vault.ContactItem
import com.yours.app.ui.vault.VaultScreen
import com.yours.app.ui.vault.VaultState
import com.yours.app.ui.messaging.ThreadListScreen
import com.yours.app.ui.messaging.ConversationScreen
import com.yours.app.ui.messaging.ContactPickerScreen
import com.yours.app.ui.security.SovereigntyScreen
import com.yours.app.mesh.MeshCoreManager
import com.yours.app.mesh.MeshConnection
import com.yours.app.mesh.MeshConnectionState
import com.yours.app.mesh.MeshEventType
import com.yours.app.mesh.TransferProgress
import com.yours.app.mesh.TransferStatus
import com.yours.app.messaging.MessageManager
import com.yours.app.messaging.MessageThread
import com.yours.app.messaging.Message
import com.yours.app.vault.Artifact
import com.yours.app.vault.ArtifactMetadata
import com.yours.app.vault.ArtifactSanitizer
import com.yours.app.identity.Contact
import com.yours.app.vault.VaultStorage
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope

/**
 * Main Activity - The only activity in the app.
 *
 * Navigation is handled through Compose screens, not multiple activities.
 * This keeps the app simple and the back stack manageable.
 *
 * Security features:
 * - FLAG_SECURE prevents screenshots and screen recording
 * - Auto-lock after 2 minutes in background
 * - Keys zeroized on lock
 */
class MainActivity : ComponentActivity() {

    private lateinit var identityManager: IdentityManager
    private lateinit var sigilManager: SigilManager
    private lateinit var vaultStorage: VaultStorage
    private lateinit var contactManager: ContactManager
    private lateinit var sovereignCamera: SovereignCamera
    private val meshCoreManager: MeshCoreManager
        get() = (application as YoursApplication).meshCoreManager
    private lateinit var messageManager: MessageManager
    private lateinit var opsecManager: OpsecManager

    // Auto-lock state
    private var backgroundedAt: Long = 0
    private val autoLockTrigger = mutableStateOf(0) // Increment to trigger recheck

    // Camera permission launcher
    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            pendingCameraAction?.invoke()
        }
        pendingCameraAction = null
    }

    private var pendingCameraAction: (() -> Unit)? = null

    // File picker launcher
    private var pendingImportCallback: ((ByteArray, String, String) -> Unit)? = null

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            try {
                contentResolver.openInputStream(it)?.use { stream ->
                    val bytes = stream.readBytes()
                    val mimeType = contentResolver.getType(it) ?: "application/octet-stream"
                    val name = getFileName(it) ?: "imported_file"
                    pendingImportCallback?.invoke(bytes, mimeType, name)
                }
            } catch (e: Exception) {
                android.util.Log.e("MainActivity", "Failed to import file", e)
            }
        }
        pendingImportCallback = null
    }

    private fun getFileName(uri: android.net.Uri): String? {
        var name: String? = null
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (nameIndex >= 0) {
                    name = cursor.getString(nameIndex)
                }
            }
        }
        return name
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Set up crash logger FIRST - catches any crashes during init
        setupCrashLogger()

        // SECURITY: Prevent screenshots and screen recording
        // Also hides app content in recent apps switcher
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Initialize components
        val app = application as YoursApplication
        identityManager = app.identityManager
        sigilManager = SigilManager(this)
        vaultStorage = app.vaultStorage
        contactManager = app.contactManager
        sovereignCamera = SovereignCamera(this, vaultStorage)
        // meshCoreManager is accessed via property delegate from YoursApplication
        // Creating multiple instances causes each to have its own MessagePool with different
        // epoch counters, meaning user messages go to one pool but transmissions happen from another.
        messageManager = app.messageManager
        opsecManager = OpsecManager(this)
        
        setContent {
            YoursTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = YoursColors.Background
                ) {
                    AppNavigation(
                        identityManager = identityManager,
                        sigilManager = sigilManager,
                        vaultStorage = vaultStorage,
                        contactManager = contactManager,
                        sovereignCamera = sovereignCamera,
                        meshCoreManager = meshCoreManager,
                        messageManager = messageManager,
                        opsecManager = opsecManager,
                        autoLockTrigger = autoLockTrigger.value,
                        onRequestCameraPermission = { action ->
                            requestCameraPermission(action)
                        },
                        onImportFile = { callback ->
                            pendingImportCallback = callback
                            filePickerLauncher.launch(arrayOf("*/*"))
                        }
                    )
                }
            }
        }
    }
    
    private fun requestCameraPermission(onGranted: () -> Unit) {
        when {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                onGranted()
            }
            else -> {
                pendingCameraAction = onGranted
                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
    }
    
    override fun onPause() {
        super.onPause()
        // Record when app went to background for auto-lock
        if (identityManager.isUnlocked()) {
            backgroundedAt = System.currentTimeMillis()
        }

        // Stop shake detection when app is backgrounded for battery efficiency
        // It will restart on resume if app is still unlocked
        opsecManager.stopShakeDetection()

        // Save vault index when app goes to background
        lifecycleScope.launch {
            if (identityManager.isUnlocked()) {
                // Get index key from identity
                // vaultStorage.saveIndex(indexKey)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Check if auto-lock timeout has expired
        if (backgroundedAt > 0 && identityManager.isUnlocked()) {
            val elapsed = System.currentTimeMillis() - backgroundedAt
            // Use OpsecManager timeout (respects paranoia mode)
            val timeout = opsecManager.getAutoLockTimeoutMs()
            if (elapsed >= timeout) {
                // Lock the identity - keys will be zeroized
                identityManager.lockSync()
                // Stop shake detection on lock
                opsecManager.stopShakeDetection()
                // Lock message manager to clear sensitive data
                lifecycleScope.launch {
                    messageManager.lock()
                }
                // Trigger UI recheck by incrementing the state
                autoLockTrigger.value++
                android.util.Log.i("MainActivity", "Auto-locked after ${elapsed}ms in background (timeout: ${timeout}ms)")
            } else {
                // App still unlocked - restart shake detection if enabled
                restartShakeDetection()
            }
        } else if (identityManager.isUnlocked()) {
            // App was unlocked and not in background long - restart shake detection
            restartShakeDetection()
        }
        backgroundedAt = 0
    }

    /**
     * Restart shake detection if enabled.
     * Called when app resumes and is unlocked.
     */
    private fun restartShakeDetection() {
        if (identityManager.isUnlocked() && opsecManager.shakeDetectionEnabled.value) {
            opsecManager.startShakeDetection(identityManager) {
                // Panic wipe triggered - navigate to Genesis
                autoLockTrigger.value++
                android.util.Log.w("MainActivity", "PANIC WIPE triggered via shake detection!")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Stop shake detection
        opsecManager.stopShakeDetection()
        // Ensure keys are cleared when activity is destroyed
        if (identityManager.isUnlocked()) {
            identityManager.lockSync()
        }
        // Shutdown message manager
        lifecycleScope.launch {
            messageManager.shutdown()
        }
    }

    /**
     * Set up crash logger to capture unhandled exceptions.
     * Writes to crash_log.txt in app's files directory.
     */
    private fun setupCrashLogger() {
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                val crashFile = java.io.File(filesDir, "crash_log.txt")
                val timestamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date())
                val stackTrace = java.io.StringWriter().also { throwable.printStackTrace(java.io.PrintWriter(it)) }.toString()

                crashFile.appendText("""
                    |
                    |========== CRASH at $timestamp ==========
                    |Thread: ${thread.name}
                    |Exception: ${throwable.javaClass.name}
                    |Message: ${throwable.message}
                    |
                    |Stack trace:
                    |$stackTrace
                    |==========================================
                    |
                """.trimMargin())

                android.util.Log.e("CrashLogger", "Crash logged to ${crashFile.absolutePath}")
            } catch (e: Exception) {
                android.util.Log.e("CrashLogger", "Failed to write crash log", e)
            }

            // Call default handler to show the crash dialog
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    companion object {
        /**
         * Read crash log from context. Call from any composable via LocalContext.
         */
        fun getCrashLog(context: android.content.Context): String? {
            val crashFile = java.io.File(context.filesDir, "crash_log.txt")
            return if (crashFile.exists()) crashFile.readText() else null
        }

        fun clearCrashLog(context: android.content.Context) {
            val crashFile = java.io.File(context.filesDir, "crash_log.txt")
            if (crashFile.exists()) crashFile.delete()
        }
    }
}

/**
 * App-level navigation.
 *
 * Flow:
 * 1. No identity → Genesis (create identity)
 * 2. Identity exists, locked → Unlock
 * 3. Identity exists, unlocked → Vault
 *
 * Auto-lock: When autoLockTrigger changes and identity is locked,
 * automatically navigate to Unlock screen.
 */
@Composable
private fun AppNavigation(
    identityManager: IdentityManager,
    sigilManager: SigilManager,
    vaultStorage: VaultStorage,
    contactManager: ContactManager,
    sovereignCamera: SovereignCamera,
    meshCoreManager: MeshCoreManager,
    messageManager: MessageManager,
    opsecManager: OpsecManager,
    autoLockTrigger: Int,
    onRequestCameraPermission: (() -> Unit) -> Unit,
    onImportFile: ((ByteArray, String, String) -> Unit) -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var appState by remember { mutableStateOf<AppState>(AppState.Loading) }
    var currentScreen by remember { mutableStateOf<Screen>(Screen.Loading) }

    // Check for crash log from previous run
    var crashLog by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        crashLog = MainActivity.getCrashLog(context)
    }

    // Show crash log dialog if there was a previous crash
    crashLog?.let { log ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = {
                MainActivity.clearCrashLog(context)
                crashLog = null
            },
            title = { androidx.compose.material3.Text("Previous Crash Detected") },
            text = {
                androidx.compose.foundation.layout.Column(
                    modifier = Modifier.fillMaxSize()
                ) {
                    androidx.compose.material3.Text(
                        "Tap SHARE to send the full log:",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium
                    )
                    androidx.compose.foundation.layout.Spacer(
                        modifier = Modifier.height(8.dp)
                    )
                    androidx.compose.foundation.layout.Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(250.dp)
                            .background(YoursColors.Surface, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                            .padding(8.dp)
                            .verticalScroll(androidx.compose.foundation.rememberScrollState())
                    ) {
                        // Show FIRST 3000 chars (where exception info is)
                        androidx.compose.material3.Text(
                            text = log.take(3000),
                            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            fontSize = 10.sp
                        )
                    }
                }
            },
            confirmButton = {
                androidx.compose.material3.TextButton(
                    onClick = {
                        MainActivity.clearCrashLog(context)
                        crashLog = null
                    }
                ) {
                    androidx.compose.material3.Text("Dismiss")
                }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(
                    onClick = {
                        // Share the crash log
                        val shareIntent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(android.content.Intent.EXTRA_SUBJECT, "Yours App Crash Log")
                            putExtra(android.content.Intent.EXTRA_TEXT, log)
                        }
                        context.startActivity(android.content.Intent.createChooser(shareIntent, "Share Crash Log"))
                    }
                ) {
                    androidx.compose.material3.Text("SHARE")
                }
            }
        )
    }

    // Check initial state
    LaunchedEffect(Unit) {
        appState = when {
            !identityManager.hasIdentity() -> AppState.NoIdentity
            identityManager.isUnlocked() -> AppState.Unlocked
            else -> AppState.Locked
        }

        currentScreen = when (appState) {
            AppState.Loading -> Screen.Loading
            AppState.NoIdentity -> Screen.Genesis
            AppState.Locked -> Screen.Unlock
            AppState.Unlocked -> Screen.Vault
        }
    }

    // React to auto-lock trigger
    LaunchedEffect(autoLockTrigger) {
        if (autoLockTrigger > 0 && !identityManager.isUnlocked()) {
            // Auto-lock occurred - navigate to unlock screen
            appState = AppState.Locked
            currentScreen = Screen.Unlock
        }
    }

    // Render current screen
    when (val screen = currentScreen) {
        Screen.Loading -> {
            // Show nothing or a loading indicator
        }
        
        Screen.Genesis -> {
            val scope = rememberCoroutineScope()
            var errorMessage by remember { mutableStateOf<String?>(null) }

            // Show error dialog if there's an error
            errorMessage?.let { error ->
                androidx.compose.material3.AlertDialog(
                    onDismissRequest = { errorMessage = null },
                    title = { androidx.compose.material3.Text("Error") },
                    text = { androidx.compose.material3.Text(error) },
                    confirmButton = {
                        androidx.compose.material3.TextButton(
                            onClick = {
                                errorMessage = null
                                // If identity exists, go to unlock
                                if (identityManager.hasIdentity()) {
                                    currentScreen = Screen.Unlock
                                }
                            }
                        ) {
                            androidx.compose.material3.Text("OK")
                        }
                    }
                )
            }

            GenesisScreen(
                onComplete = { name, passphraseBytes, pattern ->
                    scope.launch {
                        try {
                            android.util.Log.d("MainActivity", "Creating identity for $name")

                            // Check if identity already exists
                            if (identityManager.hasIdentity()) {
                                android.util.Log.d("MainActivity", "Identity already exists, setting up sigil only")
                                // Set up the sigil only if user created a pattern (not skipped)
                                if (pattern != null) {
                                    sigilManager.setupSigil(pattern, passphraseBytes)
                                } else {
                                    android.util.Log.d("MainActivity", "User skipped sigil setup - passphrase-only mode")
                                }
                                // Unlock with the passphrase
                                identityManager.unlock(passphraseBytes)
                                // Start shake detection after unlock
                                opsecManager.startShakeDetection(identityManager) {
                                    android.util.Log.w("MainActivity", "PANIC WIPE triggered via shake detection!")
                                }
                                currentScreen = Screen.Vault
                            } else {
                                // Create new identity
                                identityManager.createIdentity(
                                    name,
                                    passphraseBytes
                                )
                                android.util.Log.d("MainActivity", "Identity created")
                                // Save pattern for quick unlock only if user created one
                                if (pattern != null) {
                                    sigilManager.setupSigil(pattern, passphraseBytes)
                                    android.util.Log.d("MainActivity", "Sigil setup complete")
                                } else {
                                    android.util.Log.d("MainActivity", "User skipped sigil setup - passphrase-only mode")
                                }
                                // Start shake detection after identity creation
                                opsecManager.startShakeDetection(identityManager) {
                                    android.util.Log.w("MainActivity", "PANIC WIPE triggered via shake detection!")
                                }
                                currentScreen = Screen.Vault
                            }
                        } catch (e: Exception) {
                            android.util.Log.e("MainActivity", "Failed to create identity", e)
                            errorMessage = "Failed to create identity: ${e.message}"
                        } finally {
                            // SECURITY: Zeroize passphrase after use
                            passphraseBytes.fill(0)
                        }
                    }
                }
            )
        }

        Screen.Unlock -> {
            var identity by remember { mutableStateOf<Identity?>(null) }

            LaunchedEffect(Unit) {
                identity = identityManager.getIdentity()
            }

            identity?.let {
                UnlockScreen(
                    userName = it.name,
                    sigilManager = sigilManager,
                    onUnlockWithPassphrase = { passphraseBytes: ByteArray ->
                        try {
                            val result = identityManager.unlock(passphraseBytes)
                            if (result is IdentityManager.UnlockResult.Success) {
                                appState = AppState.Unlocked
                                currentScreen = Screen.Vault
                                // Start shake detection after successful unlock
                                opsecManager.startShakeDetection(identityManager) {
                                    // Panic wipe triggered - will navigate to Genesis via panicTriggered flow
                                    android.util.Log.w("MainActivity", "PANIC WIPE triggered via shake detection!")
                                }
                            }
                            result
                        } finally {
                            // SECURITY: Zeroize passphrase after use
                            passphraseBytes.fill(0)
                        }
                    },
                    onRecover = {
                        currentScreen = Screen.Recovery
                    },
                    onIdentityWiped = {
                        // Identity was wiped (duress/panic) - go to fresh start
                        // Stop shake detection since we're resetting
                        opsecManager.stopShakeDetection()
                        appState = AppState.NoIdentity
                        currentScreen = Screen.Genesis
                    }
                )
            }
        }

        Screen.Recovery -> {
            RecoveryScreen(
                onRecovered = { masterKey ->
                    // Master key recovered - restore identity
                    // For now, navigate back to unlock (user will need to set new passphrase)
                    currentScreen = Screen.Unlock
                },
                onCancel = {
                    currentScreen = Screen.Unlock
                },
                onRequestCameraPermission = onRequestCameraPermission
            )
        }

        Screen.Settings -> {
            SettingsScreen(
                identityManager = identityManager,
                meshCoreManager = meshCoreManager,
                messageManager = messageManager,
                onClose = {
                    currentScreen = Screen.Vault
                }
            )
        }

        Screen.Messaging -> {
            var threads by remember { mutableStateOf<List<MessageThread>>(emptyList()) }
            val scope = rememberCoroutineScope()

            // Collect message threads
            LaunchedEffect(Unit) {
                messageManager.threads.collect { threadList ->
                    threads = threadList
                }
            }

            ThreadListScreen(
                threads = threads,
                onThreadClick = { thread ->
                    scope.launch {
                        if (!identityManager.isUnlocked()) {
                            // Identity not unlocked - go to unlock screen
                            currentScreen = Screen.Unlock
                            return@launch
                        }
                        val contact = contactManager.getContact(thread.contactId)
                        if (contact != null) {
                            currentScreen = Screen.Conversation(contact)
                        }
                    }
                },
                onNewMessage = {
                    currentScreen = Screen.ContactPicker
                },
                onBack = {
                    currentScreen = Screen.Vault
                }
            )
        }

        is Screen.Conversation -> {
            val conversationScreen = screen as Screen.Conversation
            val contact = conversationScreen.contact
            var messages by remember { mutableStateOf<List<Message>>(emptyList()) }
            var isSending by remember { mutableStateOf(false) }
            var anonymityLevel by remember { mutableStateOf(com.yours.app.messaging.AnonymityLevel.FULL) }
            val scope = rememberCoroutineScope()

            // Entropy collection buffer for touch events (hedged key exchange)
            val entropyBuffer = remember { mutableListOf<Byte>() }

            // Load messages and anonymity level for this conversation
            LaunchedEffect(contact.id) {
                messages = messageManager.getMessages(contact.id)
                messageManager.markAsRead(contact.id)
                anonymityLevel = messageManager.getAnonymityLevel()
            }

            // Listen for message events
            LaunchedEffect(Unit) {
                messageManager.events.collect { event ->
                    when (event) {
                        is com.yours.app.messaging.MessageEvent.Received -> {
                            if (event.message.threadId == contact.id) {
                                messages = messageManager.getMessages(contact.id)
                                messageManager.markAsRead(contact.id)
                            }
                        }
                        is com.yours.app.messaging.MessageEvent.StatusChanged -> {
                            messages = messageManager.getMessages(contact.id)
                        }
                        is com.yours.app.messaging.MessageEvent.MessageQueued -> {
                            // Message queued in epoch pool
                            messages = messageManager.getMessages(contact.id)
                        }
                        is com.yours.app.messaging.MessageEvent.InsufficientRelays -> {
                            // Update anonymity level display
                            anonymityLevel = messageManager.getAnonymityLevel()
                        }
                        is com.yours.app.messaging.MessageEvent.ReducedAnonymity -> {
                            anonymityLevel = com.yours.app.messaging.AnonymityLevel.REDUCED
                        }
                        else -> { /* ignore other events */ }
                    }
                }
            }

            ConversationScreen(
                contact = contact,
                messages = messages,
                onSendMessage = { text ->
                    scope.launch {
                        isSending = true
                        try {
                            if (!messageManager.isInitialized) {
                                android.util.Log.e("MainActivity", "Cannot send message: MessageManager not initialized")
                                return@launch
                            }
                            messageManager.sendMessage(contact, text)
                            messages = messageManager.getMessages(contact.id)
                        } catch (e: Exception) {
                            android.util.Log.e("MainActivity", "Failed to send message", e)
                        } finally {
                            isSending = false
                        }
                    }
                },
                onBack = {
                    currentScreen = Screen.Messaging
                },
                onTouchEntropy = { event ->
                    // SECURITY: Collect entropy from touch events for hedged key exchange
                    // Even if system RNG is compromised, touch patterns provide entropy
                    synchronized(entropyBuffer) {
                        val x = event.x
                        val y = event.y
                        val time = event.eventTime
                        val pressure = event.pressure

                        // Extract entropy from low bits of touch data
                        val xBits = java.lang.Float.floatToIntBits(x)
                        val yBits = java.lang.Float.floatToIntBits(y)
                        val pressureBits = java.lang.Float.floatToIntBits(pressure)

                        entropyBuffer.add((xBits and 0xFF).toByte())
                        entropyBuffer.add((yBits and 0xFF).toByte())
                        entropyBuffer.add((time and 0xFF).toByte())
                        entropyBuffer.add(((time shr 8) and 0xFF).toByte())
                        entropyBuffer.add((pressureBits and 0xFF).toByte())

                        // Keep buffer bounded
                        while (entropyBuffer.size > 512) {
                            entropyBuffer.removeAt(0)
                        }
                    }
                },
                onKeyboardEntropy = {
                    // SECURITY: Collect keyboard timing entropy
                    synchronized(entropyBuffer) {
                        val nanos = System.nanoTime()
                        entropyBuffer.add((nanos and 0xFF).toByte())
                        entropyBuffer.add(((nanos shr 8) and 0xFF).toByte())
                        entropyBuffer.add(((nanos shr 16) and 0xFF).toByte())
                        entropyBuffer.add(((nanos shr 24) and 0xFF).toByte())

                        while (entropyBuffer.size > 512) {
                            entropyBuffer.removeAt(0)
                        }
                    }
                },
                anonymityLevel = anonymityLevel,
                isSending = isSending
            )
        }

        Screen.ContactPicker -> {
            var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
            val scope = rememberCoroutineScope()

            // Load contacts
            LaunchedEffect(Unit) {
                val masterKey = identityManager.getMasterKey()
                contacts = contactManager.getContacts(masterKey)
            }

            ContactPickerScreen(
                contacts = contacts,
                onContactSelected = { contact ->
                    currentScreen = Screen.Conversation(contact)
                },
                onBack = {
                    currentScreen = Screen.Messaging
                }
            )
        }

        Screen.Sovereignty -> {
            SovereigntyScreen(
                onBack = {
                    currentScreen = Screen.Vault
                }
            )
        }

        Screen.Vault -> {
            var showCamera by remember { mutableStateOf(false) }
            var showAddContact by remember { mutableStateOf(false) }
            var viewingArtifact by remember { mutableStateOf<Artifact?>(null) }
            var vaultState by remember { mutableStateOf(VaultState()) }
            var myContactHello by remember { mutableStateOf<ContactHello?>(null) }
            var transferState by remember { mutableStateOf<TransferState>(TransferState.Idle) }
            val scope = rememberCoroutineScope()

            // Load vault state and prepare contact hello
            LaunchedEffect(Unit) {
                val identity = identityManager.getIdentity()
                vaultState = vaultState.copy(userName = identity?.name ?: "")

                // Prepare ContactHello for sharing
                identity?.let {
                    val signingKey = identityManager.getSigningKey()
                    myContactHello = contactManager.createHello(it, signingKey)
                }

                // Initialize MessageManager with encryption keys
                try {
                    val masterKey = identityManager.getMasterKey()
                    val unlockedKeys = identityManager.getUnlockedKeys()
                    if (unlockedKeys != null) {
                        val currentIdentity = identityManager.getIdentity()
                        messageManager.initialize(
                            encryptionKey = masterKey,
                            ourSecretKey = unlockedKeys.sessionPrivateKey,  // X25519 (32 bytes) for Double Ratchet
                            ourDid = currentIdentity?.did ?: "",
                            ourPublicKey = currentIdentity?.sessionPublicKey  // Pass for debug logging
                        )
                    }
                } catch (e: Exception) {
                    android.util.Log.e("MainActivity", "Failed to initialize MessageManager", e)
                }

                // Observe artifacts
                vaultStorage.artifacts.onEach { entries ->
                    vaultState = vaultState.copy(
                        artifacts = entries.map { entry ->
                            ArtifactItem(
                                id = entry.id,
                                contentType = entry.contentType,
                                name = entry.metadata.name,
                                createdAt = entry.createdAt
                            )
                        }
                    )
                }.launchIn(this)

                // Observe contacts
                val masterKey = identityManager.getMasterKey()
                contactManager.contacts.onEach { contactList ->
                    vaultState = vaultState.copy(
                        contacts = contactList.map { contact ->
                            ContactItem(
                                id = contact.id,
                                petname = contact.petname,
                                initial = contact.petname.firstOrNull()?.uppercase() ?: "?"
                            )
                        }
                    )
                }.launchIn(this)

                // Load contacts initially (triggers flow)
                contactManager.getContacts(masterKey)
            }
            
            when {
                showCamera -> {
                    var identity by remember { mutableStateOf<com.yours.app.identity.Identity?>(null) }
                    LaunchedEffect(Unit) {
                        identity = identityManager.getIdentity()
                    }

                    CameraScreen(
                        sovereignCamera = sovereignCamera,
                        ownerPublicKey = identity?.encryptionPublicKey ?: ByteArray(0),
                        onClose = { showCamera = false },
                        onCaptured = { artifactId ->
                            showCamera = false
                        }
                    )
                }
                showAddContact && myContactHello != null -> {
                    AddContactScreen(
                        myHello = myContactHello!!,
                        onContactAdded = { theirHello, petname ->
                            scope.launch {
                                try {
                                    val masterKey = identityManager.getMasterKey()
                                    contactManager.addContact(theirHello, petname, masterKey)
                                } catch (e: Exception) {
                                    // Handle error silently for now
                                }
                                showAddContact = false
                            }
                        },
                        onClose = { showAddContact = false },
                        onRequestCameraPermission = onRequestCameraPermission
                    )
                }
                viewingArtifact != null -> {
                    var identity by remember { mutableStateOf<com.yours.app.identity.Identity?>(null) }
                    LaunchedEffect(Unit) {
                        identity = identityManager.getIdentity()
                    }

                    identity?.let { id ->
                        ArtifactViewerScreen(
                            artifact = viewingArtifact!!,
                            ownerSecretKey = identityManager.getUnlockedKeys()?.encryptionPrivateKey ?: ByteArray(0),
                            onClose = { viewingArtifact = null },
                            onDelete = {
                                scope.launch {
                                    vaultStorage.delete(viewingArtifact!!.id)
                                    viewingArtifact = null
                                }
                            },
                            onRename = { newName ->
                                scope.launch {
                                    vaultStorage.rename(viewingArtifact!!.id, newName)
                                    viewingArtifact = null
                                }
                            },
                            onShare = {
                                // Initiate transfer - show contact selection
                                transferState = TransferState.SelectingContact(
                                    artifactId = viewingArtifact!!.id,
                                    artifactName = viewingArtifact!!.metadata.name ?: "Unnamed artifact"
                                )
                            }
                        )
                    }

                    // Transfer state UI overlay
                    when (val state = transferState) {
                        is TransferState.SelectingContact -> {
                            TransferContactSelectionDialog(
                                artifactName = state.artifactName,
                                contacts = vaultState.contacts,
                                onContactSelected = { contactId ->
                                    scope.launch {
                                        transferState = TransferState.Preparing(
                                            artifactId = state.artifactId,
                                            contactId = contactId
                                        )
                                        initiateTransfer(
                                            artifactId = state.artifactId,
                                            contactId = contactId,
                                            vaultStorage = vaultStorage,
                                            contactManager = contactManager,
                                            identityManager = identityManager,
                                            meshCoreManager = meshCoreManager,
                                            onStateChange = { newState -> transferState = newState }
                                        )
                                    }
                                },
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Preparing -> {
                            TransferProgressDialog(
                                message = "Preparing artifact for transfer...",
                                progress = null,
                                onCancel = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.AwaitingConnection -> {
                            TransferProgressDialog(
                                message = "Waiting for MeshCore connection...\n\nConnect via USB-C to ESP32 device or enable Bluetooth.",
                                progress = null,
                                onCancel = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Transferring -> {
                            TransferProgressDialog(
                                message = "Transferring '${state.artifactName}'...",
                                progress = state.progress,
                                onCancel = null // Cannot cancel during transfer
                            )
                        }
                        is TransferState.Completed -> {
                            TransferCompletedDialog(
                                artifactName = state.artifactName,
                                recipientName = state.recipientName,
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Failed -> {
                            TransferFailedDialog(
                                error = state.error,
                                onRetry = {
                                    state.artifactId?.let { artifactId ->
                                        state.contactId?.let { contactId ->
                                            scope.launch {
                                                initiateTransfer(
                                                    artifactId = artifactId,
                                                    contactId = contactId,
                                                    vaultStorage = vaultStorage,
                                                    contactManager = contactManager,
                                                    identityManager = identityManager,
                                                    meshCoreManager = meshCoreManager,
                                                    onStateChange = { newState -> transferState = newState }
                                                )
                                            }
                                        }
                                    }
                                },
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        TransferState.Idle -> { /* No dialog shown */ }
                    }
                }
                else -> {
                    VaultScreen(
                        state = vaultState,
                        onOpenCamera = {
                            onRequestCameraPermission {
                                showCamera = true
                            }
                        },
                        onImportFile = {
                            onImportFile { bytes, mimeType, fileName ->
                                scope.launch {
                                    try {
                                        val identity = identityManager.getIdentity()
                                        identity?.let {
                                            // - Strips EXIF metadata (GPS, timestamps, device info)
                                            // - Generates anonymous name (no filename leakage)
                                            val sanitized = ArtifactSanitizer.sanitize(
                                                content = bytes,
                                                contentType = mimeType,
                                                originalFileName = fileName
                                            )

                                            val artifact = Artifact.create(
                                                content = sanitized.content,
                                                contentType = mimeType,
                                                ownerPublicKey = it.encryptionPublicKey,
                                                metadata = ArtifactMetadata(name = sanitized.anonymousName)
                                            )
                                            vaultStorage.store(artifact)
                                        }
                                    } catch (e: Exception) {
                                    }
                                }
                            }
                        },
                        onOpenArtifact = { id ->
                            scope.launch {
                                val artifact = vaultStorage.load(id)
                                viewingArtifact = artifact
                            }
                        },
                        onAddContact = {
                            showAddContact = true
                        },
                        onOpenSettings = {
                            currentScreen = Screen.Settings
                        },
                        onOpenMessaging = {
                            currentScreen = Screen.Messaging
                        },
                        onOpenSovereignty = {
                            currentScreen = Screen.Sovereignty
                        },
                        onTransfer = { artifactId, contactId ->
                            scope.launch {
                                transferState = TransferState.Preparing(
                                    artifactId = artifactId,
                                    contactId = contactId
                                )
                                initiateTransfer(
                                    artifactId = artifactId,
                                    contactId = contactId,
                                    vaultStorage = vaultStorage,
                                    contactManager = contactManager,
                                    identityManager = identityManager,
                                    meshCoreManager = meshCoreManager,
                                    onStateChange = { newState -> transferState = newState }
                                )
                            }
                        }
                    )

                    // Transfer state UI overlay (for vault screen transfers)
                    when (val state = transferState) {
                        is TransferState.SelectingContact -> {
                            TransferContactSelectionDialog(
                                artifactName = state.artifactName,
                                contacts = vaultState.contacts,
                                onContactSelected = { contactId ->
                                    scope.launch {
                                        transferState = TransferState.Preparing(
                                            artifactId = state.artifactId,
                                            contactId = contactId
                                        )
                                        initiateTransfer(
                                            artifactId = state.artifactId,
                                            contactId = contactId,
                                            vaultStorage = vaultStorage,
                                            contactManager = contactManager,
                                            identityManager = identityManager,
                                            meshCoreManager = meshCoreManager,
                                            onStateChange = { newState -> transferState = newState }
                                        )
                                    }
                                },
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Preparing -> {
                            TransferProgressDialog(
                                message = "Preparing artifact for transfer...",
                                progress = null,
                                onCancel = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.AwaitingConnection -> {
                            TransferProgressDialog(
                                message = "Waiting for MeshCore connection...\n\nConnect via USB-C to ESP32 device or enable Bluetooth.",
                                progress = null,
                                onCancel = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Transferring -> {
                            TransferProgressDialog(
                                message = "Transferring '${state.artifactName}'...",
                                progress = state.progress,
                                onCancel = null
                            )
                        }
                        is TransferState.Completed -> {
                            TransferCompletedDialog(
                                artifactName = state.artifactName,
                                recipientName = state.recipientName,
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        is TransferState.Failed -> {
                            TransferFailedDialog(
                                error = state.error,
                                onRetry = {
                                    state.artifactId?.let { artifactId ->
                                        state.contactId?.let { contactId ->
                                            scope.launch {
                                                initiateTransfer(
                                                    artifactId = artifactId,
                                                    contactId = contactId,
                                                    vaultStorage = vaultStorage,
                                                    contactManager = contactManager,
                                                    identityManager = identityManager,
                                                    meshCoreManager = meshCoreManager,
                                                    onStateChange = { newState -> transferState = newState }
                                                )
                                            }
                                        }
                                    }
                                },
                                onDismiss = { transferState = TransferState.Idle }
                            )
                        }
                        TransferState.Idle -> { /* No dialog shown */ }
                    }
                }
            }
        }
        
        is Screen.Camera -> {
            // Handled inline in Vault screen
        }
    }
}

private sealed class AppState {
    object Loading : AppState()
    object NoIdentity : AppState()
    object Locked : AppState()
    object Unlocked : AppState()
}

private sealed class Screen {
    object Loading : Screen()
    object Genesis : Screen()
    object Unlock : Screen()
    object Vault : Screen()
    object Camera : Screen()
    object Recovery : Screen()
    object Settings : Screen()
    object Messaging : Screen()
    data class Conversation(val contact: Contact) : Screen()
    object ContactPicker : Screen()
    object Sovereignty : Screen()
}

/**
 * Transfer state machine for artifact sharing via MeshCore.
 */
private sealed class TransferState {
    /** No transfer in progress */
    object Idle : TransferState()

    /** User is selecting which contact to send to */
    data class SelectingContact(
        val artifactId: String,
        val artifactName: String
    ) : TransferState()

    /** Preparing the artifact for transfer (encrypting for recipient) */
    data class Preparing(
        val artifactId: String,
        val contactId: String
    ) : TransferState()

    /** Waiting for MeshCore hardware connection */
    data class AwaitingConnection(
        val artifactId: String,
        val contactId: String,
        val encryptedPayload: ByteArray
    ) : TransferState()

    /** Transfer in progress */
    data class Transferring(
        val artifactId: String,
        val artifactName: String,
        val recipientName: String,
        val progress: Float
    ) : TransferState()

    /** Transfer completed successfully */
    data class Completed(
        val artifactName: String,
        val recipientName: String
    ) : TransferState()

    /** Transfer failed */
    data class Failed(
        val error: String,
        val artifactId: String? = null,
        val contactId: String? = null
    ) : TransferState()
}

/**
 * Initiates artifact transfer to a contact using real MeshCore transport.
 *
 * This function handles the complete transfer flow:
 * 1. Load the artifact and decrypt it
 * 2. Re-encrypt for the recipient's public key
 * 3. Establish MeshCore connection (if not already connected)
 * 4. Send the encrypted artifact using MeshCoreManager.transferFile()
 * 5. Track real transfer progress
 */
private suspend fun initiateTransfer(
    artifactId: String,
    contactId: String,
    vaultStorage: VaultStorage,
    contactManager: ContactManager,
    identityManager: IdentityManager,
    meshCoreManager: MeshCoreManager,
    onStateChange: (TransferState) -> Unit
) {
    try {
        // Load artifact
        val artifact = vaultStorage.load(artifactId)
        if (artifact == null) {
            onStateChange(TransferState.Failed(
                error = "Artifact not found",
                artifactId = artifactId,
                contactId = contactId
            ))
            return
        }

        // Get recipient contact
        val contact = contactManager.getContact(contactId)
        if (contact == null) {
            onStateChange(TransferState.Failed(
                error = "Contact not found",
                artifactId = artifactId,
                contactId = contactId
            ))
            return
        }

        // Get our decryption key
        val unlockedKeys = identityManager.getUnlockedKeys()
        if (unlockedKeys == null) {
            onStateChange(TransferState.Failed(
                error = "Vault is locked",
                artifactId = artifactId,
                contactId = contactId
            ))
            return
        }

        // Decrypt the artifact
        val decryptedContent = artifact.decrypt(unlockedKeys.encryptionPrivateKey)
        if (decryptedContent == null) {
            onStateChange(TransferState.Failed(
                error = "Failed to decrypt artifact",
                artifactId = artifactId,
                contactId = contactId
            ))
            return
        }

        // Re-encrypt for recipient using their public key
        val recipientArtifact = Artifact.create(
            content = decryptedContent,
            contentType = artifact.contentType,
            ownerPublicKey = contact.encryptionPublicKey,
            metadata = artifact.metadata.copy(
                name = artifact.metadata.name,
                description = "Received from ${identityManager.getIdentity()?.name ?: "Unknown"}"
            )
        )

        // Zeroize decrypted content after re-encryption
        com.yours.app.crypto.BedrockCore.zeroize(decryptedContent)

        // Serialize for transport using the same format as VaultStorage
        val transferPayload = serializeArtifactForTransfer(recipientArtifact)

        val artifactName = artifact.metadata.name ?: "Unnamed artifact"
        val recipientName = contact.petname

        // Check if MeshCore is connected
        if (!meshCoreManager.isConnected()) {
            // Update state to awaiting connection
            onStateChange(TransferState.AwaitingConnection(
                artifactId = artifactId,
                contactId = contactId,
                encryptedPayload = transferPayload
            ))

            // Try to auto-connect to first available device
            val usbDevices = meshCoreManager.getAvailableUsbDevices()
            val connectResult = if (usbDevices.isNotEmpty()) {
                // Prefer USB connection for reliability
                meshCoreManager.connectToFirstUsbDevice()
            } else {
                // Fall back to BLE
                meshCoreManager.connectToFirstBleDevice()
            }

            if (connectResult.isFailure) {
                onStateChange(TransferState.Failed(
                    error = "No MeshCore device available. Connect via USB or Bluetooth in Settings.",
                    artifactId = artifactId,
                    contactId = contactId
                ))
                return
            }
        }

        // Start transfer with real progress tracking
        onStateChange(TransferState.Transferring(
            artifactId = artifactId,
            artifactName = artifactName,
            recipientName = recipientName,
            progress = 0f
        ))

        // Use MeshCoreManager's transferFile for real transfer with progress
        val transferResult = meshCoreManager.transferFile(
            recipientPublicKey = contact.encryptionPublicKey,
            data = transferPayload,
            metadata = mapOf(
                "name" to (artifact.metadata.name ?: "artifact"),
                "type" to artifact.contentType,
                "size" to transferPayload.size.toString()
            )
        ) { progress: TransferProgress ->
            // Update UI with real transfer progress
            when (progress.status) {
                TransferStatus.PENDING, TransferStatus.IN_PROGRESS -> {
                    onStateChange(TransferState.Transferring(
                        artifactId = artifactId,
                        artifactName = artifactName,
                        recipientName = recipientName,
                        progress = progress.progress
                    ))
                }
                TransferStatus.COMPLETED -> {
                    // Will be handled after the call returns
                }
                TransferStatus.FAILED -> {
                    onStateChange(TransferState.Failed(
                        error = progress.error ?: "Transfer failed",
                        artifactId = artifactId,
                        contactId = contactId
                    ))
                }
            }
        }

        if (transferResult.isSuccess) {
            // Transfer complete
            onStateChange(TransferState.Completed(
                artifactName = artifactName,
                recipientName = recipientName
            ))
        } else {
            onStateChange(TransferState.Failed(
                error = transferResult.exceptionOrNull()?.message ?: "Transfer failed",
                artifactId = artifactId,
                contactId = contactId
            ))
        }

    } catch (e: Exception) {
        android.util.Log.e("Transfer", "Transfer failed", e)
        onStateChange(TransferState.Failed(
            error = e.message ?: "Unknown error during transfer",
            artifactId = artifactId,
            contactId = contactId
        ))
    }
}


/**
 * Dialog for selecting a contact to transfer an artifact to.
 */
@Composable
private fun TransferContactSelectionDialog(
    artifactName: String,
    contacts: List<ContactItem>,
    onContactSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            androidx.compose.material3.Text("Send '$artifactName'")
        },
        text = {
            if (contacts.isEmpty()) {
                androidx.compose.material3.Text(
                    "No contacts available.\n\nAdd a contact first to share artifacts."
                )
            } else {
                androidx.compose.foundation.layout.Column {
                    androidx.compose.material3.Text(
                        "Select recipient:",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium
                    )
                    androidx.compose.foundation.layout.Spacer(
                        modifier = Modifier.height(8.dp)
                    )
                    contacts.forEach { contact ->
                        androidx.compose.material3.TextButton(
                            onClick = { onContactSelected(contact.id) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            androidx.compose.material3.Text(
                                text = contact.petname,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                androidx.compose.material3.Text("Cancel")
            }
        },
        containerColor = YoursColors.Surface
    )
}

/**
 * Dialog showing transfer progress.
 */
@Composable
private fun TransferProgressDialog(
    message: String,
    progress: Float?,
    onCancel: (() -> Unit)?
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { /* Cannot dismiss during transfer */ },
        title = {
            androidx.compose.material3.Text("Transfer")
        },
        text = {
            androidx.compose.foundation.layout.Column(
                horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (progress != null) {
                    androidx.compose.material3.LinearProgressIndicator(
                        progress = progress,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp),
                        color = YoursColors.Primary
                    )
                    androidx.compose.material3.Text(
                        text = "${(progress * 100).toInt()}%",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium
                    )
                } else {
                    androidx.compose.material3.CircularProgressIndicator(
                        modifier = Modifier.padding(16.dp),
                        color = YoursColors.Primary
                    )
                }
                androidx.compose.foundation.layout.Spacer(modifier = Modifier.height(8.dp))
                androidx.compose.material3.Text(
                    text = message,
                    style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        },
        confirmButton = {},
        dismissButton = {
            if (onCancel != null) {
                androidx.compose.material3.TextButton(onClick = onCancel) {
                    androidx.compose.material3.Text("Cancel")
                }
            }
        },
        containerColor = YoursColors.Surface
    )
}

/**
 * Dialog shown when transfer completes successfully.
 */
@Composable
private fun TransferCompletedDialog(
    artifactName: String,
    recipientName: String,
    onDismiss: () -> Unit
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            androidx.compose.material3.Text("Transfer Complete")
        },
        text = {
            androidx.compose.material3.Text(
                "'$artifactName' has been sent to $recipientName.\n\n" +
                "The artifact was encrypted with their public key and delivered via MeshCore."
            )
        },
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                androidx.compose.material3.Text("OK")
            }
        },
        containerColor = YoursColors.Surface
    )
}

/**
 * Dialog shown when transfer fails.
 */
@Composable
private fun TransferFailedDialog(
    error: String,
    onRetry: () -> Unit,
    onDismiss: () -> Unit
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            androidx.compose.material3.Text("Transfer Failed")
        },
        text = {
            androidx.compose.material3.Text(
                "Failed to transfer artifact:\n\n$error"
            )
        },
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = onRetry) {
                androidx.compose.material3.Text("Retry")
            }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                androidx.compose.material3.Text("Cancel")
            }
        },
        containerColor = YoursColors.Surface
    )
}

/**
 * Serialize an artifact for transfer.
 * Uses the same format as VaultStorage for compatibility.
 */
private fun serializeArtifactForTransfer(artifact: Artifact): ByteArray {
    val buffer = mutableListOf<Byte>()

    // Version
    buffer.add(0x01)

    // ID
    val idBytes = artifact.id.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
    buffer.addAll(intToBytes(idBytes.size).toList())
    buffer.addAll(idBytes.toList())

    // Content type
    val contentTypeBytes = artifact.contentType.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
    buffer.addAll(intToBytes(contentTypeBytes.size).toList())
    buffer.addAll(contentTypeBytes.toList())

    // Content hash
    buffer.addAll(artifact.contentHash.toList())

    // Created at
    buffer.addAll(longToBytes(artifact.createdAt).toList())

    // Owner DID
    if (artifact.ownerDid != null) {
        val ownerBytes = artifact.ownerDid.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(ownerBytes.size).toList())
        buffer.addAll(ownerBytes.toList())
    } else {
        buffer.addAll(intToBytes(0).toList())
    }

    // Metadata
    val metadataBytes = serializeMetadataForTransfer(artifact.metadata)
    buffer.addAll(intToBytes(metadataBytes.size).toList())
    buffer.addAll(metadataBytes.toList())

    // Encrypted content
    buffer.addAll(intToBytes(artifact.encryptedContent.size).toList())
    buffer.addAll(artifact.encryptedContent.toList())

    return buffer.toByteArray()
}

/**
 * Serialize artifact metadata to bytes.
 */
private fun serializeMetadataForTransfer(metadata: ArtifactMetadata): ByteArray {
    val sb = StringBuilder()
    sb.append("{")
    metadata.name?.let { sb.append("\"name\":\"$it\",") }
    metadata.description?.let { sb.append("\"desc\":\"$it\",") }
    if (metadata.tags.isNotEmpty()) {
        sb.append("\"tags\":[${metadata.tags.joinToString(",") { "\"$it\"" }}]")
    }
    sb.append("}")
    return sb.toString().toByteArray(java.nio.charset.StandardCharsets.UTF_8)
}

/**
 * Convert an Int to a 4-byte big-endian array.
 */
private fun intToBytes(value: Int): ByteArray {
    return byteArrayOf(
        (value shr 24).toByte(),
        (value shr 16).toByte(),
        (value shr 8).toByte(),
        value.toByte()
    )
}

/**
 * Convert a Long to an 8-byte big-endian array.
 */
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
