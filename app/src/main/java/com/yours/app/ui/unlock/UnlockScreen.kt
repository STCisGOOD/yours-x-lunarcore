package com.yours.app.ui.unlock

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.identity.IdentityManager
import com.yours.app.security.AuthPreferences
import com.yours.app.security.HumanCentricAuth
import com.yours.app.security.OpsecManager
import com.yours.app.security.RateLimitException
import com.yours.app.security.SigilManager
import com.yours.app.security.ThreatDetector
import com.yours.app.ui.components.ConstellationAuthCanvas
import com.yours.app.ui.components.ConstellationMode
import com.yours.app.ui.components.PatternSigilCanvas
import com.yours.app.ui.components.PatternMode
import com.yours.app.ui.components.SecurePassphraseInput
import com.yours.app.ui.components.toUtf8Bytes
import com.yours.app.ui.components.zeroize
import com.yours.app.ui.theme.GluspFontFamily
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.launch

/**
 * Secure Unlock Screen - The Lunarpunk Vow
 *
 * Supports two authentication methods:
 * - Sigil: Traditional 6x6 grid pattern (SigilManager)
 * - Constellation: Enhanced 7x5 grid with timing/pressure (HumanCentricAuth)
 *
 * Fallback method: 8-word passphrase
 *
 * Security features:
 * - Rate limiting on failed attempts
 * - Threat detection before unlock
 * - Duress passphrase triggers panic wipe
 * - ~61-80 bit security from pattern + device binding
 */

sealed class UnlockState {
    object SigilMode : UnlockState()
    object ConstellationMode : UnlockState()
    object PassphraseMode : UnlockState()
    object Unlocking : UnlockState()
    data class SecurityWarning(val threats: List<ThreatDetector.DetectedThreat>) : UnlockState()
    data class Error(val message: String, val attemptsRemaining: Int = 0, val authMethod: AuthPreferences.AuthMethod = AuthPreferences.AuthMethod.SIGIL) : UnlockState()
    data class LockedOut(val remainingMs: Long) : UnlockState()
    object WipedDueToFailedAttempts : UnlockState() // Identity wiped after too many wrong attempts
}

@Composable
fun UnlockScreen(
    userName: String,
    sigilManager: SigilManager,
    humanCentricAuth: HumanCentricAuth? = null,
    onUnlockWithPassphrase: suspend (passphraseBytes: ByteArray) -> IdentityManager.UnlockResult,
    onUnlockWithMasterKey: suspend (masterKey: ByteArray) -> IdentityManager.UnlockResult = { _ ->
        IdentityManager.UnlockResult.Failed("Master key unlock not configured")
    },
    onRecover: () -> Unit = {},
    onIdentityWiped: () -> Unit = {},  // Called after panic wipe to navigate to Genesis
    isReauthentication: Boolean = false,  // True when re-authenticating for sensitive operations
    reauthMessage: String? = null  // Custom message for re-authentication context
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val opsecManager = remember { OpsecManager(context) }
    val authPreferences = remember { AuthPreferences.getInstance(context) }

    // SECURITY AUDIT FIX #7: Persist sigil rate limiting across app restarts
    val sigilRateLimitFile = remember { java.io.File(context.filesDir, "sigil_attempts.enc") }
    val constellationRateLimitFile = remember { java.io.File(context.filesDir, "constellation_attempts.enc") }
    val secureDeviceKey = remember { com.yours.app.security.SecureDeviceKey.getInstance(context) }

    // Load persisted sigil attempts on startup
    var sigilAttempts by remember {
        mutableStateOf(
            try {
                if (sigilRateLimitFile.exists()) {
                    val deviceKey = secureDeviceKey.getDeviceKey()
                    val decrypted = com.yours.app.crypto.BedrockCore.aesDecrypt(
                        deviceKey, sigilRateLimitFile.readBytes(), byteArrayOf()
                    )
                    com.yours.app.crypto.BedrockCore.zeroize(deviceKey)
                    decrypted?.get(0)?.toInt() ?: 0
                } else 0
            } catch (e: Exception) { 0 }
        )
    }
    var sigilLockedOut by remember { mutableStateOf(sigilAttempts >= 3) }

    // Load persisted constellation attempts on startup
    var constellationAttempts by remember {
        mutableStateOf(
            try {
                if (constellationRateLimitFile.exists()) {
                    val deviceKey = secureDeviceKey.getDeviceKey()
                    val decrypted = com.yours.app.crypto.BedrockCore.aesDecrypt(
                        deviceKey, constellationRateLimitFile.readBytes(), byteArrayOf()
                    )
                    com.yours.app.crypto.BedrockCore.zeroize(deviceKey)
                    decrypted?.get(0)?.toInt() ?: 0
                } else 0
            } catch (e: Exception) { 0 }
        )
    }
    var constellationLockedOut by remember { mutableStateOf(constellationAttempts >= 5) }

    // Persist sigil attempts when changed
    fun persistSigilAttempts(attempts: Int) {
        try {
            val deviceKey = secureDeviceKey.getDeviceKey()
            val encrypted = com.yours.app.crypto.BedrockCore.aesEncrypt(
                deviceKey, byteArrayOf(attempts.toByte()), byteArrayOf()
            )
            sigilRateLimitFile.writeBytes(encrypted)
            com.yours.app.crypto.BedrockCore.zeroize(deviceKey)
        } catch (e: Exception) { /* best effort */ }
    }

    // Persist constellation attempts when changed
    fun persistConstellationAttempts(attempts: Int) {
        try {
            val deviceKey = secureDeviceKey.getDeviceKey()
            val encrypted = com.yours.app.crypto.BedrockCore.aesEncrypt(
                deviceKey, byteArrayOf(attempts.toByte()), byteArrayOf()
            )
            constellationRateLimitFile.writeBytes(encrypted)
            com.yours.app.crypto.BedrockCore.zeroize(deviceKey)
        } catch (e: Exception) { /* best effort */ }
    }

    // Check which auth methods are set up
    val hasSigil = remember { sigilManager.hasSigil() }
    val hasConstellation = remember { authPreferences.isConstellationSetup && humanCentricAuth != null }
    val configuredMethod = remember { authPreferences.authMethod }

    // Determine initial state based on configured auth method
    var state by remember {
        mutableStateOf<UnlockState>(
            when {
                configuredMethod == AuthPreferences.AuthMethod.CONSTELLATION && hasConstellation && !constellationLockedOut ->
                    UnlockState.ConstellationMode
                configuredMethod == AuthPreferences.AuthMethod.SIGIL && hasSigil && !sigilLockedOut ->
                    UnlockState.SigilMode
                hasSigil && !sigilLockedOut ->
                    UnlockState.SigilMode
                hasConstellation && !constellationLockedOut ->
                    UnlockState.ConstellationMode
                else ->
                    UnlockState.PassphraseMode
            }
        )
    }
    var showSecurityDetails by remember { mutableStateOf(false) }

    // Observe panic wipe state - navigate to Genesis after wipe
    val panicTriggered by opsecManager.panicTriggered.collectAsState()
    LaunchedEffect(panicTriggered) {
        if (panicTriggered) {
            // Brief delay then navigate to Genesis (fresh start)
            kotlinx.coroutines.delay(500)
            onIdentityWiped()
        }
    }

    // Handle wipe due to failed attempts
    LaunchedEffect(state) {
        if (state is UnlockState.WipedDueToFailedAttempts) {
            // Identity was wiped due to too many failed attempts - navigate to Genesis
            kotlinx.coroutines.delay(500)
            onIdentityWiped()
        }
    }

    // Check for security threats on screen load
    LaunchedEffect(Unit) {
        val report = ThreatDetector.scan(context)
        if (report.hasCriticalThreats || report.hasHighThreats) {
            state = UnlockState.SecurityWarning(report.actualThreats)
        }
    }

    // Handle lockout countdown
    LaunchedEffect(state) {
        if (state is UnlockState.LockedOut) {
            val lockedState = state as UnlockState.LockedOut
            kotlinx.coroutines.delay(1000)
            val newRemaining = lockedState.remainingMs - 1000
            if (newRemaining > 0) {
                state = UnlockState.LockedOut(newRemaining)
            } else {
                // Return to appropriate auth method based on lockout status
                state = when {
                    configuredMethod == AuthPreferences.AuthMethod.CONSTELLATION && hasConstellation && !constellationLockedOut ->
                        UnlockState.ConstellationMode
                    hasSigil && !sigilLockedOut ->
                        UnlockState.SigilMode
                    hasConstellation && !constellationLockedOut ->
                        UnlockState.ConstellationMode
                    else ->
                        UnlockState.PassphraseMode
                }
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            // Identity badge with single frame
            Box(
                modifier = Modifier
                    .border(1.dp, YoursColors.Primary, RoundedCornerShape(0.dp))
                    .padding(horizontal = 24.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // [ YOURS ] tag
                    Text(
                        text = "[ YOURS ]",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = GluspFontFamily
                        ),
                        color = YoursColors.Primary,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    // Username - large
                    Text(
                        text = if (isReauthentication) "VERIFY" else userName.uppercase(),
                        style = MaterialTheme.typography.headlineLarge,
                        color = YoursColors.OnBackground,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 4.sp,
                        textAlign = TextAlign.Center
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Instruction text
            Text(
                text = if (isReauthentication) (reauthMessage ?: "DRAW YOUR CONSTELLATION") else "DRAW YOUR CONSTELLATION",
                style = MaterialTheme.typography.labelMedium,
                color = YoursColors.OnBackgroundMuted,
                letterSpacing = 2.sp,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Katakana hint
            Text(
                text = "星座を入力",
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.PrimaryDim,
                letterSpacing = 3.sp,
                fontSize = 10.sp
            )

            Spacer(modifier = Modifier.height(16.dp))

            // State-based content
            AnimatedContent(
                targetState = state,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) { currentState ->
                when (currentState) {
                    is UnlockState.SecurityWarning -> {
                        SecurityWarningContent(
                            threats = currentState.threats,
                            showDetails = showSecurityDetails,
                            onToggleDetails = { showSecurityDetails = !showSecurityDetails },
                            onProceedAnyway = {
                                state = when {
                                    configuredMethod == AuthPreferences.AuthMethod.CONSTELLATION && hasConstellation ->
                                        UnlockState.ConstellationMode
                                    hasSigil ->
                                        UnlockState.SigilMode
                                    hasConstellation ->
                                        UnlockState.ConstellationMode
                                    else ->
                                        UnlockState.PassphraseMode
                                }
                            },
                            onCancel = onRecover
                        )
                    }

                    is UnlockState.ConstellationMode -> {
                        ConstellationUnlockContent(
                            humanCentricAuth = humanCentricAuth!!,
                            onUnlock = { masterKey ->
                                state = UnlockState.Unlocking
                                scope.launch {
                                    try {
                                        val result = onUnlockWithMasterKey(masterKey)
                                        state = handleUnlockResult(result, AuthPreferences.AuthMethod.CONSTELLATION)
                                        // Reset constellation attempts on success
                                        if (result is IdentityManager.UnlockResult.Success) {
                                            constellationAttempts = 0
                                            persistConstellationAttempts(0)
                                        }
                                    } catch (e: Exception) {
                                        state = UnlockState.Error(
                                            e.message ?: "Unlock failed",
                                            authMethod = AuthPreferences.AuthMethod.CONSTELLATION
                                        )
                                    } finally {
                                        com.yours.app.crypto.BedrockCore.zeroize(masterKey)
                                    }
                                }
                            },
                            onConstellationFailed = { errorMessage ->
                                constellationAttempts++
                                persistConstellationAttempts(constellationAttempts)
                                if (constellationAttempts >= 5) {
                                    constellationLockedOut = true
                                    state = UnlockState.Error(
                                        "Constellation not recognized. Use your passphrase.",
                                        authMethod = AuthPreferences.AuthMethod.CONSTELLATION
                                    )
                                } else {
                                    state = UnlockState.Error(
                                        errorMessage ?: "Constellation not recognized",
                                        attemptsRemaining = 5 - constellationAttempts,
                                        authMethod = AuthPreferences.AuthMethod.CONSTELLATION
                                    )
                                }
                            },
                            onUsePassphrase = { state = UnlockState.PassphraseMode },
                            onUseSigil = if (hasSigil && !sigilLockedOut) {
                                { state = UnlockState.SigilMode }
                            } else null
                        )
                    }

                    is UnlockState.LockedOut -> {
                        LockoutContent(remainingMs = currentState.remainingMs)
                    }

                    is UnlockState.SigilMode -> {
                        SigilUnlockContent(
                            sigilManager = sigilManager,
                            onUnlock = { passphraseBytes ->
                                state = UnlockState.Unlocking
                                scope.launch {
                                    try {
                                        val result = onUnlockWithPassphrase(passphraseBytes)
                                        state = handleUnlockResult(result, AuthPreferences.AuthMethod.SIGIL)
                                        // Reset sigil attempts on success
                                        if (result is IdentityManager.UnlockResult.Success) {
                                            sigilAttempts = 0
                                            persistSigilAttempts(0)
                                        }
                                    } catch (e: Exception) {
                                        state = UnlockState.Error(
                                            e.message ?: "Unlock failed",
                                            authMethod = AuthPreferences.AuthMethod.SIGIL
                                        )
                                    }
                                }
                            },
                            onSigilFailed = {
                                sigilAttempts++
                                persistSigilAttempts(sigilAttempts)  // SECURITY FIX #7: Persist across restarts
                                if (sigilAttempts >= 3) {
                                    // After 3 failed sigil attempts, PERMANENTLY lock out sigil
                                    sigilLockedOut = true
                                    state = UnlockState.Error(
                                        "Sigil not recognized. Use your passphrase.",
                                        authMethod = AuthPreferences.AuthMethod.SIGIL
                                    )
                                } else {
                                    state = UnlockState.Error(
                                        "Sigil not recognized",
                                        attemptsRemaining = 3 - sigilAttempts,
                                        authMethod = AuthPreferences.AuthMethod.SIGIL
                                    )
                                }
                            },
                            onUsePassphrase = { state = UnlockState.PassphraseMode },
                            onUseConstellation = if (hasConstellation && !constellationLockedOut) {
                                { state = UnlockState.ConstellationMode }
                            } else null
                        )
                    }

                    is UnlockState.PassphraseMode -> {
                        PassphraseUnlockContent(
                            onSubmit = { passphraseBytes ->
                                state = UnlockState.Unlocking
                                scope.launch {
                                    try {
                                        val result = onUnlockWithPassphrase(passphraseBytes)
                                        state = handleUnlockResult(result, AuthPreferences.AuthMethod.SIGIL)
                                    } catch (e: Exception) {
                                        state = UnlockState.Error(
                                            e.message ?: "Unlock failed",
                                            authMethod = AuthPreferences.AuthMethod.SIGIL
                                        )
                                    }
                                }
                            },
                            // Allow switching to sigil if available and not locked out
                            onUseSigil = if (hasSigil && !sigilLockedOut) {
                                { state = UnlockState.SigilMode }
                            } else null,
                            // Allow switching to constellation if available and not locked out
                            onUseConstellation = if (hasConstellation && !constellationLockedOut) {
                                { state = UnlockState.ConstellationMode }
                            } else null,
                            // Check for duress phrase on every keystroke
                            onDuressCheck = { enteredText ->
                                val duressPhrase = opsecManager.duressPassphrase
                                if (duressPhrase != null &&
                                    enteredText.trim().equals(duressPhrase.trim(), ignoreCase = true)) {
                                    // DURESS TRIGGERED - Panic wipe!
                                    opsecManager.triggerPanicWipe()
                                    true
                                } else {
                                    false
                                }
                            }
                        )
                    }

                    is UnlockState.Unlocking -> {
                        UnlockingContent()
                    }

                    is UnlockState.Error -> {
                        ErrorContent(
                            message = currentState.message,
                            attemptsRemaining = currentState.attemptsRemaining,
                            onRetry = {
                                state = when {
                                    currentState.authMethod == AuthPreferences.AuthMethod.CONSTELLATION && hasConstellation && !constellationLockedOut ->
                                        UnlockState.ConstellationMode
                                    currentState.authMethod == AuthPreferences.AuthMethod.SIGIL && hasSigil && !sigilLockedOut ->
                                        UnlockState.SigilMode
                                    hasSigil && !sigilLockedOut ->
                                        UnlockState.SigilMode
                                    hasConstellation && !constellationLockedOut ->
                                        UnlockState.ConstellationMode
                                    else ->
                                        UnlockState.PassphraseMode
                                }
                            },
                            onSwitchToPassphrase = { state = UnlockState.PassphraseMode },
                            onSwitchToSigil = if (hasSigil && !sigilLockedOut && currentState.authMethod != AuthPreferences.AuthMethod.SIGIL) {
                                { state = UnlockState.SigilMode }
                            } else null,
                            onSwitchToConstellation = if (hasConstellation && !constellationLockedOut && currentState.authMethod != AuthPreferences.AuthMethod.CONSTELLATION) {
                                { state = UnlockState.ConstellationMode }
                            } else null
                        )
                    }

                    is UnlockState.WipedDueToFailedAttempts -> {
                        // Show brief message - LaunchedEffect will navigate to Genesis
                        WipedContent()
                    }
                }
            }
        }
    }
}

@Composable
private fun WipedContent() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Identity Wiped",
                style = MaterialTheme.typography.headlineMedium,
                color = YoursColors.Error
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Too many failed attempts",
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }
    }
}

private fun handleUnlockResult(result: IdentityManager.UnlockResult, authMethod: AuthPreferences.AuthMethod): UnlockState {
    return when (result) {
        is IdentityManager.UnlockResult.Success -> UnlockState.SigilMode // Will trigger navigation
        is IdentityManager.UnlockResult.Failed -> UnlockState.Error(
            result.reason,
            result.attemptsRemaining,
            authMethod
        )
        is IdentityManager.UnlockResult.LockedOut -> UnlockState.LockedOut(result.remainingMs)
        is IdentityManager.UnlockResult.WipedDueToFailedAttempts -> UnlockState.WipedDueToFailedAttempts
    }
}

@Composable
private fun SigilUnlockContent(
    sigilManager: SigilManager,
    onUnlock: (ByteArray) -> Unit,
    onSigilFailed: () -> Unit,
    onUsePassphrase: () -> Unit,
    onUseConstellation: (() -> Unit)? = null
) {
    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        // Full-screen constellation canvas
        PatternSigilCanvas(
            modifier = Modifier.fillMaxSize(),
            mode = PatternMode.Create,
            onPatternComplete = { pattern ->
                // Verify the pattern
                val passphraseBytes = sigilManager.verifySigil(pattern)
                if (passphraseBytes != null) {
                    onUnlock(passphraseBytes)
                } else {
                    onSigilFailed()
                }
            }
        )

        // Alternative auth options at very bottom (below the 12 dots)
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (onUseConstellation != null) {
                TextButton(onClick = onUseConstellation) {
                    Text(
                        text = "USE ENHANCED SECURITY",
                        style = MaterialTheme.typography.labelMedium,
                        letterSpacing = 2.sp,
                        color = YoursColors.Primary
                    )
                }
            }
            TextButton(onClick = onUsePassphrase) {
                Text(
                    text = "USE PASSPHRASE INSTEAD",
                    fontSize = 10.sp,
                    letterSpacing = 2.sp,
                    color = YoursColors.Primary
                )
            }
        }
    }
}

// Neon glow modifier for constellation frame
private fun Modifier.neonGlow(
    color: androidx.compose.ui.graphics.Color
) = this.drawBehind {
    val glowLayers = listOf(40f to 0.15f, 20f to 0.3f, 10f to 0.5f)
    for ((blur, alpha) in glowLayers) {
        drawIntoCanvas { canvas ->
            val frameworkCanvas = canvas.nativeCanvas
            val paint = android.graphics.Paint().apply {
                this.color = color.copy(alpha = alpha).toArgb()
                this.style = android.graphics.Paint.Style.STROKE
                this.strokeWidth = blur
                this.maskFilter = android.graphics.BlurMaskFilter(
                    blur,
                    android.graphics.BlurMaskFilter.Blur.NORMAL
                )
            }
            frameworkCanvas.drawRect(0f, 0f, size.width, size.height, paint)
        }
    }
}

@Composable
private fun ConstellationUnlockContent(
    humanCentricAuth: HumanCentricAuth,
    onUnlock: (ByteArray) -> Unit,
    onConstellationFailed: (String?) -> Unit,
    onUsePassphrase: () -> Unit,
    onUseSigil: (() -> Unit)? = null
) {
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Constellation canvas
        ConstellationAuthCanvas(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            mode = ConstellationMode.Verify,
            onPatternComplete = { pattern ->
                scope.launch {
                    try {
                        val masterKey = humanCentricAuth.unlock(pattern)
                        if (masterKey != null) {
                            onUnlock(masterKey)
                        } else {
                            onConstellationFailed(null)
                        }
                    } catch (e: RateLimitException) {
                        onConstellationFailed(e.message)
                    } catch (e: Exception) {
                        onConstellationFailed(e.message ?: "Authentication failed")
                    }
                }
            },
            onPatternFailed = {
                onConstellationFailed(null)
            }
        )

        Spacer(modifier = Modifier.height(48.dp))

        // Alternative auth options at bottom
        Column(
            modifier = Modifier.padding(bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (onUseSigil != null) {
                TextButton(onClick = onUseSigil) {
                    Text(
                        text = "USE PATTERN SIGIL",
                        style = MaterialTheme.typography.labelMedium,
                        letterSpacing = 2.sp,
                        color = YoursColors.Primary
                    )
                }
            }
            TextButton(onClick = onUsePassphrase) {
                Text(
                    text = "USE PASSPHRASE INSTEAD",
                    fontSize = 10.sp,
                    letterSpacing = 2.sp,
                    color = YoursColors.Primary
                )
            }
        }
    }
}

@Composable
private fun PassphraseUnlockContent(
    onSubmit: (ByteArray) -> Unit,
    onUseSigil: (() -> Unit)?,
    onUseConstellation: (() -> Unit)? = null,
    onDuressCheck: (String) -> Boolean
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Enter your passphrase",
            style = MaterialTheme.typography.bodyLarge,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(24.dp))

        SecurePassphraseInput(
            hint = "Enter your 8 words",
            minWords = 8,
            randomizeLayout = false,
            onSubmit = { charArray ->
                val passphraseBytes = charArray.toUtf8Bytes()
                charArray.zeroize()
                onSubmit(passphraseBytes)
            },
            onCancel = {},
            onDuressCheck = onDuressCheck
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Show available alternative auth methods
        if (onUseConstellation != null) {
            TextButton(onClick = onUseConstellation) {
                Text(
                    text = "USE ENHANCED SECURITY",
                    style = MaterialTheme.typography.labelMedium,
                    letterSpacing = 2.sp,
                    color = YoursColors.Primary
                )
            }
        }

        if (onUseSigil != null) {
            TextButton(onClick = onUseSigil) {
                Text(
                    text = "USE SIGIL INSTEAD",
                    style = MaterialTheme.typography.labelMedium,
                    letterSpacing = 2.sp,
                    color = YoursColors.OnBackgroundMuted
                )
            }
        }
    }
}

@Composable
private fun UnlockingContent() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(200.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(
                color = YoursColors.Primary,
                modifier = Modifier.size(48.dp)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Unlocking...",
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }
    }
}

@Composable
private fun ErrorContent(
    message: String,
    attemptsRemaining: Int,
    onRetry: () -> Unit,
    onSwitchToPassphrase: () -> Unit,
    onSwitchToSigil: (() -> Unit)? = null,
    onSwitchToConstellation: (() -> Unit)? = null
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, YoursColors.Error.copy(alpha = 0.3f), RoundedCornerShape(0.dp))
                .background(YoursColors.Background)
                .padding(20.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = message.uppercase(),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    letterSpacing = 2.sp,
                    color = YoursColors.Error,
                    textAlign = TextAlign.Center
                )
                if (attemptsRemaining > 0) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "$attemptsRemaining ATTEMPTS REMAINING",
                        fontSize = 10.sp,
                        letterSpacing = 1.sp,
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onRetry,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = YoursColors.Primary),
            shape = RoundedCornerShape(0.dp)
        ) {
            Text(
                text = "TRY AGAIN",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 2.sp
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Show alternative authentication methods
        if (onSwitchToConstellation != null) {
            TextButton(onClick = onSwitchToConstellation) {
                Text(
                    text = "USE CONSTELLATION",
                    fontSize = 10.sp,
                    letterSpacing = 2.sp,
                    color = YoursColors.Primary
                )
            }
        }

        if (onSwitchToSigil != null) {
            TextButton(onClick = onSwitchToSigil) {
                Text(
                    text = "USE PATTERN",
                    fontSize = 10.sp,
                    letterSpacing = 2.sp,
                    color = YoursColors.Gray
                )
            }
        }

        TextButton(onClick = onSwitchToPassphrase) {
            Text(
                text = "USE PASSPHRASE",
                fontSize = 10.sp,
                letterSpacing = 2.sp,
                color = YoursColors.Gray
            )
        }
    }
}

@Composable
private fun SecurityWarningContent(
    threats: List<ThreatDetector.DetectedThreat>,
    showDetails: Boolean,
    onToggleDetails: () -> Unit,
    onProceedAnyway: () -> Unit,
    onCancel: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = YoursColors.Warning.copy(alpha = 0.15f)
            ),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Security Warning",
                    style = MaterialTheme.typography.titleLarge,
                    color = YoursColors.Warning,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Your device may be compromised.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnSurface,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "${threats.size} threat${if (threats.size > 1) "s" else ""} detected",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )

                if (showDetails) {
                    Spacer(modifier = Modifier.height(12.dp))
                    threats.forEach { threat ->
                        Text(
                            text = "- ${threat.description}",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnSurface
                        )
                    }
                }

                TextButton(onClick = onToggleDetails) {
                    Text(
                        text = if (showDetails) "Hide details" else "Show details",
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onProceedAnyway,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = YoursColors.Warning),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Proceed anyway")
        }

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedButton(
            onClick = onCancel,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Cancel")
        }
    }
}

@Composable
private fun LockoutContent(remainingMs: Long) {
    val seconds = (remainingMs / 1000).toInt()
    val minutes = seconds / 60
    val displaySeconds = seconds % 60

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = YoursColors.Error.copy(alpha = 0.1f)
            ),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Too Many Attempts",
                    style = MaterialTheme.typography.titleLarge,
                    color = YoursColors.Error,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Please wait before trying again.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnSurface,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    text = if (minutes > 0) {
                        String.format("%d:%02d", minutes, displaySeconds)
                    } else {
                        "$displaySeconds seconds"
                    },
                    style = MaterialTheme.typography.displaySmall,
                    color = YoursColors.Error,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
