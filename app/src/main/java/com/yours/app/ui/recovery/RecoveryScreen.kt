package com.yours.app.ui.recovery

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import com.yours.app.ui.components.SecurePassphraseInput
import com.yours.app.ui.components.SecurityGatedContent
import com.yours.app.ui.components.toUtf8Bytes
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.crypto.BedrockCore
import com.yours.app.security.SecurityGate
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * Passphrase-Only Recovery Screen
 *
 * Recovery is simple and honest:
 * 1. Enter your 4-word passphrase
 * 2. Identity keys are derived deterministically
 * 3. Done.
 *
 * No guardians. No mesh nodes. No social graph.
 * Your passphrase IS your identity.
 *
 * If you lose your passphrase, you lose everything.
 * This is the cost of true sovereignty.
 */

/**
 * Fix #17: Removed masterKey from Compose state to prevent debugger exposure.
 * The Success state no longer holds sensitive key material.
 * Keys are passed directly to callback and zeroized immediately.
 */
sealed class RecoveryState {
    object EnterPassphrase : RecoveryState()
    data class Recovering(val passphrase: ByteArray) : RecoveryState()
    object Success : RecoveryState()  // No longer stores masterKey
    data class Error(val message: String) : RecoveryState()
}

@Composable
fun RecoveryScreen(
    onRecovered: (masterKey: ByteArray) -> Unit,
    onCancel: () -> Unit,
    onRequestCameraPermission: (() -> Unit) -> Unit = { it() } // Kept for API compatibility
) {
    // SECURITY GATE: Recovery operations require CRITICAL security level
    // This prevents identity recovery on compromised devices where:
    // - Keyloggers could capture the recovery phrase
    // - MITM infrastructure could intercept derived keys
    // - Device integrity is compromised
    SecurityGatedContent(
        level = SecurityGate.SecurityLevel.CRITICAL,
        operationName = "Identity Recovery",
        onClose = onCancel
    ) {
        RecoveryScreenContent(
            onRecovered = onRecovered,
            onCancel = onCancel
        )
    }
}

@Composable
private fun RecoveryScreenContent(
    onRecovered: (masterKey: ByteArray) -> Unit,
    onCancel: () -> Unit
) {
    var state by remember { mutableStateOf<RecoveryState>(RecoveryState.EnterPassphrase) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        Column(
            modifier = Modifier.fillMaxSize()
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = when (state) {
                        RecoveryState.EnterPassphrase -> "Recover Identity"
                        is RecoveryState.Recovering -> "Recovering..."
                        is RecoveryState.Success -> "Recovery Complete"
                        is RecoveryState.Error -> "Recovery Failed"
                    },
                    style = MaterialTheme.typography.headlineMedium,
                    color = YoursColors.OnBackground
                )

                IconButton(onClick = onCancel) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = YoursColors.OnBackgroundMuted
                    )
                }
            }

            // Content
            AnimatedContent(
                targetState = state,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) { currentState ->
                when (currentState) {
                    RecoveryState.EnterPassphrase -> {
                        PassphraseEntryContent(
                            onSubmit = { passphrase ->
                                state = RecoveryState.Recovering(passphrase)
                            }
                        )
                    }

                    is RecoveryState.Recovering -> {
                        RecoveringContent()

                        LaunchedEffect(currentState.passphrase) {
                            try {
                                // Fix #2: Derive salt from passphrase hash instead of using zero salt
                                // This ensures each passphrase gets a unique salt while still being deterministic
                                // Domain separator "YOURS_RECOVERY_SALT_V1" prevents collisions with other uses
                                val passphraseCopy = currentState.passphrase.copyOf()
                                val salt = withContext(Dispatchers.Default) {
                                    BedrockCore.sha3_256(
                                        "YOURS_RECOVERY_SALT_V1".toByteArray() + passphraseCopy
                                    )
                                }

                                val masterKey = withContext(Dispatchers.Default) {
                                    BedrockCore.deriveKey(passphraseCopy, salt)
                                }

                                // Fix #6: Zeroize passphrase after use
                                BedrockCore.zeroize(passphraseCopy)
                                BedrockCore.zeroize(currentState.passphrase)

                                if (masterKey.isNotEmpty()) {
                                    // Fix #17: Pass key directly to callback, don't store in state
                                    // Make a copy for the callback since we'll zeroize
                                    val keyCopy = masterKey.copyOf()
                                    BedrockCore.zeroize(masterKey)
                                    state = RecoveryState.Success
                                    // Callback is called after state update
                                    onRecovered(keyCopy)
                                } else {
                                    state = RecoveryState.Error("Failed to derive keys")
                                }
                            } catch (e: Exception) {
                                // Ensure zeroization even on error
                                BedrockCore.zeroize(currentState.passphrase)
                                state = RecoveryState.Error(e.message ?: "Recovery failed")
                            }
                        }
                    }

                    is RecoveryState.Success -> {
                        // Fix #17: Success state no longer holds keys
                        SuccessContent(
                            onDone = {
                                // Key already passed via callback, just dismiss
                            }
                        )
                    }

                    is RecoveryState.Error -> {
                        ErrorContent(
                            message = currentState.message,
                            onRetry = {
                                state = RecoveryState.EnterPassphrase
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PassphraseEntryContent(onSubmit: (ByteArray) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Enter Your 8 Words",
            style = MaterialTheme.typography.headlineSmall,
            color = YoursColors.OnBackground,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Your passphrase is your identity",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(24.dp))

        // SECURE: Uses in-app keyboard, no system IME
        SecurePassphraseInput(
            hint = "Enter your 8 words",
            minWords = 8,
            randomizeLayout = false,
            onSubmit = { charArray ->
                // Convert to ByteArray and submit
                val bytes = charArray.toUtf8Bytes()
                // Zeroize the CharArray
                charArray.fill('\u0000')
                onSubmit(bytes)
            },
            onCancel = null
        )

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            colors = CardDefaults.cardColors(
                containerColor = YoursColors.SurfaceVariant
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = "No passphrase = No recovery",
                    style = MaterialTheme.typography.labelMedium,
                    color = YoursColors.Warning,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "There are no guardians, no customer support, no backdoors.",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnSurface,
                    lineHeight = 16.sp
                )
            }
        }
    }
}

@Composable
private fun RecoveringContent() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            color = YoursColors.Primary,
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Deriving your identity...",
            style = MaterialTheme.typography.titleMedium,
            color = YoursColors.OnBackground
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Regenerating keys from passphrase",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted
        )
    }
}

@Composable
private fun SuccessContent(
    onDone: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "\u2705",
            style = MaterialTheme.typography.displayLarge
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Identity Recovered",
            style = MaterialTheme.typography.headlineSmall,
            color = YoursColors.OnBackground,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Your keys have been regenerated from your passphrase.",
            style = MaterialTheme.typography.bodyLarge,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onDone,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = YoursColors.Primary,
                contentColor = YoursColors.OnPrimary
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Continue", fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun ErrorContent(
    message: String,
    onRetry: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Recovery Failed",
            style = MaterialTheme.typography.headlineSmall,
            color = YoursColors.Error,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(24.dp))

        Card(
            colors = CardDefaults.cardColors(
                containerColor = YoursColors.Surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Check your passphrase",
                    style = MaterialTheme.typography.labelMedium,
                    color = YoursColors.OnSurface,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Make sure you entered exactly the 8 words " +
                            "you wrote down during setup, in the correct order.",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted,
                    lineHeight = 18.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = onRetry,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = YoursColors.Primary
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Try Again", fontWeight = FontWeight.Bold)
        }
    }
}
