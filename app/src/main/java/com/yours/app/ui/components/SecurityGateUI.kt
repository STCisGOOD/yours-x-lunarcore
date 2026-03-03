package com.yours.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.security.SecurityGate
import com.yours.app.security.Threat
import com.yours.app.security.ThreatSeverity
import com.yours.app.security.checkSecurityGate
import com.yours.app.ui.theme.YoursColors

/**
 * Security Gate UI Components
 *
 * Provides composables for enforcing and displaying security gate status.
 * These components ensure sensitive operations are blocked on compromised devices.
 *
 * Usage:
 * ```
 * SecurityGatedContent(
 *     level = SecurityGate.SecurityLevel.CRITICAL,
 *     operationName = "View Recovery Phrase",
 *     onBlocked = { /* optional callback */ }
 * ) {
 *     // Your sensitive content here
 * }
 * ```
 */

/**
 * Wraps content with a security gate check.
 * Shows blocked UI if security requirements not met.
 *
 * @param level The security level required for this operation
 * @param operationName Human-readable name of the operation (shown in blocked UI)
 * @param onBlocked Optional callback when operation is blocked
 * @param onClose Optional callback to close/navigate away when blocked
 * @param allowBypass If true, shows "I understand the risks" button to proceed anyway
 * @param content The protected content to show if security check passes
 */
@Composable
fun SecurityGatedContent(
    level: SecurityGate.SecurityLevel,
    operationName: String,
    onBlocked: (() -> Unit)? = null,
    onClose: (() -> Unit)? = null,
    allowBypass: Boolean = false,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    var gateResult by remember { mutableStateOf<SecurityGate.GateResult?>(null) }
    var isChecking by remember { mutableStateOf(true) }
    var userBypassed by remember { mutableStateOf(false) }

    // Perform security check on composition
    LaunchedEffect(Unit) {
        gateResult = context.checkSecurityGate(level)
        isChecking = false

        // Call blocked callback if blocked
        if (gateResult is SecurityGate.GateResult.Blocked) {
            onBlocked?.invoke()
        }
    }

    when {
        isChecking -> {
            // Show loading while checking
            SecurityCheckingIndicator()
        }
        userBypassed -> {
            // User acknowledged risks - show content
            content()
        }
        gateResult is SecurityGate.GateResult.Blocked -> {
            // Show blocked UI
            val blocked = gateResult as SecurityGate.GateResult.Blocked
            SecurityBlockedScreen(
                operationName = operationName,
                reason = blocked.reason,
                threats = blocked.threats,
                recommendation = blocked.recommendation,
                onClose = onClose,
                allowBypass = allowBypass,
                onBypass = {
                    android.util.Log.w("SecurityGate",
                        "USER BYPASSED SECURITY GATE: $operationName - " +
                        "Threats: ${blocked.threats.map { it.name }}")
                    userBypassed = true
                }
            )
        }
        else -> {
            // Security check passed - show content
            content()
        }
    }
}

/**
 * Shows a loading indicator while security check is in progress.
 */
@Composable
private fun SecurityCheckingIndicator() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            CircularProgressIndicator(
                color = YoursColors.Primary,
                modifier = Modifier.size(48.dp)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Checking device security...",
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }
    }
}

/**
 * Full-screen blocked UI when security requirements are not met.
 * Styled with YOURS branding.
 */
@Composable
fun SecurityBlockedScreen(
    operationName: String,
    reason: String,
    threats: List<Threat>,
    recommendation: String,
    onClose: (() -> Unit)? = null,
    allowBypass: Boolean = false,
    onBypass: (() -> Unit)? = null
) {
    var showThreatDetails by remember { mutableStateOf(false) }
    var bypassConfirmStep by remember { mutableStateOf(0) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            // Branded header
            Text(
                text = "[ADVISORY]",
                style = MaterialTheme.typography.headlineLarge.copy(
                    fontWeight = FontWeight.Light,
                    letterSpacing = 2.sp
                ),
                color = YoursColors.Warning,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "DEVICE INTEGRITY",
                style = MaterialTheme.typography.labelMedium.copy(
                    letterSpacing = 2.sp
                ),
                color = YoursColors.OnBackgroundMuted,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Explain why this matters
            Text(
                text = "Yours protects your keys, identity, and messages with strong cryptography — but if your device is compromised, that protection means nothing. Malware can read your keys before encryption, log your passphrase as you type it, or intercept messages before they're sent.",
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 8.dp)
            )

            Spacer(modifier = Modifier.height(24.dp))

            // How to fix - scoring explanation
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = YoursColors.Primary.copy(alpha = 0.3f),
                        shape = RoundedCornerShape(4.dp)
                    )
                    .padding(20.dp)
            ) {
                Text(
                    text = "HOW TO FIX",
                    style = MaterialTheme.typography.labelMedium.copy(
                        letterSpacing = 1.sp
                    ),
                    color = YoursColors.Primary
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "We recommend scores above 70.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnBackground,
                    fontWeight = FontWeight.Medium
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Your device was scanned for:",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "• 400+ known surveillance packages (carrier bloatware, tracking SDKs, silent installers)\n" +
                           "• Enabled accessibility services (keylogger vector)\n" +
                           "• Device admin/MDM apps\n" +
                           "• User-installed CA certificates (MITM vector)\n" +
                           "• Security config (ADB, unknown sources, encryption)\n" +
                           "• Root/bootloader status\n" +
                           "• Apps with dangerous permission combos",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted,
                    lineHeight = 18.sp
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Run our device scanner to check your score:",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "stcisgood.com/scanner",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.Primary
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Note section with current threats - compact
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = YoursColors.Error.copy(alpha = 0.3f),
                        shape = RoundedCornerShape(4.dp)
                    )
                    .padding(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${threats.size} issue${if (threats.size != 1) "s" else ""} detected",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.Error
                    )

                    TextButton(
                        onClick = { showThreatDetails = !showThreatDetails },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = if (showThreatDetails) "Hide" else "Details",
                            color = YoursColors.OnBackgroundMuted,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                if (showThreatDetails) {
                    Spacer(modifier = Modifier.height(8.dp))

                    threats.forEach { threat ->
                        ThreatRow(threat)
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            Spacer(modifier = Modifier.height(16.dp))

            // Bypass button if allowed (requires 2-step confirmation)
            if (allowBypass && onBypass != null) {
                when (bypassConfirmStep) {
                    0 -> {
                        OutlinedButton(
                            onClick = { bypassConfirmStep = 1 },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(56.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = YoursColors.Warning
                            ),
                            border = androidx.compose.foundation.BorderStroke(
                                width = 1.dp,
                                color = YoursColors.Warning
                            ),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "[I UNDERSTAND THE RISKS]",
                                style = MaterialTheme.typography.labelLarge.copy(
                                    letterSpacing = 0.5.sp
                                )
                            )
                        }
                    }
                    1 -> {
                        Column {
                            Text(
                                text = "Are you sure? Your keys may be compromised on this device.",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.Error,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(bottom = 12.dp)
                            )
                            Button(
                                onClick = { onBypass() },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(56.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = YoursColors.Error,
                                    contentColor = androidx.compose.ui.graphics.Color.White
                                ),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = "[PROCEED ANYWAY]",
                                    style = MaterialTheme.typography.labelLarge.copy(
                                        letterSpacing = 0.5.sp
                                    )
                                )
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            TextButton(
                                onClick = { bypassConfirmStep = 0 },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Cancel", color = YoursColors.OnBackgroundMuted)
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Close button if provided
            if (onClose != null) {
                OutlinedButton(
                    onClick = onClose,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = YoursColors.OnBackground
                    ),
                    border = androidx.compose.foundation.BorderStroke(
                        width = 1.dp,
                        color = YoursColors.GrayDim
                    ),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = "[GO BACK]",
                        style = MaterialTheme.typography.labelLarge.copy(
                            letterSpacing = 0.5.sp
                        )
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

/**
 * Individual threat row in the details list.
 */
@Composable
private fun ThreatRow(threat: Threat) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        // Severity indicator
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(
                    when (threat.severity) {
                        ThreatSeverity.CRITICAL -> YoursColors.Error
                        ThreatSeverity.HIGH -> YoursColors.Warning
                        ThreatSeverity.MEDIUM -> YoursColors.Warning.copy(alpha = 0.7f)
                        ThreatSeverity.LOW -> YoursColors.OnBackgroundMuted
                    },
                    RoundedCornerShape(4.dp)
                )
        )

        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = threat.name,
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnSurface,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = threat.description,
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted
            )
        }
    }
}

/**
 * Dialog version of security blocked screen for inline usage.
 */
@Composable
fun SecurityBlockedDialog(
    operationName: String,
    reason: String,
    threats: List<Threat>,
    recommendation: String,
    onDismiss: () -> Unit
) {
    var showThreatDetails by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Shield,
                    contentDescription = "Security",
                    tint = YoursColors.Error,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Operation Blocked",
                    color = YoursColors.Error
                )
            }
        },
        text = {
            Column {
                Text(
                    text = "Cannot perform: $operationName",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnSurface
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.Error
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "${threats.size} threat${if (threats.size != 1) "s" else ""} detected",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )

                if (showThreatDetails) {
                    Spacer(modifier = Modifier.height(12.dp))
                    threats.forEach { threat ->
                        Text(
                            text = "- ${threat.name}",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                }

                TextButton(
                    onClick = { showThreatDetails = !showThreatDetails }
                ) {
                    Text(
                        text = if (showThreatDetails) "Hide details" else "Show details",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.Primary
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = YoursColors.Warning.copy(alpha = 0.1f)
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = recommendation,
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnSurface,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Understood")
            }
        },
        containerColor = YoursColors.Surface
    )
}

/**
 * Performs a security check and returns the result.
 * Use this for programmatic checks before operations.
 *
 * @param level The security level to check
 * @return GateResult indicating if operation is allowed or blocked
 */
@Composable
fun rememberSecurityGateCheck(level: SecurityGate.SecurityLevel): State<SecurityGate.GateResult?> {
    val context = LocalContext.current
    val result = remember { mutableStateOf<SecurityGate.GateResult?>(null) }

    LaunchedEffect(level) {
        result.value = context.checkSecurityGate(level)
    }

    return result
}

/**
 * Utility function to check security gate and show dialog if blocked.
 * Returns true if operation should proceed, false if blocked.
 */
@Composable
fun SecurityGateCheck(
    level: SecurityGate.SecurityLevel,
    operationName: String,
    onResult: (allowed: Boolean) -> Unit
) {
    val context = LocalContext.current
    var showBlockedDialog by remember { mutableStateOf(false) }
    var blockedResult by remember { mutableStateOf<SecurityGate.GateResult.Blocked?>(null) }

    LaunchedEffect(Unit) {
        when (val result = context.checkSecurityGate(level)) {
            is SecurityGate.GateResult.Allowed -> {
                onResult(true)
            }
            is SecurityGate.GateResult.Blocked -> {
                blockedResult = result
                showBlockedDialog = true
                onResult(false)
            }
        }
    }

    if (showBlockedDialog && blockedResult != null) {
        SecurityBlockedDialog(
            operationName = operationName,
            reason = blockedResult!!.reason,
            threats = blockedResult!!.threats,
            recommendation = blockedResult!!.recommendation,
            onDismiss = { showBlockedDialog = false }
        )
    }
}
