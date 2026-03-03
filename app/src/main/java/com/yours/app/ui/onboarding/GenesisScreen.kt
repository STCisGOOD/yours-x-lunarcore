package com.yours.app.ui.onboarding

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import com.yours.app.ui.components.SecurePassphraseInput
import com.yours.app.ui.components.Pattern
import com.yours.app.ui.components.PatternSigilCanvas
import com.yours.app.ui.components.PatternMode
import com.yours.app.ui.components.MIN_PATTERN_LENGTH
import com.yours.app.ui.components.SecurityGatedContent
import com.yours.app.ui.components.toUtf8Bytes
import com.yours.app.security.SecurityGate
import com.yours.app.ui.theme.GluspFontFamily
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.delay

/**
 * Genesis - Streamlined identity creation.
 *
 * Flow:
 * 1. Welcome (what this is)
 * 2. Name (who are you)
 * 3. Passphrase (8 recovery words - show when secure)
 * 4. ConfirmWords (re-enter to verify)
 * 5. SigilIntro (explain the sigil ritual)
 * 6. SigilCreate (trace 13 stars to create constellation)
 * 7. SigilConfirm (trace again to confirm)
 * 8. Creating (REAL key generation)
 * 9. Done (enter the app)
 */

sealed class GenesisStep {
    object Welcome : GenesisStep()
    object Name : GenesisStep()
    object Passphrase : GenesisStep()
    object ConfirmWords : GenesisStep()
    object SigilIntro : GenesisStep()
    object SigilCreate : GenesisStep()
    data class SigilConfirm(val firstPattern: Pattern) : GenesisStep()
    object Creating : GenesisStep()
    object Done : GenesisStep()
}

/**
 * SECURITY FIX: Callback now accepts ByteArray for passphrase instead of String.
 * This prevents immutable String objects from lingering in memory.
 * Caller must zeroize the ByteArray after use.
 *
 * The pattern (grid pattern) is also passed for storage. Pattern may be null if
 * the user skipped sigil setup (passphrase-only mode). Caller must handle null
 * pattern gracefully by skipping sigil storage.
 */
@Composable
fun GenesisScreen(
    onComplete: (name: String, passphraseBytes: ByteArray, pattern: Pattern?) -> Unit
) {
    // SECURITY GATE: Identity creation requires CRITICAL security level
    // This prevents creating an identity on a compromised device where:
    // - Keys could be intercepted during generation
    // - Recovery phrase could be captured by keyloggers
    // - Pattern could be recorded for later attack
    // Note: onClose is null because there's no navigation to go back to during genesis
    // allowBypass = true lets users proceed with warning acknowledgment
    SecurityGatedContent(
        level = SecurityGate.SecurityLevel.CRITICAL,
        operationName = "Identity Creation",
        onClose = null, // No back navigation during initial setup
        allowBypass = true // Allow proceeding with risk acknowledgment
    ) {
        GenesisScreenContent(onComplete = onComplete)
    }
}

@Composable
private fun GenesisScreenContent(
    onComplete: (name: String, passphraseBytes: ByteArray, pattern: Pattern?) -> Unit
) {
    var step by remember { mutableStateOf<GenesisStep>(GenesisStep.Welcome) }
    var name by remember { mutableStateOf("") }
    // SECURITY: suggestedPassphrase is for DISPLAY ONLY (user writes it down)
    // The actual passphrase for crypto comes from ConfirmWords input as ByteArray
    var confirmedPassphraseBytes by remember { mutableStateOf<ByteArray?>(null) }
    var pattern by remember { mutableStateOf<Pattern?>(null) }
    var suggestedPassphrase by remember { mutableStateOf(generatePassphrase()) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background),
        contentAlignment = Alignment.Center
    ) {
        AnimatedContent(
            targetState = step,
            transitionSpec = {
                fadeIn(animationSpec = tween(400)) togetherWith
                fadeOut(animationSpec = tween(200))
            }
        ) { currentStep ->
            when (currentStep) {
                GenesisStep.Welcome -> WelcomeScreen(
                    onContinue = { step = GenesisStep.Name }
                )
                GenesisStep.Name -> NameScreen(
                    onNameChosen = {
                        name = it
                        step = GenesisStep.Passphrase
                    }
                )
                GenesisStep.Passphrase -> PassphraseScreen(
                    suggested = suggestedPassphrase,
                    onContinue = {
                        // SECURITY: Don't store passphrase string in state
                        // User will re-enter in ConfirmWords, providing ByteArray
                        step = GenesisStep.ConfirmWords
                    }
                )
                GenesisStep.ConfirmWords -> ConfirmWordsScreen(
                    expectedWords = suggestedPassphrase,
                    onConfirmed = { passphraseBytes ->
                        // SECURITY: Store ByteArray, not String
                        confirmedPassphraseBytes = passphraseBytes
                        step = GenesisStep.SigilIntro
                    },
                    onBack = {
                        // Zeroize if going back
                        confirmedPassphraseBytes?.let {
                            it.fill(0)
                            confirmedPassphraseBytes = null
                        }
                        step = GenesisStep.Passphrase
                    }
                )
                GenesisStep.SigilIntro -> SigilIntroScreen(
                    onBegin = { step = GenesisStep.SigilCreate },
                    onSkip = { step = GenesisStep.Creating } // Allow skipping for now
                )
                GenesisStep.SigilCreate -> PatternCreateScreen(
                    onPatternCreated = { createdPattern ->
                        pattern = createdPattern
                        step = GenesisStep.SigilConfirm(createdPattern)
                    },
                    onBack = { step = GenesisStep.SigilIntro }
                )
                is GenesisStep.SigilConfirm -> PatternConfirmScreen(
                    expectedPattern = currentStep.firstPattern,
                    onConfirmed = { confirmedPattern ->
                        pattern = confirmedPattern
                        step = GenesisStep.Creating
                    },
                    onRetry = {
                        pattern = null
                        step = GenesisStep.SigilCreate
                    }
                )
                GenesisStep.Creating -> CreatingScreen(
                    name = name,
                    onCreated = {
                        step = GenesisStep.Done
                    },
                    doCreate = {
                        // This is where REAL key generation happens
                        // SECURITY: Pass ByteArray directly, caller will zeroize
                        confirmedPassphraseBytes?.let { bytes ->
                            // Pattern may be null if user skipped sigil setup
                            // Caller must handle null pattern gracefully (passphrase-only mode)
                            onComplete(name, bytes, pattern)
                            // Note: Caller is responsible for zeroizing bytes
                        }
                    }
                )
                GenesisStep.Done -> DoneScreen(
                    name = name
                )
            }
        }
    }
}

@Composable
private fun WelcomeScreen(onContinue: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        // Left side Japanese text (vertical)
        Column(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .padding(start = 12.dp),
            verticalArrangement = Arrangement.Center
        ) {
            // Vertical katakana - "オフグリッド" (Off-grid)
            "オフグリッド".forEach { char ->
                Text(
                    text = char.toString(),
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontSize = 10.sp,
                        letterSpacing = 0.sp
                    ),
                    color = YoursColors.OnBackgroundMuted.copy(alpha = 0.4f)
                )
            }
        }

        // Right side Japanese text (vertical)
        Column(
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.Center
        ) {
            // Vertical katakana - "プロトコル" (Protocol)
            "プロトコル".forEach { char ->
                Text(
                    text = char.toString(),
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontSize = 10.sp,
                        letterSpacing = 0.sp
                    ),
                    color = YoursColors.OnBackgroundMuted.copy(alpha = 0.4f)
                )
            }
        }

        // Main content
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(modifier = Modifier.weight(0.5f))

            // Branded logo frame with animated gold line tracing the border
            val infiniteTransition = rememberInfiniteTransition(label = "frame")
            val lineProgress by infiniteTransition.animateFloat(
                initialValue = 0f,
                targetValue = 1f,
                animationSpec = infiniteRepeatable(
                    animation = tween(6000, easing = LinearEasing),
                    repeatMode = RepeatMode.Restart
                ),
                label = "lineTrace"
            )

            val frameColor = YoursColors.PrimaryDim
            val traceColor = YoursColors.Primary
            val traceLength = 0.15f // Length of the tracing line as fraction of perimeter

            Box(
                modifier = Modifier
                    .drawBehind {
                        val strokeWidth = 1.dp.toPx()
                        val cornerRadius = 4.dp.toPx()

                        // Draw base dim border
                        drawRoundRect(
                            color = frameColor,
                            style = Stroke(width = strokeWidth),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(cornerRadius)
                        )

                        // Calculate perimeter for animation
                        val width = size.width
                        val height = size.height
                        val perimeter = 2 * (width + height) - 8 * cornerRadius + 2 * Math.PI.toFloat() * cornerRadius

                        // Draw animated trace line
                        val traceStart = lineProgress * perimeter
                        val traceEnd = (lineProgress + traceLength) * perimeter

                        // Draw the trace as segments around the perimeter
                        val path = androidx.compose.ui.graphics.Path()

                        // Helper to get point on perimeter
                        fun getPerimeterPoint(distance: Float): Offset {
                            var d = distance % perimeter
                            if (d < 0) d += perimeter

                            val topWidth = width - 2 * cornerRadius
                            val rightHeight = height - 2 * cornerRadius
                            val bottomWidth = width - 2 * cornerRadius
                            val leftHeight = height - 2 * cornerRadius
                            val cornerArc = (Math.PI.toFloat() / 2) * cornerRadius

                            // Top edge (left to right)
                            if (d < topWidth) {
                                return Offset(cornerRadius + d, 0f)
                            }
                            d -= topWidth

                            // Top-right corner
                            if (d < cornerArc) {
                                val angle = -Math.PI.toFloat() / 2 + (d / cornerRadius)
                                return Offset(
                                    width - cornerRadius + cornerRadius * kotlin.math.cos(angle),
                                    cornerRadius + cornerRadius * kotlin.math.sin(angle)
                                )
                            }
                            d -= cornerArc

                            // Right edge
                            if (d < rightHeight) {
                                return Offset(width, cornerRadius + d)
                            }
                            d -= rightHeight

                            // Bottom-right corner
                            if (d < cornerArc) {
                                val angle = 0f + (d / cornerRadius)
                                return Offset(
                                    width - cornerRadius + cornerRadius * kotlin.math.cos(angle),
                                    height - cornerRadius + cornerRadius * kotlin.math.sin(angle)
                                )
                            }
                            d -= cornerArc

                            // Bottom edge (right to left)
                            if (d < bottomWidth) {
                                return Offset(width - cornerRadius - d, height)
                            }
                            d -= bottomWidth

                            // Bottom-left corner
                            if (d < cornerArc) {
                                val angle = Math.PI.toFloat() / 2 + (d / cornerRadius)
                                return Offset(
                                    cornerRadius + cornerRadius * kotlin.math.cos(angle),
                                    height - cornerRadius + cornerRadius * kotlin.math.sin(angle)
                                )
                            }
                            d -= cornerArc

                            // Left edge (bottom to top)
                            if (d < leftHeight) {
                                return Offset(0f, height - cornerRadius - d)
                            }
                            d -= leftHeight

                            // Top-left corner
                            val angle = Math.PI.toFloat() + (d / cornerRadius)
                            return Offset(
                                cornerRadius + cornerRadius * kotlin.math.cos(angle),
                                cornerRadius + cornerRadius * kotlin.math.sin(angle)
                            )
                        }

                        // Draw trace line segments
                        val segments = 30
                        for (i in 0 until segments) {
                            val segStart = traceStart + (traceEnd - traceStart) * i / segments
                            val segEnd = traceStart + (traceEnd - traceStart) * (i + 1) / segments
                            val p1 = getPerimeterPoint(segStart)
                            val p2 = getPerimeterPoint(segEnd)

                            // Fade the trace at the tail
                            val alpha = (i.toFloat() / segments).coerceIn(0f, 1f)
                            drawLine(
                                color = traceColor.copy(alpha = alpha),
                                start = p1,
                                end = p2,
                                strokeWidth = strokeWidth * 2,
                                cap = StrokeCap.Round
                            )
                        }
                    }
                    .padding(16.dp)
            ) {
                YoursLogoFrame()
            }

            Spacer(modifier = Modifier.height(48.dp))

            Text(
                text = "Your keys.",
                style = MaterialTheme.typography.displayMedium,
                color = YoursColors.OnBackground
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Your data.",
                style = MaterialTheme.typography.displayMedium,
                color = YoursColors.OnBackground
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Yours.",
                style = MaterialTheme.typography.displayMedium,
                color = YoursColors.Primary
            )

            Spacer(modifier = Modifier.weight(1f))

            PrimaryButton(
                text = "[CREATE IDENTITY]",
                onClick = onContinue
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Bottom coordinates text
            Text(
                text = "OFF-GRID MESH PROTOCOL",
                style = MaterialTheme.typography.labelSmall.copy(
                    letterSpacing = 2.sp,
                    fontSize = 9.sp
                ),
                color = YoursColors.OnBackgroundMuted.copy(alpha = 0.5f)
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "LAT 40.703639 — LONG -73.984888",
                style = MaterialTheme.typography.labelSmall.copy(
                    letterSpacing = 1.sp,
                    fontSize = 8.sp
                ),
                color = YoursColors.OnBackgroundMuted.copy(alpha = 0.3f)
            )

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun NameScreen(onNameChosen: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current

    LaunchedEffect(Unit) {
        delay(300)
        focusRequester.requestFocus()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Step indicator
        Text(
            text = "01 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "[NAME]",
            style = MaterialTheme.typography.headlineLarge.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "This name stays on your device.\nIt's just for you.",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(32.dp))

        BasicTextField(
            value = name,
            onValueChange = { name = it },
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester),
            textStyle = MaterialTheme.typography.headlineMedium.copy(
                color = YoursColors.OnBackground,
                textAlign = TextAlign.Center
            ),
            singleLine = true,
            cursorBrush = SolidColor(YoursColors.Primary),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Words,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (name.isNotBlank()) {
                        focusManager.clearFocus()
                        onNameChosen(name.trim())
                    }
                }
            ),
            decorationBox = { innerTextField ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            width = 1.dp,
                            color = YoursColors.PrimaryDim,
                            shape = RoundedCornerShape(4.dp)
                        )
                        .background(
                            YoursColors.Background,
                            RoundedCornerShape(4.dp)
                        )
                        .padding(20.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (name.isEmpty()) {
                        Text(
                            text = "Enter your name",
                            style = MaterialTheme.typography.headlineMedium,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                    innerTextField()
                }
            }
        )

        Spacer(modifier = Modifier.height(48.dp))

        PrimaryButton(
            text = "[CONTINUE]",
            enabled = name.isNotBlank(),
            onClick = { onNameChosen(name.trim()) }
        )
    }
}

@Composable
private fun PassphraseScreen(
    suggested: String,
    onContinue: () -> Unit
) {
    val suggestedWords = suggested.split(" ")
    var wordsRevealed by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Step indicator
        Text(
            text = "02 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "[RECOVERY WORDS]",
            style = MaterialTheme.typography.headlineLarge.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = if (!wordsRevealed)
                "These 8 words are your only way to recover\nyour identity if you lose access."
            else
                "Write these down in order.\nStore them somewhere only you can access.",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Word grid - 2 columns, 4 rows for 8 words
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    width = 1.dp,
                    color = YoursColors.PrimaryDim,
                    shape = RoundedCornerShape(4.dp)
                )
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            for (row in 0 until 4) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    for (col in 0 until 2) {
                        val index = row * 2 + col
                        if (index < suggestedWords.size) {
                            // Individual word box
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .border(
                                        width = 1.dp,
                                        color = YoursColors.GrayDim,
                                        shape = RoundedCornerShape(2.dp)
                                    )
                                    .padding(12.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "${index + 1}.",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = YoursColors.OnBackgroundMuted,
                                        modifier = Modifier.width(24.dp)
                                    )

                                    if (wordsRevealed) {
                                        Text(
                                            text = suggestedWords[index],
                                            style = MaterialTheme.typography.bodyLarge.copy(
                                                fontWeight = FontWeight.Medium
                                            ),
                                            color = YoursColors.OnBackground
                                        )
                                    } else {
                                        // Hidden dots
                                        Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
                                            repeat(suggestedWords[index].length.coerceAtMost(6)) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(6.dp)
                                                        .clip(CircleShape)
                                                        .background(YoursColors.GrayDim)
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (!wordsRevealed) {
            // Security prompt
            Text(
                text = "Make sure no one can see your screen.",
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.Warning,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(16.dp))

            SecondaryButton(
                text = "[SHOW RECOVERY WORDS]",
                onClick = { wordsRevealed = true }
            )
        } else {
            Text(
                text = "You'll need to re-enter these next.",
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(16.dp))

            PrimaryButton(
                text = "[I'VE WRITTEN THESE DOWN]",
                onClick = onContinue
            )
        }
    }
}

@Composable
private fun SigilIntroScreen(
    onBegin: () -> Unit,
    onSkip: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Step indicator
        Text(
            text = "03 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "[QUICK LOGIN]",
            style = MaterialTheme.typography.headlineLarge.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Set up a pattern for fast, secure access\nwithout typing your full passphrase.",
            style = MaterialTheme.typography.bodyLarge,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Info box
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    width = 1.dp,
                    color = YoursColors.PrimaryDim,
                    shape = RoundedCornerShape(4.dp)
                )
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "HOW IT WORKS",
                style = MaterialTheme.typography.labelMedium.copy(
                    letterSpacing = 1.sp
                ),
                color = YoursColors.Primary
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Connect at least $MIN_PATTERN_LENGTH points.\n\n" +
                       "Unlike a simple pattern lock, you can connect ANY points - " +
                       "not just neighbors. This creates a strong, memorable login.",
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnBackgroundMuted,
                textAlign = TextAlign.Center
            )
        }

        Spacer(modifier = Modifier.height(48.dp))

        PrimaryButton(
            text = "[BEGIN]",
            onClick = onBegin
        )

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onSkip) {
            Text(
                text = "Skip (passphrase only)",
                color = YoursColors.OnBackgroundMuted,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun PatternCreateScreen(
    onPatternCreated: (Pattern) -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // Step indicator
        Text(
            text = "03 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "[DRAW CONSTELLATION]",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Connect at least $MIN_PATTERN_LENGTH stars.\nYou can connect any star to any other.",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        PatternSigilCanvas(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            mode = PatternMode.Create,
            onPatternComplete = onPatternCreated
        )

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onBack) {
            Text(
                text = "← Go back",
                color = YoursColors.OnBackgroundMuted,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun PatternConfirmScreen(
    expectedPattern: Pattern,
    onConfirmed: (Pattern) -> Unit,
    onRetry: () -> Unit
) {
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // Step indicator
        Text(
            text = "03 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "[CONFIRM CONSTELLATION]",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Draw the same pattern again to confirm.",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        PatternSigilCanvas(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            mode = PatternMode.Verify,
            existingPattern = expectedPattern,
            onPatternVerified = onConfirmed,
            onPatternFailed = {
                errorMessage = "Constellations don't match. Try again."
            }
        )

        errorMessage?.let { message ->
            Spacer(modifier = Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = YoursColors.Error.copy(alpha = 0.5f),
                        shape = RoundedCornerShape(4.dp)
                    )
                    .padding(12.dp)
            ) {
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.Error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onRetry) {
            Text(
                text = "Start over",
                color = YoursColors.OnBackgroundMuted,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}


@Composable
private fun CreatingScreen(
    name: String,
    onCreated: () -> Unit,
    doCreate: () -> Unit
) {
    var progress by remember { mutableStateOf(0f) }
    var statusText by remember { mutableStateOf("Generating keys...") }

    LaunchedEffect(Unit) {
        // Show progress while actually creating identity
        val steps = listOf(
            0.2f to "Generating Ed25519 signing key...",
            0.4f to "Generating X25519 encryption key...",
            0.6f to "Deriving identity (did:key)...",
            0.8f to "Encrypting with passphrase...",
            1.0f to "Done!"
        )

        for ((targetProgress, text) in steps) {
            statusText = text
            while (progress < targetProgress) {
                progress += 0.02f
                delay(30)
            }
            delay(200)
        }

        // Actually create the identity
        doCreate()

        delay(500)
        onCreated()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Step indicator
        Text(
            text = "04 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "[CREATING]",
            style = MaterialTheme.typography.headlineLarge.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(48.dp))

        // Logo frame with perimeter loading animation
        YoursLogoFrame(progress = progress)

        Spacer(modifier = Modifier.height(48.dp))

        Text(
            text = statusText,
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted
        )
    }
}

@Composable
private fun DoneScreen(name: String) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Completed logo with glow
        YoursLogoFrame(progress = 1f, showGlow = true)

        Spacer(modifier = Modifier.height(48.dp))

        Text(
            text = "Welcome, $name.",
            style = MaterialTheme.typography.displayMedium.copy(
                fontWeight = FontWeight.Light
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Your identity exists.\nEverything from here is yours.",
            style = MaterialTheme.typography.bodyLarge,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(48.dp))

        // Auto-continue after a moment
        LaunchedEffect(Unit) {
            delay(2000)
            // Navigation happens via the onComplete callback in Creating step
        }

        // Subtle loading indicator
        Text(
            text = "Entering...",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )
    }
}

// ============================================================================
// COMPONENTS
// ============================================================================

/**
 * Branded YOURS logo frame with [stc] header and ユアーズ katakana.
 * Used on Welcome screen with subtle breathing animation.
 * Used on Creating/Done screens with perimeter loading animation.
 */
@Composable
private fun YoursLogoFrame(
    modifier: Modifier = Modifier,
    progress: Float? = null, // null = breathing animation, 0-1 = loading progress
    showGlow: Boolean = false
) {
    val infiniteTransition = rememberInfiniteTransition(label = "logo")

    // Breathing animation for welcome screen (when progress is null)
    val breatheAlpha by infiniteTransition.animateFloat(
        initialValue = 0.6f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2500, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse
        ),
        label = "breathe"
    )

    // Glow pulse for completed state
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow"
    )

    val frameSize = 120.dp
    val actualProgress = progress ?: 0f
    val isLoading = progress != null
    val isComplete = progress != null && progress >= 1f

    // Smooth animated progress for fluid trace
    val animatedProgress by animateFloatAsState(
        targetValue = actualProgress,
        animationSpec = tween(durationMillis = 150, easing = LinearEasing),
        label = "progress"
    )

    Box(
        modifier = modifier.size(frameSize + 32.dp),
        contentAlignment = Alignment.Center
    ) {
        // Main frame with trace animation
        Box(
            modifier = Modifier
                .size(frameSize)
                .drawBehind {
                    val strokeWidth = 2.dp.toPx()
                    val goldStrokeWidth = 3.dp.toPx()
                    val width = size.width
                    val height = size.height

                    // Calculate perimeter (simple rectangle, no rounded corners)
                    val perimeter = 2 * (width + height)

                    // Helper to get point on perimeter (clockwise from top-left)
                    fun getPerimeterPoint(distance: Float): Offset {
                        var d = distance % perimeter
                        if (d < 0) d += perimeter

                        // Top edge (left to right)
                        if (d < width) {
                            return Offset(d, 0f)
                        }
                        d -= width

                        // Right edge (top to bottom)
                        if (d < height) {
                            return Offset(width, d)
                        }
                        d -= height

                        // Bottom edge (right to left)
                        if (d < width) {
                            return Offset(width - d, height)
                        }
                        d -= width

                        // Left edge (bottom to top)
                        return Offset(0f, height - d)
                    }

                    // Draw base dim border (only when loading, not on welcome screen)
                    if (isLoading) {
                        drawRect(
                            color = YoursColors.GrayDim,
                            style = Stroke(width = strokeWidth)
                        )
                    }

                    // Draw gold progress fill around perimeter
                    if (isLoading && animatedProgress > 0.001f) {
                        val fillLength = perimeter * animatedProgress.coerceIn(0f, 1f)
                        val segments = 60

                        for (i in 0 until segments) {
                            val segStartDist = (fillLength * i / segments)
                            val segEndDist = (fillLength * (i + 1) / segments)

                            if (segEndDist <= fillLength) {
                                val p1 = getPerimeterPoint(segStartDist)
                                val p2 = getPerimeterPoint(segEndDist)

                                drawLine(
                                    color = YoursColors.Primary,
                                    start = p1,
                                    end = p2,
                                    strokeWidth = goldStrokeWidth,
                                    cap = StrokeCap.Square
                                )
                            }
                        }
                    }

                    // Glow effect when complete - draw the border line with multiple
                    // overlapping strokes of increasing width and decreasing alpha
                    // This makes the LINE itself glow rather than adding separate frames
                    if (showGlow || isComplete) {
                        // Outer glow (widest, most transparent)
                        drawRect(
                            color = YoursColors.Primary.copy(alpha = glowAlpha * 0.08f),
                            style = Stroke(width = 20.dp.toPx())
                        )
                        // Middle glow
                        drawRect(
                            color = YoursColors.Primary.copy(alpha = glowAlpha * 0.15f),
                            style = Stroke(width = 12.dp.toPx())
                        )
                        // Inner glow
                        drawRect(
                            color = YoursColors.Primary.copy(alpha = glowAlpha * 0.3f),
                            style = Stroke(width = 6.dp.toPx())
                        )
                        // Core line (brightest)
                        drawRect(
                            color = YoursColors.Primary,
                            style = Stroke(width = goldStrokeWidth)
                        )
                    }
                }
                .background(YoursColors.Background),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.padding(16.dp)
            ) {
                // [stc] header - lights up gold at 40%
                Text(
                    text = "[stc]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontSize = 10.sp,
                        letterSpacing = 1.sp
                    ),
                    color = if (isLoading) {
                        if (actualProgress >= 0.4f) YoursColors.Primary else YoursColors.GrayDim
                    } else YoursColors.OnBackgroundMuted.copy(alpha = breatheAlpha)
                )

                Spacer(modifier = Modifier.height(8.dp))

                // YOURS text - lights up gold at 60%
                Text(
                    text = "YOURS",
                    style = MaterialTheme.typography.headlineLarge.copy(
                        fontFamily = GluspFontFamily,
                        fontWeight = FontWeight.Light,
                        letterSpacing = 4.sp,
                        fontSize = 28.sp
                    ),
                    color = if (isLoading) {
                        if (actualProgress >= 0.6f) YoursColors.Primary else YoursColors.GrayDim
                    } else YoursColors.OnBackground.copy(alpha = breatheAlpha)
                )

                Spacer(modifier = Modifier.height(4.dp))

                // ユアーズ katakana - lights up gold at 80%
                Text(
                    text = "ユアーズ",
                    style = MaterialTheme.typography.labelMedium.copy(
                        letterSpacing = 2.sp,
                        fontSize = 11.sp
                    ),
                    color = if (isLoading) {
                        if (actualProgress >= 0.8f) YoursColors.Primary else YoursColors.GrayDim.copy(alpha = 0.5f)
                    } else YoursColors.OnBackgroundMuted.copy(alpha = breatheAlpha * 0.7f)
                )
            }
        }
    }
}

/**
 * Screen to confirm user has written down their recovery words.
 * Uses grid-based word entry with secure in-app keyboard.
 * SECURITY FIX: Callback now returns ByteArray instead of void.
 */
@Composable
private fun ConfirmWordsScreen(
    expectedWords: String,
    onConfirmed: (ByteArray) -> Unit,
    onBack: () -> Unit
) {
    val expectedWordList = expectedWords.split(" ")
    var enteredWords by remember { mutableStateOf(List(8) { "" }) }
    var currentWordIndex by remember { mutableStateOf(0) }
    var currentInput by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    // Visibility state for each word (default hidden)
    var wordVisibility by remember { mutableStateOf(List(8) { false }) }

    // Check if all words are entered and match
    fun validateAndSubmit() {
        val enteredNorm = enteredWords.joinToString(" ").trim().lowercase()
        val expectedNorm = expectedWords.trim().lowercase()

        if (enteredNorm == expectedNorm) {
            error = null
            val normalizedBytes = enteredNorm.toByteArray(Charsets.UTF_8)
            onConfirmed(normalizedBytes)
        } else {
            error = "Words don't match. Check what you wrote down."
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Step indicator
        Text(
            text = "02 / 04",
            style = MaterialTheme.typography.labelSmall.copy(
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "[VERIFY WORDS]",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontWeight = FontWeight.Light,
                letterSpacing = 2.sp
            ),
            color = YoursColors.OnBackground,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Enter word ${currentWordIndex + 1} of 8",
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Word grid - 2 columns, 4 rows for 8 words
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    width = 1.dp,
                    color = YoursColors.PrimaryDim,
                    shape = RoundedCornerShape(4.dp)
                )
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            for (row in 0 until 4) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    for (col in 0 until 2) {
                        val index = row * 2 + col
                        val isActive = index == currentWordIndex
                        val word = if (isActive) currentInput else enteredWords[index]
                        val isCompleted = enteredWords[index].isNotEmpty() && !isActive

                        // Individual word box
                        val isVisible = wordVisibility[index]
                        val displayText = when {
                            word.isEmpty() -> "—"
                            isVisible -> word
                            else -> "●".repeat(word.length.coerceAtMost(8))
                        }

                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(2.dp))
                                .border(
                                    width = if (isActive) 2.dp else 1.dp,
                                    color = when {
                                        isActive -> YoursColors.Primary
                                        isCompleted -> YoursColors.Success.copy(alpha = 0.5f)
                                        else -> YoursColors.GrayDim
                                    },
                                    shape = RoundedCornerShape(2.dp)
                                )
                                .background(
                                    if (isActive) YoursColors.Primary.copy(alpha = 0.05f) else YoursColors.Background
                                )
                                .clickable {
                                    // Tap to edit any word
                                    if (!isActive) {
                                        // Save current input first
                                        enteredWords = enteredWords.toMutableList().also {
                                            it[currentWordIndex] = currentInput
                                        }
                                        // Switch to tapped word
                                        currentWordIndex = index
                                        currentInput = enteredWords[index]
                                    }
                                }
                                .padding(horizontal = 8.dp, vertical = 10.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        text = "${index + 1}.",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (isActive) YoursColors.Primary else YoursColors.OnBackgroundMuted,
                                        modifier = Modifier.width(18.dp)
                                    )

                                    Text(
                                        text = displayText,
                                        style = MaterialTheme.typography.bodyMedium.copy(
                                            fontWeight = if (isCompleted) FontWeight.Medium else FontWeight.Normal,
                                            letterSpacing = if (!isActive && !isVisible && word.isNotEmpty()) 1.sp else 0.sp
                                        ),
                                        color = when {
                                            word.isEmpty() -> YoursColors.GrayDim
                                            isActive -> YoursColors.OnBackground
                                            else -> YoursColors.Success
                                        },
                                        maxLines = 1
                                    )
                                }

                                // Eye toggle for words with content
                                if (word.isNotEmpty()) {
                                    Box(
                                        modifier = Modifier
                                            .size(20.dp)
                                            .clickable {
                                                wordVisibility = wordVisibility.toMutableList().also {
                                                    it[index] = !it[index]
                                                }
                                            },
                                        contentAlignment = Alignment.Center
                                    ) {
                                        // Simple eye icon using text
                                        Text(
                                            text = if (isVisible) "◉" else "◎",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = YoursColors.OnBackgroundMuted.copy(alpha = 0.6f)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Navigation row with prev/next buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Previous button
            TextButton(
                onClick = {
                    if (currentWordIndex > 0) {
                        // Save current input
                        enteredWords = enteredWords.toMutableList().also {
                            it[currentWordIndex] = currentInput
                        }
                        currentWordIndex--
                        currentInput = enteredWords[currentWordIndex]
                    }
                },
                enabled = currentWordIndex > 0
            ) {
                Text(
                    text = "← PREV",
                    color = if (currentWordIndex > 0) YoursColors.OnBackgroundMuted else YoursColors.GrayDim,
                    style = MaterialTheme.typography.labelMedium
                )
            }

            // Word counter
            Text(
                text = "${currentWordIndex + 1} / 8",
                style = MaterialTheme.typography.labelMedium,
                color = YoursColors.Primary
            )

            // Next button
            TextButton(
                onClick = {
                    if (currentInput.isNotEmpty()) {
                        // Save current input and move to next
                        enteredWords = enteredWords.toMutableList().also {
                            it[currentWordIndex] = currentInput
                        }
                        if (currentWordIndex < 7) {
                            currentWordIndex++
                            currentInput = enteredWords[currentWordIndex]
                        } else {
                            // Last word - validate
                            validateAndSubmit()
                        }
                    }
                },
                enabled = currentInput.isNotEmpty()
            ) {
                Text(
                    text = if (currentWordIndex < 7) "NEXT →" else "VERIFY",
                    color = if (currentInput.isNotEmpty()) YoursColors.Primary else YoursColors.GrayDim,
                    style = MaterialTheme.typography.labelMedium.copy(
                        fontWeight = if (currentWordIndex == 7) FontWeight.Bold else FontWeight.Normal
                    )
                )
            }
        }

        error?.let {
            Spacer(modifier = Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = YoursColors.Error.copy(alpha = 0.5f),
                        shape = RoundedCornerShape(4.dp)
                    )
                    .padding(12.dp)
            ) {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.Error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Secure keyboard (simplified - just letters)
        SecureWordKeyboard(
            onKeyPress = { char ->
                if (currentInput.length < 20) {
                    currentInput += char
                }
            },
            onBackspace = {
                if (currentInput.isNotEmpty()) {
                    currentInput = currentInput.dropLast(1)
                }
            },
            onClear = {
                currentInput = ""
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        TextButton(onClick = onBack) {
            Text(
                text = "← Go back and see words again",
                color = YoursColors.OnBackgroundMuted,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

/**
 * Secure keyboard for word entry - letters only, no numbers.
 * CLR and backspace integrated into bottom row with gold accent.
 */
@Composable
private fun SecureWordKeyboard(
    onKeyPress: (Char) -> Unit,
    onBackspace: () -> Unit,
    onClear: () -> Unit
) {
    val keyHeight = 42.dp

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        // Row 1: qwertyuiop (10 keys)
        Row(
            horizontalArrangement = Arrangement.spacedBy(3.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            "qwertyuiop".forEach { char ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(keyHeight)
                        .clip(RoundedCornerShape(4.dp))
                        .background(YoursColors.SurfaceVariant)
                        .clickable { onKeyPress(char) },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = char.toString(),
                        style = MaterialTheme.typography.bodyLarge,
                        color = YoursColors.OnSurface
                    )
                }
            }
        }

        // Row 2: asdfghjkl (9 keys, centered)
        Row(
            horizontalArrangement = Arrangement.spacedBy(3.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            // Half-key spacer for centering
            Spacer(modifier = Modifier.weight(0.5f))
            "asdfghjkl".forEach { char ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(keyHeight)
                        .clip(RoundedCornerShape(4.dp))
                        .background(YoursColors.SurfaceVariant)
                        .clickable { onKeyPress(char) },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = char.toString(),
                        style = MaterialTheme.typography.bodyLarge,
                        color = YoursColors.OnSurface
                    )
                }
            }
            Spacer(modifier = Modifier.weight(0.5f))
        }

        // Row 3: CLR + zxcvbnm + ⌫ (9 items total)
        Row(
            horizontalArrangement = Arrangement.spacedBy(3.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            // CLR button - gold
            Box(
                modifier = Modifier
                    .weight(1.3f)
                    .height(keyHeight)
                    .clip(RoundedCornerShape(4.dp))
                    .background(YoursColors.SurfaceVariant)
                    .border(1.dp, YoursColors.Primary.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    .clickable { onClear() },
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "CLR",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.Primary
                )
            }

            // zxcvbnm (7 keys)
            "zxcvbnm".forEach { char ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(keyHeight)
                        .clip(RoundedCornerShape(4.dp))
                        .background(YoursColors.SurfaceVariant)
                        .clickable { onKeyPress(char) },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = char.toString(),
                        style = MaterialTheme.typography.bodyLarge,
                        color = YoursColors.OnSurface
                    )
                }
            }

            // Backspace button - gold
            Box(
                modifier = Modifier
                    .weight(1.3f)
                    .height(keyHeight)
                    .clip(RoundedCornerShape(4.dp))
                    .background(YoursColors.SurfaceVariant)
                    .border(1.dp, YoursColors.Primary.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    .clickable { onBackspace() },
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "⌫",
                    style = MaterialTheme.typography.bodyLarge,
                    color = YoursColors.Primary
                )
            }
        }
    }
}

sealed class GlyphState {
    object Empty : GlyphState()
    object Full : GlyphState()
    data class Filling(val progress: Float) : GlyphState()
}

@Composable
private fun Glyph(
    state: GlyphState,
    size: androidx.compose.ui.unit.Dp = 64.dp
) {
    val fillProgress = when (state) {
        GlyphState.Empty -> 0f
        GlyphState.Full -> 1f
        is GlyphState.Filling -> state.progress
    }

    Box(
        modifier = Modifier
            .size(size)
            .clip(CircleShape)
            .background(YoursColors.Surface),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .size(size * fillProgress)
                .clip(CircleShape)
                .background(YoursColors.Primary)
        )
    }
}

@Composable
private fun PrimaryButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = YoursColors.Primary,
            contentColor = YoursColors.OnPrimary,
            disabledContainerColor = YoursColors.Surface,
            disabledContentColor = YoursColors.OnBackgroundMuted
        ),
        shape = RoundedCornerShape(4.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge.copy(
                letterSpacing = 0.5.sp
            )
        )
    }
}

@Composable
private fun SecondaryButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = YoursColors.Primary,
            disabledContentColor = YoursColors.OnBackgroundMuted
        ),
        border = androidx.compose.foundation.BorderStroke(
            width = 1.dp,
            color = if (enabled) YoursColors.Primary else YoursColors.GrayDim
        ),
        shape = RoundedCornerShape(4.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge.copy(
                letterSpacing = 0.5.sp
            )
        )
    }
}

// ============================================================================
// PASSPHRASE GENERATION (Full BIP-39 wordlist - 2048 words)
// ============================================================================

private val WORDLIST = listOf(
    // A (56 words)
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
    // A-B (56 words)
    "already", "also", "alter", "always", "amateur", "amazing", "among", "amount",
    "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
    "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
    "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
    // B (56 words)
    "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
    "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    // B-C (56 words)
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
    "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
    "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
    "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    // C (56 words)
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business",
    "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart",
    // C-D (56 words)
    "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery",
    "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion",
    "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check",
    "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney",
    "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw",
    // D (56 words)
    "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb",
    "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown",
    "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code",
    "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy",
    "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country",
    // D-E (56 words)
    "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft",
    "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross",
    "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush",
    "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current",
    "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage",
    "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day",
    // E (56 words)
    "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate",
    "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver",
    "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair",
    "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial",
    "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity",
    "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease",
    // E-F (56 words)
    "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce",
    "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate",
    "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
    "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink",
    "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune",
    "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle",
    "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology",
    // F (56 words)
    "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
    "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower",
    "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy",
    "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich",
    "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal",
    "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape",
    // F-G (56 words)
    "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke",
    "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic",
    "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
    "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith",
    "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy",
    "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite",
    // G (56 words)
    "feature", "february", "federal", "fee", "feed", "feel", "female", "fence",
    "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure",
    "file", "film", "filter", "final", "find", "fine", "finger", "finish",
    "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix",
    "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
    // G-H (56 words)
    "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
    "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe",
    "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun",
    "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas",
    "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre",
    "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger",
    // H (56 words)
    "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide",
    "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat",
    "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern",
    "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity",
    "great", "green", "grid", "grief", "grit", "grocery", "group", "grow",
    "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym",
    "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor",
    // H-I (56 words)
    "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head",
    "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help",
    "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire",
    "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
    "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor",
    "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
    // I-J (56 words)
    "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal",
    "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve",
    "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor",
    "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject",
    "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect",
    "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
    "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket",
    // J-K-L (56 words)
    "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job",
    "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle",
    "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key",
    "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen",
    "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab",
    "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop",
    "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn",
    // L (56 words)
    "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture",
    "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length",
    "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
    "license", "life", "lift", "light", "like", "limb", "limit", "link",
    "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery",
    "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar",
    // L-M (56 words)
    "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid",
    "mail", "main", "major", "make", "mammal", "man", "manage", "mandate",
    "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math",
    "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat",
    "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention",
    "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal",
    // M-N (56 words)
    "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
    "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor",
    "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito",
    "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much",
    "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must",
    "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow",
    // N-O (56 words)
    "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never",
    "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle",
    "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel",
    "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
    "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october",
    "odor", "off", "offer", "office", "often", "oil", "okay", "old",
    // O-P (56 words)
    "olive", "olympic", "omit", "once", "one", "onion", "online", "only",
    "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
    "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other",
    "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own",
    "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
    "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path", "patient",
    // P (56 words)
    "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear",
    "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect",
    "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano",
    "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink",
    "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic",
    "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem",
    "poet", "point", "polar", "pole", "police", "pond", "pony", "pool",
    // P-Q-R (56 words)
    "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty",
    "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present",
    "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project",
    "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public",
    "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy",
    "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid",
    // Q-R (56 words)
    "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote",
    "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain",
    "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare",
    "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason",
    "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce",
    "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax",
    "release", "relief", "rely", "remain", "remember", "remind", "remove", "render",
    // R-S (56 words)
    "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
    "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat",
    "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon",
    "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring",
    "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast",
    "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose",
    "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug",
    // S (56 words)
    "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe",
    "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample",
    "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale",
    "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors",
    "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search",
    "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series",
    // S (56 words)
    "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow",
    "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
    "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove",
    "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege",
    "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple",
    "since", "sing", "siren", "sister", "situate", "six", "size", "skate",
    "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam",
    // S-T (56 words)
    "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
    "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock",
    "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone",
    "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source",
    "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed",
    "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit",
    // T (56 words)
    "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread",
    "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff",
    "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak",
    "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock",
    "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike",
    "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
    // T (56 words)
    "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure",
    "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow",
    "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing",
    "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle",
    "tag", "tail", "talent", "talk", "tank", "tape", "target", "task",
    "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant",
    "tennis", "tent", "term", "test", "text", "thank", "that", "theme",
    // T-U-V (56 words)
    "then", "theory", "there", "they", "thing", "this", "thought", "three",
    "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast",
    "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato",
    "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic",
    "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward",
    "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train",
    // U-V (56 words)
    "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend",
    "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble",
    "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube",
    "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve",
    "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly",
    "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock",
    // V-W (56 words)
    "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper",
    "upset", "urban", "urge", "usage", "use", "used", "useful", "useless",
    "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve",
    "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village",
    "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital",
    // W-X-Y-Z (56 words)
    "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage",
    "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare",
    "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend",
    "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel",
    "when", "where", "whip", "whisper", "wide", "width", "wife", "wild",
    "will", "win", "window", "wine", "wing", "wink", "winner", "winter",
    // Final words
    "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap",
    "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow",
    "you", "young", "youth", "zebra", "zero", "zone", "zoo"
)

private fun generatePassphrase(): String {
    // 4 words = ~44 bits (crackable in ~5 hours with GPU cluster)
    // 8 words = ~88 bits (computationally infeasible)
    return WORDLIST.shuffled().take(8).joinToString(" ")
}
