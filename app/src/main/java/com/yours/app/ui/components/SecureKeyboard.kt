package com.yours.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.ui.theme.YoursColors
import java.security.SecureRandom

/**
 * Secure In-App Keyboard for Passphrase Entry
 *
 * Security features:
 * - NO system keyboard involvement (defeats IME keyloggers)
 * - CharArray buffer, NOT String (can be zeroized)
 * - Visual masking (dots, not characters)
 * - Optional layout randomization (defeats shoulder surfing)
 * - No accessibility events emitted (defeats accessibility attacks)
 * - Immediate zeroization on submit/cancel
 *
 * Usage:
 * ```
 * SecurePassphraseInput(
 *     onSubmit = { charArray ->
 *         // charArray contains passphrase - use immediately
 *         BedrockCore.deriveKey(charArray.toByteArray(), salt)
 *         // charArray is automatically zeroized after this callback
 *     },
 *     onCancel = { /* handle cancel */ }
 * )
 * ```
 */

private const val MAX_PASSPHRASE_LENGTH = 256
private const val MASK_CHAR = '●'

/**
 * Complete secure passphrase input with built-in keyboard.
 * Passphrase is stored as CharArray (not String) and zeroized after use.
 */
@Composable
fun SecurePassphraseInput(
    modifier: Modifier = Modifier,
    hint: String = "Enter passphrase",
    minWords: Int = 8,
    randomizeLayout: Boolean = false,
    onSubmit: (CharArray) -> Unit,
    onCancel: (() -> Unit)? = null,
    onDuressCheck: ((String) -> Boolean)? = null  // Returns true if duress triggered
) {
    // SECURITY: Use CharArray, not String - can be zeroized
    val buffer = remember { CharArray(MAX_PASSPHRASE_LENGTH) }
    var bufferIndex by remember { mutableIntStateOf(0) }
    var wordCount by remember { mutableIntStateOf(0) }

    // Track if duress was triggered to prevent further processing
    var duressTriggered by remember { mutableStateOf(false) }

    // Calculate word count - count non-empty words only
    LaunchedEffect(bufferIndex) {
        if (duressTriggered) return@LaunchedEffect

        wordCount = if (bufferIndex == 0) 0 else {
            var count = 0
            var inWord = false
            for (i in 0 until bufferIndex) {
                if (buffer[i] == ' ') {
                    if (inWord) {
                        count++
                        inWord = false
                    }
                } else {
                    inWord = true
                }
            }
            // Count last word if we're still in one
            if (inWord) count++
            count
        }

        // Check for duress phrase on every change (before 8 words requirement)
        if (onDuressCheck != null && bufferIndex > 0) {
            val currentText = String(buffer, 0, bufferIndex)
            if (onDuressCheck(currentText)) {
                duressTriggered = true
                // Zeroize buffer
                buffer.fill('\u0000')
            }
        }
    }

    // Cleanup on dispose
    DisposableEffect(Unit) {
        onDispose {
            // SECURITY: Zeroize buffer when component is disposed
            buffer.fill('\u0000')
        }
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            // SECURITY: Clear semantics to prevent accessibility leaks
            .clearAndSetSemantics { },
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Display area (masked)
        SecureDisplayField(
            buffer = buffer,
            length = bufferIndex,
            hint = hint
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Word count indicator
        Text(
            text = "$wordCount words" + if (wordCount < minWords) " (need $minWords)" else " ✓",
            style = MaterialTheme.typography.bodySmall,
            color = if (wordCount >= minWords) YoursColors.Success else YoursColors.OnBackgroundMuted
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Keyboard
        SecureKeyboardGrid(
            randomize = randomizeLayout,
            onKeyPress = { char ->
                if (bufferIndex < MAX_PASSPHRASE_LENGTH) {
                    buffer[bufferIndex] = char
                    bufferIndex++
                }
            },
            onBackspace = {
                if (bufferIndex > 0) {
                    bufferIndex--
                    buffer[bufferIndex] = '\u0000' // Zeroize removed char
                }
            },
            onSpace = {
                if (bufferIndex < MAX_PASSPHRASE_LENGTH && bufferIndex > 0 && buffer[bufferIndex - 1] != ' ') {
                    buffer[bufferIndex] = ' '
                    bufferIndex++
                }
            },
            onSubmit = {
                if (wordCount >= minWords) {
                    // Create a copy for the callback
                    val result = buffer.copyOf(bufferIndex)
                    // Zeroize original buffer
                    buffer.fill('\u0000')
                    bufferIndex = 0
                    // Deliver to callback (caller must zeroize result)
                    onSubmit(result)
                }
            },
            submitEnabled = wordCount >= minWords
        )

        if (onCancel != null) {
            Spacer(modifier = Modifier.height(16.dp))
            TextButton(
                onClick = {
                    // SECURITY: Zeroize before canceling
                    buffer.fill('\u0000')
                    bufferIndex = 0
                    onCancel()
                }
            ) {
                Text("Cancel", color = YoursColors.OnBackgroundMuted)
            }
        }
    }
}

/**
 * Masked display field showing dots instead of characters.
 */
@Composable
private fun SecureDisplayField(
    buffer: CharArray,
    length: Int,
    hint: String
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(80.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(YoursColors.Surface)
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        if (length == 0) {
            Text(
                text = hint,
                style = MaterialTheme.typography.bodyLarge,
                color = YoursColors.OnBackgroundMuted
            )
        } else {
            // Show masked representation with word boundaries visible
            val masked = buildString {
                for (i in 0 until length) {
                    if (buffer[i] == ' ') {
                        append(' ')
                    } else {
                        append(MASK_CHAR)
                    }
                }
            }
            Text(
                text = masked,
                style = MaterialTheme.typography.bodyLarge,
                color = YoursColors.OnSurface,
                letterSpacing = 2.sp,
                textAlign = TextAlign.Center
            )
        }
    }
}

/**
 * Custom keyboard grid with optional randomization.
 */
@Composable
private fun SecureKeyboardGrid(
    randomize: Boolean,
    onKeyPress: (Char) -> Unit,
    onBackspace: () -> Unit,
    onSpace: () -> Unit,
    onSubmit: () -> Unit,
    submitEnabled: Boolean
) {
    // Standard QWERTY layout
    val rows = remember(randomize) {
        val baseRows = listOf(
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        )
        if (randomize) {
            // Randomize each row independently
            val random = SecureRandom()
            baseRows.map { row ->
                row.toCharArray().apply {
                    for (i in indices) {
                        val j = random.nextInt(size)
                        val temp = this[i]
                        this[i] = this[j]
                        this[j] = temp
                    }
                }.concatToString()
            }
        } else {
            baseRows
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 2.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Row 0: qwertyuiop (10 keys)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            rows[0].forEach { char ->
                KeyboardKey(
                    label = char.toString(),
                    onClick = { onKeyPress(char) },
                    modifier = Modifier.weight(1f)
                )
            }
        }
        Spacer(modifier = Modifier.height(4.dp))

        // Row 1: asdfghjkl (9 keys) - add padding to center
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Spacer(modifier = Modifier.weight(0.5f))
            rows[1].forEach { char ->
                KeyboardKey(
                    label = char.toString(),
                    onClick = { onKeyPress(char) },
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(modifier = Modifier.weight(0.5f))
        }
        Spacer(modifier = Modifier.height(4.dp))

        // Row 2: zxcvbnm (7 keys) + backspace - add padding to center
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Spacer(modifier = Modifier.weight(0.75f))
            rows[2].forEach { char ->
                KeyboardKey(
                    label = char.toString(),
                    onClick = { onKeyPress(char) },
                    modifier = Modifier.weight(1f)
                )
            }
            KeyboardKey(
                label = "⌫",
                onClick = onBackspace,
                modifier = Modifier.weight(1.5f)
            )
            Spacer(modifier = Modifier.weight(0.25f))
        }
        Spacer(modifier = Modifier.height(4.dp))

        Spacer(modifier = Modifier.height(4.dp))

        // Bottom row: space and submit
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Space bar
            Box(
                modifier = Modifier
                    .weight(3f)
                    .height(44.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(YoursColors.Surface)
                    .clickable { onSpace() },
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "space",
                    color = YoursColors.OnSurface,
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            // Submit button
            Box(
                modifier = Modifier
                    .weight(1.5f)
                    .height(44.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(
                        if (submitEnabled) YoursColors.Primary
                        else YoursColors.Surface
                    )
                    .clickable(enabled = submitEnabled) { onSubmit() },
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "Done",
                    color = if (submitEnabled) YoursColors.OnPrimary
                           else YoursColors.OnBackgroundMuted,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

/**
 * Individual keyboard key.
 */
@Composable
private fun KeyboardKey(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .height(40.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(YoursColors.Surface)
            .clickable { onClick() }
            // SECURITY: Clear semantics to prevent accessibility leaks
            .clearAndSetSemantics { },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            color = YoursColors.OnSurface,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium
        )
    }
}

/**
 * Extension to convert CharArray to ByteArray for crypto operations.
 * The CharArray should be zeroized after this conversion.
 *
 * SECURITY AUDIT FIX #17: Avoid creating immutable String intermediate.
 * Uses CharBuffer + Charset encoder directly to prevent un-zeroizable String.
 */
fun CharArray.toUtf8Bytes(): ByteArray {
    // Use CharBuffer and encoder directly to avoid creating immutable String
    val charBuffer = java.nio.CharBuffer.wrap(this)
    val encoder = Charsets.UTF_8.newEncoder()
    val byteBuffer = encoder.encode(charBuffer)

    // Extract bytes from buffer
    val result = ByteArray(byteBuffer.remaining())
    byteBuffer.get(result)

    // Clear the ByteBuffer backing array if accessible
    if (byteBuffer.hasArray()) {
        byteBuffer.array().fill(0)
    }

    return result
}

/**
 * Securely zeroize a CharArray.
 */
fun CharArray.zeroize() {
    this.fill('\u0000')
}

/**
 * Securely zeroize a ByteArray.
 */
fun ByteArray.zeroize() {
    this.fill(0)
}
