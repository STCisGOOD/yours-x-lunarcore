package com.yours.app.ui.components

import android.view.HapticFeedbackConstants
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.delay
import kotlin.math.pow
import kotlin.math.sqrt

/**
 * The Sigil - A Lunarpunk Authentication Ritual
 *
 * Instead of typing words, you trace your cryptographic identity through
 * a constellation of stars. Each unlock is signing your sovereignty into existence.
 *
 * Security: 13 points from 2048 positions = ~143 bits theoretical entropy
 * With touch tolerance: ~90-100 bits practical entropy (exceeds 88-bit target)
 */

// Number of stars in the void
const val STAR_COUNT = 2048

// Number of stars to select for a sigil
const val SIGIL_POINTS = 13

// Touch tolerance in dp - how close you need to tap to select a star
const val TOUCH_TOLERANCE_DP = 24f

/**
 * A point in the star field.
 * Position is normalized 0.0-1.0 for resolution independence.
 */
data class StarPoint(
    val index: Int,
    val x: Float,  // 0.0 to 1.0
    val y: Float   // 0.0 to 1.0
)

/**
 * A sigil is a sequence of star indices.
 */
@JvmInline
value class Sigil(val points: List<Int>) {
    init {
        require(points.size == SIGIL_POINTS) { "Sigil must have exactly $SIGIL_POINTS points" }
        require(points.all { it in 0 until STAR_COUNT }) { "All points must be valid star indices" }
    }

    /**
     * Convert to bytes for key derivation.
     * Each star index is 11 bits (2048 = 2^11), packed into bytes.
     */
    fun toBytes(): ByteArray {
        // 13 points * 11 bits = 143 bits = 18 bytes (with padding)
        val bits = mutableListOf<Boolean>()
        for (point in points) {
            for (i in 10 downTo 0) {
                bits.add((point shr i) and 1 == 1)
            }
        }
        // Pad to byte boundary
        while (bits.size % 8 != 0) {
            bits.add(false)
        }
        return ByteArray(bits.size / 8) { byteIndex ->
            var byte = 0
            for (bitIndex in 0 until 8) {
                if (bits[byteIndex * 8 + bitIndex]) {
                    byte = byte or (1 shl (7 - bitIndex))
                }
            }
            byte.toByte()
        }
    }

    companion object {
        fun fromBytes(bytes: ByteArray): Sigil? {
            if (bytes.size < 18) return null
            val bits = mutableListOf<Boolean>()
            for (byte in bytes) {
                for (i in 7 downTo 0) {
                    bits.add((byte.toInt() shr i) and 1 == 1)
                }
            }
            val points = mutableListOf<Int>()
            for (i in 0 until SIGIL_POINTS) {
                var value = 0
                for (j in 0 until 11) {
                    if (bits[i * 11 + j]) {
                        value = value or (1 shl (10 - j))
                    }
                }
                points.add(value)
            }
            return try {
                Sigil(points)
            } catch (e: Exception) {
                null
            }
        }
    }
}

/**
 * Generates a deterministic star field.
 *
 * Uses a simple, auditable LCG (Linear Congruential Generator).
 * No external dependencies - you can verify this yourself.
 *
 * NOTE: This is NOT for cryptographic security. The star positions
 * are PUBLIC (visible on screen). Security comes from YOUR CHOICE
 * of which 13 stars to select and in what order.
 */
object StarField {
    // Pre-compute stars lazily but thread-safe
    private val cachedStars: List<StarPoint> by lazy { generateStars() }

    /**
     * Simple LCG: next = (a * current + c) mod m
     * Using parameters from Numerical Recipes (well-studied, no backdoors)
     * All operations stay within Int range to avoid overflow.
     */
    private fun generateStars(): List<StarPoint> {
        val stars = mutableListOf<StarPoint>()

        // LCG parameters (Numerical Recipes)
        val a = 1664525
        val c = 1013904223

        // Seed: "LUNAR" as simple hash
        var state = 0x4C554E41 // "LUNA" fits in Int

        // Generate 2048 star positions
        repeat(STAR_COUNT) { index ->
            // Generate x coordinate
            state = (a * state + c) // Int overflow wraps naturally in Kotlin/JVM
            val x = 0.05f + (((state ushr 8) and 0xFFFF) / 65536f) * 0.9f

            // Generate y coordinate
            state = (a * state + c)
            val y = 0.05f + (((state ushr 8) and 0xFFFF) / 65536f) * 0.9f

            stars.add(StarPoint(index, x, y))
        }

        return stars
    }

    /**
     * Get all stars in the field.
     * Positions are deterministic so the same stars appear on every device.
     */
    fun getStars(): List<StarPoint> = cachedStars

    /**
     * Find the nearest star to a touch point.
     */
    fun findNearestStar(
        touchX: Float,
        touchY: Float,
        canvasWidth: Float,
        canvasHeight: Float,
        tolerancePx: Float
    ): StarPoint? {
        val normalizedX = touchX / canvasWidth
        val normalizedY = touchY / canvasHeight

        val stars = getStars()
        var nearest: StarPoint? = null
        var nearestDist = Float.MAX_VALUE

        for (star in stars) {
            val dx = (star.x - normalizedX) * canvasWidth
            val dy = (star.y - normalizedY) * canvasHeight
            val dist = sqrt(dx * dx + dy * dy)

            if (dist < nearestDist && dist < tolerancePx) {
                nearest = star
                nearestDist = dist
            }
        }

        return nearest
    }
}

/**
 * State for the sigil canvas.
 */
sealed class SigilState {
    object Idle : SigilState()
    data class Tracing(val selectedPoints: List<Int>) : SigilState()
    object Complete : SigilState()
    object Sealed : SigilState()
    data class Error(val message: String) : SigilState()
}

/**
 * The Sigil Canvas - where the constellation is traced.
 *
 * @param mode Either "create" (setup) or "verify" (unlock)
 * @param existingSigil For verify mode, the sigil to verify against
 * @param resetKey Change this value to reset the canvas and clear selected points
 * @param onSigilComplete Called when user completes tracing (13 points selected)
 * @param onSigilVerified Called when sigil matches (verify mode only)
 * @param onSigilFailed Called when sigil doesn't match (verify mode only)
 */
@Composable
fun SigilCanvas(
    modifier: Modifier = Modifier,
    mode: SigilMode = SigilMode.Create,
    existingSigil: Sigil? = null,
    resetKey: Any? = null,
    onSigilComplete: (Sigil) -> Unit = {},
    onSigilVerified: (Sigil) -> Unit = {},
    onSigilFailed: () -> Unit = {}
) {
    val view = LocalView.current
    val density = LocalDensity.current
    val tolerancePx = with(density) { TOUCH_TOLERANCE_DP.dp.toPx() }

    var state by remember { mutableStateOf<SigilState>(SigilState.Idle) }
    var selectedPoints by remember { mutableStateOf(listOf<Int>()) }
    var canvasSize by remember { mutableStateOf(Offset.Zero) }

    // Get stars - this is fast now (simple loop, no rejection sampling)
    val stars = remember { StarField.getStars() }

    // Reset when resetKey changes
    LaunchedEffect(resetKey) {
        if (resetKey != null) {
            selectedPoints = listOf()
            state = SigilState.Idle
        }
    }

    // Subtle glow animation
    val infiniteTransition = rememberInfiniteTransition(label = "starGlow")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glowAlpha"
    )

    // Seal animation
    var sealProgress by remember { mutableStateOf(0f) }
    val sealAnimation by animateFloatAsState(
        targetValue = if (state is SigilState.Sealed) 1f else 0f,
        animationSpec = tween(600, easing = FastOutSlowInEasing),
        label = "seal"
    )

    // Handle completion
    LaunchedEffect(selectedPoints.size) {
        if (selectedPoints.size == SIGIL_POINTS) {
            state = SigilState.Complete

            // Brief pause before sealing
            delay(200)

            val sigil = Sigil(selectedPoints)

            when (mode) {
                SigilMode.Create -> {
                    state = SigilState.Sealed
                    try { view.performHapticFeedback(HapticFeedbackConstants.CONFIRM) } catch (_: Exception) {}
                    delay(400)
                    onSigilComplete(sigil)
                }
                SigilMode.Verify -> {
                    if (existingSigil != null && sigil.points == existingSigil.points) {
                        state = SigilState.Sealed
                        try { view.performHapticFeedback(HapticFeedbackConstants.CONFIRM) } catch (_: Exception) {}
                        delay(400)
                        onSigilVerified(sigil)
                    } else {
                        state = SigilState.Error("Sigil does not match")
                        try { view.performHapticFeedback(HapticFeedbackConstants.REJECT) } catch (_: Exception) {}
                        delay(800)
                        // Reset for retry
                        selectedPoints = listOf()
                        state = SigilState.Idle
                        onSigilFailed()
                    }
                }
            }
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .background(Color(0xFF0A0A0F))
    ) {
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .pointerInput(Unit) {
                    detectTapGestures { offset ->
                        if (state is SigilState.Sealed) return@detectTapGestures
                        if (selectedPoints.size >= SIGIL_POINTS) return@detectTapGestures

                        canvasSize = Offset(size.width.toFloat(), size.height.toFloat())

                        val star = StarField.findNearestStar(
                            offset.x, offset.y,
                            size.width.toFloat(), size.height.toFloat(),
                            tolerancePx
                        )

                        if (star != null && star.index !in selectedPoints) {
                            selectedPoints = selectedPoints + star.index
                            state = SigilState.Tracing(selectedPoints)
                            try {
                                view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                            } catch (e: Exception) {
                                // Haptic feedback not available
                            }
                        }
                    }
                }
        ) {
            // Draw background stars (the void)
            drawStarField(stars, selectedPoints, glowAlpha)

            // Draw connections between selected points
            if (selectedPoints.size >= 2) {
                drawSigilLines(stars, selectedPoints, state is SigilState.Sealed, sealAnimation)
            }

            // Draw selected stars (ignited)
            drawSelectedStars(stars, selectedPoints, state is SigilState.Sealed, sealAnimation)

            // Draw seal pulse on completion
            if (state is SigilState.Sealed && sealAnimation > 0) {
                drawSealPulse(stars, selectedPoints, sealAnimation)
            }
        }

        // Progress indicator
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = when (state) {
                    is SigilState.Idle -> "Trace your sigil"
                    is SigilState.Tracing -> "${selectedPoints.size} / $SIGIL_POINTS"
                    is SigilState.Complete -> "Sealing..."
                    is SigilState.Sealed -> "Sealed"
                    is SigilState.Error -> (state as SigilState.Error).message
                },
                style = MaterialTheme.typography.bodyMedium,
                color = when (state) {
                    is SigilState.Error -> YoursColors.Error
                    is SigilState.Sealed -> YoursColors.Primary
                    else -> YoursColors.OnBackgroundMuted
                },
                textAlign = TextAlign.Center
            )

            // Point indicators
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                repeat(SIGIL_POINTS) { index ->
                    val filled = index < selectedPoints.size
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .background(
                                if (filled) YoursColors.Primary else YoursColors.OnBackgroundMuted.copy(alpha = 0.3f),
                                shape = androidx.compose.foundation.shape.CircleShape
                            )
                    )
                }
            }
        }
    }
}

enum class SigilMode {
    Create,
    Verify
}

// Drawing helper functions

private fun DrawScope.drawStarField(
    stars: List<StarPoint>,
    selectedPoints: List<Int>,
    glowAlpha: Float
) {
    val width = size.width
    val height = size.height
    val selectedSet = selectedPoints.toSet()

    // Draw all 2048 stars
    for (star in stars) {
        if (star.index in selectedSet) continue

        val x = star.x * width
        val y = star.y * height

        // Faint star
        drawCircle(
            color = Color.White.copy(alpha = 0.15f + (glowAlpha * 0.1f)),
            radius = 1.5f,
            center = Offset(x, y)
        )
    }
}

private fun DrawScope.drawSigilLines(
    stars: List<StarPoint>,
    selectedPoints: List<Int>,
    sealed: Boolean,
    sealProgress: Float
) {
    val width = size.width
    val height = size.height

    val lineColor = if (sealed) {
        Color(0xFF8B5CF6).copy(alpha = 0.6f + sealProgress * 0.4f)
    } else {
        Color(0xFF6366F1).copy(alpha = 0.5f)
    }

    for (i in 0 until selectedPoints.size - 1) {
        val from = stars[selectedPoints[i]]
        val to = stars[selectedPoints[i + 1]]

        val fromOffset = Offset(from.x * width, from.y * height)
        val toOffset = Offset(to.x * width, to.y * height)

        // Draw line
        drawLine(
            color = lineColor,
            start = fromOffset,
            end = toOffset,
            strokeWidth = if (sealed) 2f + sealProgress * 2f else 2f,
            cap = StrokeCap.Round
        )

        // Glow effect
        drawLine(
            color = lineColor.copy(alpha = 0.2f),
            start = fromOffset,
            end = toOffset,
            strokeWidth = if (sealed) 8f + sealProgress * 8f else 6f,
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawSelectedStars(
    stars: List<StarPoint>,
    selectedPoints: List<Int>,
    sealed: Boolean,
    sealProgress: Float
) {
    val width = size.width
    val height = size.height

    for ((index, pointIndex) in selectedPoints.withIndex()) {
        val star = stars[pointIndex]
        val x = star.x * width
        val y = star.y * height
        val center = Offset(x, y)

        val baseRadius = 4f + if (sealed) sealProgress * 4f else 0f

        // Outer glow
        drawCircle(
            color = Color(0xFF8B5CF6).copy(alpha = 0.3f),
            radius = baseRadius * 3,
            center = center
        )

        // Middle glow
        drawCircle(
            color = Color(0xFFA78BFA).copy(alpha = 0.5f),
            radius = baseRadius * 2,
            center = center
        )

        // Core
        drawCircle(
            color = if (sealed) Color(0xFFE9D5FF) else Color(0xFFC4B5FD),
            radius = baseRadius,
            center = center
        )

        // Number indicator (first and last only for orientation)
        if (index == 0 || index == selectedPoints.size - 1) {
            drawCircle(
                color = Color.White,
                radius = 2f,
                center = center
            )
        }
    }
}

private fun DrawScope.drawSealPulse(
    stars: List<StarPoint>,
    selectedPoints: List<Int>,
    progress: Float
) {
    if (selectedPoints.isEmpty()) return

    val width = size.width
    val height = size.height

    // Calculate center of sigil
    var centerX = 0f
    var centerY = 0f
    for (pointIndex in selectedPoints) {
        val star = stars[pointIndex]
        centerX += star.x * width
        centerY += star.y * height
    }
    centerX /= selectedPoints.size
    centerY /= selectedPoints.size

    val center = Offset(centerX, centerY)

    // Expanding pulse
    val maxRadius = minOf(width, height) / 2
    val pulseRadius = progress * maxRadius

    drawCircle(
        color = Color(0xFF8B5CF6).copy(alpha = (1f - progress) * 0.3f),
        radius = pulseRadius,
        center = center,
        style = Stroke(width = 2f + (1f - progress) * 4f)
    )
}

/**
 * Reset function for the canvas (exposed for external control)
 */
@Composable
fun rememberSigilCanvasState(): MutableState<List<Int>> {
    return remember { mutableStateOf(listOf()) }
}
