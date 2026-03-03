package com.yours.app.ui.components

import android.view.HapticFeedbackConstants
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
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
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.ui.theme.YoursColors
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Pattern Sigil - A Constellation Grid for Sovereign Authentication
 *
 * "In the void between stars, you trace your sovereignty into existence."
 *
 * A night sky with 36 celestial anchors. Your pattern becomes your seal,
 * your constellation, your cryptographic signature written in starlight.
 *
 * Security: 36 points, 12 selections = log2(36!/24!) ≈ 61 bits
 * Combined with device-bound key for defense against theft.
 */

const val GRID_SIZE = 6
const val TOTAL_POINTS = GRID_SIZE * GRID_SIZE
const val MIN_PATTERN_LENGTH = 12
const val STAR_HIT_RADIUS_DP = 32f
const val BACKGROUND_STAR_COUNT = 150

// Color palette - realistic night sky with warm gold ignition
private val VoidBlack = Color(0xFF000000)        // True black
private val NebulaDeep = Color(0xFF020204)       // Near black
private val NebulaMid = Color(0xFF050508)        // Hint darker

// Dormant stars - realistic silver/white like real stars
private val StarWhite = Color(0xFFFFFFFF)        // Pure white core
private val StarSilver = Color(0xFFE8E8F0)       // Silver white
private val StarBlue = Color(0xFFCAD0E8)         // Slight blue tint (hot stars)
private val StarWarm = Color(0xFFF0E8E0)         // Slight warm tint (some stars)
private val StarGlow = Color(0xFFB8C0D8)         // Subtle silver-blue glow

// Ignited stars - warm gold (sovereignty activated)
private val IgnitedCore = Color(0xFFFFFAF0)      // Warm white
private val IgnitedInner = Color(0xFFF8E8C8)     // Soft gold
private val IgnitedGlow = Color(0xFFE8B866)      // Warm gold
private val IgnitedOuter = Color(0xFFD4A554)     // Deeper gold
private val ConstellationLine = Color(0xFFE8B866) // Gold line

// Accent
private val GoldAccent = Color(0xFFE8B866)       // For UI elements

@JvmInline
value class Pattern(val points: List<Int>) {
    init {
        require(points.size >= MIN_PATTERN_LENGTH) {
            "Pattern must have at least $MIN_PATTERN_LENGTH points"
        }
        require(points.all { it in 0 until TOTAL_POINTS }) {
            "All points must be valid grid indices"
        }
        require(points.distinct().size == points.size) {
            "Pattern cannot have repeated points"
        }
    }

    fun toBytes(): ByteArray {
        val bits = mutableListOf<Boolean>()
        for (point in points) {
            for (i in 5 downTo 0) {
                bits.add((point shr i) and 1 == 1)
            }
        }
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
        fun fromBytes(bytes: ByteArray): Pattern? {
            if (bytes.size < 9) return null
            val bits = mutableListOf<Boolean>()
            for (byte in bytes) {
                for (i in 7 downTo 0) {
                    bits.add((byte.toInt() shr i) and 1 == 1)
                }
            }
            val points = mutableListOf<Int>()
            var i = 0
            while (i + 6 <= bits.size && points.size < MIN_PATTERN_LENGTH) {
                var value = 0
                for (j in 0 until 6) {
                    if (bits[i + j]) {
                        value = value or (1 shl (5 - j))
                    }
                }
                if (value < TOTAL_POINTS) {
                    points.add(value)
                }
                i += 6
            }
            return try {
                Pattern(points)
            } catch (e: Exception) {
                null
            }
        }
    }
}

data class BackgroundStar(
    val x: Float,
    val y: Float,
    val size: Float,
    val brightness: Float,
    val twinkleSpeed: Float
)

object NightSky {
    val stars: List<BackgroundStar> by lazy {
        val result = mutableListOf<BackgroundStar>()
        val a = 1664525
        val c = 1013904223
        var state = 0x4C554E41 // "LUNA"

        repeat(BACKGROUND_STAR_COUNT) {
            state = a * state + c
            val x = ((state ushr 8) and 0xFFFF) / 65536f

            state = a * state + c
            val y = ((state ushr 8) and 0xFFFF) / 65536f

            state = a * state + c
            val size = 0.5f + (((state ushr 8) and 0xFF) / 255f) * 1.5f

            state = a * state + c
            val brightness = 0.15f + (((state ushr 8) and 0xFF) / 255f) * 0.4f

            state = a * state + c
            val twinkleSpeed = 0.5f + (((state ushr 8) and 0xFF) / 255f) * 1.5f

            result.add(BackgroundStar(x, y, size, brightness, twinkleSpeed))
        }
        result.toList()
    }
}

sealed class PatternState {
    object Idle : PatternState()
    data class Drawing(val points: List<Int>) : PatternState()
    object Complete : PatternState()
    object Sealed : PatternState()
    data class Error(val message: String) : PatternState()
}

enum class PatternMode { Create, Verify }

@Composable
fun PatternSigilCanvas(
    modifier: Modifier = Modifier,
    mode: PatternMode = PatternMode.Create,
    existingPattern: Pattern? = null,
    onPatternComplete: (Pattern) -> Unit = {},
    onPatternVerified: (Pattern) -> Unit = {},
    onPatternFailed: () -> Unit = {}
) {
    val view = LocalView.current
    val density = LocalDensity.current
    val hitRadiusPx = with(density) { STAR_HIT_RADIUS_DP.dp.toPx() }

    var state by remember { mutableStateOf<PatternState>(PatternState.Idle) }
    var selectedPoints by remember { mutableStateOf(listOf<Int>()) }
    var currentTouch by remember { mutableStateOf<Offset?>(null) }
    var gridOrigin by remember { mutableStateOf(Offset.Zero) }
    var cellSize by remember { mutableStateOf(0f) }

    val backgroundStars = remember { NightSky.stars }

    fun getStarCenter(index: Int): Offset {
        val row = index / GRID_SIZE
        val col = index % GRID_SIZE
        return Offset(
            gridOrigin.x + col * cellSize + cellSize / 2,
            gridOrigin.y + row * cellSize + cellSize / 2
        )
    }

    fun findStarAt(touch: Offset): Int? {
        for (i in 0 until TOTAL_POINTS) {
            val center = getStarCenter(i)
            val dx = touch.x - center.x
            val dy = touch.y - center.y
            if (sqrt(dx * dx + dy * dy) < hitRadiusPx) {
                return i
            }
        }
        return null
    }

    // Animations
    val infiniteTransition = rememberInfiniteTransition(label = "cosmos")

    val cosmicPulse by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(4000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    val starRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(60000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val twinklePhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 6.28f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "twinkle"
    )

    val sealAnimation by animateFloatAsState(
        targetValue = if (state is PatternState.Sealed) 1f else 0f,
        animationSpec = tween(800, easing = FastOutSlowInEasing),
        label = "seal"
    )

    LaunchedEffect(selectedPoints.size) {
        if (selectedPoints.size >= MIN_PATTERN_LENGTH && state is PatternState.Drawing) {
            state = PatternState.Complete
        }
    }

    // Full-screen immersive layout
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(VoidBlack)
    ) {
        // Full-screen canvas
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    detectDragGestures(
                        onDragStart = { offset ->
                            if (state is PatternState.Sealed) return@detectDragGestures

                            // Calculate grid to fill most of the screen with padding
                            val screenWidth = size.width.toFloat()
                            val screenHeight = size.height.toFloat()
                            val gridSize = (screenWidth.coerceAtMost(screenHeight) * 0.85f)
                            val horizontalPadding = (screenWidth - gridSize) / 2
                            val verticalPadding = (screenHeight - gridSize) / 2 - 40f // Offset up slightly

                            cellSize = gridSize / GRID_SIZE
                            gridOrigin = Offset(horizontalPadding, verticalPadding)

                            val star = findStarAt(offset)
                            if (star != null) {
                                selectedPoints = listOf(star)
                                currentTouch = offset
                                state = PatternState.Drawing(selectedPoints)
                                try {
                                    view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                } catch (_: Exception) {}
                            }
                        },
                        onDrag = { change, _ ->
                            if (state !is PatternState.Drawing) return@detectDragGestures

                            currentTouch = change.position
                            val star = findStarAt(change.position)

                            if (star != null && star !in selectedPoints) {
                                selectedPoints = selectedPoints + star
                                state = PatternState.Drawing(selectedPoints)
                                try {
                                    view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                } catch (_: Exception) {}
                            }
                        },
                        onDragEnd = {
                            currentTouch = null

                            if (selectedPoints.size >= MIN_PATTERN_LENGTH) {
                                val pattern = try { Pattern(selectedPoints) } catch (e: Exception) { null }

                                if (pattern != null) {
                                    when (mode) {
                                        PatternMode.Create -> {
                                            state = PatternState.Sealed
                                            try { view.performHapticFeedback(HapticFeedbackConstants.CONFIRM) } catch (_: Exception) {}
                                            onPatternComplete(pattern)
                                        }
                                        PatternMode.Verify -> {
                                            if (existingPattern != null && pattern.points == existingPattern.points) {
                                                state = PatternState.Sealed
                                                try { view.performHapticFeedback(HapticFeedbackConstants.CONFIRM) } catch (_: Exception) {}
                                                onPatternVerified(pattern)
                                            } else {
                                                state = PatternState.Error("Pattern doesn't match")
                                                try { view.performHapticFeedback(HapticFeedbackConstants.REJECT) } catch (_: Exception) {}
                                                selectedPoints = listOf()
                                                onPatternFailed()
                                            }
                                        }
                                    }
                                }
                            } else if (selectedPoints.isNotEmpty()) {
                                state = PatternState.Error("Connect at least $MIN_PATTERN_LENGTH stars")
                                selectedPoints = listOf()
                            }
                        },
                        onDragCancel = {
                            currentTouch = null
                            selectedPoints = listOf()
                            state = PatternState.Idle
                        }
                    )
                }
        ) {
            // Calculate grid to fill most of the screen
            val screenWidth = size.width
            val screenHeight = size.height
            val gridSize = (screenWidth.coerceAtMost(screenHeight) * 0.85f)
            val horizontalPadding = (screenWidth - gridSize) / 2
            val verticalPadding = (screenHeight - gridSize) / 2 - 40f

            cellSize = gridSize / GRID_SIZE
            gridOrigin = Offset(horizontalPadding, verticalPadding)

            // Layer 1: Deep void background with nebula
            drawCosmicBackground(cosmicPulse)

            // Layer 2: Distant stars across entire screen
            drawDistantStars(backgroundStars, twinklePhase)

            // Layer 3: Constellation lines
            if (selectedPoints.size >= 2) {
                drawConstellationPath(
                    selectedPoints = selectedPoints,
                    getCenter = { getStarCenter(it) },
                    sealed = state is PatternState.Sealed,
                    sealProgress = sealAnimation,
                    pulse = cosmicPulse
                )
            }

            // Layer 4: Active tracing line
            if (currentTouch != null && selectedPoints.isNotEmpty()) {
                val lastStar = getStarCenter(selectedPoints.last())
                drawTracingLine(lastStar, currentTouch!!, cosmicPulse)
            }

            // Layer 5: Grid stars (celestial anchors)
            drawCelestialAnchors(
                selectedPoints = selectedPoints,
                getCenter = { getStarCenter(it) },
                pulse = cosmicPulse,
                rotation = starRotation,
                sealed = state is PatternState.Sealed,
                sealProgress = sealAnimation
            )

            // Layer 6: Seal effect
            if (state is PatternState.Sealed && sealAnimation > 0) {
                drawSealingRitual(
                    selectedPoints = selectedPoints,
                    getCenter = { getStarCenter(it) },
                    progress = sealAnimation
                )
            }
        }

        // Overlaid UI at bottom
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status text
            Text(
                text = when (state) {
                    is PatternState.Idle -> "TRACE YOUR CONSTELLATION"
                    is PatternState.Drawing -> "${selectedPoints.size} STARS CONNECTED"
                    is PatternState.Complete -> "RELEASE TO SEAL"
                    is PatternState.Sealed -> "CONSTELLATION SEALED"
                    is PatternState.Error -> (state as PatternState.Error).message.uppercase()
                },
                fontSize = 12.sp,
                fontStyle = FontStyle.Italic,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp,
                color = when (state) {
                    is PatternState.Error -> Color(0xFFef4444)
                    is PatternState.Sealed -> IgnitedGlow
                    is PatternState.Complete -> IgnitedGlow
                    else -> StarSilver.copy(alpha = 0.85f)  // Silvery, realistic
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Progress dots
            Row(
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                repeat(MIN_PATTERN_LENGTH) { index ->
                    val filled = index < selectedPoints.size
                    val isSealed = state is PatternState.Sealed
                    Box(
                        modifier = Modifier
                            .size(if (filled) 8.dp else 5.dp)
                            .background(
                                when {
                                    isSealed -> IgnitedGlow
                                    filled -> GoldAccent
                                    else -> StarSilver.copy(alpha = 0.3f)
                                },
                                shape = CircleShape
                            )
                    )
                }
            }
        }
    }
}

// =============================================================================
// DRAWING FUNCTIONS - Creating the Cosmic Experience
// =============================================================================

private fun DrawScope.drawCosmicBackground(pulse: Float) {
    // True night sky - deep black with very subtle gradient
    drawRect(
        brush = Brush.radialGradient(
            colors = listOf(
                NebulaDeep,  // Very slightly lighter at center
                VoidBlack,
                VoidBlack
            ),
            center = Offset(size.width * 0.5f, size.height * 0.45f),
            radius = size.maxDimension * 0.9f
        )
    )
}

private fun DrawScope.drawDistantStars(stars: List<BackgroundStar>, twinklePhase: Float) {
    for (star in stars) {
        val x = star.x * size.width
        val y = star.y * size.height

        val twinkle = sin(twinklePhase * star.twinkleSpeed + star.x * 10).toFloat()
        val alpha = (star.brightness * (0.6f + twinkle * 0.4f)).coerceIn(0f, 1f)

        // Tiny glow
        drawCircle(
            color = Color.White.copy(alpha = alpha * 0.3f),
            radius = star.size * 2.5f,
            center = Offset(x, y)
        )

        // Star point
        drawCircle(
            color = Color.White.copy(alpha = alpha),
            radius = star.size,
            center = Offset(x, y)
        )
    }
}

private fun DrawScope.drawCelestialAnchors(
    selectedPoints: List<Int>,
    getCenter: (Int) -> Offset,
    pulse: Float,
    rotation: Float,
    sealed: Boolean,
    sealProgress: Float
) {
    val selectedSet = selectedPoints.toSet()

    for (i in 0 until TOTAL_POINTS) {
        val center = getCenter(i)
        val isSelected = i in selectedSet
        val order = selectedPoints.indexOf(i)

        if (isSelected) {
            drawIgnitedStar(center, order, selectedPoints.size, pulse, sealed, sealProgress)
        } else {
            drawDormantStar(center, pulse, rotation)
        }
    }
}

private fun DrawScope.drawDormantStar(center: Offset, pulse: Float, rotation: Float) {
    val baseAlpha = (0.5f + pulse * 0.2f).coerceIn(0f, 0.75f)
    val baseRadius = 4.5f

    // Soft outer glow - very subtle, realistic
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                StarGlow.copy(alpha = baseAlpha * 0.15f),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 4
        ),
        radius = baseRadius * 4,
        center = center
    )

    // Subtle cross rays (diffraction spikes like real stars)
    val rayLength = baseRadius * 2.5f
    val rayAlpha = baseAlpha * 0.3f
    for (angle in listOf(0f, 90f)) {
        val rad = Math.toRadians((angle + rotation * 0.05).toDouble())
        val dx = cos(rad).toFloat() * rayLength
        val dy = sin(rad).toFloat() * rayLength

        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(Color.Transparent, StarSilver.copy(alpha = rayAlpha), Color.Transparent),
                start = Offset(center.x - dx, center.y - dy),
                end = Offset(center.x + dx, center.y + dy)
            ),
            start = Offset(center.x - dx, center.y - dy),
            end = Offset(center.x + dx, center.y + dy),
            strokeWidth = 1f
        )
    }

    // Inner glow - silver
    drawCircle(
        color = StarSilver.copy(alpha = baseAlpha * 0.4f),
        radius = baseRadius * 1.5f,
        center = center
    )

    // Core - white
    drawCircle(
        color = StarWhite.copy(alpha = (baseAlpha + 0.2f).coerceIn(0f, 1f)),
        radius = baseRadius,
        center = center
    )

    // Bright center point
    drawCircle(
        color = StarWhite,
        radius = 1.5f,
        center = center
    )
}

private fun DrawScope.drawIgnitedStar(
    center: Offset,
    order: Int,
    total: Int,
    pulse: Float,
    sealed: Boolean,
    sealProgress: Float
) {
    val intensity = if (sealed) 0.9f + sealProgress * 0.1f else 0.85f
    val baseRadius = 6f + if (sealed) sealProgress * 3f else pulse * 1f
    val glowExpand = if (sealed) 1f + sealProgress * 0.5f else 1f

    // Large outer aura - dusty rose mauve
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                IgnitedOuter.copy(alpha = 0.2f * intensity),
                IgnitedOuter.copy(alpha = 0.08f * intensity),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 8 * glowExpand
        ),
        radius = baseRadius * 8 * glowExpand,
        center = center
    )

    // Cross rays - rose gold
    val rayLength = baseRadius * 6 * glowExpand
    val rayAlpha = 0.55f * intensity
    for (angle in listOf(0f, 45f, 90f, 135f)) {
        val rad = Math.toRadians(angle.toDouble())
        val dx = cos(rad).toFloat() * rayLength
        val dy = sin(rad).toFloat() * rayLength
        val width = if (angle % 90 == 0f) 2.5f else 1.5f

        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(Color.Transparent, IgnitedGlow.copy(alpha = rayAlpha), Color.Transparent),
                start = Offset(center.x - dx, center.y - dy),
                end = Offset(center.x + dx, center.y + dy)
            ),
            start = Offset(center.x - dx, center.y - dy),
            end = Offset(center.x + dx, center.y + dy),
            strokeWidth = width
        )
    }

    // Mid glow - rose gold
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                IgnitedGlow.copy(alpha = 0.65f * intensity),
                IgnitedGlow.copy(alpha = 0.25f * intensity),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 4
        ),
        radius = baseRadius * 4,
        center = center
    )

    // Inner glow - soft rose
    drawCircle(
        color = IgnitedInner.copy(alpha = 0.85f * intensity),
        radius = baseRadius * 2,
        center = center
    )

    // Core - warm cream
    drawCircle(
        color = IgnitedCore,
        radius = baseRadius,
        center = center
    )

    // Bright center
    drawCircle(
        color = Color.White,
        radius = baseRadius * 0.4f,
        center = center
    )

    // Order marker for first star - subtle rose gold ring
    if (order == 0) {
        drawCircle(
            color = IgnitedGlow,
            radius = baseRadius * 1.3f,
            center = center,
            style = Stroke(width = 1.5f)
        )
    }
}

private fun DrawScope.drawConstellationPath(
    selectedPoints: List<Int>,
    getCenter: (Int) -> Offset,
    sealed: Boolean,
    sealProgress: Float,
    pulse: Float
) {
    val lineAlpha = if (sealed) 0.8f + sealProgress * 0.2f else 0.6f + pulse * 0.1f
    val glowWidth = if (sealed) 16f + sealProgress * 8f else 12f
    val coreWidth = if (sealed) 3f + sealProgress * 1.5f else 2.5f

    for (i in 0 until selectedPoints.size - 1) {
        val from = getCenter(selectedPoints[i])
        val to = getCenter(selectedPoints[i + 1])

        // Wide glow
        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(
                    ConstellationLine.copy(alpha = lineAlpha * 0.15f),
                    ConstellationLine.copy(alpha = lineAlpha * 0.25f),
                    ConstellationLine.copy(alpha = lineAlpha * 0.15f)
                ),
                start = from,
                end = to
            ),
            start = from,
            end = to,
            strokeWidth = glowWidth,
            cap = StrokeCap.Round
        )

        // Core line
        drawLine(
            color = ConstellationLine.copy(alpha = lineAlpha),
            start = from,
            end = to,
            strokeWidth = coreWidth,
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawTracingLine(from: Offset, to: Offset, pulse: Float) {
    val alpha = 0.4f + pulse * 0.1f

    drawLine(
        color = ConstellationLine.copy(alpha = alpha * 0.5f),
        start = from,
        end = to,
        strokeWidth = 8f,
        cap = StrokeCap.Round
    )

    drawLine(
        color = ConstellationLine.copy(alpha = alpha),
        start = from,
        end = to,
        strokeWidth = 2f,
        cap = StrokeCap.Round
    )
}

private fun DrawScope.drawSealingRitual(
    selectedPoints: List<Int>,
    getCenter: (Int) -> Offset,
    progress: Float
) {
    if (selectedPoints.isEmpty()) return

    // Calculate constellation center
    var cx = 0f
    var cy = 0f
    for (idx in selectedPoints) {
        val pos = getCenter(idx)
        cx += pos.x
        cy += pos.y
    }
    cx /= selectedPoints.size
    cy /= selectedPoints.size
    val center = Offset(cx, cy)

    val maxRadius = size.minDimension * 0.5f

    // Expanding rings
    listOf(0.3f, 0.5f, 0.7f, 1f).forEach { ringOffset ->
        val ringProgress = ((progress - ringOffset * 0.2f) / 0.8f).coerceIn(0f, 1f)
        if (ringProgress > 0) {
            val radius = ringProgress * maxRadius
            val alpha = ((1f - ringProgress) * 0.4f).coerceIn(0f, 1f)

            drawCircle(
                color = IgnitedGlow.copy(alpha = alpha),
                radius = radius,
                center = center,
                style = Stroke(width = 2f + (1f - ringProgress) * 3f)
            )
        }
    }
}
