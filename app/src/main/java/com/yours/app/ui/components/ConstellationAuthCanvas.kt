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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yours.app.security.HumanCentricAuth
import com.yours.app.ui.theme.YoursColors
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Constellation Authentication Canvas - Enhanced Security Pattern Input
 *
 * A 7x5 grid constellation interface that captures:
 * - Spatial pattern (which stars are connected)
 * - Timing (rhythm between points)
 * - Pressure (if device supports)
 *
 * This provides enhanced security through multi-factor authentication
 * using spatial, motor, and temporal memory.
 *
 * "Draw your constellation across the night sky"
 */

// Grid dimensions for constellation (matches HumanCentricAuth)
private const val CONSTELLATION_COLS = HumanCentricAuth.GRID_COLS  // 7
private const val CONSTELLATION_ROWS = HumanCentricAuth.GRID_ROWS  // 5
private const val CONSTELLATION_TOTAL = CONSTELLATION_COLS * CONSTELLATION_ROWS  // 35
private const val CONSTELLATION_MIN_LENGTH = HumanCentricAuth.MIN_PATTERN_LENGTH  // 6
private const val CONSTELLATION_STAR_HIT_RADIUS = 36f

// Colors - deep space theme with cyan/teal accent for "enhanced" feel
private val ConstellationVoid = Color(0xFF000508)
private val ConstellationDeep = Color(0xFF010810)

private val ConstellationStarWhite = Color(0xFFFFFFFF)
private val ConstellationStarSilver = Color(0xFFE0E8F0)
private val ConstellationStarGlow = Color(0xFF98B4D8)

private val ConstellationIgnitedCore = Color(0xFFF0FFFF)
private val ConstellationIgnitedInner = Color(0xFFB8F4F8)
private val ConstellationIgnitedGlow = Color(0xFF4ECDC4)
private val ConstellationIgnitedOuter = Color(0xFF26A69A)
private val ConstellationLine = Color(0xFF4ECDC4)

/**
 * A point in the constellation with timing and pressure data.
 */
data class ConstellationTouchPoint(
    val gridX: Int,
    val gridY: Int,
    val timestamp: Long,
    val pressure: Float = 0.5f
) {
    val gridIndex: Int get() = gridY * CONSTELLATION_COLS + gridX

    fun toHumanCentricPoint(): HumanCentricAuth.ConstellationPoint {
        return HumanCentricAuth.ConstellationPoint(
            x = gridX,
            y = gridY,
            timestamp = timestamp,
            pressure = pressure
        )
    }
}

sealed class ConstellationState {
    object Idle : ConstellationState()
    data class Drawing(val points: List<ConstellationTouchPoint>) : ConstellationState()
    object Complete : ConstellationState()
    object Sealed : ConstellationState()
    data class Error(val message: String) : ConstellationState()
}

enum class ConstellationMode {
    Create,  // Setting up new pattern
    Verify   // Verifying existing pattern
}

/**
 * Constellation authentication canvas for HumanCentricAuth.
 *
 * @param modifier Modifier for the canvas
 * @param mode Create for new pattern, Verify for authentication
 * @param onPatternComplete Called when pattern is complete with enough points
 * @param onPatternFailed Called when verification fails (Verify mode only)
 */
@Composable
fun ConstellationAuthCanvas(
    modifier: Modifier = Modifier,
    mode: ConstellationMode = ConstellationMode.Create,
    onPatternComplete: (HumanCentricAuth.ConstellationPattern) -> Unit = {},
    onPatternFailed: () -> Unit = {}
) {
    val view = LocalView.current
    val density = LocalDensity.current
    val hitRadiusPx = with(density) { CONSTELLATION_STAR_HIT_RADIUS.dp.toPx() }

    var state by remember { mutableStateOf<ConstellationState>(ConstellationState.Idle) }
    var touchPoints by remember { mutableStateOf(listOf<ConstellationTouchPoint>()) }
    var currentTouch by remember { mutableStateOf<Offset?>(null) }
    var gridOrigin by remember { mutableStateOf(Offset.Zero) }
    var cellWidth by remember { mutableStateOf(0f) }
    var cellHeight by remember { mutableStateOf(0f) }

    // Background stars for ambiance
    val backgroundStars = remember {
        generateConstellationBackgroundStars(120)
    }

    fun getStarCenter(col: Int, row: Int): Offset {
        return Offset(
            gridOrigin.x + col * cellWidth + cellWidth / 2,
            gridOrigin.y + row * cellHeight + cellHeight / 2
        )
    }

    fun getStarCenterByIndex(index: Int): Offset {
        val row = index / CONSTELLATION_COLS
        val col = index % CONSTELLATION_COLS
        return getStarCenter(col, row)
    }

    fun findStarAt(touch: Offset): Pair<Int, Int>? {
        for (row in 0 until CONSTELLATION_ROWS) {
            for (col in 0 until CONSTELLATION_COLS) {
                val center = getStarCenter(col, row)
                val dx = touch.x - center.x
                val dy = touch.y - center.y
                if (sqrt(dx * dx + dy * dy) < hitRadiusPx) {
                    return col to row
                }
            }
        }
        return null
    }

    // Animations
    val infiniteTransition = rememberInfiniteTransition(label = "constellation")

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
            animation = tween(80000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val twinklePhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 6.28f,
        animationSpec = infiniteRepeatable(
            animation = tween(2500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "twinkle"
    )

    val sealAnimation by animateFloatAsState(
        targetValue = if (state is ConstellationState.Sealed) 1f else 0f,
        animationSpec = tween(800, easing = FastOutSlowInEasing),
        label = "seal"
    )

    // Check if pattern is complete
    LaunchedEffect(touchPoints.size) {
        if (touchPoints.size >= CONSTELLATION_MIN_LENGTH && state is ConstellationState.Drawing) {
            state = ConstellationState.Complete
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(ConstellationVoid)
    ) {
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    detectDragGestures(
                        onDragStart = { offset ->
                            if (state is ConstellationState.Sealed) return@detectDragGestures

                            // Calculate grid dimensions
                            val screenWidth = size.width.toFloat()
                            val screenHeight = size.height.toFloat()

                            // 7x5 grid - wider than tall
                            val aspectRatio = CONSTELLATION_COLS.toFloat() / CONSTELLATION_ROWS.toFloat()
                            val maxGridWidth = screenWidth * 0.9f
                            val maxGridHeight = screenHeight * 0.7f

                            val gridWidth: Float
                            val gridHeight: Float

                            if (maxGridWidth / aspectRatio <= maxGridHeight) {
                                gridWidth = maxGridWidth
                                gridHeight = maxGridWidth / aspectRatio
                            } else {
                                gridHeight = maxGridHeight
                                gridWidth = maxGridHeight * aspectRatio
                            }

                            cellWidth = gridWidth / CONSTELLATION_COLS
                            cellHeight = gridHeight / CONSTELLATION_ROWS
                            gridOrigin = Offset(
                                (screenWidth - gridWidth) / 2,
                                (screenHeight - gridHeight) / 2 - 40f
                            )

                            val star = findStarAt(offset)
                            if (star != null) {
                                val (col, row) = star
                                val point = ConstellationTouchPoint(
                                    gridX = col,
                                    gridY = row,
                                    timestamp = System.currentTimeMillis(),
                                    pressure = 0.5f // Default pressure, real implementation would use MotionEvent
                                )
                                touchPoints = listOf(point)
                                currentTouch = offset
                                state = ConstellationState.Drawing(touchPoints)
                                try {
                                    view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                } catch (_: Exception) {}
                            }
                        },
                        onDrag = { change, _ ->
                            if (state !is ConstellationState.Drawing) return@detectDragGestures

                            currentTouch = change.position
                            val star = findStarAt(change.position)

                            if (star != null) {
                                val (col, row) = star
                                val index = row * CONSTELLATION_COLS + col

                                // Check if this star is already in the pattern
                                val alreadySelected = touchPoints.any {
                                    it.gridX == col && it.gridY == row
                                }

                                if (!alreadySelected) {
                                    val point = ConstellationTouchPoint(
                                        gridX = col,
                                        gridY = row,
                                        timestamp = System.currentTimeMillis(),
                                        pressure = 0.5f
                                    )
                                    touchPoints = touchPoints + point
                                    state = ConstellationState.Drawing(touchPoints)
                                    try {
                                        view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                    } catch (_: Exception) {}
                                }
                            }
                        },
                        onDragEnd = {
                            currentTouch = null

                            if (touchPoints.size >= CONSTELLATION_MIN_LENGTH) {
                                try {
                                    val humanCentricPoints = touchPoints.map { it.toHumanCentricPoint() }
                                    val pattern = HumanCentricAuth.ConstellationPattern(humanCentricPoints)

                                    state = ConstellationState.Sealed
                                    try {
                                        view.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
                                    } catch (_: Exception) {}
                                    onPatternComplete(pattern)
                                } catch (e: Exception) {
                                    state = ConstellationState.Error("Invalid pattern: ${e.message}")
                                    touchPoints = listOf()
                                    onPatternFailed()
                                }
                            } else if (touchPoints.isNotEmpty()) {
                                state = ConstellationState.Error("Connect at least $CONSTELLATION_MIN_LENGTH stars")
                                touchPoints = listOf()
                            }
                        },
                        onDragCancel = {
                            currentTouch = null
                            touchPoints = listOf()
                            state = ConstellationState.Idle
                        }
                    )
                }
        ) {
            // Calculate grid dimensions
            val screenWidth = size.width
            val screenHeight = size.height

            val aspectRatio = CONSTELLATION_COLS.toFloat() / CONSTELLATION_ROWS.toFloat()
            val maxGridWidth = screenWidth * 0.9f
            val maxGridHeight = screenHeight * 0.7f

            val gridWidth: Float
            val gridHeight: Float

            if (maxGridWidth / aspectRatio <= maxGridHeight) {
                gridWidth = maxGridWidth
                gridHeight = maxGridWidth / aspectRatio
            } else {
                gridHeight = maxGridHeight
                gridWidth = maxGridHeight * aspectRatio
            }

            cellWidth = gridWidth / CONSTELLATION_COLS
            cellHeight = gridHeight / CONSTELLATION_ROWS
            gridOrigin = Offset(
                (screenWidth - gridWidth) / 2,
                (screenHeight - gridHeight) / 2 - 40f
            )

            // Layer 1: Deep space background
            drawConstellationBackground(cosmicPulse)

            // Layer 2: Background stars
            drawConstellationDistantStars(backgroundStars, twinklePhase)

            // Layer 3: Connection lines
            if (touchPoints.size >= 2) {
                drawConstellationPath(
                    points = touchPoints,
                    getCenter = { getStarCenterByIndex(it.gridIndex) },
                    sealed = state is ConstellationState.Sealed,
                    sealProgress = sealAnimation,
                    pulse = cosmicPulse
                )
            }

            // Layer 4: Active tracing line
            if (currentTouch != null && touchPoints.isNotEmpty()) {
                val lastPoint = touchPoints.last()
                val lastCenter = getStarCenter(lastPoint.gridX, lastPoint.gridY)
                drawConstellationTracingLine(lastCenter, currentTouch!!, cosmicPulse)
            }

            // Layer 5: Grid stars
            val selectedIndices = touchPoints.map { it.gridIndex }.toSet()
            drawConstellationStars(
                selectedIndices = selectedIndices,
                getCenter = { getStarCenterByIndex(it) },
                pulse = cosmicPulse,
                rotation = starRotation,
                sealed = state is ConstellationState.Sealed,
                sealProgress = sealAnimation
            )

            // Layer 6: Seal effect
            if (state is ConstellationState.Sealed && sealAnimation > 0) {
                drawConstellationSealEffect(
                    points = touchPoints,
                    getCenter = { getStarCenterByIndex(it.gridIndex) },
                    progress = sealAnimation
                )
            }
        }

        // UI overlay at bottom
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Enhanced security badge
            if (state is ConstellationState.Idle) {
                Box(
                    modifier = Modifier
                        .background(
                            ConstellationIgnitedGlow.copy(alpha = 0.15f),
                            shape = CircleShape
                        )
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "ENHANCED SECURITY",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.5.sp,
                        color = ConstellationIgnitedGlow
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            // Status text - matches top instruction font, italicized for hint feel
            Text(
                text = when (state) {
                    is ConstellationState.Idle -> "TRACE YOUR CONSTELLATION"
                    is ConstellationState.Drawing -> "${touchPoints.size} STARS CONNECTED"
                    is ConstellationState.Complete -> "RELEASE TO SEAL"
                    is ConstellationState.Sealed -> "CONSTELLATION SEALED"
                    is ConstellationState.Error -> (state as ConstellationState.Error).message.uppercase()
                },
                fontSize = 12.sp,
                fontStyle = FontStyle.Italic,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp,
                color = when (state) {
                    is ConstellationState.Error -> Color(0xFFef4444)
                    is ConstellationState.Sealed -> ConstellationIgnitedGlow
                    is ConstellationState.Complete -> ConstellationIgnitedGlow
                    else -> ConstellationStarSilver.copy(alpha = 0.85f)
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Progress dots
            Row(
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                repeat(CONSTELLATION_MIN_LENGTH) { index ->
                    val filled = index < touchPoints.size
                    val isSealed = state is ConstellationState.Sealed
                    Box(
                        modifier = Modifier
                            .size(if (filled) 8.dp else 5.dp)
                            .background(
                                when {
                                    isSealed -> ConstellationIgnitedGlow
                                    filled -> ConstellationIgnitedGlow
                                    else -> ConstellationStarSilver.copy(alpha = 0.3f)
                                },
                                shape = CircleShape
                            )
                    )
                }
            }

            // Timing hint
            if (state is ConstellationState.Drawing && touchPoints.size >= 2) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Rhythm matters - your timing is part of the pattern",
                    style = MaterialTheme.typography.labelSmall,
                    color = ConstellationStarSilver.copy(alpha = 0.5f)
                )
            }
        }
    }
}

// =============================================================================
// DRAWING FUNCTIONS
// =============================================================================

private data class ConstellationBackgroundStar(
    val x: Float,
    val y: Float,
    val size: Float,
    val brightness: Float,
    val twinkleSpeed: Float
)

private fun generateConstellationBackgroundStars(count: Int): List<ConstellationBackgroundStar> {
    val result = mutableListOf<ConstellationBackgroundStar>()
    val a = 1664525
    val c = 1013904223
    var state = 0x434F4E53  // "CONS"

    repeat(count) {
        state = a * state + c
        val x = ((state ushr 8) and 0xFFFF) / 65536f

        state = a * state + c
        val y = ((state ushr 8) and 0xFFFF) / 65536f

        state = a * state + c
        val size = 0.4f + (((state ushr 8) and 0xFF) / 255f) * 1.2f

        state = a * state + c
        val brightness = 0.12f + (((state ushr 8) and 0xFF) / 255f) * 0.35f

        state = a * state + c
        val twinkleSpeed = 0.4f + (((state ushr 8) and 0xFF) / 255f) * 1.2f

        result.add(ConstellationBackgroundStar(x, y, size, brightness, twinkleSpeed))
    }
    return result
}

private fun DrawScope.drawConstellationBackground(pulse: Float) {
    drawRect(
        brush = Brush.radialGradient(
            colors = listOf(
                ConstellationDeep,
                ConstellationVoid,
                ConstellationVoid
            ),
            center = Offset(size.width * 0.5f, size.height * 0.4f),
            radius = size.maxDimension * 0.85f
        )
    )
}

private fun DrawScope.drawConstellationDistantStars(
    stars: List<ConstellationBackgroundStar>,
    twinklePhase: Float
) {
    for (star in stars) {
        val x = star.x * size.width
        val y = star.y * size.height

        val twinkle = sin(twinklePhase * star.twinkleSpeed + star.x * 12).toFloat()
        val alpha = (star.brightness * (0.55f + twinkle * 0.45f)).coerceIn(0f, 1f)

        drawCircle(
            color = Color.White.copy(alpha = alpha * 0.25f),
            radius = star.size * 2.2f,
            center = Offset(x, y)
        )

        drawCircle(
            color = Color.White.copy(alpha = alpha),
            radius = star.size,
            center = Offset(x, y)
        )
    }
}

private fun DrawScope.drawConstellationStars(
    selectedIndices: Set<Int>,
    getCenter: (Int) -> Offset,
    pulse: Float,
    rotation: Float,
    sealed: Boolean,
    sealProgress: Float
) {
    for (i in 0 until CONSTELLATION_TOTAL) {
        val center = getCenter(i)
        val isSelected = i in selectedIndices

        if (isSelected) {
            drawConstellationIgnitedStar(center, pulse, sealed, sealProgress)
        } else {
            drawConstellationDormantStar(center, pulse, rotation)
        }
    }
}

private fun DrawScope.drawConstellationDormantStar(center: Offset, pulse: Float, rotation: Float) {
    val baseAlpha = (0.45f + pulse * 0.18f).coerceIn(0f, 0.7f)
    val baseRadius = 4f

    // Outer glow
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                ConstellationStarGlow.copy(alpha = baseAlpha * 0.12f),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 3.5f
        ),
        radius = baseRadius * 3.5f,
        center = center
    )

    // Subtle cross rays
    val rayLength = baseRadius * 2.2f
    val rayAlpha = baseAlpha * 0.25f
    for (angle in listOf(0f, 90f)) {
        val rad = Math.toRadians((angle + rotation * 0.03).toDouble())
        val dx = cos(rad).toFloat() * rayLength
        val dy = sin(rad).toFloat() * rayLength

        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(
                    Color.Transparent,
                    ConstellationStarSilver.copy(alpha = rayAlpha),
                    Color.Transparent
                ),
                start = Offset(center.x - dx, center.y - dy),
                end = Offset(center.x + dx, center.y + dy)
            ),
            start = Offset(center.x - dx, center.y - dy),
            end = Offset(center.x + dx, center.y + dy),
            strokeWidth = 0.8f
        )
    }

    // Inner glow
    drawCircle(
        color = ConstellationStarSilver.copy(alpha = baseAlpha * 0.35f),
        radius = baseRadius * 1.4f,
        center = center
    )

    // Core
    drawCircle(
        color = ConstellationStarWhite.copy(alpha = (baseAlpha + 0.18f).coerceIn(0f, 1f)),
        radius = baseRadius,
        center = center
    )

    // Bright center
    drawCircle(
        color = ConstellationStarWhite,
        radius = 1.3f,
        center = center
    )
}

private fun DrawScope.drawConstellationIgnitedStar(
    center: Offset,
    pulse: Float,
    sealed: Boolean,
    sealProgress: Float
) {
    val intensity = if (sealed) 0.88f + sealProgress * 0.12f else 0.82f
    val baseRadius = 5.5f + if (sealed) sealProgress * 2.5f else pulse * 0.8f
    val glowExpand = if (sealed) 1f + sealProgress * 0.4f else 1f

    // Large outer aura
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                ConstellationIgnitedOuter.copy(alpha = 0.18f * intensity),
                ConstellationIgnitedOuter.copy(alpha = 0.06f * intensity),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 7 * glowExpand
        ),
        radius = baseRadius * 7 * glowExpand,
        center = center
    )

    // Cross rays
    val rayLength = baseRadius * 5.5f * glowExpand
    val rayAlpha = 0.5f * intensity
    for (angle in listOf(0f, 45f, 90f, 135f)) {
        val rad = Math.toRadians(angle.toDouble())
        val dx = cos(rad).toFloat() * rayLength
        val dy = sin(rad).toFloat() * rayLength
        val width = if (angle % 90 == 0f) 2.2f else 1.3f

        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(
                    Color.Transparent,
                    ConstellationIgnitedGlow.copy(alpha = rayAlpha),
                    Color.Transparent
                ),
                start = Offset(center.x - dx, center.y - dy),
                end = Offset(center.x + dx, center.y + dy)
            ),
            start = Offset(center.x - dx, center.y - dy),
            end = Offset(center.x + dx, center.y + dy),
            strokeWidth = width
        )
    }

    // Mid glow
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                ConstellationIgnitedGlow.copy(alpha = 0.6f * intensity),
                ConstellationIgnitedGlow.copy(alpha = 0.22f * intensity),
                Color.Transparent
            ),
            center = center,
            radius = baseRadius * 3.5f
        ),
        radius = baseRadius * 3.5f,
        center = center
    )

    // Inner glow
    drawCircle(
        color = ConstellationIgnitedInner.copy(alpha = 0.8f * intensity),
        radius = baseRadius * 1.8f,
        center = center
    )

    // Core
    drawCircle(
        color = ConstellationIgnitedCore,
        radius = baseRadius,
        center = center
    )

    // Bright center
    drawCircle(
        color = Color.White,
        radius = baseRadius * 0.35f,
        center = center
    )
}

private fun DrawScope.drawConstellationPath(
    points: List<ConstellationTouchPoint>,
    getCenter: (ConstellationTouchPoint) -> Offset,
    sealed: Boolean,
    sealProgress: Float,
    pulse: Float
) {
    val lineAlpha = if (sealed) 0.75f + sealProgress * 0.25f else 0.55f + pulse * 0.08f
    val glowWidth = if (sealed) 14f + sealProgress * 6f else 10f
    val coreWidth = if (sealed) 2.8f + sealProgress * 1.2f else 2.2f

    for (i in 0 until points.size - 1) {
        val from = getCenter(points[i])
        val to = getCenter(points[i + 1])

        // Wide glow
        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(
                    ConstellationLine.copy(alpha = lineAlpha * 0.12f),
                    ConstellationLine.copy(alpha = lineAlpha * 0.22f),
                    ConstellationLine.copy(alpha = lineAlpha * 0.12f)
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

private fun DrawScope.drawConstellationTracingLine(from: Offset, to: Offset, pulse: Float) {
    val alpha = 0.35f + pulse * 0.08f

    drawLine(
        color = ConstellationLine.copy(alpha = alpha * 0.45f),
        start = from,
        end = to,
        strokeWidth = 7f,
        cap = StrokeCap.Round
    )

    drawLine(
        color = ConstellationLine.copy(alpha = alpha),
        start = from,
        end = to,
        strokeWidth = 1.8f,
        cap = StrokeCap.Round
    )
}

private fun DrawScope.drawConstellationSealEffect(
    points: List<ConstellationTouchPoint>,
    getCenter: (ConstellationTouchPoint) -> Offset,
    progress: Float
) {
    if (points.isEmpty()) return

    // Calculate constellation center
    var cx = 0f
    var cy = 0f
    for (point in points) {
        val pos = getCenter(point)
        cx += pos.x
        cy += pos.y
    }
    cx /= points.size
    cy /= points.size
    val center = Offset(cx, cy)

    val maxRadius = size.minDimension * 0.45f

    // Expanding rings
    listOf(0.25f, 0.45f, 0.65f, 0.9f).forEach { ringOffset ->
        val ringProgress = ((progress - ringOffset * 0.18f) / 0.82f).coerceIn(0f, 1f)
        if (ringProgress > 0) {
            val radius = ringProgress * maxRadius
            val alpha = ((1f - ringProgress) * 0.35f).coerceIn(0f, 1f)

            drawCircle(
                color = ConstellationIgnitedGlow.copy(alpha = alpha),
                radius = radius,
                center = center,
                style = Stroke(width = 1.8f + (1f - ringProgress) * 2.5f)
            )
        }
    }
}
