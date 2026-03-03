package com.yours.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.yours.app.R

/**
 * Yours color palette.
 *
 * True black. The void. Protected.
 * Warm gold accents. Sovereign.
 */
object YoursColors {
    // Backgrounds - true black
    val Background = Color(0xFF000000)     // Pure black
    val Surface = Color(0xFF0A0A0A)        // Near black for cards/surfaces
    val SurfaceVariant = Color(0xFF141414) // Elevated surfaces

    // Text
    val OnBackground = Color(0xFFF5F5F5)
    val OnBackgroundMuted = Color(0xFF808080)  // Gray for secondary text
    val OnSurface = Color(0xFFF0F0F0)

    // Accent - Warm gold
    val Primary = Color(0xFFE8B866)        // Warm gold
    val PrimaryVariant = Color(0xFFD4A554)
    val PrimaryLight = Color(0xFFF5D89A)
    val PrimaryDim = Color(0x26E8B866)     // 15% opacity gold for borders
    val OnPrimary = Color(0xFF000000)

    // Gray scale for UI elements
    val Gray = Color(0xFF808080)
    val GrayLight = Color(0xFFAAAAAA)
    val GrayDim = Color(0xFF2A2A2A)

    // States
    val Success = Color(0xFF5CB85C)
    val Error = Color(0xFFE57373)
    val Warning = Color(0xFFFFA726)

    // Glyph / Logo loader
    val GlyphEmpty = Color(0xFF2A2A2A)
    val GlyphFilling = Color(0xFFE8B866)
    val GlyphFull = Color(0xFFE8B866)
}

/**
 * JetBrains Mono - The YOURS brand font.
 * Used exclusively for [ YOURS ] brand mark.
 * Technical monospace aesthetic.
 */
val JetBrainsMonoFamily = FontFamily(
    Font(R.font.jetbrainsmono)
)

// Alias for backwards compatibility
val GluspFontFamily = JetBrainsMonoFamily

/**
 * Brand text style for [ YOURS ] mark.
 */
val YoursBrandStyle = TextStyle(
    fontFamily = JetBrainsMonoFamily,
    fontWeight = FontWeight.Normal,
    letterSpacing = 2.sp
)

private val DarkColorScheme = darkColorScheme(
    primary = YoursColors.Primary,
    onPrimary = YoursColors.OnPrimary,
    primaryContainer = YoursColors.PrimaryVariant,
    secondary = YoursColors.Primary,
    background = YoursColors.Background,
    onBackground = YoursColors.OnBackground,
    surface = YoursColors.Surface,
    onSurface = YoursColors.OnSurface,
    surfaceVariant = YoursColors.SurfaceVariant,
    error = YoursColors.Error
)

/**
 * Yours typography.
 * 
 * One typeface, confident weight.
 * Let the words do the work.
 */
val YoursTypography = Typography(
    // Large display - "This is you"
    displayLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Light,
        fontSize = 36.sp,
        lineHeight = 44.sp,
        letterSpacing = (-0.5).sp
    ),
    
    // Medium display - Section headers
    displayMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Light,
        fontSize = 28.sp,
        lineHeight = 36.sp,
        letterSpacing = 0.sp
    ),
    
    // Headlines
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 24.sp,
        lineHeight = 32.sp
    ),
    
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 20.sp,
        lineHeight = 28.sp
    ),
    
    // Body
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp
    ),
    
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        color = YoursColors.OnBackgroundMuted
    ),
    
    // Labels
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.1.sp
    ),
    
    labelMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
)

@Composable
fun YoursTheme(
    content: @Composable () -> Unit
) {
    // Always dark - light feels exposed, dark feels protected
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = YoursTypography,
        content = content
    )
}
