# Yours ProGuard Rules
# ===================
# Keep crypto code unobfuscated to avoid JNI issues

# Keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Bedrock crypto classes
-keep class com.yours.app.crypto.** { *; }

# Keep identity classes (serialization)
-keep class com.yours.app.identity.** { *; }

# Keep vault classes (serialization)
-keep class com.yours.app.vault.** { *; }

# Keep Compose
-keep class androidx.compose.** { *; }

# Kotlin serialization (if used later)
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# CameraX
-keep class androidx.camera.** { *; }
