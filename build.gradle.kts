// Yours - Sovereign Digital Ownership
// Root build configuration

plugins {
    id("com.android.application") version "8.2.0" apply false
    id("com.android.library") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
    // Rust library prebuilt with cargo-ndk
    // id("org.mozilla.rust-android-gradle.rust-android") version "0.9.3" apply false
}

tasks.register("clean", Delete::class) {
    delete(layout.buildDirectory)
}
