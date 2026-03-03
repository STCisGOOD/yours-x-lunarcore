plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    // Rust library prebuilt with cargo-ndk
    // id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    namespace = "com.yours.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.yours.app"
        minSdk = 26  // Android 8.0+ for modern crypto APIs
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    
    kotlinOptions {
        jvmTarget = "17"
    }
    
    buildFeatures {
        viewBinding = true
        compose = true
    }
    
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4"
    }
}

// Rust library already built with cargo-ndk
// cargo {
//     module = "../bedrock-core"
//     libname = "bedrock_core"
//     targets = listOf("arm64", "arm")
//     profile = "release"
// }

dependencies {
    // Core Android
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")

    // Activity/Fragment (no Material - using Compose Material3 only)
    implementation("androidx.activity:activity-ktx:1.8.1")
    implementation("androidx.fragment:fragment-ktx:1.6.2")
    
    // Compose UI
    implementation(platform("androidx.compose:compose-bom:2023.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.8.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.6.2")
    implementation("androidx.navigation:navigation-compose:2.7.5")
    debugImplementation("androidx.compose.ui:ui-tooling")
    
    // CameraX - Direct camera access
    val cameraxVersion = "1.3.0"
    implementation("androidx.camera:camera-core:$cameraxVersion")
    implementation("androidx.camera:camera-camera2:$cameraxVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraxVersion")
    implementation("androidx.camera:camera-view:$cameraxVersion")
    
    // Image processing (EXIF stripping)
    implementation("androidx.exifinterface:exifinterface:1.3.6")
    
    // REMOVED: androidx.security:security-crypto - using Rust crypto instead
    
    // Lifecycle
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.6.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")
    
    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    
    // DataStore for preferences
    implementation("androidx.datastore:datastore-preferences:1.0.0")
    
    // QR Code generation - ZXing core only (pure Java, no wrapper)
    implementation("com.google.zxing:core:3.5.3")

    // QR Code scanning - BoofCV (pure Java, no Google)
    // With UR 2.0 fountain codes, each QR is ~250 bytes (Version 10-12) - easy to scan
    implementation("org.boofcv:boofcv-core:1.1.7")
    implementation("org.boofcv:boofcv-android:1.1.7")

    // UR 2.0 animated QR protocol - Hummingbird (fountain codes for rateless encoding)
    // Handles out-of-order frame capture, ~5-10% redundancy for reliable transfers
    implementation("com.sparrowwallet:hummingbird:1.7.4")

    // USB Serial for ESP32 LoRa communication
    implementation("com.github.mik3y:usb-serial-for-android:3.7.0")
    
    // REMOVED: biometric - not used, relies on OS trust
    
    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    
    // NO Google Play Services
    // NO Firebase  
    // NO Analytics
    // NO Cloud dependencies
}

// Native library prebuilt with cargo-ndk, no need to build during Gradle
// tasks.matching { it.name.contains("Jni") || it.name.contains("Rust") }.configureEach {
//     dependsOn("cargoBuild")
// }
