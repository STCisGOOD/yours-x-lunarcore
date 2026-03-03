package com.yours.app.security

import android.content.Context
import android.os.Build
import java.io.File

/**
 * DeviceLiberation - Take back control of your device.
 *
 * PHILOSOPHY:
 * The Samsung zero-click exploit (CVE-2025-21043) existed in Samsung's
 * closed-source libimagecodec.quram.so. On a sovereign device running
 * GrapheneOS or CalyxOS, that library doesn't exist.
 *
 * THE SCANNER TELLS YOU THAT YOU'RE ENSLAVED.
 * THIS MODULE HELPS YOU BREAK FREE.
 *
 * CAPABILITIES:
 * 1. Bootloader unlock guidance (device-specific)
 * 2. Magisk installation for root access
 * 3. Bloatware removal (ADB + root methods)
 * 4. Custom ROM recommendations and flashing
 * 5. Complete degoogle process
 *
 * THREAT MODEL:
 * - Samsung/Google control your device firmware
 * - Their closed-source code has vulnerabilities (proven repeatedly)
 * - You cannot audit what you cannot see
 * - Solution: Replace their code with auditable open-source
 *
 * "If you can't open it, you don't own it."
 */
object DeviceLiberation {

    // =========================================================================
    // DEVICE DATABASE
    // =========================================================================

    /**
     * Device-specific liberation paths.
     * Each device has different bootloader unlock procedures.
     */
    private val DEVICE_PROFILES = mapOf(
        // Google Pixel (best supported for GrapheneOS)
        "google" to DeviceProfile(
            manufacturer = "Google",
            bootloaderUnlockMethod = BootloaderUnlockMethod.OEM_UNLOCK,
            customRomSupport = CustomRomSupport.FULL,
            recommendedRom = "GrapheneOS",
            romUrl = "https://grapheneos.org/install/",
            notes = "Best privacy ROM support. Verified boot with custom keys."
        ),

        // Samsung (Knox complicates things)
        "samsung" to DeviceProfile(
            manufacturer = "Samsung",
            bootloaderUnlockMethod = BootloaderUnlockMethod.SAMSUNG_UNLOCK,
            customRomSupport = CustomRomSupport.LIMITED,
            recommendedRom = "LineageOS",
            romUrl = "https://wiki.lineageos.org/devices/",
            notes = "Knox fuse may be tripped. Some features lost. Check XDA for your model.",
            warnings = listOf(
                "Knox warranty void e-fuse will be tripped permanently",
                "Samsung Pay and Secure Folder will stop working",
                "Some banking apps may not work"
            )
        ),

        // OnePlus (generally good support)
        "oneplus" to DeviceProfile(
            manufacturer = "OnePlus",
            bootloaderUnlockMethod = BootloaderUnlockMethod.OEM_UNLOCK,
            customRomSupport = CustomRomSupport.GOOD,
            recommendedRom = "LineageOS",
            romUrl = "https://wiki.lineageos.org/devices/",
            notes = "Good custom ROM support. OEM unlock straightforward."
        ),

        // Xiaomi (requires unlock token)
        "xiaomi" to DeviceProfile(
            manufacturer = "Xiaomi",
            bootloaderUnlockMethod = BootloaderUnlockMethod.XIAOMI_UNLOCK,
            customRomSupport = CustomRomSupport.GOOD,
            recommendedRom = "LineageOS",
            romUrl = "https://wiki.lineageos.org/devices/",
            notes = "Requires Mi Unlock tool and 7-day waiting period.",
            warnings = listOf(
                "Must use official Mi Unlock tool (Windows only)",
                "7-day waiting period after requesting unlock",
                "Xiaomi account required (privacy concern)"
            )
        ),

        // Fairphone (designed for sovereignty)
        "fairphone" to DeviceProfile(
            manufacturer = "Fairphone",
            bootloaderUnlockMethod = BootloaderUnlockMethod.OEM_UNLOCK,
            customRomSupport = CustomRomSupport.FULL,
            recommendedRom = "CalyxOS or /e/OS",
            romUrl = "https://calyxos.org/install/",
            notes = "Designed for user sovereignty. Easy unlock, great ROM support."
        )
    )

    /**
     * Custom ROM security ratings.
     */
    private val ROM_SECURITY_RATINGS = mapOf(
        "GrapheneOS" to RomProfile(
            name = "GrapheneOS",
            securityRating = 10,
            privacyRating = 10,
            usabilityRating = 7,
            googleFree = true,
            verifiedBoot = true,
            hardening = listOf(
                "Hardened memory allocator",
                "Exploit mitigations beyond AOSP",
                "Network permission toggle",
                "Sensor permission toggle",
                "Secure app spawning",
                "Hardened WebView"
            ),
            deviceSupport = listOf("Pixel 4+"),
            url = "https://grapheneos.org"
        ),

        "CalyxOS" to RomProfile(
            name = "CalyxOS",
            securityRating = 9,
            privacyRating = 9,
            usabilityRating = 8,
            googleFree = true,
            verifiedBoot = true,
            hardening = listOf(
                "microG support (Google services alternative)",
                "Datura firewall",
                "Seedvault backup",
                "F-Droid included"
            ),
            deviceSupport = listOf("Pixel 3+", "Fairphone 4/5", "Motorola"),
            url = "https://calyxos.org"
        ),

        "LineageOS" to RomProfile(
            name = "LineageOS",
            securityRating = 7,
            privacyRating = 7,
            usabilityRating = 9,
            googleFree = false, // Can add GApps
            verifiedBoot = false, // Usually disabled
            hardening = listOf(
                "Privacy Guard",
                "Trust interface",
                "Wide device support"
            ),
            deviceSupport = listOf("Many devices"),
            url = "https://lineageos.org"
        ),

        "DivestOS" to RomProfile(
            name = "DivestOS",
            securityRating = 8,
            privacyRating = 9,
            usabilityRating = 6,
            googleFree = true,
            verifiedBoot = false,
            hardening = listOf(
                "Kernel hardening backports",
                "Deblobbed firmware where possible",
                "Long-term support for older devices"
            ),
            deviceSupport = listOf("Many older devices"),
            url = "https://divestos.org"
        ),

        "/e/OS" to RomProfile(
            name = "/e/OS",
            securityRating = 6,
            privacyRating = 8,
            usabilityRating = 9,
            googleFree = true,
            verifiedBoot = false,
            hardening = listOf(
                "microG included",
                "Cloud services (optional)",
                "App Lounge store"
            ),
            deviceSupport = listOf("Many devices", "Sells pre-installed phones"),
            url = "https://e.foundation"
        )
    )

    // =========================================================================
    // LIBERATION ASSESSMENT
    // =========================================================================

    /**
     * Assess device liberation options.
     */
    fun assessDevice(context: Context): LiberationAssessment {
        val manufacturer = Build.MANUFACTURER.lowercase()
        val model = Build.MODEL
        val device = Build.DEVICE
        val androidVersion = Build.VERSION.SDK_INT

        val profile = DEVICE_PROFILES[manufacturer] ?: DEVICE_PROFILES["google"]!!

        val currentState = DeviceState(
            manufacturer = Build.MANUFACTURER,
            model = model,
            device = device,
            androidVersion = androidVersion,
            isRooted = checkRootStatus(),
            isBootloaderUnlocked = checkBootloaderStatus(),
            hasCustomRom = checkCustomRom(),
            isGoogleFree = checkGoogleFree(context)
        )

        val liberationPath = determineLiberationPath(currentState, profile)

        return LiberationAssessment(
            currentState = currentState,
            deviceProfile = profile,
            recommendedPath = liberationPath,
            compatibleRoms = getCompatibleRoms(manufacturer, model),
            estimatedDifficulty = calculateDifficulty(profile, currentState)
        )
    }

    /**
     * Get step-by-step liberation instructions.
     */
    fun getLiberationSteps(assessment: LiberationAssessment): List<LiberationStep> {
        val steps = mutableListOf<LiberationStep>()
        val state = assessment.currentState
        val profile = assessment.deviceProfile

        // Step 1: Backup
        steps.add(LiberationStep(
            order = 1,
            title = "Backup Your Data",
            description = "Before proceeding, backup all important data. This process WILL wipe your device.",
            commands = listOf(
                "# Backup via ADB:",
                "adb backup -apk -shared -all -f backup.ab",
                "",
                "# Or use Seedvault if installed:",
                "# Settings > System > Backup"
            ),
            warnings = listOf("ALL DATA WILL BE ERASED"),
            isCompleted = false,
            canSkip = false
        ))

        // Step 2: Enable Developer Options
        if (!state.isBootloaderUnlocked) {
            steps.add(LiberationStep(
                order = 2,
                title = "Enable Developer Options",
                description = "Required to access bootloader unlock settings.",
                commands = listOf(
                    "# On device:",
                    "Settings > About Phone > Tap 'Build Number' 7 times",
                    "",
                    "# Then:",
                    "Settings > Developer Options > Enable 'OEM Unlocking'"
                ),
                warnings = if (profile.manufacturer == "Samsung") {
                    listOf("This will trip Knox fuse permanently")
                } else emptyList(),
                isCompleted = false,
                canSkip = false
            ))

            // Step 3: Unlock Bootloader
            steps.add(LiberationStep(
                order = 3,
                title = "Unlock Bootloader",
                description = getBootloaderUnlockDescription(profile.bootloaderUnlockMethod),
                commands = getBootloaderUnlockCommands(profile.bootloaderUnlockMethod),
                warnings = profile.warnings,
                isCompleted = false,
                canSkip = false
            ))
        }

        // Step 4: Install Custom Recovery (if not Pixel)
        if (profile.manufacturer != "Google") {
            steps.add(LiberationStep(
                order = steps.size + 1,
                title = "Install Custom Recovery (TWRP)",
                description = "Custom recovery allows flashing custom ROMs.",
                commands = listOf(
                    "# Download TWRP for your device from:",
                    "# https://twrp.me/Devices/",
                    "",
                    "# Boot into bootloader:",
                    "adb reboot bootloader",
                    "",
                    "# Flash TWRP:",
                    "fastboot flash recovery twrp-<version>-<device>.img",
                    "",
                    "# Boot into recovery:",
                    "fastboot boot twrp-<version>-<device>.img"
                ),
                warnings = emptyList(),
                isCompleted = false,
                canSkip = false
            ))
        }

        // Step 5: Flash Custom ROM
        val recommendedRom = ROM_SECURITY_RATINGS[profile.recommendedRom]
        steps.add(LiberationStep(
            order = steps.size + 1,
            title = "Flash ${profile.recommendedRom}",
            description = "Install privacy-respecting operating system.",
            commands = if (profile.manufacturer == "Google" && profile.recommendedRom == "GrapheneOS") {
                listOf(
                    "# GrapheneOS has a web installer:",
                    "# Visit: https://grapheneos.org/install/web",
                    "",
                    "# Or manual install:",
                    "adb reboot bootloader",
                    "fastboot flashing unlock",
                    "# Follow official instructions at grapheneos.org"
                )
            } else {
                listOf(
                    "# Download ROM from: ${profile.romUrl}",
                    "",
                    "# Boot to recovery:",
                    "adb reboot recovery",
                    "",
                    "# In TWRP:",
                    "# 1. Wipe > Advanced Wipe > Select Dalvik, Cache, System, Data",
                    "# 2. Install > Select ROM zip",
                    "# 3. Reboot > System"
                )
            },
            warnings = listOf("This will completely replace your operating system"),
            isCompleted = false,
            canSkip = false
        ))

        // Step 6: Root with Magisk (optional)
        steps.add(LiberationStep(
            order = steps.size + 1,
            title = "Install Magisk (Optional Root)",
            description = "Root access enables complete control and bloatware removal.",
            commands = listOf(
                "# Download Magisk from:",
                "# https://github.com/topjohnwu/Magisk/releases",
                "",
                "# Method 1 - Patch boot image:",
                "# 1. Extract boot.img from your ROM",
                "# 2. Install Magisk app",
                "# 3. Magisk > Install > Select boot.img",
                "# 4. Flash patched boot.img:",
                "adb reboot bootloader",
                "fastboot flash boot magisk_patched.img",
                "",
                "# Method 2 - Flash in recovery:",
                "# Flash Magisk.apk (renamed to .zip) in TWRP"
            ),
            warnings = listOf(
                "Root can break SafetyNet/Play Integrity",
                "Some banking apps may not work"
            ),
            isCompleted = false,
            canSkip = true  // Optional
        ))

        // Step 7: Degoogle
        if (!state.isGoogleFree) {
            steps.add(LiberationStep(
                order = steps.size + 1,
                title = "Complete Degoogle",
                description = "Remove all Google services and tracking.",
                commands = listOf(
                    "# If using GrapheneOS/CalyxOS: Already done!",
                    "",
                    "# If using LineageOS without GApps: Already done!",
                    "",
                    "# If Google services installed, remove with root:",
                    "# Install App Manager from F-Droid",
                    "# Or use ADB:",
                    "adb shell pm uninstall -k --user 0 com.google.android.gms",
                    "adb shell pm uninstall -k --user 0 com.google.android.gsf",
                    "adb shell pm uninstall -k --user 0 com.android.vending",
                    "",
                    "# For Google services alternative, install microG:",
                    "# https://microg.org"
                ),
                warnings = listOf(
                    "Some apps require Google Play Services",
                    "Consider microG as a privacy-respecting alternative"
                ),
                isCompleted = false,
                canSkip = true
            ))
        }

        // Step 8: Post-liberation hardening
        steps.add(LiberationStep(
            order = steps.size + 1,
            title = "Post-Liberation Hardening",
            description = "Final security configuration.",
            commands = listOf(
                "# Essential apps (from F-Droid):",
                "# - Orbot (Tor)",
                "# - NetGuard or AFWall+ (Firewall)",
                "# - Shelter (Work profile isolation)",
                "",
                "# Security settings:",
                "# - Enable full disk encryption",
                "# - Set strong PIN (6+ digits)",
                "# - Disable USB debugging",
                "# - Disable OEM unlocking (re-lock if supported)",
                "",
                "# Network settings:",
                "# - Use private DNS (dns.quad9.net)",
                "# - Disable WiFi auto-connect",
                "# - Use VPN or Tor for all traffic",
                "",
                "# Install Yours app from:",
                "# [Your distribution method]"
            ),
            warnings = emptyList(),
            isCompleted = false,
            canSkip = false
        ))

        return steps
    }

    // =========================================================================
    // BLOATWARE REMOVAL
    // =========================================================================

    /**
     * Generate bloatware removal commands.
     * Works without root using ADB.
     */
    fun getBloatwareRemovalCommands(threats: List<Threat>): BloatwareRemovalPlan {
        val adbCommands = mutableListOf<String>()
        val rootCommands = mutableListOf<String>()
        val cannotRemove = mutableListOf<String>()

        adbCommands.add("# Connect device via USB with debugging enabled")
        adbCommands.add("# Run these commands from computer terminal:")
        adbCommands.add("")

        rootCommands.add("# If rooted, run these on device terminal:")
        rootCommands.add("")

        for (threat in threats) {
            if (threat.category in listOf(
                ThreatCategory.BACKDOOR,
                ThreatCategory.ALWAYS_LISTENING,
                ThreatCategory.SURVEILLANCE,
                ThreatCategory.ANALYTICS,
                ThreatCategory.CARRIER
            )) {
                val packageId = threat.id

                // ADB method (works without root, disables for current user)
                adbCommands.add("# Remove: ${threat.name}")
                adbCommands.add("adb shell pm uninstall -k --user 0 $packageId")
                adbCommands.add("")

                // Root method (complete removal)
                rootCommands.add("# Remove: ${threat.name}")
                rootCommands.add("pm uninstall $packageId")
                rootCommands.add("# Or with Magisk module: add to debloat list")
                rootCommands.add("")
            }
        }

        // Critical system packages that might break things
        val criticalPackages = setOf(
            "com.google.android.gms",  // Many apps depend on this
            "com.google.android.gsf",
        )

        return BloatwareRemovalPlan(
            adbCommands = adbCommands,
            rootCommands = rootCommands,
            warnings = listOf(
                "Some apps may stop working after bloatware removal",
                "Google Play Services removal affects many apps",
                "Factory reset will restore bloatware",
                "Custom ROM is the permanent solution"
            ),
            cannotRemove = cannotRemove,
            estimatedSpaceReclaimed = threats.size * 50 // Rough MB estimate
        )
    }

    /**
     * Get Magisk module recommendations for privacy.
     */
    fun getMagiskModuleRecommendations(): List<MagiskModule> {
        return listOf(
            MagiskModule(
                name = "Universal SafetyNet Fix",
                description = "Pass SafetyNet/Play Integrity on rooted devices",
                url = "https://github.com/kdrag0n/safetynet-fix",
                privacyBenefit = "Allows banking apps to work on rooted device"
            ),
            MagiskModule(
                name = "MagiskHide Props Config",
                description = "Modify device fingerprint to pass checks",
                url = "https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf",
                privacyBenefit = "Hide root from detection"
            ),
            MagiskModule(
                name = "Debloater",
                description = "Systemlessly remove bloatware",
                url = "https://github.com/sunilpaulmathew/De-Bloater",
                privacyBenefit = "Remove surveillance apps without breaking system"
            ),
            MagiskModule(
                name = "Busybox for Android NDK",
                description = "Unix utilities for advanced operations",
                url = "https://github.com/Magisk-Modules-Repo/busybox-ndk",
                privacyBenefit = "Tools for system manipulation"
            ),
            MagiskModule(
                name = "AFWall+ (requires module)",
                description = "Firewall to block app network access",
                url = "https://github.com/ukanth/afwall",
                privacyBenefit = "Prevent apps from phoning home"
            ),
            MagiskModule(
                name = "XPrivacyLua",
                description = "Feed fake data to privacy-invasive apps",
                url = "https://github.com/M66B/XPrivacyLua",
                privacyBenefit = "Return fake location, contacts, device ID"
            )
        )
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private fun checkRootStatus(): Boolean {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/data/adb/magisk"
        )
        return suPaths.any { File(it).exists() }
    }

    private fun checkBootloaderStatus(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate")
            val result = process.inputStream.bufferedReader().readText().trim()
            result == "orange" // Orange = unlocked
        } catch (e: Exception) {
            false
        }
    }

    private fun checkCustomRom(): Boolean {
        // Check for common custom ROM indicators
        val customRomProps = listOf(
            "ro.lineage.version",
            "ro.grapheneos.version",
            "ro.calyxos.version",
            "ro.e.version",
            "ro.divestos.version"
        )

        return customRomProps.any { prop ->
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                process.inputStream.bufferedReader().readText().trim().isNotEmpty()
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun checkGoogleFree(context: Context): Boolean {
        val googlePackages = listOf(
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending"
        )

        val pm = context.packageManager
        return googlePackages.none { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun determineLiberationPath(state: DeviceState, profile: DeviceProfile): LiberationPath {
        return when {
            state.hasCustomRom && state.isGoogleFree -> LiberationPath.ALREADY_LIBERATED
            state.hasCustomRom && !state.isGoogleFree -> LiberationPath.DEGOOGLE_ONLY
            state.isBootloaderUnlocked -> LiberationPath.FLASH_ROM
            else -> LiberationPath.FULL_LIBERATION
        }
    }

    /**
     * Device compatibility database with specific model support.
     *
     * This is a comprehensive mapping of device models to compatible ROMs.
     * Data sourced from official ROM websites and community wikis.
     */
    private val DEVICE_ROM_COMPATIBILITY = mapOf(
        // Google Pixel devices - GrapheneOS official support
        "oriole" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),           // Pixel 6
        "raven" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 6 Pro
        "bluejay" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),          // Pixel 6a
        "panther" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),          // Pixel 7
        "cheetah" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),          // Pixel 7 Pro
        "lynx" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),             // Pixel 7a
        "felix" to listOf("GrapheneOS", "CalyxOS"),                          // Pixel Fold
        "tangorpro" to listOf("GrapheneOS", "CalyxOS"),                      // Pixel Tablet
        "shiba" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 8
        "husky" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 8 Pro
        "akita" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 8a
        "caiman" to listOf("GrapheneOS", "CalyxOS"),                         // Pixel 9
        "komodo" to listOf("GrapheneOS", "CalyxOS"),                         // Pixel 9 Pro
        "comet" to listOf("GrapheneOS", "CalyxOS"),                          // Pixel 9 Pro XL
        "tokay" to listOf("GrapheneOS", "CalyxOS"),                          // Pixel 9 Pro Fold
        "redfin" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),           // Pixel 5
        "barbet" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),           // Pixel 5a
        "bramble" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),          // Pixel 4a 5G
        "sunfish" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),          // Pixel 4a
        "flame" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 4
        "coral" to listOf("GrapheneOS", "CalyxOS", "LineageOS"),            // Pixel 4 XL

        // Fairphone devices - CalyxOS and /e/OS official support
        "fp4" to listOf("CalyxOS", "/e/OS", "LineageOS", "DivestOS"),       // Fairphone 4
        "fp5" to listOf("CalyxOS", "/e/OS", "LineageOS"),                   // Fairphone 5

        // OnePlus devices - Good LineageOS support
        "bacon" to listOf("LineageOS", "DivestOS"),                          // OnePlus One
        "oneplus2" to listOf("LineageOS", "DivestOS"),                       // OnePlus 2
        "oneplus3" to listOf("LineageOS", "DivestOS"),                       // OnePlus 3
        "oneplus3t" to listOf("LineageOS", "DivestOS"),                      // OnePlus 3T
        "cheeseburger" to listOf("LineageOS", "DivestOS"),                   // OnePlus 5
        "dumpling" to listOf("LineageOS", "DivestOS"),                       // OnePlus 5T
        "enchilada" to listOf("LineageOS", "DivestOS"),                      // OnePlus 6
        "fajita" to listOf("LineageOS", "DivestOS"),                         // OnePlus 6T
        "guacamole" to listOf("LineageOS", "DivestOS"),                      // OnePlus 7 Pro
        "guacamoleb" to listOf("LineageOS", "DivestOS"),                     // OnePlus 7
        "hotdog" to listOf("LineageOS", "DivestOS"),                         // OnePlus 7T Pro
        "hotdogb" to listOf("LineageOS", "DivestOS"),                        // OnePlus 7T
        "instantnoodle" to listOf("LineageOS"),                              // OnePlus 8
        "instantnoodlep" to listOf("LineageOS"),                             // OnePlus 8 Pro
        "kebab" to listOf("LineageOS"),                                      // OnePlus 8T
        "lemonade" to listOf("LineageOS"),                                   // OnePlus 9
        "lemonadep" to listOf("LineageOS"),                                  // OnePlus 9 Pro
        "martini" to listOf("LineageOS"),                                    // OnePlus 9RT

        // Samsung devices - Limited but available
        "beyond0lte" to listOf("LineageOS", "/e/OS"),                        // Galaxy S10e
        "beyond1lte" to listOf("LineageOS", "/e/OS"),                        // Galaxy S10
        "beyond2lte" to listOf("LineageOS", "/e/OS"),                        // Galaxy S10+
        "crownlte" to listOf("LineageOS", "DivestOS"),                       // Galaxy Note 9
        "starlte" to listOf("LineageOS", "DivestOS"),                        // Galaxy S9
        "star2lte" to listOf("LineageOS", "DivestOS"),                       // Galaxy S9+
        "greatlte" to listOf("LineageOS", "DivestOS"),                       // Galaxy Note 8
        "dreamlte" to listOf("LineageOS", "DivestOS"),                       // Galaxy S8
        "dream2lte" to listOf("LineageOS", "DivestOS"),                      // Galaxy S8+

        // Xiaomi devices - Good community support
        "beryllium" to listOf("LineageOS", "DivestOS", "/e/OS"),             // Poco F1
        "cepheus" to listOf("LineageOS", "DivestOS"),                        // Mi 9
        "raphael" to listOf("LineageOS", "DivestOS"),                        // Mi 9T Pro / K20 Pro
        "davinci" to listOf("LineageOS", "DivestOS"),                        // Mi 9T / K20
        "vayu" to listOf("LineageOS", "DivestOS"),                           // Poco X3 Pro
        "surya" to listOf("LineageOS", "DivestOS"),                          // Poco X3 NFC
        "alioth" to listOf("LineageOS", "DivestOS"),                         // Poco F3 / Mi 11X
        "lmi" to listOf("LineageOS", "DivestOS"),                            // Poco F2 Pro / K30 Pro
        "apollo" to listOf("LineageOS"),                                     // Mi 10T / Mi 10T Pro
        "miatoll" to listOf("LineageOS", "DivestOS"),                        // Redmi Note 9 Pro/S/Max

        // Motorola devices - CalyxOS and LineageOS support
        "river" to listOf("CalyxOS", "LineageOS"),                           // Moto G7
        "ocean" to listOf("CalyxOS", "LineageOS"),                           // Moto G7 Power
        "troika" to listOf("LineageOS"),                                     // Moto G8
        "sofiar" to listOf("LineageOS"),                                     // Moto G8 Power
        "racer" to listOf("LineageOS"),                                      // Moto Edge (2020)
        "nio" to listOf("LineageOS"),                                        // Moto Edge S
        "pstar" to listOf("LineageOS"),                                      // Moto Edge 20 Pro
        "rhode" to listOf("LineageOS")                                       // Moto G Power (2022)
    )

    /**
     * Model name to codename mapping for user-friendly lookup.
     */
    private val MODEL_TO_CODENAME = mapOf(
        // Pixel models
        "pixel 6" to "oriole",
        "pixel 6 pro" to "raven",
        "pixel 6a" to "bluejay",
        "pixel 7" to "panther",
        "pixel 7 pro" to "cheetah",
        "pixel 7a" to "lynx",
        "pixel 8" to "shiba",
        "pixel 8 pro" to "husky",
        "pixel 8a" to "akita",
        "pixel 9" to "caiman",
        "pixel 9 pro" to "komodo",
        "pixel 5" to "redfin",
        "pixel 4a" to "sunfish",
        "pixel 4" to "flame",

        // Fairphone models
        "fairphone 4" to "fp4",
        "fairphone 5" to "fp5",
        "fp4" to "fp4",
        "fp5" to "fp5"
    )

    /**
     * Query device compatibility database for supported ROMs.
     *
     * Uses multiple lookup strategies:
     * 1. Direct codename match (most accurate)
     * 2. Model name to codename mapping
     * 3. Manufacturer-based fallback
     *
     * @param manufacturer Device manufacturer
     * @param model Device model name
     * @return List of compatible ROM profiles, sorted by security rating
     */
    private fun getCompatibleRoms(manufacturer: String, model: String): List<RomProfile> {
        val manufacturerLower = manufacturer.lowercase()
        val modelLower = model.lowercase()

        // Strategy 1: Direct codename lookup (device codename from Build.DEVICE)
        val deviceCodename = android.os.Build.DEVICE.lowercase()
        val directMatch = DEVICE_ROM_COMPATIBILITY[deviceCodename]
        if (directMatch != null) {
            return directMatch.mapNotNull { ROM_SECURITY_RATINGS[it] }
                .sortedByDescending { it.securityRating }
        }

        // Strategy 2: Model name mapping
        val codename = MODEL_TO_CODENAME[modelLower]
        if (codename != null) {
            val codenamMatch = DEVICE_ROM_COMPATIBILITY[codename]
            if (codenamMatch != null) {
                return codenamMatch.mapNotNull { ROM_SECURITY_RATINGS[it] }
                    .sortedByDescending { it.securityRating }
            }
        }

        // Strategy 3: Partial model match (e.g., "SM-G973F" contains "beyond1")
        for ((code, roms) in DEVICE_ROM_COMPATIBILITY) {
            if (modelLower.contains(code) || code.contains(modelLower.take(6))) {
                return roms.mapNotNull { ROM_SECURITY_RATINGS[it] }
                    .sortedByDescending { it.securityRating }
            }
        }

        // Strategy 4: Manufacturer-based recommendation
        val manufacturerDefault = when (manufacturerLower) {
            "google" -> listOf("GrapheneOS", "CalyxOS", "LineageOS")
            "fairphone" -> listOf("CalyxOS", "/e/OS", "LineageOS")
            "oneplus" -> listOf("LineageOS", "DivestOS")
            "samsung" -> listOf("LineageOS", "/e/OS", "DivestOS")
            "xiaomi", "redmi", "poco" -> listOf("LineageOS", "DivestOS", "/e/OS")
            "motorola" -> listOf("CalyxOS", "LineageOS")
            "sony" -> listOf("LineageOS", "DivestOS")
            "asus" -> listOf("LineageOS", "DivestOS")
            "nokia" -> listOf("LineageOS")
            else -> listOf("LineageOS", "DivestOS", "/e/OS")
        }

        return manufacturerDefault.mapNotNull { ROM_SECURITY_RATINGS[it] }
            .sortedByDescending { it.securityRating }
    }

    private fun calculateDifficulty(profile: DeviceProfile, state: DeviceState): LiberationDifficulty {
        var score = 0

        // Already unlocked is easier
        if (state.isBootloaderUnlocked) score -= 2

        // Device-specific factors
        score += when (profile.bootloaderUnlockMethod) {
            BootloaderUnlockMethod.OEM_UNLOCK -> 1
            BootloaderUnlockMethod.SAMSUNG_UNLOCK -> 3
            BootloaderUnlockMethod.XIAOMI_UNLOCK -> 4
            BootloaderUnlockMethod.CARRIER_DEPENDENT -> 5
        }

        // ROM support
        score += when (profile.customRomSupport) {
            CustomRomSupport.FULL -> 0
            CustomRomSupport.GOOD -> 1
            CustomRomSupport.LIMITED -> 3
            CustomRomSupport.NONE -> 10
        }

        return when {
            score <= 2 -> LiberationDifficulty.EASY
            score <= 4 -> LiberationDifficulty.MODERATE
            score <= 6 -> LiberationDifficulty.DIFFICULT
            else -> LiberationDifficulty.EXPERT
        }
    }

    private fun getBootloaderUnlockDescription(method: BootloaderUnlockMethod): String {
        return when (method) {
            BootloaderUnlockMethod.OEM_UNLOCK ->
                "Standard OEM unlock via fastboot. Straightforward process."
            BootloaderUnlockMethod.SAMSUNG_UNLOCK ->
                "Samsung requires Developer Options toggle. WARNING: This will permanently trip the Knox fuse."
            BootloaderUnlockMethod.XIAOMI_UNLOCK ->
                "Xiaomi requires official Mi Unlock tool, Xiaomi account, and 7-day waiting period."
            BootloaderUnlockMethod.CARRIER_DEPENDENT ->
                "Bootloader unlock depends on carrier. May be impossible on locked devices."
        }
    }

    private fun getBootloaderUnlockCommands(method: BootloaderUnlockMethod): List<String> {
        return when (method) {
            BootloaderUnlockMethod.OEM_UNLOCK -> listOf(
                "# Boot to bootloader:",
                "adb reboot bootloader",
                "",
                "# Unlock bootloader:",
                "fastboot flashing unlock",
                "",
                "# Confirm on device screen",
                "# Device will factory reset"
            )
            BootloaderUnlockMethod.SAMSUNG_UNLOCK -> listOf(
                "# 1. Enable OEM Unlock in Developer Options",
                "# 2. Boot to Download Mode:",
                "#    Power off, then hold Volume Down + Power",
                "",
                "# 3. Use Odin or Heimdall to flash:",
                "heimdall flash --RECOVERY twrp.img",
                "",
                "# WARNING: Knox will be permanently tripped"
            )
            BootloaderUnlockMethod.XIAOMI_UNLOCK -> listOf(
                "# 1. Create Mi account and sign in on device",
                "# 2. Enable OEM Unlock in Developer Options",
                "# 3. Download Mi Unlock tool (Windows):",
                "#    https://www.miui.com/unlock/download_en.html",
                "",
                "# 4. Boot to fastboot:",
                "adb reboot bootloader",
                "",
                "# 5. Run Mi Unlock tool and follow prompts",
                "# 6. Wait 7 days (168 hours) for unlock approval",
                "# 7. Run Mi Unlock again after waiting period"
            )
            BootloaderUnlockMethod.CARRIER_DEPENDENT -> listOf(
                "# Check with your carrier for unlock policy",
                "# Some carriers permanently lock bootloaders",
                "",
                "# Options:",
                "# 1. Request unlock from carrier (if policy allows)",
                "# 2. Purchase unlocked variant of device",
                "# 3. Check XDA forums for device-specific exploits"
            )
        }
    }
}

// =========================================================================
// DATA CLASSES
// =========================================================================

data class DeviceProfile(
    val manufacturer: String,
    val bootloaderUnlockMethod: BootloaderUnlockMethod,
    val customRomSupport: CustomRomSupport,
    val recommendedRom: String,
    val romUrl: String,
    val notes: String,
    val warnings: List<String> = emptyList()
)

data class RomProfile(
    val name: String,
    val securityRating: Int,  // 1-10
    val privacyRating: Int,   // 1-10
    val usabilityRating: Int, // 1-10
    val googleFree: Boolean,
    val verifiedBoot: Boolean,
    val hardening: List<String>,
    val deviceSupport: List<String>,
    val url: String
)

data class DeviceState(
    val manufacturer: String,
    val model: String,
    val device: String,
    val androidVersion: Int,
    val isRooted: Boolean,
    val isBootloaderUnlocked: Boolean,
    val hasCustomRom: Boolean,
    val isGoogleFree: Boolean
)

data class LiberationAssessment(
    val currentState: DeviceState,
    val deviceProfile: DeviceProfile,
    val recommendedPath: LiberationPath,
    val compatibleRoms: List<RomProfile>,
    val estimatedDifficulty: LiberationDifficulty
)

data class LiberationStep(
    val order: Int,
    val title: String,
    val description: String,
    val commands: List<String>,
    val warnings: List<String>,
    val isCompleted: Boolean,
    val canSkip: Boolean
)

data class BloatwareRemovalPlan(
    val adbCommands: List<String>,
    val rootCommands: List<String>,
    val warnings: List<String>,
    val cannotRemove: List<String>,
    val estimatedSpaceReclaimed: Int  // MB
)

data class MagiskModule(
    val name: String,
    val description: String,
    val url: String,
    val privacyBenefit: String
)

enum class BootloaderUnlockMethod {
    OEM_UNLOCK,        // Standard fastboot unlock
    SAMSUNG_UNLOCK,    // Samsung-specific (Knox warning)
    XIAOMI_UNLOCK,     // Requires Mi Unlock tool + waiting
    CARRIER_DEPENDENT  // May be impossible
}

enum class CustomRomSupport {
    FULL,     // Official support, verified boot possible
    GOOD,     // Community support, works well
    LIMITED,  // Partial support, some features broken
    NONE      // No known custom ROM support
}

enum class LiberationPath {
    FULL_LIBERATION,    // Unlock + flash + degoogle
    FLASH_ROM,          // Bootloader already unlocked
    DEGOOGLE_ONLY,      // Custom ROM but has Google
    ALREADY_LIBERATED   // Already sovereign
}

enum class LiberationDifficulty {
    EASY,      // Pixel with GrapheneOS web installer
    MODERATE,  // Standard OEM unlock + LineageOS
    DIFFICULT, // Samsung/Xiaomi with extra steps
    EXPERT     // Carrier-locked or minimal support
}
