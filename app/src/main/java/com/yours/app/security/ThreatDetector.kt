package com.yours.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Runtime Threat Detection (Custom RASP)
 *
 * THREAT MODEL: Sovereignty-focused
 *
 * We're protecting against:
 * - Active instrumentation/hooking (Frida injected by attacker)
 * - Debugger attachment (someone analyzing your app)
 * - Hooking frameworks being used AGAINST the user
 *
 * We're NOT penalizing:
 * - User-initiated root (for removing bloatware/spyware)
 * - Emulators (for testing)
 * - Security research tools used BY the owner
 *
 * The distinction matters:
 * - Root = neutral (user sovereignty OR attacker access)
 * - Active Frida injection = concerning (likely attacker)
 * - Debugger attached = concerning (someone watching)
 *
 * Design Decision: Warn + Proceed
 * - Inform the user of detected conditions
 * - Let them decide if it's expected (they rooted) or unexpected (attack)
 * - Never block sovereignty-seeking users from their own device
 */
object ThreatDetector {

    data class ThreatReport(
        val threats: List<DetectedThreat>,
        val riskLevel: RiskLevel
    ) {
        // Only CRITICAL and HIGH are actual threats
        // MEDIUM, LOW, INFO are informational (sovereignty tools, etc.)
        val hasCriticalThreats: Boolean get() = threats.any { it.severity == ThreatSeverity.CRITICAL }
        val hasHighThreats: Boolean get() = threats.any { it.severity == ThreatSeverity.HIGH }

        // "Safe" means no actual threats - INFO items (root, emulator) don't count
        val isSafe: Boolean get() = !hasCriticalThreats && !hasHighThreats

        // Actual threats (not informational)
        val actualThreats: List<DetectedThreat> get() = threats.filter {
            it.severity == ThreatSeverity.CRITICAL || it.severity == ThreatSeverity.HIGH
        }

        // Informational items (sovereignty tools, emulator, etc.)
        val informationalItems: List<DetectedThreat> get() = threats.filter {
            it.severity == ThreatSeverity.INFO || it.severity == ThreatSeverity.LOW
        }
    }

    data class DetectedThreat(
        val type: ThreatType,
        val severity: ThreatSeverity,
        val description: String,
        val technicalDetails: String? = null
    )

    enum class ThreatType {
        FRIDA,
        XPOSED,
        ROOT,
        EMULATOR,
        DEBUGGER,
        HOOKING,
        TAMPERING
    }

    enum class ThreatSeverity {
        CRITICAL,  // Active instrumentation/hooking detected (likely attack)
        HIGH,      // Debugger attached, active MITM
        MEDIUM,    // Hooking framework installed (could be user's tools)
        LOW,       // Informational - root/emulator (likely user sovereignty)
        INFO       // Neutral observation (user should know, not a threat)
    }

    enum class RiskLevel {
        SAFE,      // No threats detected
        CAUTION,   // Minor threats, proceed with awareness
        WARNING,   // Significant threats, user should be careful
        CRITICAL   // Active attack likely, strongly discourage use
    }

    /**
     * Run all threat detection checks.
     * Should be called before sensitive operations (unlock, key derivation).
     */
    suspend fun scan(context: Context): ThreatReport = withContext(Dispatchers.IO) {
        val threats = mutableListOf<DetectedThreat>()

        // Check for Frida
        detectFrida()?.let { threats.add(it) }

        // Check for Xposed/LSPosed
        detectXposed(context)?.let { threats.add(it) }

        // Check for root
        detectRoot()?.let { threats.add(it) }

        // Check for emulator
        detectEmulator()?.let { threats.add(it) }

        // Check for debugger
        detectDebugger()?.let { threats.add(it) }

        // Check for suspicious processes
        detectSuspiciousProcesses()?.let { threats.add(it) }

        // Calculate risk level
        val riskLevel = when {
            threats.any { it.severity == ThreatSeverity.CRITICAL } -> RiskLevel.CRITICAL
            threats.any { it.severity == ThreatSeverity.HIGH } -> RiskLevel.WARNING
            threats.any { it.severity == ThreatSeverity.MEDIUM } -> RiskLevel.CAUTION
            else -> RiskLevel.SAFE
        }

        ThreatReport(threats, riskLevel)
    }

    /**
     * Quick check - just returns if any critical threats are detected.
     * Use for fast pre-checks before expensive operations.
     */
    suspend fun hasCriticalThreats(context: Context): Boolean = withContext(Dispatchers.IO) {
        // Check most likely/dangerous threats first
        detectFrida() != null ||
        detectDebugger() != null ||
        detectXposed(context) != null
    }

    // ========================================================================
    // FRIDA DETECTION
    // ========================================================================

    private fun detectFrida(): DetectedThreat? {
        // Method 1: Check for Frida default ports
        val fridaPorts = listOf(27042, 27043)
        for (port in fridaPorts) {
            if (isPortOpen("127.0.0.1", port)) {
                return DetectedThreat(
                    type = ThreatType.FRIDA,
                    severity = ThreatSeverity.CRITICAL,
                    description = "Frida server detected",
                    technicalDetails = "Port $port is open (Frida default)"
                )
            }
        }

        // Method 2: Check for Frida artifacts in /proc/self/maps
        try {
            val maps = File("/proc/self/maps").readText()
            val fridaIndicators = listOf(
                "frida",
                "gadget",
                "linjector"
            )
            for (indicator in fridaIndicators) {
                if (maps.contains(indicator, ignoreCase = true)) {
                    return DetectedThreat(
                        type = ThreatType.FRIDA,
                        severity = ThreatSeverity.CRITICAL,
                        description = "Frida injection detected",
                        technicalDetails = "Found '$indicator' in process maps"
                    )
                }
            }
        } catch (e: Exception) {
            // Can't read maps - might be restricted
        }

        // Method 3: Check for Frida-related files
        val fridaFiles = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/sdcard/frida-server"
        )
        for (file in fridaFiles) {
            if (File(file).exists()) {
                return DetectedThreat(
                    type = ThreatType.FRIDA,
                    severity = ThreatSeverity.CRITICAL,
                    description = "Frida server binary found",
                    technicalDetails = "File exists: $file"
                )
            }
        }

        // Method 4: Check /proc/self/fd for Frida pipes
        try {
            val fdDir = File("/proc/self/fd")
            fdDir.listFiles()?.forEach { fd ->
                try {
                    val link = fd.canonicalPath
                    if (link.contains("frida") || link.contains("linjector")) {
                        return DetectedThreat(
                            type = ThreatType.FRIDA,
                            severity = ThreatSeverity.CRITICAL,
                            description = "Frida file descriptor detected",
                            technicalDetails = "FD points to: $link"
                        )
                    }
                } catch (e: Exception) {
                    // Can't resolve symlink
                }
            }
        } catch (e: Exception) {
            // Can't read fd directory
        }

        return null
    }

    private fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 100)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    // ========================================================================
    // XPOSED/LSPOSED DETECTION
    // ========================================================================

    private fun detectXposed(context: Context): DetectedThreat? {
        // Method 1: Check for Xposed installer packages
        val xposedPackages = listOf(
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.topjohnwu.magisk" // Magisk can host LSPosed
        )

        for (pkg in xposedPackages) {
            if (isPackageInstalled(context, pkg)) {
                return DetectedThreat(
                    type = ThreatType.XPOSED,
                    severity = ThreatSeverity.CRITICAL,
                    description = "Xposed/LSPosed framework detected",
                    technicalDetails = "Package installed: $pkg"
                )
            }
        }

        // Method 2: Check for Xposed in stack trace
        try {
            throw Exception("Stack trace check")
        } catch (e: Exception) {
            val stackTrace = e.stackTrace.joinToString("\n") { it.toString() }
            val xposedIndicators = listOf(
                "de.robv.android.xposed",
                "XposedBridge",
                "EdXposed",
                "LSPosed"
            )
            for (indicator in xposedIndicators) {
                if (stackTrace.contains(indicator)) {
                    return DetectedThreat(
                        type = ThreatType.XPOSED,
                        severity = ThreatSeverity.CRITICAL,
                        description = "Xposed hooks in call stack",
                        technicalDetails = "Found '$indicator' in stack trace"
                    )
                }
            }
        }

        // Method 3: Check for Xposed-related system properties
        try {
            val process = Runtime.getRuntime().exec("getprop ro.xposed.version")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            reader.close()
            if (!result.isNullOrEmpty()) {
                return DetectedThreat(
                    type = ThreatType.XPOSED,
                    severity = ThreatSeverity.HIGH,
                    description = "Xposed system property set",
                    technicalDetails = "ro.xposed.version = $result"
                )
            }
        } catch (e: Exception) {
            // Can't execute getprop
        }

        return null
    }

    private fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    // ========================================================================
    // ROOT DETECTION
    // ========================================================================
    //
    // SOVEREIGNTY NOTE: Root is NOT inherently bad!
    // Users root their devices to:
    // - Remove pre-installed spyware (Samsung, Facebook, carrier bloat)
    // - Gain full control over their hardware
    // - Install privacy-focused ROMs (GrapheneOS, CalyxOS, LineageOS)
    //
    // We detect root as INFORMATIONAL, not as a threat.
    // The user should know their device state, but we don't penalize sovereignty.
    // ========================================================================

    private fun detectRoot(): DetectedThreat? {
        // Method 1: Check for su binary
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/su/bin/su",
            "/system/sd/xbin/su"
        )

        for (path in suPaths) {
            if (File(path).exists()) {
                return DetectedThreat(
                    type = ThreatType.ROOT,
                    severity = ThreatSeverity.INFO, // Informational, not a threat
                    description = "Device is rooted (sovereignty mode)",
                    technicalDetails = "su binary at: $path - If you rooted for privacy, this is expected"
                )
            }
        }

        // Method 2: Check for Magisk
        val magiskPaths = listOf(
            "/data/adb/magisk",
            "/data/adb/modules",
            "/sbin/.magisk"
        )

        for (path in magiskPaths) {
            if (File(path).exists()) {
                return DetectedThreat(
                    type = ThreatType.ROOT,
                    severity = ThreatSeverity.INFO, // Magisk is a sovereignty tool
                    description = "Magisk detected (sovereignty mode)",
                    technicalDetails = "Magisk at: $path - Good for removing bloatware"
                )
            }
        }

        // Method 3: Try to execute su
        try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            reader.close()
            if (!result.isNullOrEmpty()) {
                return DetectedThreat(
                    type = ThreatType.ROOT,
                    severity = ThreatSeverity.INFO,
                    description = "Root access available",
                    technicalDetails = "su at: $result"
                )
            }
        } catch (e: Exception) {
            // which command failed - no root
        }

        // Method 4: Check SELinux status
        // Permissive SELinux is more concerning - could indicate compromise
        try {
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            reader.close()
            if (result?.contains("Permissive", ignoreCase = true) == true) {
                return DetectedThreat(
                    type = ThreatType.ROOT,
                    severity = ThreatSeverity.LOW, // Slightly more concerning
                    description = "SELinux permissive (reduced protection)",
                    technicalDetails = "SELinux: $result - Consider enforcing mode if not needed"
                )
            }
        } catch (e: Exception) {
            // getenforce failed
        }

        return null
    }

    // ========================================================================
    // EMULATOR DETECTION
    // ========================================================================
    //
    // SOVEREIGNTY NOTE: Emulators are fine for testing!
    // Users might run the app in an emulator for:
    // - Testing before deploying to real device
    // - Privacy (keep sensitive app isolated)
    // - Development
    //
    // We report it as INFO so users know, but don't treat it as a threat.
    // ========================================================================

    private fun detectEmulator(): DetectedThreat? {
        val emulatorIndicators = mutableListOf<String>()

        // Check Build properties
        if (Build.FINGERPRINT.contains("generic") ||
            Build.FINGERPRINT.contains("unknown") ||
            Build.FINGERPRINT.contains("emulator") ||
            Build.FINGERPRINT.contains("sdk_gphone")) {
            emulatorIndicators.add("Fingerprint: ${Build.FINGERPRINT}")
        }

        if (Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("sdk_gphone")) {
            emulatorIndicators.add("Model: ${Build.MODEL}")
        }

        if (Build.MANUFACTURER.contains("Genymotion") ||
            Build.MANUFACTURER.contains("unknown")) {
            emulatorIndicators.add("Manufacturer: ${Build.MANUFACTURER}")
        }

        if (Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu") ||
            Build.HARDWARE.contains("vbox86")) {
            emulatorIndicators.add("Hardware: ${Build.HARDWARE}")
        }

        if (Build.PRODUCT.contains("sdk") ||
            Build.PRODUCT.contains("emulator") ||
            Build.PRODUCT.contains("vbox86p")) {
            emulatorIndicators.add("Product: ${Build.PRODUCT}")
        }

        // Check for emulator-specific files
        val emulatorFiles = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )

        for (file in emulatorFiles) {
            if (File(file).exists()) {
                emulatorIndicators.add("File exists: $file")
            }
        }

        // If we found multiple indicators, report emulator as INFO
        if (emulatorIndicators.size >= 2) {
            return DetectedThreat(
                type = ThreatType.EMULATOR,
                severity = ThreatSeverity.INFO, // Not a threat, just informational
                description = "Running in emulator",
                technicalDetails = "Detected: ${emulatorIndicators.take(2).joinToString(", ")}"
            )
        }

        return null
    }

    // ========================================================================
    // DEBUGGER DETECTION
    // ========================================================================

    private fun detectDebugger(): DetectedThreat? {
        // Method 1: Check Debug.isDebuggerConnected()
        if (Debug.isDebuggerConnected()) {
            return DetectedThreat(
                type = ThreatType.DEBUGGER,
                severity = ThreatSeverity.CRITICAL,
                description = "Debugger attached",
                technicalDetails = "Debug.isDebuggerConnected() returned true"
            )
        }

        // Method 2: Check TracerPid in /proc/self/status
        try {
            val status = File("/proc/self/status").readText()
            val tracerPidLine = status.lines().find { it.startsWith("TracerPid:") }
            val tracerPid = tracerPidLine?.split(":")?.getOrNull(1)?.trim()?.toIntOrNull() ?: 0
            if (tracerPid != 0) {
                return DetectedThreat(
                    type = ThreatType.DEBUGGER,
                    severity = ThreatSeverity.CRITICAL,
                    description = "Process is being traced",
                    technicalDetails = "TracerPid: $tracerPid"
                )
            }
        } catch (e: Exception) {
            // Can't read status
        }

        // Method 3: Check for common debugger ports
        val debuggerPorts = listOf(
            23946, // IDA remote debugging
            5037,  // ADB
            8700   // JDWP
        )

        for (port in debuggerPorts) {
            if (isPortOpen("127.0.0.1", port)) {
                // Note: Port 5037 (ADB) might be open legitimately during development
                // Only flag as MEDIUM severity
                val severity = if (port == 5037) ThreatSeverity.MEDIUM else ThreatSeverity.HIGH
                return DetectedThreat(
                    type = ThreatType.DEBUGGER,
                    severity = severity,
                    description = "Debug port open",
                    technicalDetails = "Port $port is listening"
                )
            }
        }

        return null
    }

    // ========================================================================
    // SUSPICIOUS PROCESS DETECTION
    // ========================================================================

    private fun detectSuspiciousProcesses(): DetectedThreat? {
        try {
            val maps = File("/proc/self/maps").readText()

            // Check for suspicious libraries
            val suspiciousLibraries = listOf(
                "substrate",   // Cydia Substrate
                "xhook",       // xHook library
                "hookzz",      // HookZz framework
                "shadowhook",  // ShadowHook
                "bhook",       // ByteHook
                "plthook"      // PLT hook
            )

            for (lib in suspiciousLibraries) {
                if (maps.contains(lib, ignoreCase = true)) {
                    return DetectedThreat(
                        type = ThreatType.HOOKING,
                        severity = ThreatSeverity.CRITICAL,
                        description = "Hooking framework detected",
                        technicalDetails = "Found '$lib' in process maps"
                    )
                }
            }
        } catch (e: Exception) {
            // Can't read maps
        }

        return null
    }
}
