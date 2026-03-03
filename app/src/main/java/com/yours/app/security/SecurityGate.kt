package com.yours.app.security

import android.content.Context

/**
 * Security Gate - Blocks app usage if device is compromised.
 *
 * Counter-Intelligence Principle:
 * "If the endpoint is compromised, all cryptography is theater."
 *
 * This gate enforces minimum security requirements before allowing
 * access to sensitive operations. The user can still view the
 * sovereignty report, but cannot access vaults, messages, or keys.
 */
object SecurityGate {

    /**
     * Security levels for different operations.
     */
    enum class SecurityLevel {
        /**
         * Basic operations - viewing public info.
         * No security requirements.
         */
        PUBLIC,

        /**
         * Standard operations - messaging, contacts.
         * Blocks if:
         * - User CA certificates installed (MITM)
         * - Wireless ADB enabled
         */
        STANDARD,

        /**
         * Sensitive operations - vault access, key operations.
         * Blocks if:
         * - Any CRITICAL threat detected
         * - Keylogger (accessibility service) enabled
         * - MITM infrastructure present
         */
        SENSITIVE,

        /**
         * Critical operations - identity creation, recovery.
         * Blocks if:
         * - Any CRITICAL or HIGH threat detected
         * - Device not encrypted
         * - No screen lock
         */
        CRITICAL
    }

    /**
     * Result of security check.
     */
    sealed class GateResult {
        object Allowed : GateResult()
        data class Blocked(
            val reason: String,
            val threats: List<Threat>,
            val recommendation: String
        ) : GateResult()
    }

    /**
     * Check if operation at given security level is allowed.
     */
    fun check(context: Context, level: SecurityLevel): GateResult {
        if (level == SecurityLevel.PUBLIC) {
            return GateResult.Allowed
        }

        // Run scan
        val report = SovereigntyScanner.scan(context)

        return when (level) {
            SecurityLevel.PUBLIC -> GateResult.Allowed

            SecurityLevel.STANDARD -> {
                // Block on MITM or wireless ADB
                val blockers = report.threats.filter {
                    it.category == ThreatCategory.MITM ||
                    it.id == "wireless_adb"
                }

                if (blockers.isNotEmpty()) {
                    GateResult.Blocked(
                        reason = "Network security compromised",
                        threats = blockers,
                        recommendation = "Remove user CA certificates and disable wireless ADB"
                    )
                } else {
                    GateResult.Allowed
                }
            }

            SecurityLevel.SENSITIVE -> {
                // Block on any critical threat
                val blockers = report.threats.filter {
                    it.severity == ThreatSeverity.CRITICAL
                }

                if (blockers.isNotEmpty()) {
                    GateResult.Blocked(
                        reason = "Device integrity compromised",
                        threats = blockers,
                        recommendation = "Resolve critical threats before accessing sensitive data"
                    )
                } else {
                    GateResult.Allowed
                }
            }

            SecurityLevel.CRITICAL -> {
                // Block on any critical OR high threat
                val blockers = report.threats.filter {
                    it.severity == ThreatSeverity.CRITICAL ||
                    it.severity == ThreatSeverity.HIGH
                }

                if (blockers.isNotEmpty()) {
                    GateResult.Blocked(
                        reason = "Device security insufficient for this operation",
                        threats = blockers,
                        recommendation = "This operation requires a sovereign device (score >= 70)"
                    )
                } else if (report.score < 70) {
                    GateResult.Blocked(
                        reason = "Sovereignty score too low: ${report.score}/100",
                        threats = report.threats,
                        recommendation = "Remove surveillance apps to increase score"
                    )
                } else {
                    GateResult.Allowed
                }
            }
        }
    }

    /**
     * Quick check for sensitive operations.
     * Use this inline before crypto operations.
     */
    fun quickCheck(context: Context): Boolean {
        return SovereigntyScanner.quickCheck(context)
    }

    /**
     * Get current sovereignty score.
     */
    fun getScore(context: Context): Int {
        return SovereigntyScanner.scan(context).score
    }

    /**
     * Check specific threat categories.
     */
    fun hasKeylogger(context: Context): Boolean {
        return SovereigntyScanner.scan(context).threats.any {
            it.category == ThreatCategory.KEYLOGGER
        }
    }

    fun hasMITM(context: Context): Boolean {
        return SovereigntyScanner.scan(context).threats.any {
            it.category == ThreatCategory.MITM
        }
    }

    fun hasBackdoor(context: Context): Boolean {
        return SovereigntyScanner.scan(context).threats.any {
            it.category == ThreatCategory.BACKDOOR
        }
    }
}

/**
 * Extension function for easy gate checking in Composables.
 *
 * Usage:
 * ```
 * val gate = LocalContext.current.checkSecurityGate(SecurityLevel.SENSITIVE)
 * when (gate) {
 *     is GateResult.Allowed -> { /* proceed */ }
 *     is GateResult.Blocked -> { /* show blocked UI */ }
 * }
 * ```
 */
fun Context.checkSecurityGate(level: SecurityGate.SecurityLevel): SecurityGate.GateResult {
    return SecurityGate.check(this, level)
}
