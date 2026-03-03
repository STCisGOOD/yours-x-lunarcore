package com.yours.app.security

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Network Safety Checker - MeshCore First
 *
 * Priority order (best to worst):
 * 1. MeshCore (off-grid, no internet needed)
 * 2. Offline (no network = no surveillance)
 * 3. Tor (anonymous internet access)
 * 4. VPN (encrypted but provider can see)
 * 5. Clearnet (ISP sees everything)
 *
 * The goal is to get users OFF the internet entirely via MeshCore.
 * Tor/VPN are fallbacks for when internet is temporarily needed.
 */
object NetworkSafetyChecker {

    // Orbot package name for Tor
    private const val ORBOT_PACKAGE = "org.torproject.android"
    private const val ORBOT_FDROID_URL = "https://f-droid.org/packages/org.torproject.android/"

    data class NetworkStatus(
        val connectionType: ConnectionType,
        val isConnected: Boolean,
        val isMeshCoreActive: Boolean,
        val isVpnActive: Boolean,
        val isTorActive: Boolean,
        val isTorInstalled: Boolean,
        val recommendations: List<Recommendation>
    ) {
        val isFullySovereign: Boolean get() = isMeshCoreActive || !isConnected
        val isProtected: Boolean get() = isMeshCoreActive || isTorActive || isVpnActive || !isConnected
    }

    enum class ConnectionType {
        MESHCORE,      // Best: Off-grid mesh network
        OFFLINE,       // Good: No network = no surveillance
        TOR,           // Good: Anonymous internet
        VPN,           // Partial: Encrypted but trusted third party
        CLEARNET       // Danger: ISP sees everything
    }

    data class Recommendation(
        val message: String,
        val action: RecommendedAction?,
        val priority: Priority
    )

    enum class RecommendedAction {
        CONNECT_MESHCORE,
        INSTALL_ORBOT,
        LAUNCH_ORBOT,
        ENABLE_VPN,
        GO_OFFLINE
    }

    enum class Priority {
        INFO,
        SUGGESTION,
        WARNING,
        CRITICAL
    }

    /**
     * Check current network safety status.
     *
     * @param meshCoreConnected Pass true if MeshCore transport is active
     */
    suspend fun check(context: Context, meshCoreConnected: Boolean = false): NetworkStatus = withContext(Dispatchers.IO) {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = connectivityManager.activeNetwork
        val capabilities = activeNetwork?.let { connectivityManager.getNetworkCapabilities(it) }

        val isConnected = capabilities != null
        val isVpnActive = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val isTorActive = checkTorConnection()
        val isTorInstalled = isOrbotInstalled(context)

        val connectionType = when {
            meshCoreConnected -> ConnectionType.MESHCORE
            !isConnected -> ConnectionType.OFFLINE
            isTorActive -> ConnectionType.TOR
            isVpnActive -> ConnectionType.VPN
            else -> ConnectionType.CLEARNET
        }

        val recommendations = buildRecommendations(
            connectionType = connectionType,
            isConnected = isConnected,
            meshCoreConnected = meshCoreConnected,
            isTorActive = isTorActive,
            isTorInstalled = isTorInstalled,
            isVpnActive = isVpnActive
        )

        NetworkStatus(
            connectionType = connectionType,
            isConnected = isConnected,
            isMeshCoreActive = meshCoreConnected,
            isVpnActive = isVpnActive,
            isTorActive = isTorActive,
            isTorInstalled = isTorInstalled,
            recommendations = recommendations
        )
    }

    private fun buildRecommendations(
        connectionType: ConnectionType,
        isConnected: Boolean,
        meshCoreConnected: Boolean,
        isTorActive: Boolean,
        isTorInstalled: Boolean,
        isVpnActive: Boolean
    ): List<Recommendation> {
        val recommendations = mutableListOf<Recommendation>()

        when (connectionType) {
            ConnectionType.MESHCORE -> {
                recommendations.add(Recommendation(
                    message = "Off-grid via MeshCore - fully sovereign",
                    action = null,
                    priority = Priority.INFO
                ))
            }

            ConnectionType.OFFLINE -> {
                recommendations.add(Recommendation(
                    message = "Offline - no network surveillance possible",
                    action = null,
                    priority = Priority.INFO
                ))
                if (!meshCoreConnected) {
                    recommendations.add(Recommendation(
                        message = "Connect MeshCore device for off-grid messaging",
                        action = RecommendedAction.CONNECT_MESHCORE,
                        priority = Priority.SUGGESTION
                    ))
                }
            }

            ConnectionType.TOR -> {
                recommendations.add(Recommendation(
                    message = "Tor active - anonymous internet access",
                    action = null,
                    priority = Priority.INFO
                ))
                recommendations.add(Recommendation(
                    message = "For full sovereignty, use MeshCore instead",
                    action = RecommendedAction.CONNECT_MESHCORE,
                    priority = Priority.SUGGESTION
                ))
            }

            ConnectionType.VPN -> {
                recommendations.add(Recommendation(
                    message = "VPN encrypts traffic but provider can see it",
                    action = null,
                    priority = Priority.WARNING
                ))
                if (!isTorInstalled) {
                    recommendations.add(Recommendation(
                        message = "Install Orbot for anonymous internet",
                        action = RecommendedAction.INSTALL_ORBOT,
                        priority = Priority.SUGGESTION
                    ))
                } else if (!isTorActive) {
                    recommendations.add(Recommendation(
                        message = "Launch Orbot for better anonymity",
                        action = RecommendedAction.LAUNCH_ORBOT,
                        priority = Priority.SUGGESTION
                    ))
                }
                recommendations.add(Recommendation(
                    message = "Best option: Go off-grid with MeshCore",
                    action = RecommendedAction.CONNECT_MESHCORE,
                    priority = Priority.SUGGESTION
                ))
            }

            ConnectionType.CLEARNET -> {
                recommendations.add(Recommendation(
                    message = "Your ISP can see all your traffic",
                    action = null,
                    priority = Priority.CRITICAL
                ))
                if (!isTorInstalled) {
                    recommendations.add(Recommendation(
                        message = "Install Orbot for anonymous internet",
                        action = RecommendedAction.INSTALL_ORBOT,
                        priority = Priority.WARNING
                    ))
                } else {
                    recommendations.add(Recommendation(
                        message = "Launch Orbot to protect your traffic",
                        action = RecommendedAction.LAUNCH_ORBOT,
                        priority = Priority.WARNING
                    ))
                }
                recommendations.add(Recommendation(
                    message = "Best option: Go off-grid with MeshCore",
                    action = RecommendedAction.CONNECT_MESHCORE,
                    priority = Priority.SUGGESTION
                ))
            }
        }

        return recommendations
    }

    /**
     * Check if Orbot (Tor for Android) is installed.
     */
    fun isOrbotInstalled(context: Context): Boolean {
        return try {
            context.packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    /**
     * Get intent to install Orbot from F-Droid.
     */
    fun getInstallOrbotIntent(): Intent {
        return Intent(Intent.ACTION_VIEW, Uri.parse(ORBOT_FDROID_URL))
    }

    /**
     * Get intent to launch Orbot.
     */
    fun getLaunchOrbotIntent(context: Context): Intent? {
        return context.packageManager.getLaunchIntentForPackage(ORBOT_PACKAGE)
    }

    /**
     * Check if Tor is running by testing SOCKS proxy.
     */
    private fun checkTorConnection(): Boolean {
        // Check common Tor/Orbot SOCKS ports
        val ports = listOf(9050, 9150)
        for (port in ports) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 500)
                socket.close()
                return true
            } catch (e: Exception) {
                // Try next port
            }
        }
        return false
    }

    /**
     * Get human-readable status message.
     */
    fun getStatusMessage(status: NetworkStatus): String {
        return when (status.connectionType) {
            ConnectionType.MESHCORE -> "MeshCore active - off-grid"
            ConnectionType.OFFLINE -> "Offline"
            ConnectionType.TOR -> "Tor active"
            ConnectionType.VPN -> "VPN (partial protection)"
            ConnectionType.CLEARNET -> "Clearnet - exposed"
        }
    }

    /**
     * Get status icon.
     */
    fun getStatusIcon(status: NetworkStatus): String {
        return when (status.connectionType) {
            ConnectionType.MESHCORE -> "📡"
            ConnectionType.OFFLINE -> "✈️"
            ConnectionType.TOR -> "🧅"
            ConnectionType.VPN -> "🔒"
            ConnectionType.CLEARNET -> "⚠️"
        }
    }

    /**
     * Get severity level for UI display.
     */
    fun getSeverity(status: NetworkStatus): Severity {
        return when (status.connectionType) {
            ConnectionType.MESHCORE -> Severity.SAFE
            ConnectionType.OFFLINE -> Severity.SAFE
            ConnectionType.TOR -> Severity.SAFE
            ConnectionType.VPN -> Severity.WARNING
            ConnectionType.CLEARNET -> Severity.DANGER
        }
    }

    enum class Severity {
        SAFE,
        WARNING,
        DANGER
    }
}
