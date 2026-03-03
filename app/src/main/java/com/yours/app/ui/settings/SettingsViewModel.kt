package com.yours.app.ui.settings

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.yours.app.crypto.HardwareSecurityModule
import com.yours.app.crypto.HSMCapabilities
import com.yours.app.security.KeySecurityLevel
import com.yours.app.security.SecureDeviceKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Security status for display in the UI.
 */
data class SecurityHardwareStatus(
    val isInitialized: Boolean = false,
    val securityLevel: SecurityLevel = SecurityLevel.UNKNOWN,
    val hasStrongBox: Boolean = false,
    val hasTEE: Boolean = false,
    val isAttestationSupported: Boolean = false,
    val securityWarnings: List<String> = emptyList(),
    val keyStorageDescription: String = "Checking...",
    val securityIndicator: SecurityIndicator = SecurityIndicator.UNKNOWN,
    val deviceKeyLevel: KeySecurityLevel = KeySecurityLevel.UNKNOWN,
    val isDeviceKeyHardwareBacked: Boolean = false
)

/**
 * Security level enumeration for UI display.
 */
enum class SecurityLevel {
    UNKNOWN,
    SOFTWARE_ONLY,
    TEE_BACKED,
    STRONGBOX_BACKED
}

/**
 * Visual indicator for security status.
 */
enum class SecurityIndicator {
    UNKNOWN,
    WARNING,
    GOOD,
    EXCELLENT
}

/**
 * ViewModel for managing hardware security module state and settings.
 */
class SettingsViewModel(
    private val context: Context
) : ViewModel() {

    private val hsm = HardwareSecurityModule(context)
    private val secureDeviceKey = SecureDeviceKey.getInstance(context)

    private val _securityStatus = MutableStateFlow(SecurityHardwareStatus())
    val securityStatus: StateFlow<SecurityHardwareStatus> = _securityStatus.asStateFlow()

    private val _isScanning = MutableStateFlow(true)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    init {
        detectHardwareSecurity()
    }

    /**
     * Detect hardware security capabilities and update state.
     */
    fun detectHardwareSecurity() {
        viewModelScope.launch {
            _isScanning.value = true

            val capabilities = withContext(Dispatchers.IO) {
                hsm.initialize()
            }

            // Also get the actual device key security level
            val deviceKeyLevel = withContext(Dispatchers.IO) {
                // This triggers key creation if not exists, with best available backend
                val deviceKey = secureDeviceKey.getDeviceKey() // Initialize key if needed
                // Zeroize immediately - we only needed to trigger creation
                com.yours.app.crypto.BedrockCore.zeroize(deviceKey)
                secureDeviceKey.getSecurityLevel()
            }

            val status = buildSecurityStatus(capabilities, deviceKeyLevel)
            _securityStatus.value = status

            _isScanning.value = false
        }
    }

    /**
     * Build the security status from HSM capabilities and device key level.
     */
    private fun buildSecurityStatus(
        capabilities: HSMCapabilities,
        deviceKeyLevel: KeySecurityLevel
    ): SecurityHardwareStatus {
        // Use the actual device key level for the most accurate representation
        val securityLevel = when (deviceKeyLevel) {
            KeySecurityLevel.STRONGBOX -> SecurityLevel.STRONGBOX_BACKED
            KeySecurityLevel.TEE -> SecurityLevel.TEE_BACKED
            KeySecurityLevel.SOFTWARE -> SecurityLevel.SOFTWARE_ONLY
            KeySecurityLevel.UNKNOWN -> when (capabilities.level) {
                HardwareSecurityModule.CAPABILITY_STRONGBOX -> SecurityLevel.STRONGBOX_BACKED
                HardwareSecurityModule.CAPABILITY_TEE -> SecurityLevel.TEE_BACKED
                HardwareSecurityModule.CAPABILITY_SOFTWARE -> SecurityLevel.SOFTWARE_ONLY
                else -> SecurityLevel.UNKNOWN
            }
        }

        val indicator = when (securityLevel) {
            SecurityLevel.STRONGBOX_BACKED -> SecurityIndicator.EXCELLENT
            SecurityLevel.TEE_BACKED -> SecurityIndicator.GOOD
            SecurityLevel.SOFTWARE_ONLY -> SecurityIndicator.WARNING
            SecurityLevel.UNKNOWN -> SecurityIndicator.UNKNOWN
        }

        val keyStorageDescription = when (securityLevel) {
            SecurityLevel.STRONGBOX_BACKED ->
                "Keys stored in dedicated secure chip (StrongBox). Maximum hardware protection."
            SecurityLevel.TEE_BACKED ->
                "Keys stored in Trusted Execution Environment. Hardware-isolated from Android."
            SecurityLevel.SOFTWARE_ONLY ->
                "Keys stored in software. Vulnerable to rooted device attacks."
            SecurityLevel.UNKNOWN ->
                "Security status unknown."
        }

        val isDeviceKeyHardwareBacked = deviceKeyLevel == KeySecurityLevel.STRONGBOX ||
            deviceKeyLevel == KeySecurityLevel.TEE

        return SecurityHardwareStatus(
            isInitialized = true,
            securityLevel = securityLevel,
            hasStrongBox = capabilities.hasStrongBox,
            hasTEE = capabilities.hasTEE,
            isAttestationSupported = capabilities.attestationSupported,
            securityWarnings = capabilities.securityWarnings,
            keyStorageDescription = keyStorageDescription,
            securityIndicator = indicator,
            deviceKeyLevel = deviceKeyLevel,
            isDeviceKeyHardwareBacked = isDeviceKeyHardwareBacked
        )
    }

    /**
     * Get the HardwareSecurityModule instance for key operations.
     */
    fun getHSM(): HardwareSecurityModule = hsm

    /**
     * Factory for creating SettingsViewModel with context.
     */
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(SettingsViewModel::class.java)) {
                return SettingsViewModel(context) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}
