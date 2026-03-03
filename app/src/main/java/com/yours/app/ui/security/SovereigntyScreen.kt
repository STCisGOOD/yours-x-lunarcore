package com.yours.app.ui.security

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.content.Context
import android.os.Build
import com.yours.app.security.*
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Device Sovereignty Scanner
 *
 * Shows device security status with visibility into all known surveillance packages.
 * Designed to match Settings screen style.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SovereigntyScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var isScanning by remember { mutableStateOf(true) }
    var report by remember { mutableStateOf<SovereigntyReport?>(null) }

    // Run scan on first composition
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            try {
                report = SovereigntyScanner.scan(context)
            } catch (e: Exception) {
                report = SovereigntyReport(
                    score = -1,
                    threats = emptyList(),
                    timestamp = System.currentTimeMillis(),
                    isSafe = false
                )
            }
        }
        isScanning = false
    }

    // Track scroll state for header transparency
    val scrollState = rememberScrollState()
    val isScrolled = scrollState.value > 0

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        // Scrollable content
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(top = 56.dp)
        ) {
            if (isScanning) {
                ScanningView()
            } else {
                report?.let { r ->
                    ReportContent(report = r)
                }
            }
        }

        // Header
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .background(YoursColors.Background.copy(alpha = if (isScrolled) 0.95f else 1f))
        ) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(
                        imageVector = Icons.Default.ArrowBack,
                        contentDescription = "Back",
                        tint = YoursColors.OnBackground
                    )
                }

                Text(
                    text = "Device Sovereignty",
                    style = MaterialTheme.typography.titleLarge,
                    color = YoursColors.OnBackground
                )

                IconButton(
                    onClick = {
                        isScanning = true
                        scope.launch {
                            withContext(Dispatchers.IO) {
                                try {
                                    report = SovereigntyScanner.scan(context)
                                } catch (e: Exception) { }
                            }
                            isScanning = false
                        }
                    },
                    enabled = !isScanning
                ) {
                    Icon(
                        Icons.Default.Refresh,
                        contentDescription = "Rescan",
                        tint = if (isScanning) YoursColors.OnBackgroundMuted else YoursColors.OnBackground
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanningView() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            color = YoursColors.Primary,
            modifier = Modifier.size(48.dp),
            strokeWidth = 3.dp
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Scanning Device",
            color = YoursColors.OnBackground,
            fontSize = 18.sp,
            fontWeight = FontWeight.Medium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Checking for surveillance indicators...",
            color = YoursColors.OnBackgroundMuted,
            fontSize = 14.sp
        )
    }
}

@Composable
private fun ReportContent(report: SovereigntyReport) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // ================================================================
        // DUAL SCORE DISPLAY
        // ================================================================
        SectionHeader("SOVEREIGNTY")

        Card(
            colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                DualScoreDisplay(
                    sovereigntyScore = report.sovereigntyScore,
                    privacyScore = report.privacyScore,
                    domainStatuses = report.domainStatuses,
                    entityExposures = report.entityExposures
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // ================================================================
        // DOMAIN STATUS (Binary)
        // ================================================================
        if (report.domainStatuses.isNotEmpty()) {
            SectionHeader("DOMAIN STATUS")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    report.domainStatuses.forEachIndexed { index, status ->
                        DomainStatusRow(status)
                        if (index < report.domainStatuses.size - 1) {
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }

        // ================================================================
        // PRIVACY EXPOSURE (Cumulative)
        // ================================================================
        val exposedEntities = report.entityExposures.filter { it.packages.isNotEmpty() }
        if (exposedEntities.isNotEmpty()) {
            SectionHeader("PRIVACY EXPOSURE")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                EntityExposureSection(exposedEntities)
            }

            Spacer(modifier = Modifier.height(24.dp))
        }


        // ================================================================
        // DEVICE STATUS
        // ================================================================
        SectionHeader("DEVICE STATUS")

        Card(
            colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                DeviceInfoRow("Device", report.deviceStatus.deviceModel)
                Spacer(modifier = Modifier.height(8.dp))
                DeviceInfoRow("Android", "Android ${report.deviceStatus.androidVersion}")
                Spacer(modifier = Modifier.height(8.dp))
                DeviceInfoRow("Security Patch", report.deviceStatus.securityPatchLevel)

                Spacer(modifier = Modifier.height(12.dp))
                Divider(color = YoursColors.Background)
                Spacer(modifier = Modifier.height(12.dp))

                StatusRow(
                    label = "Bootloader",
                    value = if (report.deviceStatus.isBootloaderUnlocked) "Unlocked" else "Locked",
                    isGood = !report.deviceStatus.isBootloaderUnlocked
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "Firmware",
                    value = if (report.deviceStatus.hasCustomRom) (report.deviceStatus.romName ?: "Custom ROM") else "Stock ROM",
                    isGood = null // Neutral
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "Root Access",
                    value = if (report.deviceStatus.isRooted) "Detected" else "Not Detected",
                    isGood = null // Neutral - depends on user intent
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // ================================================================
        // NETWORK STATUS
        // ================================================================
        SectionHeader("NETWORK STATUS")

        Card(
            colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                StatusRow(
                    label = "VPN Protection",
                    value = if (report.networkStatus.hasVpnActive) (report.networkStatus.vpnPackage ?: "Active") else "Not Active",
                    isGood = report.networkStatus.hasVpnActive
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "WiFi Encryption",
                    value = report.networkStatus.wifiEncryption ?: "Unknown",
                    isGood = report.networkStatus.isWifiSecure
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "MITM Certificates",
                    value = if (report.networkStatus.hasMitmCertificates) "DETECTED" else "None",
                    isGood = !report.networkStatus.hasMitmCertificates
                )

                if (report.networkStatus.hasMitmCertificates) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text(
                            text = "!",
                            style = MaterialTheme.typography.labelMedium,
                            color = YoursColors.Error,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.width(20.dp)
                        )
                        Text(
                            text = "User-installed CA certificates can intercept HTTPS traffic. All encrypted connections may be compromised.",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.Error
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // ================================================================
        // ACTIVE THREATS
        // ================================================================
        if (report.threats.isNotEmpty()) {
            SectionHeader("ACTIVE THREATS (${report.threats.size})")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    val criticalThreats = report.threats.filter { it.severity == ThreatSeverity.CRITICAL }
                    val highThreats = report.threats.filter { it.severity == ThreatSeverity.HIGH }
                    val otherThreats = report.threats.filter { it.severity != ThreatSeverity.CRITICAL && it.severity != ThreatSeverity.HIGH }

                    if (criticalThreats.isNotEmpty()) {
                        ThreatSection(
                            label = "CRITICAL",
                            color = YoursColors.Error,
                            threats = criticalThreats
                        )
                        if (highThreats.isNotEmpty() || otherThreats.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Divider(color = YoursColors.Background)
                            Spacer(modifier = Modifier.height(16.dp))
                        }
                    }

                    if (highThreats.isNotEmpty()) {
                        ThreatSection(
                            label = "HIGH",
                            color = Color(0xFFFFAA00),
                            threats = highThreats
                        )
                        if (otherThreats.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Divider(color = YoursColors.Background)
                            Spacer(modifier = Modifier.height(16.dp))
                        }
                    }

                    if (otherThreats.isNotEmpty()) {
                        ThreatSection(
                            label = "MEDIUM/LOW",
                            color = YoursColors.OnBackgroundMuted,
                            threats = otherThreats
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }

        // ================================================================
        // PACKAGE SECURITY STATES
        // ================================================================
        if (report.packageStates.isNotEmpty()) {
            SectionHeader("PACKAGE SECURITY STATES")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                PackageStatesSection(packageStates = report.packageStates)
            }

            Spacer(modifier = Modifier.height(24.dp))
        }

        // ================================================================
        // RECOMMENDATIONS
        // ================================================================
        if (report.recommendations.isNotEmpty()) {
            SectionHeader("RECOMMENDATIONS")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    report.recommendations.forEachIndexed { index, rec ->
                        RecommendationRow(recommendation = rec)
                        if (index < report.recommendations.size - 1) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Divider(color = YoursColors.Background)
                            Spacer(modifier = Modifier.height(12.dp))
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }

        // ================================================================
        // DEEP SCAN INFO
        // ================================================================
        SectionHeader("DEEP SCAN")

        Card(
            colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            var expanded by remember { mutableStateOf(false) }

            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { expanded = !expanded },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Desktop Scanner",
                            style = MaterialTheme.typography.titleSmall,
                            color = YoursColors.OnSurface
                        )
                        Text(
                            text = "Run sovereignty-scanner via ADB for deeper analysis",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                    Text(
                        text = if (expanded) "-" else "+",
                        style = MaterialTheme.typography.titleMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                }

                AnimatedVisibility(visible = expanded) {
                    Column(modifier = Modifier.padding(top = 16.dp)) {
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = "The desktop scanner can detect:",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        val capabilities = listOf(
                            "Hidden system partitions and firmware implants",
                            "Baseband/modem-level surveillance",
                            "Bootloader and TEE tampering",
                            "Full APK decompilation and code analysis",
                            "Network traffic analysis for C2 beacons"
                        )

                        capabilities.forEach { cap ->
                            Row(
                                modifier = Modifier.padding(vertical = 2.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                Text(
                                    text = "-",
                                    color = YoursColors.Primary,
                                    modifier = Modifier.width(16.dp)
                                )
                                Text(
                                    text = cap,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.OnBackgroundMuted
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        Text(
                            text = "Instructions:",
                            style = MaterialTheme.typography.labelMedium,
                            color = YoursColors.OnSurface
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = "1. Enable USB Debugging in Developer Options\n2. Connect device via USB\n3. Run: sovereignty-scanner scan",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
private fun SectionHeader(text: String) {
    Column(modifier = Modifier.padding(bottom = 12.dp)) {
        Text(
            text = text,
            color = YoursColors.Primary,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.5.sp
        )
        Spacer(modifier = Modifier.height(4.dp))
        Box(
            modifier = Modifier
                .width(24.dp)
                .height(2.dp)
                .background(YoursColors.Primary.copy(alpha = 0.7f))
        )
    }
}

@Composable
private fun ScoreDisplay(score: Int, threatCount: Int) {
    val displayScore = if (score < 0) 0 else score
    val isError = score < 0

    val animatedScore by animateFloatAsState(
        targetValue = displayScore.toFloat(),
        animationSpec = tween(1000)
    )

    val scoreColor = when {
        isError -> YoursColors.OnBackgroundMuted
        score >= 80 -> YoursColors.Success
        score >= 50 -> Color(0xFFFFAA00)
        else -> YoursColors.Error
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Score indicator
        Box(
            modifier = Modifier
                .size(12.dp)
                .clip(CircleShape)
                .background(scoreColor)
        )
        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "${animatedScore.toInt()}/100",
                style = MaterialTheme.typography.titleMedium,
                color = scoreColor,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = when {
                    isError -> "Scan Error"
                    score >= 80 -> "Sovereign Device"
                    score >= 50 -> "Compromised"
                    else -> "Under Surveillance"
                },
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted
            )
        }

        // Threat count badge
        if (threatCount > 0) {
            Box(
                modifier = Modifier
                    .background(
                        YoursColors.Error.copy(alpha = 0.2f),
                        RoundedCornerShape(4.dp)
                    )
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "$threatCount threat${if (threatCount > 1) "s" else ""}",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.Error,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

// =========================================================================
// NEW DUAL SCORE COMPOSABLES
// =========================================================================

@Composable
private fun DualScoreDisplay(
    sovereigntyScore: Int,
    privacyScore: Int,
    domainStatuses: List<DomainStatus>,
    entityExposures: List<EntityExposure>
) {
    val sovereignDomains = domainStatuses.count { it.isSovereign }
    val totalDomains = domainStatuses.size
    val exposedEntities = entityExposures.count { it.packages.isNotEmpty() }

    Column {
        // Sovereignty Score (Binary domains)
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val sovereigntyColor = when {
                sovereigntyScore >= 80 -> YoursColors.Success
                sovereigntyScore >= 50 -> Color(0xFFFFAA00)
                else -> YoursColors.Error
            }

            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(sovereigntyColor)
            )
            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Sovereignty",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.OnBackgroundMuted
                )
                Text(
                    text = "$sovereignDomains/$totalDomains domains",
                    style = MaterialTheme.typography.bodyMedium,
                    color = sovereigntyColor,
                    fontWeight = FontWeight.Bold
                )
            }

            Text(
                text = "$sovereigntyScore%",
                style = MaterialTheme.typography.bodyLarge,
                color = sovereigntyColor,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
        Divider(color = YoursColors.Background)
        Spacer(modifier = Modifier.height(16.dp))

        // Privacy Score (Cumulative exposure)
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val privacyColor = when {
                privacyScore >= 80 -> YoursColors.Success
                privacyScore >= 50 -> Color(0xFFFFAA00)
                else -> YoursColors.Error
            }

            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(privacyColor)
            )
            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Privacy",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.OnBackgroundMuted
                )
                Text(
                    text = "$exposedEntities entities with data",
                    style = MaterialTheme.typography.bodyMedium,
                    color = privacyColor,
                    fontWeight = FontWeight.Bold
                )
            }

            Text(
                text = "$privacyScore%",
                style = MaterialTheme.typography.bodyLarge,
                color = privacyColor,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
private fun DomainStatusRow(status: DomainStatus) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (status.isSovereign) "[OK]" else "[!!]",
                style = MaterialTheme.typography.labelSmall,
                color = if (status.isSovereign) YoursColors.Success else YoursColors.Error,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.width(36.dp)
            )
            Column {
                Text(
                    text = status.domain.displayName(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnSurface
                )
                Text(
                    text = status.domain.description(),
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.OnBackgroundMuted
                )
            }
        }

        Text(
            text = if (status.isSovereign) "Sovereign" else "Compromised",
            style = MaterialTheme.typography.labelSmall,
            color = if (status.isSovereign) YoursColors.Success else YoursColors.Error,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun EntityExposureSection(exposures: List<EntityExposure>) {
    var expanded by remember { mutableStateOf(false) }

    Column(modifier = Modifier.padding(16.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Entities With Your Data",
                    style = MaterialTheme.typography.titleSmall,
                    color = YoursColors.OnSurface
                )
                Text(
                    text = "${exposures.size} organizations collecting data",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )
            }
            Text(
                text = if (expanded) "-" else "+",
                style = MaterialTheme.typography.titleMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }

        AnimatedVisibility(visible = expanded) {
            Column(modifier = Modifier.padding(top = 16.dp)) {
                exposures.forEach { exposure ->
                    EntityExposureRow(exposure)
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }
        }
    }
}

@Composable
private fun EntityExposureRow(exposure: EntityExposure) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = exposure.entity.displayName(),
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.Error,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = "${exposure.packages.size} pkg${if (exposure.packages.size > 1) "s" else ""}",
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.OnBackgroundMuted
            )
        }

        if (exposure.dataTypes.isNotEmpty()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Data: ${exposure.dataTypes.joinToString(", ")}",
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.OnBackgroundMuted.copy(alpha = 0.7f)
            )
        }
    }
}

@Composable
private fun DeviceInfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = YoursColors.OnBackgroundMuted
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnSurface
        )
    }
}

@Composable
private fun StatusRow(label: String, value: String, isGood: Boolean?) {
    val statusColor = when (isGood) {
        true -> YoursColors.Success
        false -> YoursColors.Error
        null -> YoursColors.OnBackgroundMuted
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = when (isGood) {
                    true -> "[OK]"
                    false -> "[!!]"
                    null -> "[--]"
                },
                style = MaterialTheme.typography.labelSmall,
                color = statusColor,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.width(36.dp)
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnSurface
            )
        }
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = statusColor,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun ThreatSection(label: String, color: Color, threats: List<Threat>) {
    var expanded by remember { mutableStateOf(true) }

    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(color)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "$label (${threats.size})",
                    style = MaterialTheme.typography.labelMedium,
                    color = color,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                text = if (expanded) "-" else "+",
                color = YoursColors.OnBackgroundMuted
            )
        }

        AnimatedVisibility(visible = expanded) {
            Column(modifier = Modifier.padding(top = 12.dp, start = 16.dp)) {
                threats.forEach { threat ->
                    ThreatRow(threat = threat)
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
        }
    }
}

@Composable
private fun ThreatRow(threat: Threat) {
    Column {
        Text(
            text = threat.name,
            style = MaterialTheme.typography.bodyMedium,
            color = YoursColors.OnSurface
        )
        Text(
            text = threat.description,
            style = MaterialTheme.typography.bodySmall,
            color = YoursColors.OnBackgroundMuted
        )
        Spacer(modifier = Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.Top) {
            Text(
                text = ">",
                color = YoursColors.Primary,
                modifier = Modifier.width(16.dp)
            )
            Text(
                text = threat.recommendation,
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.Primary
            )
        }
    }
}

@Composable
private fun PackageStatesSection(packageStates: List<PackageSecurityState>) {
    var expanded by remember { mutableStateOf(false) }

    val activePackages = packageStates.filter { it.state == PackageState.ACTIVE }
    val disabledPackages = packageStates.filter { it.state == PackageState.DISABLED }
    val notInstalledPackages = packageStates.filter { it.state == PackageState.NOT_INSTALLED }

    Column(modifier = Modifier.padding(16.dp)) {
        // Summary row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Known Surveillance Packages",
                    style = MaterialTheme.typography.titleSmall,
                    color = YoursColors.OnSurface
                )
                Text(
                    text = "${activePackages.size} active, ${disabledPackages.size} disabled, ${notInstalledPackages.size} not installed",
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )
            }
            Text(
                text = if (expanded) "-" else "+",
                style = MaterialTheme.typography.titleMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }

        // Summary badges
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StateBadge(
                count = activePackages.size,
                label = "Active",
                color = YoursColors.Error
            )
            StateBadge(
                count = disabledPackages.size,
                label = "Disabled",
                color = Color(0xFFFFAA00)
            )
            StateBadge(
                count = notInstalledPackages.size,
                label = "Removed",
                color = YoursColors.Success
            )
        }

        // Expanded detail view
        AnimatedVisibility(visible = expanded) {
            Column(modifier = Modifier.padding(top = 16.dp)) {
                Divider(color = YoursColors.Background)
                Spacer(modifier = Modifier.height(12.dp))

                // Explanation of states
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.Top
                ) {
                    Text(
                        text = "i",
                        style = MaterialTheme.typography.labelMedium,
                        color = YoursColors.Primary,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.width(20.dp)
                    )
                    Text(
                        text = "Active packages are running threats. Disabled packages are neutralized but still installed - a system update may re-enable them. Removed packages offer the best security.",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.Primary
                    )
                }

                // Active packages
                if (activePackages.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    PackageStateGroup(
                        label = "ACTIVE",
                        packages = activePackages,
                        color = YoursColors.Error
                    )
                }

                // Disabled packages
                if (disabledPackages.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    PackageStateGroup(
                        label = "DISABLED",
                        packages = disabledPackages,
                        color = Color(0xFFFFAA00),
                        warning = "System updates may re-enable these"
                    )
                }

                // Not installed packages
                if (notInstalledPackages.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    PackageStateGroup(
                        label = "NOT INSTALLED",
                        packages = notInstalledPackages,
                        color = YoursColors.Success
                    )
                }
            }
        }
    }
}

@Composable
private fun StateBadge(count: Int, label: String, color: Color) {
    Row(
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.labelMedium,
            color = color,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = color
        )
    }
}

@Composable
private fun PackageStateGroup(
    label: String,
    packages: List<PackageSecurityState>,
    color: Color,
    warning: String? = null
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(color)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "$label (${packages.size})",
                style = MaterialTheme.typography.labelSmall,
                color = color,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp
            )
        }

        warning?.let {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = it,
                style = MaterialTheme.typography.labelSmall,
                color = color.copy(alpha = 0.7f),
                modifier = Modifier.padding(start = 16.dp)
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        packages.forEach { pkg ->
            PackageRow(pkg = pkg, stateColor = color)
        }
    }
}

@Composable
private fun PackageRow(pkg: PackageSecurityState, stateColor: Color) {
    val severityColor = when (pkg.severity) {
        ThreatSeverity.CRITICAL -> YoursColors.Error
        ThreatSeverity.HIGH -> Color(0xFFFFAA00)
        else -> YoursColors.OnBackgroundMuted
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, top = 4.dp, bottom = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = pkg.name,
                style = MaterialTheme.typography.bodySmall,
                color = if (pkg.state == PackageState.ACTIVE) YoursColors.OnSurface else YoursColors.OnBackgroundMuted
            )
            Text(
                text = pkg.packageName,
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.OnBackgroundMuted.copy(alpha = 0.5f)
            )
        }
        Text(
            text = when (pkg.severity) {
                ThreatSeverity.CRITICAL -> "CRIT"
                ThreatSeverity.HIGH -> "HIGH"
                ThreatSeverity.MEDIUM -> "MED"
                ThreatSeverity.LOW -> "LOW"
            },
            style = MaterialTheme.typography.labelSmall,
            color = severityColor,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun RecommendationRow(recommendation: SecurityRecommendation) {
    val priorityColor = when (recommendation.priority) {
        RecommendationPriority.CRITICAL -> YoursColors.Error
        RecommendationPriority.HIGH -> Color(0xFFFFAA00)
        RecommendationPriority.MEDIUM -> YoursColors.Primary
        RecommendationPriority.LOW -> YoursColors.Success
    }

    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = "[${when (recommendation.priority) {
                    RecommendationPriority.CRITICAL -> "CRIT"
                    RecommendationPriority.HIGH -> "HIGH"
                    RecommendationPriority.MEDIUM -> "MED"
                    RecommendationPriority.LOW -> "LOW"
                }}]",
                style = MaterialTheme.typography.labelSmall,
                color = priorityColor,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.width(48.dp)
            )
            Text(
                text = recommendation.title,
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnSurface
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = recommendation.description,
            style = MaterialTheme.typography.bodySmall,
            color = YoursColors.OnBackgroundMuted,
            modifier = Modifier.padding(start = 48.dp)
        )
    }
}
