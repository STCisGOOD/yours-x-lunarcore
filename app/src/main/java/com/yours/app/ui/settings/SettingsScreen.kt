package com.yours.app.ui.settings

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import androidx.lifecycle.viewmodel.compose.viewModel
import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.IdentityManager
import com.yours.app.security.AuthPreferences
import com.yours.app.mesh.BleDeviceInfo
import com.yours.app.mesh.DiscoveredDevice
import com.yours.app.mesh.MeshConnection
import com.yours.app.mesh.MeshConnectionState
import com.yours.app.mesh.MeshCoreManager
import com.yours.app.mesh.MeshCoreSerialTransport
import com.yours.app.mesh.MeshEventType
import com.yours.app.mesh.MeshType
import com.yours.app.mesh.MeshtasticAdapter
import com.yours.app.mesh.MeshtasticDeviceInfo
import com.yours.app.mesh.TransportType
import com.yours.app.mesh.UsbSerialDeviceInfo
import com.yours.app.mesh.ReticulumAdapter
import com.yours.app.security.NetworkSafetyChecker
import com.yours.app.security.OpsecManager
import com.yours.app.security.SecurityGate
import com.yours.app.security.ThreatDetector
import com.yours.app.security.checkSecurityGate
import com.yours.app.ui.components.SecurityBlockedDialog
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.launch

/**
 * Settings Screen with OPSEC Features
 */
@Composable
fun SettingsScreen(
    identityManager: IdentityManager,
    onConnectLoRa: () -> Unit = {},
    meshCoreManager: MeshCoreManager? = null,
    messageManager: com.yours.app.messaging.MessageManager? = null,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val opsecManager = remember { OpsecManager(context) }

    // Create MeshCoreManager if not provided
    val manager = remember { meshCoreManager ?: MeshCoreManager(context) }

    // Hardware Security Module state
    val settingsViewModel: SettingsViewModel = viewModel(
        factory = SettingsViewModel.Factory(context)
    )
    val securityStatus by settingsViewModel.securityStatus.collectAsState()
    val isHsmScanning by settingsViewModel.isScanning.collectAsState()

    var threatReport by remember { mutableStateOf<ThreatDetector.ThreatReport?>(null) }
    var networkStatus by remember { mutableStateOf<NetworkSafetyChecker.NetworkStatus?>(null) }
    var isScanning by remember { mutableStateOf(true) }

    var paranoiaMode by remember { mutableStateOf(opsecManager.paranoiaModeEnabled.value) }
    var duressPassphrase by remember { mutableStateOf(opsecManager.duressPassphrase ?: "") }
    var showDuressDialog by remember { mutableStateOf(false) }

    // SECURITY GATE: State for blocking security-sensitive operations
    var securityGateResult by remember { mutableStateOf<SecurityGate.GateResult?>(null) }
    var showSecurityBlockedDialog by remember { mutableStateOf(false) }
    var blockedOperationName by remember { mutableStateOf("") }

    // Perform initial security check for SENSITIVE level operations
    LaunchedEffect(Unit) {
        securityGateResult = context.checkSecurityGate(SecurityGate.SecurityLevel.SENSITIVE)
    }

    // Mesh type selection (Phase 1 of multi-mesh support)
    var selectedMeshType by remember { mutableStateOf(MeshType.MESHCORE) }
    var showMeshTypeMenu by remember { mutableStateOf(false) }

    // Meshtastic adapter
    val meshtasticAdapter = remember { MeshtasticAdapter(context) }
    var meshtasticDevices by remember { mutableStateOf<List<MeshtasticDeviceInfo>>(emptyList()) }
    var isScanningMeshtastic by remember { mutableStateOf(false) }

    // Reticulum/RNode adapter
    val reticulumAdapter = remember { ReticulumAdapter(context) }

    // LoRa/MeshCore device state
    var availableLoRaDevices by remember { mutableStateOf<List<UsbSerialDeviceInfo>>(emptyList()) }
    var availableBleDevices by remember { mutableStateOf<List<BleDeviceInfo>>(emptyList()) }
    val meshConnectionState by manager.connectionState.collectAsState()
    var connectionStatusMessage by remember { mutableStateOf<String?>(null) }
    var isConnecting by remember { mutableStateOf(false) }
    var showConnectionDialog by remember { mutableStateOf(false) }
    var showTcpRelayDialog by remember { mutableStateOf(false) }
    var tcpHost by remember { mutableStateOf("") }
    var tcpPort by remember { mutableStateOf("4000") }

    // Collect MeshCore events for status messages
    LaunchedEffect(Unit) {
        manager.events.collect { event ->
            when (event.type) {
                MeshEventType.CONNECTED -> {
                    connectionStatusMessage = "Connected to MeshCore device"
                    isConnecting = false
                }
                MeshEventType.DISCONNECTED -> {
                    connectionStatusMessage = "Disconnected"
                    isConnecting = false
                }
                MeshEventType.CONNECTION_ERROR -> {
                    connectionStatusMessage = "Connection error: ${event.payload}"
                    isConnecting = false
                }
                MeshEventType.DEVICE_INFO -> {
                    connectionStatusMessage = event.payload?.toString()
                }
                else -> { /* Ignore other events */ }
            }
        }
    }

    // Scan on load
    LaunchedEffect(Unit) {
        threatReport = ThreatDetector.scan(context)
        networkStatus = NetworkSafetyChecker.check(context)
        isScanning = false

        // Check for USB LoRa devices
        try {
            availableLoRaDevices = manager.getAvailableUsbDevices()
        } catch (e: Exception) {
            // USB not available
        }

        // Check for BLE devices in background
        scope.launch {
            try {
                val discovered = manager.discoverDevices(scanBle = true, bleScanTimeoutMs = 5000)
                availableBleDevices = discovered.filterIsInstance<DiscoveredDevice.BleDevice>().map {
                    BleDeviceInfo(it.name, it.address, it.rssi, it.hasMeshCoreService)
                }
            } catch (e: Exception) {
                // BLE scan failed
            }
        }
    }

    // Track scroll state for header transparency
    val scrollState = rememberScrollState()
    val isScrolled = scrollState.value > 0

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        // Scrollable content with top padding for header
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(top = 56.dp) // Header height
                .padding(horizontal = 16.dp)
                .padding(bottom = 16.dp)
        ) {
            // ================================================================
            // LUNARCORE
            // ================================================================
            SectionHeader("LUNARCORE")

            // Mesh Type Selector
            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Mesh Protocol",
                        style = MaterialTheme.typography.labelMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Box {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(YoursColors.Background)
                                .clickable { showMeshTypeMenu = true }
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    text = selectedMeshType.displayName(),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = YoursColors.OnSurface,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = selectedMeshType.description(),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.OnBackgroundMuted
                                )
                            }
                            Text(
                                text = "▼",
                                color = YoursColors.OnBackgroundMuted
                            )
                        }

                        DropdownMenu(
                            expanded = showMeshTypeMenu,
                            onDismissRequest = { showMeshTypeMenu = false }
                        ) {
                            MeshType.values().forEach { meshType ->
                                DropdownMenuItem(
                                    text = {
                                        Column {
                                            Text(
                                                text = meshType.displayName(),
                                                fontWeight = FontWeight.Medium
                                            )
                                            Text(
                                                text = meshType.description(),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = YoursColors.OnBackgroundMuted
                                            )
                                        }
                                    },
                                    onClick = {
                                        selectedMeshType = meshType
                                        showMeshTypeMenu = false
                                    },
                                    enabled = true, // All mesh types now available
                                    trailingIcon = {
                                        if (meshType == MeshType.RETICULUM) {
                                            Text(
                                                text = "RNode/KISS",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = YoursColors.Primary.copy(alpha = 0.7f)
                                            )
                                        }
                                    }
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            var expandedFeature by remember { mutableStateOf<String?>(null) }

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Connection status
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .clip(CircleShape)
                                .background(
                                    when (meshConnectionState) {
                                        MeshConnectionState.CONNECTED -> YoursColors.Success
                                        MeshConnectionState.CONNECTING -> YoursColors.Warning
                                        MeshConnectionState.ERROR -> YoursColors.Warning
                                        MeshConnectionState.DISCONNECTED -> {
                                            if (availableLoRaDevices.isNotEmpty() || availableBleDevices.isNotEmpty()) {
                                                YoursColors.Warning
                                            } else {
                                                YoursColors.OnBackgroundMuted
                                            }
                                        }
                                    }
                                )
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = when (meshConnectionState) {
                                    MeshConnectionState.CONNECTED -> {
                                        val transportType = manager.getCurrentTransportType()
                                        "Connected (${transportType?.name ?: "Unknown"})"
                                    }
                                    MeshConnectionState.CONNECTING -> "Connecting..."
                                    MeshConnectionState.ERROR -> "Connection Error"
                                    MeshConnectionState.DISCONNECTED -> {
                                        val totalDevices = availableLoRaDevices.size + availableBleDevices.size
                                        if (totalDevices > 0) {
                                            "$totalDevices device(s) available"
                                        } else {
                                            "No devices"
                                        }
                                    }
                                },
                                style = MaterialTheme.typography.titleMedium,
                                color = YoursColors.OnSurface
                            )
                            Text(
                                text = connectionStatusMessage ?: "Off-grid mesh network",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted,
                                maxLines = 2
                            )
                        }

                        // Disconnect button when connected
                        if (meshConnectionState == MeshConnectionState.CONNECTED) {
                            TextButton(
                                onClick = {
                                    scope.launch {
                                        manager.disconnect()
                                    }
                                }
                            ) {
                                Text("Disconnect", color = YoursColors.Warning)
                            }
                        }
                    }

                    // USB Serial Devices
                    if (availableLoRaDevices.isNotEmpty() && meshConnectionState != MeshConnectionState.CONNECTED) {
                        Spacer(modifier = Modifier.height(16.dp))
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = "USB Devices",
                            style = MaterialTheme.typography.labelMedium,
                            color = YoursColors.OnBackgroundMuted
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        availableLoRaDevices.forEach { device ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = !isConnecting) {
                                        scope.launch {
                                            isConnecting = true
                                            connectionStatusMessage = "Connecting to ${device.productName}..."
                                            val result = manager.connect(
                                                MeshConnection.Serial(device.deviceName)
                                            )
                                            if (result.isFailure) {
                                                connectionStatusMessage = "Failed: ${result.exceptionOrNull()?.message}"
                                            }
                                            isConnecting = false
                                        }
                                    }
                                    .padding(vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = device.productName,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = YoursColors.OnSurface
                                    )
                                    Text(
                                        text = "${device.manufacturer} (USB)",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = YoursColors.OnBackgroundMuted
                                    )
                                }
                                if (isConnecting) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = YoursColors.Primary
                                    )
                                } else {
                                    Text(
                                        text = if (device.hasPermission) "Connect" else "Grant",
                                        color = YoursColors.Primary,
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                    }

                    // BLE Devices
                    if (availableBleDevices.isNotEmpty() && meshConnectionState != MeshConnectionState.CONNECTED) {
                        Spacer(modifier = Modifier.height(16.dp))
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = "Bluetooth Devices",
                            style = MaterialTheme.typography.labelMedium,
                            color = YoursColors.OnBackgroundMuted
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        availableBleDevices.forEach { device ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = !isConnecting) {
                                        scope.launch {
                                            isConnecting = true
                                            connectionStatusMessage = "Connecting to ${device.name ?: device.address}..."
                                            val result = manager.connect(
                                                MeshConnection.Ble(device.address)
                                            )
                                            if (result.isFailure) {
                                                connectionStatusMessage = "Failed: ${result.exceptionOrNull()?.message}"
                                            }
                                            isConnecting = false
                                        }
                                    }
                                    .padding(vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = device.name ?: "Unknown Device",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = YoursColors.OnSurface
                                    )
                                    Text(
                                        text = "${device.address} (${device.rssi} dBm)",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = YoursColors.OnBackgroundMuted
                                    )
                                }
                                if (device.hasMeshCoreService) {
                                    Text(
                                        text = "[MC]",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = YoursColors.Success
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                if (isConnecting) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = YoursColors.Primary
                                    )
                                } else {
                                    Text(
                                        text = "Connect",
                                        color = YoursColors.Primary,
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                    }

                    // TCP Relay option
                    if (meshConnectionState != MeshConnectionState.CONNECTED) {
                        Spacer(modifier = Modifier.height(16.dp))
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(enabled = !isConnecting) {
                                    showTcpRelayDialog = true
                                }
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    text = "TCP Relay",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = YoursColors.OnSurface
                                )
                                Text(
                                    text = "Connect to a MeshCore relay server",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.OnBackgroundMuted
                                )
                            }
                            Text(
                                text = "Configure",
                                color = YoursColors.Primary,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    // ============================================================
                    // MESHTASTIC DEVICES (when Meshtastic is selected)
                    // ============================================================
                    if (selectedMeshType == MeshType.MESHTASTIC) {
                        Spacer(modifier = Modifier.height(16.dp))
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Meshtastic Devices",
                                style = MaterialTheme.typography.labelMedium,
                                color = YoursColors.OnBackgroundMuted
                            )
                            TextButton(
                                onClick = {
                                    scope.launch {
                                        isScanningMeshtastic = true
                                        connectionStatusMessage = "Scanning for Meshtastic devices..."
                                        try {
                                            meshtasticDevices = meshtasticAdapter.scanForDevices(10000)
                                            connectionStatusMessage = if (meshtasticDevices.isEmpty()) {
                                                "No Meshtastic devices found"
                                            } else {
                                                "${meshtasticDevices.size} device(s) found"
                                            }
                                        } catch (e: Exception) {
                                            connectionStatusMessage = "Scan failed: ${e.message}"
                                        }
                                        isScanningMeshtastic = false
                                    }
                                },
                                enabled = !isScanningMeshtastic
                            ) {
                                if (isScanningMeshtastic) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = YoursColors.Primary
                                    )
                                } else {
                                    Text("Scan", color = YoursColors.Primary)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))

                        if (meshtasticDevices.isEmpty()) {
                            Text(
                                text = "No Meshtastic devices found. Make sure your device is powered on and Bluetooth is enabled.",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        } else {
                            meshtasticDevices.forEach { device ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable(enabled = !isConnecting) {
                                            scope.launch {
                                                isConnecting = true
                                                connectionStatusMessage = "Connecting to ${device.name}..."
                                                val result = meshtasticAdapter.connect(
                                                    com.yours.app.mesh.MeshConnectionConfig.Ble(device.macAddress)
                                                )
                                                if (result.isSuccess) {
                                                    connectionStatusMessage = "Connected to ${device.name}"
                                                } else {
                                                    connectionStatusMessage = "Failed: ${result.exceptionOrNull()?.message}"
                                                }
                                                isConnecting = false
                                            }
                                        }
                                        .padding(vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = device.name,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = YoursColors.OnSurface
                                        )
                                        Text(
                                            text = "${device.macAddress} (${device.rssi} dBm)",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = YoursColors.OnBackgroundMuted
                                        )
                                    }
                                    Text(
                                        text = "[MT]",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = YoursColors.Success
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    if (isConnecting) {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(16.dp),
                                            strokeWidth = 2.dp,
                                            color = YoursColors.Primary
                                        )
                                    } else {
                                        Text(
                                            text = "Connect",
                                            color = YoursColors.Primary,
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // ============================================================
                    // MESHCORE: No devices message
                    // ============================================================
                    if (selectedMeshType == MeshType.MESHCORE && availableLoRaDevices.isEmpty() && availableBleDevices.isEmpty() && meshConnectionState == MeshConnectionState.DISCONNECTED) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Connect an ESP32 LoRa device via USB-C or Bluetooth to communicate without internet or cell towers.",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        // Rescan button
                        TextButton(
                            onClick = {
                                scope.launch {
                                    connectionStatusMessage = "Scanning for devices..."
                                    try {
                                        availableLoRaDevices = manager.getAvailableUsbDevices()
                                        val discovered = manager.discoverDevices(scanBle = true, bleScanTimeoutMs = 5000)
                                        availableBleDevices = discovered.filterIsInstance<DiscoveredDevice.BleDevice>().map {
                                            BleDeviceInfo(it.name, it.address, it.rssi, it.hasMeshCoreService)
                                        }
                                        connectionStatusMessage = if (availableLoRaDevices.isEmpty() && availableBleDevices.isEmpty()) {
                                            "No devices found"
                                        } else {
                                            null
                                        }
                                    } catch (e: Exception) {
                                        connectionStatusMessage = "Scan failed: ${e.message}"
                                    }
                                }
                            }
                        ) {
                            Text("Scan for Devices", color = YoursColors.Primary)
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(12.dp))

                    // Tappable feature rows
                    LunarFeatureRow(
                        label = "Onion Routing",
                        isExpanded = expandedFeature == "onion",
                        onClick = { expandedFeature = if (expandedFeature == "onion") null else "onion" },
                        description = "Messages are encrypted in layers and routed through 3+ random nodes. Each node only knows the previous and next hop, never the full path or content."
                    )
                    LunarFeatureRow(
                        label = "Post-Quantum Keys",
                        isExpanded = expandedFeature == "pq",
                        onClick = { expandedFeature = if (expandedFeature == "pq") null else "pq" },
                        description = "Uses ML-KEM-768 (Kyber), a NIST-standardized algorithm resistant to quantum computer attacks. Your messages stay private even against future threats."
                    )
                    LunarFeatureRow(
                        label = "Anonymous Credentials",
                        isExpanded = expandedFeature == "creds",
                        onClick = { expandedFeature = if (expandedFeature == "creds") null else "creds" },
                        description = "BBS+ signatures let you prove you're authorized to use the mesh without revealing your identity. Spam prevention without surveillance."
                    )
                    LunarFeatureRow(
                        label = "Long Range Radio",
                        isExpanded = expandedFeature == "lora",
                        onClick = { expandedFeature = if (expandedFeature == "lora") null else "lora" },
                        description = "LoRa radio reaches up to 10km line-of-sight, works without internet or cell towers. Communicate during outages, in remote areas, or when networks are compromised."
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // SECURITY
            // ================================================================
            SectionHeader("SECURITY")

            // Travel Mode state
            var travelMode by remember { mutableStateOf(opsecManager.travelModeEnabled.value) }
            var showTravelModeDialog by remember { mutableStateOf(false) }

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Paranoia Mode
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Paranoia Mode",
                                style = MaterialTheme.typography.titleSmall,
                                color = YoursColors.OnSurface
                            )
                            Text(
                                text = if (paranoiaMode) "Auto-lock after 30 seconds, clipboard cleared"
                                       else "Auto-lock after 2 minutes",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                        Switch(
                            checked = paranoiaMode,
                            onCheckedChange = { newValue ->
                                // SECURITY GATE: Check before allowing security setting changes
                                val gateResult = securityGateResult
                                if (gateResult is SecurityGate.GateResult.Blocked) {
                                    blockedOperationName = "Change Paranoia Mode"
                                    showSecurityBlockedDialog = true
                                } else {
                                    paranoiaMode = newValue
                                    if (newValue) opsecManager.enableParanoiaMode()
                                    else opsecManager.disableParanoiaMode()
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = YoursColors.Primary,
                                checkedTrackColor = YoursColors.Primary.copy(alpha = 0.5f)
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(16.dp))

                    // Travel Mode
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Travel Mode",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = if (travelMode) YoursColors.Warning else YoursColors.OnSurface
                                )
                                if (travelMode) {
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                YoursColors.Warning.copy(alpha = 0.2f),
                                                RoundedCornerShape(4.dp)
                                            )
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = "ACTIVE",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = YoursColors.Warning,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                            Text(
                                text = if (travelMode) "Reduced functionality, enhanced security"
                                       else "For border crossings and high-risk situations",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                        Switch(
                            checked = travelMode,
                            onCheckedChange = { newValue ->
                                val gateResult = securityGateResult
                                if (gateResult is SecurityGate.GateResult.Blocked) {
                                    blockedOperationName = "Change Travel Mode"
                                    showSecurityBlockedDialog = true
                                } else {
                                    if (newValue) {
                                        // Show confirmation dialog before enabling
                                        showTravelModeDialog = true
                                    } else {
                                        travelMode = false
                                        opsecManager.disableTravelMode()
                                    }
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = YoursColors.Warning,
                                checkedTrackColor = YoursColors.Warning.copy(alpha = 0.5f)
                            )
                        )
                    }

                    // Travel mode info button
                    TextButton(
                        onClick = { showTravelModeDialog = true },
                        modifier = Modifier.align(Alignment.End)
                    ) {
                        Text(
                            text = "What does this do?",
                            style = MaterialTheme.typography.labelSmall,
                            color = YoursColors.Primary
                        )
                    }
                }
            }

            // Travel Mode Confirmation Dialog
            if (showTravelModeDialog) {
                AlertDialog(
                    onDismissRequest = { showTravelModeDialog = false },
                    title = {
                        Text(
                            text = if (travelMode) "Travel Mode" else "Enable Travel Mode?",
                            color = YoursColors.Warning
                        )
                    },
                    text = {
                        Column {
                            Text(
                                text = opsecManager.getTravelModeDescription(),
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                            if (!travelMode) {
                                Spacer(modifier = Modifier.height(16.dp))
                                Text(
                                    text = "Are you sure you want to enable Travel Mode?",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = YoursColors.Warning,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    },
                    confirmButton = {
                        if (!travelMode) {
                            TextButton(
                                onClick = {
                                    travelMode = true
                                    opsecManager.enableTravelMode()
                                    showTravelModeDialog = false
                                }
                            ) {
                                Text("Enable", color = YoursColors.Warning)
                            }
                        } else {
                            TextButton(onClick = { showTravelModeDialog = false }) {
                                Text("OK")
                            }
                        }
                    },
                    dismissButton = {
                        if (!travelMode) {
                            TextButton(onClick = { showTravelModeDialog = false }) {
                                Text("Cancel")
                            }
                        }
                    },
                    containerColor = YoursColors.Background
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // TRAFFIC PRIVACY (Cover Traffic Mode)
            // ================================================================
            SectionHeader("TRAFFIC PRIVACY")

            // Cover traffic mode state
            var currentCoverMode by remember {
                mutableStateOf(
                    messageManager?.getCoverTrafficMode()
                        ?: com.yours.app.messaging.CoverTrafficMode.OFF
                )
            }
            var showCoverModeMenu by remember { mutableStateOf(false) }

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Warning banner
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                YoursColors.Warning.copy(alpha = 0.1f),
                                RoundedCornerShape(8.dp)
                            )
                            .padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text(
                            text = "⚠",
                            style = MaterialTheme.typography.titleMedium,
                            color = YoursColors.Warning
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Cover traffic hides WHEN you communicate but RF transmissions can reveal your LOCATION via direction finding.",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.Warning
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Text(
                        text = "Cover Traffic Mode",
                        style = MaterialTheme.typography.labelMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Box {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(YoursColors.Background)
                                .clickable { showCoverModeMenu = true }
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = currentCoverMode.name,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = YoursColors.OnSurface,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = when (currentCoverMode) {
                                        com.yours.app.messaging.CoverTrafficMode.OFF ->
                                            "No cover traffic - saves battery but timing exposed"
                                        com.yours.app.messaging.CoverTrafficMode.PROBABILISTIC ->
                                            "30% chance per interval - low bandwidth"
                                        com.yours.app.messaging.CoverTrafficMode.BURST ->
                                            "Cover accompanies real messages"
                                        com.yours.app.messaging.CoverTrafficMode.CONTINUOUS ->
                                            "Always maintain traffic - strong timing privacy"
                                        com.yours.app.messaging.CoverTrafficMode.PARANOID ->
                                            "Maximum cover traffic - best timing privacy"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.OnBackgroundMuted
                                )
                            }
                            Text(
                                text = "▼",
                                color = YoursColors.OnBackgroundMuted
                            )
                        }

                        DropdownMenu(
                            expanded = showCoverModeMenu,
                            onDismissRequest = { showCoverModeMenu = false }
                        ) {
                            com.yours.app.messaging.CoverTrafficMode.entries.forEach { mode ->
                                DropdownMenuItem(
                                    text = {
                                        Column {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text(
                                                    text = mode.name,
                                                    fontWeight = if (mode == currentCoverMode) FontWeight.Bold else FontWeight.Medium,
                                                    color = if (mode == currentCoverMode) YoursColors.Primary else YoursColors.OnSurface
                                                )
                                                if (mode == currentCoverMode) {
                                                    Spacer(modifier = Modifier.width(8.dp))
                                                    Box(
                                                        modifier = Modifier
                                                            .size(8.dp)
                                                            .clip(CircleShape)
                                                            .background(YoursColors.Primary)
                                                    )
                                                }
                                            }
                                            Text(
                                                text = mode.description,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = YoursColors.OnBackgroundMuted
                                            )
                                        }
                                    },
                                    onClick = {
                                        currentCoverMode = mode
                                        messageManager?.setCoverTrafficMode(mode)
                                        showCoverModeMenu = false
                                    }
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(12.dp))

                    // Privacy vs Location trade-off info
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "🛡",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Timing Privacy",
                                style = MaterialTheme.typography.labelMedium,
                                color = YoursColors.OnSurface
                            )
                        }
                        Text(
                            text = "Higher modes hide when you're active. Observers can't tell real messages from chaff.",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "📍",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Location Exposure",
                                style = MaterialTheme.typography.labelMedium,
                                color = YoursColors.Warning
                            )
                        }
                        Text(
                            text = "More RF transmissions = easier to locate via direction finding, triangulation, and RSSI analysis.",
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // AUTHENTICATION METHOD
            // ================================================================
            SectionHeader("AUTHENTICATION")

            // Auth preferences state
            val authPreferences = remember { AuthPreferences.getInstance(context) }
            var currentAuthMethod by remember { mutableStateOf(authPreferences.authMethod) }
            var showAuthMethodDialog by remember { mutableStateOf(false) }
            var showConstellationSetupDialog by remember { mutableStateOf(false) }

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Current authentication method
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val gateResult = securityGateResult
                                if (gateResult is SecurityGate.GateResult.Blocked) {
                                    blockedOperationName = "Change Authentication Method"
                                    showSecurityBlockedDialog = true
                                } else {
                                    showAuthMethodDialog = true
                                }
                            }
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Unlock Method",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = YoursColors.OnSurface
                                )
                                if (currentAuthMethod == AuthPreferences.AuthMethod.CONSTELLATION) {
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                YoursColors.Primary.copy(alpha = 0.2f),
                                                RoundedCornerShape(4.dp)
                                            )
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = "ENHANCED",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = YoursColors.Primary,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                            Text(
                                text = authPreferences.getDisplayName(currentAuthMethod),
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                            Text(
                                text = authPreferences.getDescription(currentAuthMethod),
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                        Text(
                            text = "Change",
                            color = YoursColors.Primary,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(12.dp))

                    // Security info
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
                        Column {
                            Text(
                                text = authPreferences.getSecurityInfo(currentAuthMethod),
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.Primary
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Combined with device key for full security",
                                style = MaterialTheme.typography.labelSmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                    }
                }
            }

            // Authentication Method Selection Dialog
            if (showAuthMethodDialog) {
                AlertDialog(
                    onDismissRequest = { showAuthMethodDialog = false },
                    title = { Text("Choose Authentication Method") },
                    text = {
                        Column {
                            AuthPreferences.AuthMethod.entries.forEach { method ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            if (method == AuthPreferences.AuthMethod.CONSTELLATION && !authPreferences.isConstellationSetup) {
                                                // Need to set up constellation first
                                                showAuthMethodDialog = false
                                                showConstellationSetupDialog = true
                                            } else {
                                                currentAuthMethod = method
                                                authPreferences.authMethod = method
                                                showAuthMethodDialog = false
                                            }
                                        }
                                        .padding(vertical = 12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = authPreferences.getDisplayName(method),
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = if (method == currentAuthMethod)
                                                    YoursColors.Primary
                                                else
                                                    YoursColors.OnSurface,
                                                fontWeight = if (method == currentAuthMethod)
                                                    FontWeight.Bold
                                                else
                                                    FontWeight.Normal
                                            )
                                            if (method == AuthPreferences.AuthMethod.CONSTELLATION) {
                                                Spacer(modifier = Modifier.width(8.dp))
                                                Text(
                                                    text = if (authPreferences.isConstellationSetup) "[OK]" else "[Setup Required]",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = if (authPreferences.isConstellationSetup)
                                                        YoursColors.Success
                                                    else
                                                        YoursColors.Warning
                                                )
                                            }
                                        }
                                        Text(
                                            text = authPreferences.getDescription(method),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = YoursColors.OnBackgroundMuted
                                        )
                                        Text(
                                            text = authPreferences.getSecurityInfo(method),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = YoursColors.Primary.copy(alpha = 0.8f)
                                        )
                                    }
                                    if (method == currentAuthMethod) {
                                        Box(
                                            modifier = Modifier
                                                .size(8.dp)
                                                .clip(CircleShape)
                                                .background(YoursColors.Primary)
                                        )
                                    }
                                }
                                if (method != AuthPreferences.AuthMethod.entries.last()) {
                                    Divider(color = YoursColors.Background)
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { showAuthMethodDialog = false }) {
                            Text("Cancel")
                        }
                    },
                    containerColor = YoursColors.Background
                )
            }

            // Constellation Setup Dialog
            if (showConstellationSetupDialog) {
                AlertDialog(
                    onDismissRequest = { showConstellationSetupDialog = false },
                    title = {
                        Text(
                            text = "Enhanced Security Setup",
                            color = YoursColors.Primary
                        )
                    },
                    text = {
                        Column {
                            Text(
                                text = "Enhanced Security uses a constellation pattern with timing and pressure sensitivity for stronger authentication.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "Features:",
                                style = MaterialTheme.typography.labelMedium,
                                color = YoursColors.OnBackgroundMuted
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "- 7x5 constellation grid (35 stars)\n- Rhythm/timing detection\n- Pressure sensitivity (where supported)\n- ~61-80 bits of entropy",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnSurface
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "To set up Enhanced Security, you'll need to draw your constellation pattern. This will be used alongside your recovery passphrase.",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(
                            onClick = {
                                showConstellationSetupDialog = false
                                // For now, mark as set up for demo purposes
                                // In production, this would open a setup screen
                            }
                        ) {
                            Text("Set Up Now", color = YoursColors.Primary)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showConstellationSetupDialog = false }) {
                            Text("Later")
                        }
                    },
                    containerColor = YoursColors.Background
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // HARDWARE SECURITY
            // ================================================================
            SectionHeader("KEY PROTECTION")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    if (isHsmScanning) {
                        // Loading state
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = YoursColors.Primary,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(
                                text = "Detecting hardware security...",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                    } else {
                        // Security level indicator
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            // Status indicator dot
                            Box(
                                modifier = Modifier
                                    .size(12.dp)
                                    .clip(CircleShape)
                                    .background(
                                        when (securityStatus.securityIndicator) {
                                            SecurityIndicator.EXCELLENT -> YoursColors.Success
                                            SecurityIndicator.GOOD -> YoursColors.Primary
                                            SecurityIndicator.WARNING -> YoursColors.Warning
                                            SecurityIndicator.UNKNOWN -> YoursColors.OnBackgroundMuted
                                        }
                                    )
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = when (securityStatus.securityLevel) {
                                        SecurityLevel.STRONGBOX_BACKED -> "StrongBox Protected"
                                        SecurityLevel.TEE_BACKED -> "Hardware Protected"
                                        SecurityLevel.SOFTWARE_ONLY -> "Software Only"
                                        SecurityLevel.UNKNOWN -> "Unknown"
                                    },
                                    style = MaterialTheme.typography.titleSmall,
                                    color = YoursColors.OnSurface
                                )
                                Text(
                                    text = securityStatus.keyStorageDescription,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.OnBackgroundMuted
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))
                        Divider(color = YoursColors.Background)
                        Spacer(modifier = Modifier.height(12.dp))

                        // Capabilities list
                        HsmCapabilityRow(
                            label = "StrongBox (Secure Chip)",
                            isAvailable = securityStatus.hasStrongBox,
                            description = if (securityStatus.hasStrongBox)
                                "Dedicated tamper-resistant hardware"
                            else
                                "Not available on this device"
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        HsmCapabilityRow(
                            label = "Trusted Execution Environment",
                            isAvailable = securityStatus.hasTEE,
                            description = if (securityStatus.hasTEE)
                                "Hardware-isolated secure enclave"
                            else
                                "Not available on this device"
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        HsmCapabilityRow(
                            label = "Hardware Attestation",
                            isAvailable = securityStatus.isAttestationSupported,
                            description = if (securityStatus.isAttestationSupported)
                                "Can prove keys are hardware-bound"
                            else
                                "Requires TEE or StrongBox"
                        )

                        // Security warnings
                        if (securityStatus.securityWarnings.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Divider(color = YoursColors.Background)
                            Spacer(modifier = Modifier.height(12.dp))

                            securityStatus.securityWarnings.forEach { warning ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Text(
                                        text = "!",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = YoursColors.Warning,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.width(20.dp)
                                    )
                                    Text(
                                        text = warning,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = YoursColors.Warning
                                    )
                                }
                            }
                        }

                        // Additional info for hardware-backed devices
                        if (securityStatus.securityLevel == SecurityLevel.STRONGBOX_BACKED ||
                            securityStatus.securityLevel == SecurityLevel.TEE_BACKED) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Divider(color = YoursColors.Background)
                            Spacer(modifier = Modifier.height(12.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.Top
                            ) {
                                Text(
                                    text = "i",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = YoursColors.Primary,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier
                                        .width(20.dp)
                                        .padding(top = 2.dp)
                                )
                                Text(
                                    text = if (securityStatus.securityLevel == SecurityLevel.STRONGBOX_BACKED)
                                        "Your private keys never leave the secure chip. Even if your device is compromised, keys cannot be extracted."
                                    else
                                        "Your private keys are stored in a hardware-isolated environment. They are protected from most software attacks.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = YoursColors.Primary
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // PANIC WIPE
            // ================================================================
            SectionHeader("EMERGENCY")

            // Shake detection state
            var shakeDetectionEnabled by remember { mutableStateOf(opsecManager.shakeDetectionEnabled.value) }
            var shakeSensitivity by remember { mutableStateOf(opsecManager.shakeSensitivity.value) }
            var showSensitivityPicker by remember { mutableStateOf(false) }

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Shake Detection Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Shake to Wipe",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = YoursColors.OnSurface
                                )
                                if (shakeDetectionEnabled && opsecManager.isShakeDetectionActive.value) {
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .clip(CircleShape)
                                            .background(YoursColors.Success)
                                    )
                                }
                            }
                            Text(
                                text = if (shakeDetectionEnabled)
                                    "Active - ${shakeSensitivity.displayName}"
                                else
                                    "Shake device rapidly to trigger panic wipe",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                        Switch(
                            checked = shakeDetectionEnabled,
                            onCheckedChange = { newValue ->
                                val gateResult = securityGateResult
                                if (gateResult is SecurityGate.GateResult.Blocked) {
                                    blockedOperationName = "Change Shake Detection"
                                    showSecurityBlockedDialog = true
                                } else {
                                    shakeDetectionEnabled = newValue
                                    opsecManager.setShakeDetectionEnabled(newValue)
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = YoursColors.Error,
                                checkedTrackColor = YoursColors.Error.copy(alpha = 0.5f)
                            )
                        )
                    }

                    // Sensitivity selector (only shown when enabled)
                    AnimatedVisibility(visible = shakeDetectionEnabled) {
                        Column {
                            Spacer(modifier = Modifier.height(12.dp))

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { showSensitivityPicker = true }
                                    .padding(vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(
                                        text = "Shake Sensitivity",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = YoursColors.OnSurface
                                    )
                                    Text(
                                        text = shakeSensitivity.displayName,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = YoursColors.OnBackgroundMuted
                                    )
                                }
                                Text(
                                    text = "Change",
                                    color = YoursColors.Primary,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(16.dp))

                    // Duress passphrase
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                // SECURITY GATE: Duress passphrase requires SENSITIVE level
                                // This prevents setting duress phrase on compromised devices where:
                                // - Keyloggers could capture the duress phrase
                                // - The duress protection could be circumvented
                                val gateResult = securityGateResult
                                if (gateResult is SecurityGate.GateResult.Blocked) {
                                    blockedOperationName = "Configure Duress Passphrase"
                                    showSecurityBlockedDialog = true
                                } else {
                                    showDuressDialog = true
                                }
                            }
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "Duress Passphrase",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                            Text(
                                text = if (duressPassphrase.isNotEmpty()) "Set (tap to change)"
                                else "Not set (tap to configure)",
                                style = MaterialTheme.typography.bodySmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                        }
                        Text(
                            text = "Configure",
                            color = YoursColors.Primary,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "If duress passphrase is entered at unlock, wipes everything instantly",
                        style = MaterialTheme.typography.labelSmall,
                        color = YoursColors.Warning
                    )
                }
            }

            // Shake Sensitivity Picker Dialog
            if (showSensitivityPicker) {
                AlertDialog(
                    onDismissRequest = { showSensitivityPicker = false },
                    title = { Text("Shake Sensitivity") },
                    text = {
                        Column {
                            Text(
                                text = "Choose how sensitive shake detection should be:",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnBackgroundMuted
                            )
                            Spacer(modifier = Modifier.height(16.dp))

                            OpsecManager.ShakeSensitivity.entries.forEach { sensitivity ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            shakeSensitivity = sensitivity
                                            opsecManager.setShakeSensitivity(sensitivity)
                                            showSensitivityPicker = false
                                        }
                                        .padding(vertical = 12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = sensitivity.name,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = if (sensitivity == shakeSensitivity)
                                                YoursColors.Primary
                                            else
                                                YoursColors.OnSurface,
                                            fontWeight = if (sensitivity == shakeSensitivity)
                                                FontWeight.Bold
                                            else
                                                FontWeight.Normal
                                        )
                                        Text(
                                            text = sensitivity.displayName,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = YoursColors.OnBackgroundMuted
                                        )
                                    }
                                    if (sensitivity == shakeSensitivity) {
                                        Box(
                                            modifier = Modifier
                                                .size(8.dp)
                                                .clip(CircleShape)
                                                .background(YoursColors.Primary)
                                        )
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "Higher sensitivity triggers easier in emergencies but may cause accidental wipes.",
                                style = MaterialTheme.typography.labelSmall,
                                color = YoursColors.Warning
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { showSensitivityPicker = false }) {
                            Text("Cancel")
                        }
                    },
                    containerColor = YoursColors.Background
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // IDENTITY
            // ================================================================
            SectionHeader("IDENTITY")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Text(
                        text = "Device-Bound",
                        style = MaterialTheme.typography.titleSmall,
                        color = YoursColors.OnSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Your identity exists only on this device. Lose the device, lose the identity. There is no recovery.",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // CRYPTOGRAPHY
            // ================================================================
            SectionHeader("CRYPTOGRAPHY")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Core cryptographic primitives
                    CryptoRow("Key Exchange", "ML-KEM-768 (Kyber)", "NIST PQC Standard")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Signatures", "Ed25519 (fiat)", "Constant-time")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Encryption", "AES-256-GCM", "Authenticated")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Key Derivation", "Argon2id", "Memory-hard")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Hashing", "SHA3-256", "Keccak")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Key Zeroization", "Automatic", "Secrets cleared on drop")

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "Mesh Protocol (LunarCore)",
                        style = MaterialTheme.typography.labelMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Anonymous Auth", "BBS+ Signatures", "Zero-knowledge proofs")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Rate Limiting", "Epoch tokens", "Sybil-resistant")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Key Encapsulation", "Hk-OVCT", "Hedged KEM (RNG-safe)")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Session Keys", "Double Ratchet", "Forward secrecy")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Onion Routing", "AES-256-GCM circuits", "3+ hops, layered encryption")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Onion Fallback", "ChaCha20-Poly1305", "Per-message onion layers")
                    Spacer(modifier = Modifier.height(8.dp))
                    CryptoRow("Node/Session IDs", "32/64-bit hints", "Birthday-resistant")
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ================================================================
            // ABOUT
            // ================================================================
            SectionHeader("ABOUT")

            Card(
                colors = CardDefaults.cardColors(containerColor = YoursColors.Background),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Yours",
                        style = MaterialTheme.typography.titleMedium,
                        color = YoursColors.OnSurface
                    )
                    Text(
                        text = "Self-sovereign identity & off-grid communication",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                text = "Version",
                                style = MaterialTheme.typography.labelSmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                            Text(
                                text = "0.2.0",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text(
                                text = "Protocol",
                                style = MaterialTheme.typography.labelSmall,
                                color = YoursColors.OnBackgroundMuted
                            )
                            Text(
                                text = "LunarCore v1",
                                style = MaterialTheme.typography.bodyMedium,
                                color = YoursColors.OnSurface
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Divider(color = YoursColors.Background)
                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "Your keys. Your data. Your network.",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.Primary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Built by [stc]",
                        style = MaterialTheme.typography.labelSmall,
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }

            Spacer(modifier = Modifier.height(32.dp))
        }

        // Frosted glass header overlay
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .zIndex(1f)
                .background(YoursColors.Background.copy(alpha = if (isScrolled) 0.95f else 1f))
        ) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onClose) {
                    Icon(
                        imageVector = Icons.Default.ArrowBack,
                        contentDescription = "Back",
                        tint = YoursColors.OnBackground
                    )
                }

                Text(
                    text = "Settings",
                    style = MaterialTheme.typography.titleLarge,
                    color = YoursColors.OnBackground
                )

                Spacer(modifier = Modifier.size(48.dp))
            }
        }
    }

    // Duress passphrase dialog
    if (showDuressDialog) {
        var newDuress by remember { mutableStateOf(duressPassphrase) }

        AlertDialog(
            onDismissRequest = { showDuressDialog = false },
            title = { Text("Duress Passphrase") },
            text = {
                Column {
                    Text(
                        text = "If this phrase is entered at unlock, ALL DATA will be wiped immediately.",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = newDuress,
                        onValueChange = { newDuress = it },
                        label = { Text("Duress phrase") },
                        placeholder = { Text("e.g. help or clear") },
                        singleLine = true
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        opsecManager.duressPassphrase = newDuress.ifBlank { null }
                        duressPassphrase = newDuress
                        showDuressDialog = false
                    }
                ) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDuressDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Security blocked dialog for sensitive operations
    if (showSecurityBlockedDialog) {
        val blocked = securityGateResult as? SecurityGate.GateResult.Blocked
        if (blocked != null) {
            SecurityBlockedDialog(
                operationName = blockedOperationName,
                reason = blocked.reason,
                threats = blocked.threats,
                recommendation = blocked.recommendation,
                onDismiss = { showSecurityBlockedDialog = false }
            )
        }
    }

    // TCP Relay connection dialog
    if (showTcpRelayDialog) {
        AlertDialog(
            onDismissRequest = { showTcpRelayDialog = false },
            title = { Text("TCP Relay Connection") },
            text = {
                Column {
                    Text(
                        text = "Connect to a MeshCore relay server. This allows you to use the mesh network over WiFi/internet when no local device is available.",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = tcpHost,
                        onValueChange = { tcpHost = it },
                        label = { Text("Host") },
                        placeholder = { Text("e.g., relay.meshcore.io") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = tcpPort,
                        onValueChange = { tcpPort = it.filter { c -> c.isDigit() } },
                        label = { Text("Port") },
                        placeholder = { Text("4000") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showTcpRelayDialog = false
                        scope.launch {
                            isConnecting = true
                            connectionStatusMessage = "Connecting to $tcpHost:$tcpPort..."
                            val port = tcpPort.toIntOrNull() ?: 4000
                            val result = manager.connect(
                                MeshConnection.Tcp(tcpHost, port)
                            )
                            if (result.isFailure) {
                                connectionStatusMessage = "Failed: ${result.exceptionOrNull()?.message}"
                            }
                            isConnecting = false
                        }
                    },
                    enabled = tcpHost.isNotBlank()
                ) {
                    Text("Connect")
                }
            },
            dismissButton = {
                TextButton(onClick = { showTcpRelayDialog = false }) {
                    Text("Cancel")
                }
            }
        )
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
        // Partial underline - just the beginning
        Box(
            modifier = Modifier
                .width(24.dp)
                .height(2.dp)
                .background(YoursColors.Primary.copy(alpha = 0.7f))
        )
    }
}

@Composable
private fun LunarFeatureRow(
    label: String,
    isExpanded: Boolean,
    onClick: () -> Unit,
    description: String
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnSurface
            )
            Text(
                text = if (isExpanded) "−" else "+",
                style = MaterialTheme.typography.titleMedium,
                color = YoursColors.OnBackgroundMuted
            )
        }

        AnimatedVisibility(visible = isExpanded) {
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
    }
}

@Composable
private fun CryptoRow(
    category: String,
    algorithm: String,
    note: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = category,
            style = MaterialTheme.typography.bodySmall,
            color = YoursColors.OnBackgroundMuted,
            modifier = Modifier.width(100.dp)
        )
        Column(
            modifier = Modifier.weight(1f),
            horizontalAlignment = Alignment.End
        ) {
            Text(
                text = algorithm,
                style = MaterialTheme.typography.bodyMedium,
                color = YoursColors.OnSurface
            )
            Text(
                text = note,
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.Success
            )
        }
    }
}

/**
 * Row displaying a hardware security capability with availability status.
 */
@Composable
private fun HsmCapabilityRow(
    label: String,
    isAvailable: Boolean,
    description: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (isAvailable) "[OK]" else "[--]",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isAvailable) YoursColors.Success else YoursColors.OnBackgroundMuted,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.width(36.dp)
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (isAvailable) YoursColors.OnSurface else YoursColors.OnBackgroundMuted
                )
            }
            Text(
                text = description,
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.OnBackgroundMuted,
                modifier = Modifier.padding(start = 36.dp)
            )
        }
    }
}
