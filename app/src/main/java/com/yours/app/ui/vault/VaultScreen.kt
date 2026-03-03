package com.yours.app.ui.vault

import android.graphics.BitmapFactory
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.text.font.FontWeight
import com.yours.app.security.OpsecManager
import com.yours.app.security.SecurityGate
import com.yours.app.security.checkSecurityGate
import com.yours.app.ui.components.SecurityBlockedDialog
import com.yours.app.ui.theme.GluspFontFamily
import com.yours.app.ui.theme.YoursColors
import com.yours.app.vault.VaultStorage
import kotlinx.coroutines.flow.Flow
import kotlin.math.roundToInt

/**
 * The Vault - Your stuff, your people.
 * 
 * This is the main screen. Everything you own is here.
 * Everyone you trust is here.
 */

data class VaultState(
    val userName: String = "",
    val artifacts: List<ArtifactItem> = emptyList(),
    val contacts: List<ContactItem> = emptyList(),
    val isLoading: Boolean = false
)

data class ArtifactItem(
    val id: String,
    val contentType: String,
    val name: String?,
    val createdAt: Long,
    val thumbnailBytes: ByteArray? = null
)

data class ContactItem(
    val id: String,
    val petname: String,
    val initial: String
)

@Composable
fun VaultScreen(
    state: VaultState,
    onOpenCamera: () -> Unit,
    onImportFile: () -> Unit,
    onOpenArtifact: (String) -> Unit,
    onAddContact: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenMessaging: () -> Unit,
    onOpenSovereignty: () -> Unit,
    onTransfer: (artifactId: String, contactId: String) -> Unit
) {
    val context = LocalContext.current
    var draggedArtifact by remember { mutableStateOf<String?>(null) }
    var dragOffset by remember { mutableStateOf(Offset.Zero) }
    var targetContact by remember { mutableStateOf<String?>(null) }

    // OPSEC Manager for travel mode state
    val opsecManager = remember { OpsecManager(context) }
    val travelModeEnabled by opsecManager.travelModeEnabled.collectAsState()

    // SECURITY GATE: State for blocking transfer operations
    var securityGateResult by remember { mutableStateOf<SecurityGate.GateResult?>(null) }
    var showSecurityBlockedDialog by remember { mutableStateOf(false) }
    var pendingTransfer by remember { mutableStateOf<Pair<String, String>?>(null) }

    // Perform initial security check for SENSITIVE level operations (transfers)
    LaunchedEffect(Unit) {
        securityGateResult = context.checkSecurityGate(SecurityGate.SecurityLevel.SENSITIVE)
    }

    // Security-gated transfer function (also blocked in travel mode)
    val secureTransfer: (String, String) -> Unit = { artifactId, contactId ->
        if (travelModeEnabled) {
            // Transfers are blocked in travel mode - silently ignore
            // (Contacts are hidden anyway, so this shouldn't normally trigger)
        } else {
            val gateResult = securityGateResult
            if (gateResult is SecurityGate.GateResult.Blocked) {
                // Store pending transfer and show blocked dialog
                pendingTransfer = artifactId to contactId
                showSecurityBlockedDialog = true
            } else {
                // Security check passed, proceed with transfer
                onTransfer(artifactId, contactId)
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        Column(
            modifier = Modifier.fillMaxSize()
        ) {
            // Header with travel mode indicator
            VaultHeader(
                userName = state.userName,
                isTravelMode = travelModeEnabled,
                onSettingsClick = onOpenSettings,
                onMessagingClick = onOpenMessaging,
                onSovereigntyClick = onOpenSovereignty
            )

            // Content area
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                if (state.artifacts.isEmpty()) {
                    // Empty state - show read-only message in travel mode
                    if (travelModeEnabled) {
                        TravelModeEmptyVault()
                    } else {
                        EmptyVault(
                            onOpenCamera = onOpenCamera,
                            onImportFile = onImportFile
                        )
                    }
                } else {
                    // Artifact grid - read-only in travel mode
                    ArtifactGrid(
                        artifacts = state.artifacts,
                        onOpenArtifact = onOpenArtifact,
                        onStartDrag = { id ->
                            // Disable drag in travel mode
                            if (!travelModeEnabled) {
                                draggedArtifact = id
                            }
                        },
                        onDrag = { offset -> dragOffset = offset },
                        onEndDrag = {
                            if (draggedArtifact != null && targetContact != null) {
                                // SECURITY GATE: Use security-gated transfer
                                secureTransfer(draggedArtifact!!, targetContact!!)
                            }
                            draggedArtifact = null
                            dragOffset = Offset.Zero
                            targetContact = null
                        },
                        // Disable camera and import in travel mode
                        onOpenCamera = if (travelModeEnabled) null else onOpenCamera,
                        onImportFile = if (travelModeEnabled) null else onImportFile,
                        isTravelMode = travelModeEnabled
                    )
                }
            }

            // People bar - hidden in travel mode
            AnimatedVisibility(
                visible = !travelModeEnabled,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
            ) {
                PeopleBar(
                    contacts = state.contacts,
                    onAddContact = onAddContact
                )
            }
        }

        // Drag overlay
        if (draggedArtifact != null) {
            DragOverlay(
                offset = dragOffset,
                artifact = state.artifacts.find { it.id == draggedArtifact }
            )
        }
    }

    // Security blocked dialog for transfer operations
    if (showSecurityBlockedDialog) {
        val blocked = securityGateResult as? SecurityGate.GateResult.Blocked
        if (blocked != null) {
            SecurityBlockedDialog(
                operationName = "Transfer Artifact",
                reason = blocked.reason,
                threats = blocked.threats,
                recommendation = blocked.recommendation,
                onDismiss = {
                    showSecurityBlockedDialog = false
                    pendingTransfer = null
                }
            )
        }
    }
}

@Composable
private fun VaultHeader(
    userName: String,
    isTravelMode: Boolean,
    onSettingsClick: () -> Unit,
    onMessagingClick: () -> Unit,
    onSovereigntyClick: () -> Unit,
    loraConnected: Boolean = false,
    loraLocation: String? = null
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        // Travel Mode Banner
        AnimatedVisibility(
            visible = isTravelMode,
            enter = slideInVertically() + fadeIn(),
            exit = slideOutVertically() + fadeOut()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(YoursColors.Warning.copy(alpha = 0.15f))
                    .clickable { onSettingsClick() }
                    .padding(horizontal = 20.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(YoursColors.Warning)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "TRAVEL MODE ACTIVE",
                    style = MaterialTheme.typography.labelMedium,
                    color = YoursColors.Warning,
                    letterSpacing = 1.5.sp
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "- Tap to disable",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.Warning.copy(alpha = 0.7f)
                )
            }
        }

        // Main header row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            // Left side - Brand mark with [ YOURS ] tag
            Column {
                // [ YOURS ] brand tag
                Text(
                    text = "[ YOURS ]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = GluspFontFamily
                    ),
                    color = YoursColors.Primary,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 2.sp
                )

                Spacer(modifier = Modifier.height(2.dp))

                // User name
                Text(
                    text = userName.uppercase(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = if (isTravelMode) YoursColors.OnBackground.copy(alpha = 0.7f) else YoursColors.OnBackground,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 3.sp
                )

                // Location / LoRa status
                Text(
                    text = if (loraConnected && loraLocation != null) loraLocation else "-- / ---.----°",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.OnBackgroundMuted,
                    letterSpacing = 2.sp
                )

                if (isTravelMode) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Box(
                        modifier = Modifier
                            .background(
                                YoursColors.Warning.copy(alpha = 0.2f),
                                RoundedCornerShape(0.dp)
                            )
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "LIMITED",
                            style = MaterialTheme.typography.labelSmall,
                            color = YoursColors.Warning,
                            letterSpacing = 1.sp
                        )
                    }
                }
            }

            // Right side - Icon buttons with proper spacing
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Messaging button
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .border(1.dp, YoursColors.GrayDim, RoundedCornerShape(0.dp))
                        .clickable(enabled = !isTravelMode) { onMessagingClick() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Email,
                        contentDescription = "Messages",
                        tint = if (isTravelMode)
                            YoursColors.Gray.copy(alpha = 0.3f)
                        else
                            YoursColors.Gray,
                        modifier = Modifier.size(20.dp)
                    )
                }

                // Shield button
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .border(1.dp, YoursColors.GrayDim, RoundedCornerShape(0.dp))
                        .clickable { onSovereigntyClick() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Shield,
                        contentDescription = "Device Sovereignty",
                        tint = YoursColors.Gray,
                        modifier = Modifier.size(20.dp)
                    )
                }

                // Settings button
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .border(1.dp, YoursColors.GrayDim, RoundedCornerShape(0.dp))
                        .clickable { onSettingsClick() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Settings,
                        contentDescription = "Settings",
                        tint = if (isTravelMode) YoursColors.Warning else YoursColors.Gray,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}

// Neon glow modifier - border glow only, not filled
private fun Modifier.neonBorder(
    color: Color
) = this
    .drawBehind {
        // Draw multiple blurred border strokes for glow effect
        val glowLayers = listOf(40f to 0.15f, 20f to 0.3f, 10f to 0.5f)

        for ((blur, alpha) in glowLayers) {
            drawIntoCanvas { canvas ->
                val frameworkCanvas = canvas.nativeCanvas
                val paint = android.graphics.Paint().apply {
                    this.color = color.copy(alpha = alpha).toArgb()
                    this.style = android.graphics.Paint.Style.STROKE
                    this.strokeWidth = blur
                    this.maskFilter = android.graphics.BlurMaskFilter(
                        blur,
                        android.graphics.BlurMaskFilter.Blur.NORMAL
                    )
                }
                frameworkCanvas.drawRect(
                    0f, 0f, size.width, size.height, paint
                )
            }
        }
    }

@Composable
private fun EmptyVault(
    onOpenCamera: () -> Unit,
    onImportFile: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Neon glow empty card
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1.4f)
                .neonBorder(YoursColors.Primary)
                .border(2.dp, YoursColors.Primary, RoundedCornerShape(0.dp))
                .clickable { onImportFile() },
            contentAlignment = Alignment.Center
        ) {
            // Inner border
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(4.dp)
                    .border(1.dp, YoursColors.PrimaryDim, RoundedCornerShape(0.dp))
            )

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                // [ YOURS ] brand tag
                Text(
                    text = "[ YOURS ]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = GluspFontFamily
                    ),
                    color = YoursColors.Primary,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "DROP SOMETHING",
                    style = MaterialTheme.typography.headlineSmall,
                    color = YoursColors.OnBackground,
                    fontWeight = FontWeight.Medium,
                    letterSpacing = 2.sp,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = "to make it yours",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnBackgroundMuted,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Katakana hint
                Text(
                    text = "ヴォールト",
                    style = MaterialTheme.typography.labelSmall,
                    color = YoursColors.PrimaryDim,
                    letterSpacing = 3.sp,
                    fontSize = 10.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Capture button
            OutlinedButton(
                onClick = onOpenCamera,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = YoursColors.Primary
                ),
                border = BorderStroke(1.dp, YoursColors.PrimaryDim),
                shape = RoundedCornerShape(0.dp)
            ) {
                Text(
                    text = "[ CAPTURE ]",
                    letterSpacing = 0.5.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // Import button
            OutlinedButton(
                onClick = onImportFile,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = YoursColors.Primary
                ),
                border = BorderStroke(1.dp, YoursColors.PrimaryDim),
                shape = RoundedCornerShape(0.dp)
            ) {
                Text(
                    text = "[ + IMPORT ]",
                    letterSpacing = 0.5.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

/**
 * Empty vault display for travel mode - read-only message.
 */
@Composable
private fun TravelModeEmptyVault() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1.4f)
                .border(2.dp, YoursColors.Warning.copy(alpha = 0.3f), RoundedCornerShape(0.dp)),
            contentAlignment = Alignment.Center
        ) {
            // Inner border
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(4.dp)
                    .border(1.dp, YoursColors.Warning.copy(alpha = 0.15f), RoundedCornerShape(0.dp))
            )

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "[ YOURS ]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = GluspFontFamily
                    ),
                    color = YoursColors.Warning.copy(alpha = 0.5f),
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "VAULT EMPTY",
                    style = MaterialTheme.typography.headlineSmall,
                    color = YoursColors.OnBackgroundMuted,
                    fontWeight = FontWeight.Medium,
                    letterSpacing = 2.sp,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Travel Mode active - read only",
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.Warning.copy(alpha = 0.7f),
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
private fun ArtifactGrid(
    artifacts: List<ArtifactItem>,
    onOpenArtifact: (String) -> Unit,
    onStartDrag: (String) -> Unit,
    onDrag: (Offset) -> Unit,
    onEndDrag: () -> Unit,
    onOpenCamera: (() -> Unit)?,
    onImportFile: (() -> Unit)?,
    isTravelMode: Boolean = false
) {
    LazyVerticalGrid(
        columns = GridCells.Fixed(3),
        contentPadding = PaddingValues(12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(artifacts) { artifact ->
            ArtifactTile(
                artifact = artifact,
                onClick = { onOpenArtifact(artifact.id) },
                onStartDrag = { onStartDrag(artifact.id) },
                onDrag = onDrag,
                onEndDrag = onEndDrag
            )
        }

        // Add buttons - only shown when not in travel mode
        if (!isTravelMode && onOpenCamera != null) {
            item {
                AddTile(
                    icon = Icons.Outlined.PhotoCamera,
                    label = "Capture",
                    onClick = onOpenCamera
                )
            }
        }

        if (!isTravelMode && onImportFile != null) {
            item {
                AddTile(
                    icon = Icons.Outlined.Add,
                    label = "Import",
                    onClick = onImportFile
                )
            }
        }
    }
}

@Composable
private fun ArtifactTile(
    artifact: ArtifactItem,
    onClick: () -> Unit,
    onStartDrag: () -> Unit,
    onDrag: (Offset) -> Unit,
    onEndDrag: () -> Unit
) {
    var isDragging by remember { mutableStateOf(false) }
    
    Card(
        modifier = Modifier
            .aspectRatio(1f)
            .pointerInput(artifact.id) {
                detectDragGestures(
                    onDragStart = {
                        isDragging = true
                        onStartDrag()
                    },
                    onDragEnd = {
                        isDragging = false
                        onEndDrag()
                    },
                    onDragCancel = {
                        isDragging = false
                        onEndDrag()
                    },
                    onDrag = { change, _ ->
                        change.consume()
                        onDrag(change.position)
                    }
                )
            }
            .clickable(enabled = !isDragging) { onClick() },
        colors = CardDefaults.cardColors(
            containerColor = if (isDragging)
                YoursColors.Surface.copy(alpha = 0.5f)
            else
                YoursColors.Surface
        ),
        shape = RoundedCornerShape(0.dp)
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            when {
                artifact.thumbnailBytes != null -> {
                    val bitmap = remember(artifact.thumbnailBytes) {
                        BitmapFactory.decodeByteArray(
                            artifact.thumbnailBytes,
                            0,
                            artifact.thumbnailBytes.size
                        )?.asImageBitmap()
                    }

                    bitmap?.let {
                        Image(
                            bitmap = it,
                            contentDescription = artifact.name,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Crop
                        )
                    }
                }
                artifact.contentType.startsWith("image/") -> {
                    Text(
                        text = "🖼️",
                        style = MaterialTheme.typography.headlineLarge
                    )
                }
                artifact.contentType == "application/pdf" -> {
                    Text(
                        text = "📄",
                        style = MaterialTheme.typography.headlineLarge
                    )
                }
                else -> {
                    Text(
                        text = "📁",
                        style = MaterialTheme.typography.headlineLarge
                    )
                }
            }

            // Name overlay
            artifact.name?.let { name ->
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .background(Color.Black.copy(alpha = 0.6f))
                        .padding(4.dp)
                ) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.labelSmall,
                        color = Color.White,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = TextAlign.Center
                    )
                }
            }
        }
    }
}

@Composable
private fun AddTile(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .aspectRatio(1f)
            .clickable { onClick() },
        colors = CardDefaults.cardColors(
            containerColor = YoursColors.SurfaceVariant.copy(alpha = 0.5f)
        ),
        shape = RoundedCornerShape(0.dp),
        border = BorderStroke(
            width = 1.dp,
            color = YoursColors.GrayDim
        )
    ) {
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = YoursColors.Gray,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "[$label]".uppercase(),
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.Gray,
                letterSpacing = 0.5.sp
            )
        }
    }
}

@Composable
private fun PeopleBar(
    contacts: List<ContactItem>,
    onAddContact: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = YoursColors.SurfaceVariant
    ) {
        Column {
            // Top border
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(YoursColors.GrayDim)
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (contacts.isEmpty()) {
                    Text(
                        text = "No one here yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = YoursColors.Gray,
                        modifier = Modifier.weight(1f)
                    )
                } else {
                    contacts.forEach { contact ->
                        ContactBubble(contact = contact)
                    }

                    Spacer(modifier = Modifier.weight(1f))
                }

                // Add contact button - square with dashed border style
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .border(
                            width = 1.dp,
                            color = YoursColors.GrayDim,
                            shape = RoundedCornerShape(0.dp)
                        )
                        .clickable { onAddContact() },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "+",
                        color = YoursColors.Gray,
                        fontSize = 18.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun ContactBubble(
    contact: ContactItem
) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .background(YoursColors.Primary),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = contact.initial,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold,
            color = YoursColors.OnPrimary
        )
        // Online status indicator
        Box(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .offset(x = 2.dp, y = 2.dp)
                .size(10.dp)
                .background(YoursColors.Success)
                .border(2.dp, YoursColors.SurfaceVariant, RoundedCornerShape(0.dp))
        )
    }
}

@Composable
private fun DragOverlay(
    offset: Offset,
    artifact: ArtifactItem?
) {
    if (artifact == null) return

    Box(
        modifier = Modifier
            .offset { IntOffset(offset.x.roundToInt(), offset.y.roundToInt()) }
            .size(80.dp)
            .background(YoursColors.Primary.copy(alpha = 0.8f)),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = when {
                artifact.contentType.startsWith("image/") -> "🖼️"
                artifact.contentType == "application/pdf" -> "📄"
                else -> "📁"
            },
            style = MaterialTheme.typography.headlineMedium
        )
    }
}
