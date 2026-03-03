package com.yours.app.ui.vault

import android.graphics.BitmapFactory
import androidx.compose.animation.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.yours.app.crypto.BedrockCore
import com.yours.app.security.SecurityGate
import com.yours.app.security.checkSecurityGate
import com.yours.app.ui.components.SecurityBlockedDialog
import com.yours.app.ui.theme.YoursColors
import com.yours.app.vault.Artifact
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

/**
 * Artifact Viewer Screen - View decrypted photos/files.
 *
 * Security:
 * - Decrypts in-memory only
 * - Never caches plaintext to disk
 * - Zeroizes on close
 */

sealed class ViewerState {
    object Loading : ViewerState()
    data class Ready(val decryptedBytes: ByteArray) : ViewerState()
    data class Error(val message: String) : ViewerState()
}

@Composable
fun ArtifactViewerScreen(
    artifact: Artifact,
    ownerSecretKey: ByteArray,
    onClose: () -> Unit,
    onDelete: () -> Unit,
    onRename: (String) -> Unit,
    onShare: () -> Unit
) {
    val context = LocalContext.current
    var viewerState by remember { mutableStateOf<ViewerState>(ViewerState.Loading) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var showRenameDialog by remember { mutableStateOf(false) }
    var showMetadata by remember { mutableStateOf(false) }

    // SECURITY GATE: State for blocking sensitive operations
    var securityGateResult by remember { mutableStateOf<SecurityGate.GateResult?>(null) }
    var showSecurityBlockedDialog by remember { mutableStateOf(false) }
    var blockedOperationName by remember { mutableStateOf("") }

    // Perform initial security check for SENSITIVE level operations
    LaunchedEffect(Unit) {
        securityGateResult = context.checkSecurityGate(SecurityGate.SecurityLevel.SENSITIVE)
    }

    // Security-gated share function
    val secureShare: () -> Unit = {
        val gateResult = securityGateResult
        if (gateResult is SecurityGate.GateResult.Blocked) {
            blockedOperationName = "Share Artifact"
            showSecurityBlockedDialog = true
        } else {
            onShare()
        }
    }

    // Security-gated delete function (still shows confirmation dialog first)
    val secureDeleteConfirm: () -> Unit = {
        val gateResult = securityGateResult
        if (gateResult is SecurityGate.GateResult.Blocked) {
            blockedOperationName = "Delete Artifact"
            showSecurityBlockedDialog = true
        } else {
            showDeleteConfirm = true
        }
    }

    // Pinch-to-zoom state
    var scale by remember { mutableStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }

    // Decrypt artifact on load
    LaunchedEffect(artifact.id) {
        viewerState = withContext(Dispatchers.Default) {
            try {
                val decrypted = artifact.decrypt(ownerSecretKey)
                if (decrypted != null) {
                    ViewerState.Ready(decrypted)
                } else {
                    ViewerState.Error("Failed to decrypt")
                }
            } catch (e: Exception) {
                ViewerState.Error(e.message ?: "Unknown error")
            }
        }
    }

    // Cleanup on dispose
    DisposableEffect(Unit) {
        onDispose {
            // Zeroize decrypted content
            (viewerState as? ViewerState.Ready)?.decryptedBytes?.let {
                BedrockCore.zeroize(it)
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
    ) {
        when (val state = viewerState) {
            ViewerState.Loading -> {
                CircularProgressIndicator(
                    modifier = Modifier.align(Alignment.Center),
                    color = YoursColors.Primary
                )
            }

            is ViewerState.Ready -> {
                // Render based on content type
                if (artifact.contentType.startsWith("image/")) {
                    val bitmap = remember(state.decryptedBytes) {
                        BitmapFactory.decodeByteArray(
                            state.decryptedBytes,
                            0,
                            state.decryptedBytes.size
                        )
                    }

                    bitmap?.let {
                        Image(
                            bitmap = it.asImageBitmap(),
                            contentDescription = artifact.metadata.name ?: "Artifact",
                            modifier = Modifier
                                .fillMaxSize()
                                .graphicsLayer(
                                    scaleX = scale,
                                    scaleY = scale,
                                    translationX = offset.x,
                                    translationY = offset.y
                                )
                                .pointerInput(Unit) {
                                    detectTransformGestures { _, pan, zoom, _ ->
                                        scale = (scale * zoom).coerceIn(0.5f, 5f)
                                        offset = Offset(
                                            x = offset.x + pan.x,
                                            y = offset.y + pan.y
                                        )
                                    }
                                },
                            contentScale = ContentScale.Fit
                        )
                    }
                } else {
                    // Non-image file
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = getFileEmoji(artifact.contentType),
                            style = MaterialTheme.typography.displayLarge
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        Text(
                            text = artifact.metadata.name ?: "Unnamed file",
                            style = MaterialTheme.typography.headlineSmall,
                            color = YoursColors.OnBackground,
                            textAlign = TextAlign.Center
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = artifact.contentType,
                            style = MaterialTheme.typography.bodyMedium,
                            color = YoursColors.OnBackgroundMuted
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = formatFileSize(state.decryptedBytes.size),
                            style = MaterialTheme.typography.bodyMedium,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                }
            }

            is ViewerState.Error -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "Cannot view this artifact",
                        style = MaterialTheme.typography.headlineSmall,
                        color = YoursColors.Error
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = YoursColors.OnBackgroundMuted,
                        textAlign = TextAlign.Center
                    )
                }
            }
        }

        // Top bar with close button
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .align(Alignment.TopCenter),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onClose,
                modifier = Modifier
                    .size(48.dp)
                    .background(Color.Black.copy(alpha = 0.5f), CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Close",
                    tint = Color.White
                )
            }

            // Info button
            IconButton(
                onClick = { showMetadata = !showMetadata },
                modifier = Modifier
                    .size(48.dp)
                    .background(Color.Black.copy(alpha = 0.5f), CircleShape)
            ) {
                Text(
                    text = "i",
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White
                )
            }
        }

        // Metadata overlay
        AnimatedVisibility(
            visible = showMetadata,
            enter = fadeIn() + slideInVertically(),
            exit = fadeOut() + slideOutVertically(),
            modifier = Modifier.align(Alignment.TopCenter)
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 80.dp, start = 16.dp, end = 16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = YoursColors.Surface.copy(alpha = 0.95f)
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = artifact.metadata.name ?: "Unnamed",
                        style = MaterialTheme.typography.titleMedium,
                        color = YoursColors.OnSurface
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    MetadataRow("Type", artifact.contentType)
                    MetadataRow("Created", formatDate(artifact.createdAt))
                    MetadataRow("Origin", if (artifact.ownerDid == null) "You" else "Received")

                    artifact.metadata.description?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = YoursColors.OnBackgroundMuted
                        )
                    }
                }
            }
        }

        // Bottom action bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .align(Alignment.BottomCenter),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            // Share - SECURITY GATED (requires SENSITIVE level)
            ActionButton(
                icon = { Icon(Icons.Default.Share, "Share", tint = Color.White) },
                label = "Send",
                onClick = secureShare
            )

            // Rename
            ActionButton(
                icon = { Icon(Icons.Default.Edit, "Rename", tint = Color.White) },
                label = "Rename",
                onClick = { showRenameDialog = true }
            )

            // Delete - SECURITY GATED (requires SENSITIVE level)
            ActionButton(
                icon = { Icon(Icons.Default.Delete, "Delete", tint = YoursColors.Error) },
                label = "Delete",
                onClick = secureDeleteConfirm
            )
        }
    }

    // Delete confirmation dialog
    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete this artifact?") },
            text = { Text("This cannot be undone. The file will be securely erased.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDeleteConfirm = false
                        onDelete()
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = YoursColors.Error
                    )
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
                    Text("Cancel")
                }
            },
            containerColor = YoursColors.Surface
        )
    }

    // Rename dialog
    if (showRenameDialog) {
        var newName by remember { mutableStateOf(artifact.metadata.name ?: "") }

        AlertDialog(
            onDismissRequest = { showRenameDialog = false },
            title = { Text("Rename artifact") },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    placeholder = { Text("Enter name") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = YoursColors.Primary,
                        cursorColor = YoursColors.Primary
                    )
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showRenameDialog = false
                        onRename(newName)
                    },
                    enabled = newName.isNotBlank()
                ) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRenameDialog = false }) {
                    Text("Cancel")
                }
            },
            containerColor = YoursColors.Surface
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
}

@Composable
private fun MetadataRow(label: String, value: String) {
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
            style = MaterialTheme.typography.bodySmall,
            color = YoursColors.OnSurface
        )
    }
}

@Composable
private fun ActionButton(
    icon: @Composable () -> Unit,
    label: String,
    onClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        IconButton(
            onClick = onClick,
            modifier = Modifier
                .size(56.dp)
                .background(Color.Black.copy(alpha = 0.5f), CircleShape)
        ) {
            icon()
        }

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = Color.White.copy(alpha = 0.8f)
        )
    }
}

private fun getFileEmoji(contentType: String): String {
    return when {
        contentType.startsWith("image/") -> "\uD83D\uDDBC"
        contentType.startsWith("video/") -> "\uD83C\uDFA5"
        contentType.startsWith("audio/") -> "\uD83C\uDFB5"
        contentType.startsWith("text/") -> "\uD83D\uDCC4"
        contentType.contains("pdf") -> "\uD83D\uDCC4"
        contentType.contains("zip") || contentType.contains("archive") -> "\uD83D\uDCE6"
        else -> "\uD83D\uDCC1"
    }
}

private fun formatFileSize(bytes: Int): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        else -> "${bytes / (1024 * 1024)} MB"
    }
}

private fun formatDate(timestamp: Long): String {
    val sdf = SimpleDateFormat("MMM d, yyyy 'at' h:mm a", Locale.getDefault())
    return sdf.format(Date(timestamp * 1000))
}
