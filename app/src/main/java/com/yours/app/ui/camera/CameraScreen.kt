package com.yours.app.ui.camera

import android.view.ViewGroup
import androidx.camera.view.PreviewView
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.yours.app.camera.SovereignCamera
import com.yours.app.ui.theme.YoursColors
import com.yours.app.vault.VaultStorage
import kotlinx.coroutines.launch

/**
 * Sovereign Camera Screen
 * 
 * - No location captured
 * - No metadata embedded
 * - Encrypted immediately to vault
 */

sealed class CameraState {
    object Initializing : CameraState()
    object Ready : CameraState()
    object Capturing : CameraState()
    data class Captured(val artifactId: String) : CameraState()
    data class Error(val message: String) : CameraState()
}

@Composable
fun CameraScreen(
    sovereignCamera: SovereignCamera,
    ownerPublicKey: ByteArray,
    onClose: () -> Unit,
    onCaptured: (artifactId: String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    
    var state by remember { mutableStateOf<CameraState>(CameraState.Initializing) }
    var previewView by remember { mutableStateOf<PreviewView?>(null) }
    
    // Initialize camera
    LaunchedEffect(previewView) {
        previewView?.let { preview ->
            try {
                sovereignCamera.startPreview(lifecycleOwner, preview)
                state = CameraState.Ready
            } catch (e: Exception) {
                state = CameraState.Error("Camera unavailable: ${e.message}")
            }
        }
    }
    
    // Cleanup on dispose
    DisposableEffect(Unit) {
        onDispose {
            sovereignCamera.stopPreview()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        // Camera preview
        AndroidView(
            factory = { ctx ->
                PreviewView(ctx).apply {
                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )
                    scaleType = PreviewView.ScaleType.FILL_CENTER
                    previewView = this
                }
            },
            modifier = Modifier.fillMaxSize()
        )
        
        // UI Overlay
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
        ) {
            // Top bar - close button
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                IconButton(
                    onClick = onClose,
                    modifier = Modifier
                        .size(44.dp)
                        .clip(CircleShape)
                        .background(YoursColors.Background.copy(alpha = 0.5f))
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = YoursColors.OnBackground
                    )
                }
            }
            
            Spacer(modifier = Modifier.weight(1f))
            
            // Bottom controls
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Status text
                AnimatedContent(
                    targetState = state,
                    transitionSpec = {
                        fadeIn() togetherWith fadeOut()
                    }
                ) { currentState ->
                    when (currentState) {
                        CameraState.Initializing -> {
                            StatusPill(text = "Initializing...")
                        }
                        CameraState.Ready -> {
                            StatusPill(text = "No location · No metadata · Yours")
                        }
                        CameraState.Capturing -> {
                            StatusPill(text = "Encrypting...")
                        }
                        is CameraState.Captured -> {
                            StatusPill(
                                text = "Captured. It's yours.",
                                color = YoursColors.Success
                            )
                        }
                        is CameraState.Error -> {
                            StatusPill(
                                text = currentState.message,
                                color = YoursColors.Error
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(32.dp))
                
                // Capture button
                when (state) {
                    CameraState.Ready -> {
                        CaptureButton(
                            onClick = {
                                scope.launch {
                                    state = CameraState.Capturing
                                    try {
                                        val artifact = sovereignCamera.captureToVault(ownerPublicKey)
                                        state = CameraState.Captured(artifact.id)
                                        
                                        // Brief delay to show success
                                        kotlinx.coroutines.delay(1000)
                                        
                                        onCaptured(artifact.id)
                                    } catch (e: Exception) {
                                        state = CameraState.Error("Capture failed: ${e.message}")
                                    }
                                }
                            }
                        )
                    }
                    CameraState.Capturing -> {
                        CapturingIndicator()
                    }
                    is CameraState.Captured -> {
                        CapturedActions(
                            onAnother = { state = CameraState.Ready },
                            onDone = onClose
                        )
                    }
                    else -> {
                        // Show disabled button for other states
                        CaptureButton(
                            onClick = {},
                            enabled = false
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(48.dp))
            }
        }
    }
}

@Composable
private fun StatusPill(
    text: String,
    color: androidx.compose.ui.graphics.Color = YoursColors.OnBackgroundMuted
) {
    Surface(
        color = YoursColors.Background.copy(alpha = 0.7f),
        shape = RoundedCornerShape(20.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = color,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun CaptureButton(
    onClick: () -> Unit,
    enabled: Boolean = true
) {
    Box(
        modifier = Modifier
            .size(72.dp)
            .clip(CircleShape)
            .border(
                width = 4.dp,
                color = if (enabled) YoursColors.OnBackground else YoursColors.OnBackgroundMuted,
                shape = CircleShape
            )
            .clickable(enabled = enabled) { onClick() }
            .padding(4.dp),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .clip(CircleShape)
                .background(
                    if (enabled) YoursColors.OnBackground else YoursColors.OnBackgroundMuted
                )
        )
    }
}

@Composable
private fun CapturingIndicator() {
    Box(
        modifier = Modifier.size(72.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(56.dp),
            color = YoursColors.Primary,
            strokeWidth = 4.dp
        )
    }
}

@Composable
private fun CapturedActions(
    onAnother: () -> Unit,
    onDone: () -> Unit
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedButton(
            onClick = onAnother,
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = YoursColors.OnBackground
            ),
            border = ButtonDefaults.outlinedButtonBorder.copy(
                brush = androidx.compose.ui.graphics.SolidColor(YoursColors.OnBackground)
            )
        ) {
            Text("Take another")
        }
        
        Button(
            onClick = onDone,
            colors = ButtonDefaults.buttonColors(
                containerColor = YoursColors.Primary,
                contentColor = YoursColors.OnPrimary
            )
        ) {
            Text("Done")
        }
    }
}
