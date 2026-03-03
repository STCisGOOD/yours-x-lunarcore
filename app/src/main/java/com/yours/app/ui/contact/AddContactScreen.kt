package com.yours.app.ui.contact

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.Base64
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import boofcv.abst.fiducial.QrCodeDetector
import boofcv.alg.fiducial.qrcode.QrCode
import boofcv.android.ConvertBitmap
import boofcv.factory.fiducial.ConfigQrCode
import boofcv.factory.fiducial.FactoryFiducial
import boofcv.struct.image.GrayU8
import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.UREncoder
import com.sparrowwallet.hummingbird.URDecoder
import com.sparrowwallet.hummingbird.ResultType
import com.yours.app.R
import com.yours.app.identity.ContactHello
import com.yours.app.ui.theme.GluspFontFamily
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.delay
import java.util.concurrent.Executors

/**
 * Add Contact Screen - Exchange QR codes to connect.
 * 
 * Flow:
 * 1. Show your QR code (they scan)
 * 2. Scan their QR code
 * 3. Choose a petname
 * 4. Connected!
 */

sealed class AddContactState {
    object ShowMyCode : AddContactState()
    object ScanTheirCode : AddContactState()
    data class NameThem(val theirHello: ContactHello) : AddContactState()
    data class Connected(val petname: String) : AddContactState()
    data class Error(val message: String) : AddContactState()
}

@Composable
fun AddContactScreen(
    myHello: ContactHello,
    onContactAdded: (theirHello: ContactHello, petname: String) -> Unit,
    onClose: () -> Unit,
    onRequestCameraPermission: (() -> Unit) -> Unit = { it() }
) {
    var state by remember { mutableStateOf<AddContactState>(AddContactState.ShowMyCode) }
    var selectedTab by remember { mutableStateOf(0) } // 0 = MY CODE, 1 = SCAN

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(YoursColors.Background)
    ) {
        // Katakana side decorations
        KatakanaSideDecoration(
            text = "接続",
            modifier = Modifier
                .align(Alignment.CenterStart)
                .padding(start = 6.dp)
        )
        KatakanaSideDecoration(
            text = "認証",
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .padding(end = 6.dp)
        )

        Column(
            modifier = Modifier.fillMaxSize()
        ) {
            // Header - streetwear style
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 50.dp, start = 24.dp, end = 24.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // Square close button
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .border(1.dp, YoursColors.GrayDim)
                        .clickable { onClose() },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "×",
                        color = YoursColors.Gray,
                        fontSize = 18.sp
                    )
                }

                // Title - tracked uppercase
                Text(
                    text = when (state) {
                        AddContactState.ShowMyCode -> "YOUR CODE"
                        AddContactState.ScanTheirCode -> "SCAN CODE"
                        is AddContactState.NameThem -> "NAME THEM"
                        is AddContactState.Connected -> "CONNECTED"
                        is AddContactState.Error -> "ERROR"
                    },
                    color = YoursColors.OnBackground,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 2.sp
                )
            }

            // Tab switcher (only show for MY CODE / SCAN states)
            if (state == AddContactState.ShowMyCode || state == AddContactState.ScanTheirCode) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp)
                ) {
                    // MY CODE tab
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .background(
                                if (selectedTab == 0) YoursColors.Primary else Color.Transparent
                            )
                            .border(1.dp, if (selectedTab == 0) YoursColors.Primary else YoursColors.GrayDim)
                            .clickable {
                                selectedTab = 0
                                state = AddContactState.ShowMyCode
                            }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "MY CODE",
                            color = if (selectedTab == 0) YoursColors.Background else YoursColors.Gray,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            letterSpacing = 1.sp
                        )
                    }

                    // SCAN tab
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .background(
                                if (selectedTab == 1) YoursColors.Primary else Color.Transparent
                            )
                            .border(1.dp, if (selectedTab == 1) YoursColors.Primary else YoursColors.GrayDim)
                            .clickable {
                                selectedTab = 1
                                onRequestCameraPermission {
                                    state = AddContactState.ScanTheirCode
                                }
                            }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "SCAN",
                            color = if (selectedTab == 1) YoursColors.Background else YoursColors.Gray,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            letterSpacing = 1.sp
                        )
                    }
                }
            }

            // Content
            AnimatedContent(
                targetState = state,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) { currentState ->
                when (currentState) {
                    AddContactState.ShowMyCode -> {
                        ShowMyCodeContent(
                            myHello = myHello,
                            onScanTheirs = {
                                selectedTab = 1
                                onRequestCameraPermission {
                                    state = AddContactState.ScanTheirCode
                                }
                            }
                        )
                    }
                    AddContactState.ScanTheirCode -> {
                        ScanTheirCodeContent(
                            onScanned = { hello ->
                                state = AddContactState.NameThem(hello)
                            },
                            onError = { msg ->
                                state = AddContactState.Error(msg)
                            },
                            onShowMyCode = {
                                selectedTab = 0
                                state = AddContactState.ShowMyCode
                            }
                        )
                    }
                    is AddContactState.NameThem -> {
                        NameThemContent(
                            theirName = currentState.theirHello.displayName,
                            onNameChosen = { petname ->
                                onContactAdded(currentState.theirHello, petname)
                                state = AddContactState.Connected(petname = petname)
                            }
                        )
                    }
                    is AddContactState.Connected -> {
                        ConnectedContent(
                            petname = currentState.petname,
                            onDone = onClose
                        )
                    }
                    is AddContactState.Error -> {
                        ErrorContent(
                            message = currentState.message,
                            onRetry = {
                                selectedTab = 1
                                state = AddContactState.ScanTheirCode
                            }
                        )
                    }
                }
            }

            // Geo stamp footer
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "OFF-GRID MESH PROTOCOL",
                    color = YoursColors.GrayDim,
                    fontSize = 8.sp,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 1.sp
                )
            }
        }
    }
}

/**
 * Katakana side decoration - vertical text.
 */
@Composable
private fun KatakanaSideDecoration(
    text: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        text.forEach { char ->
            Text(
                text = char.toString(),
                color = YoursColors.GrayDim,
                fontSize = 9.sp,
                letterSpacing = 4.sp
            )
        }
    }
}

// Neon glow modifier - border glow only
private fun Modifier.neonBorder(
    color: Color
) = this.drawBehind {
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
            frameworkCanvas.drawRect(0f, 0f, size.width, size.height, paint)
        }
    }
}

@Composable
private fun ShowMyCodeContent(
    myHello: ContactHello,
    onScanTheirs: () -> Unit
) {
    // Create UR encoder (generates fountain-coded frames)
    val urEncoder = remember(myHello) { createUREncoder(myHello) }

    // Current QR bitmap and frame info
    var currentQR by remember { mutableStateOf<Bitmap?>(null) }
    var frameNum by remember { mutableStateOf(0) }
    val totalFrames = urEncoder?.seqLen ?: 0

    // Animate through UR frames at 12 FPS
    LaunchedEffect(urEncoder) {
        urEncoder?.let { encoder ->
            while (true) {
                val fragment = encoder.nextPart()
                currentQR = generateURQRCode(fragment)
                frameNum = (frameNum + 1)
                delay(UR_FRAME_DELAY_MS)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Double-bordered QR card with neon glow
        // UR 2.0 animated QR display (fountain codes)
        Box(
            modifier = Modifier
                .size(280.dp)
                .neonBorder(YoursColors.Primary)
                .border(2.dp, YoursColors.Primary)
                .padding(4.dp)
                .border(1.dp, YoursColors.PrimaryDim)
                .background(YoursColors.Background),
            contentAlignment = Alignment.Center
        ) {
            currentQR?.let { bitmap ->
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "Your QR code (UR frame $frameNum)",
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(8.dp)
                )
            } ?: run {
                // Loading/Error state
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = if (urEncoder == null) "QR ERROR" else "LOADING...",
                        color = if (urEncoder == null) YoursColors.Error else YoursColors.Gray,
                        fontSize = 10.sp,
                        letterSpacing = 2.sp
                    )
                }
            }
        }

        // Frame indicator for UR 2.0 (shows looping fountain frames)
        if (totalFrames > 0) {
            Spacer(modifier = Modifier.height(8.dp))
            // Animated dot indicator (cycles through source frames)
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                (0 until totalFrames).forEach { index ->
                    val isActive = (frameNum % totalFrames) == index
                    Box(
                        modifier = Modifier
                            .size(if (isActive) 10.dp else 6.dp)
                            .background(
                                if (isActive) YoursColors.Primary else YoursColors.GrayDim,
                                shape = RoundedCornerShape(50)
                            )
                    )
                }
            }
            Text(
                text = "UR FRAME ${(frameNum % totalFrames) + 1}/$totalFrames",
                color = YoursColors.Gray,
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp,
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Identity section
        Text(
            text = "[ YOURS ]",
            fontFamily = GluspFontFamily,
            color = YoursColors.Primary,
            fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 1.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = myHello.displayName.uppercase(),
            color = YoursColors.OnBackground,
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 3.sp
        )

        Spacer(modifier = Modifier.height(2.dp))

        Text(
            text = "YOURS IDENTITY",
            color = YoursColors.Gray,
            fontSize = 10.sp,
            letterSpacing = 2.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = "ユアーズ",
            color = YoursColors.Primary.copy(alpha = 0.15f),
            fontSize = 9.sp,
            letterSpacing = 2.sp
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Full DID display - plain monospace, no border
        Text(
            text = myHello.did,
            color = YoursColors.Gray,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            lineHeight = 13.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun ScanTheirCodeContent(
    onScanned: (ContactHello) -> Unit,
    onError: (String) -> Unit,
    onShowMyCode: () -> Unit
) {
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasScanned by remember { mutableStateOf(false) }

    // UR 2.0 decoder - handles fountain codes, out-of-order frames
    val urDecoder = remember { URDecoder() }
    var scanProgress by remember { mutableStateOf(0f) }

    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        // Camera preview - clipped to prevent overflow into tabs
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .clip(RoundedCornerShape(0.dp))  // Clip to bounds
        ) {
            AndroidView(
                factory = { ctx ->
                    val previewView = PreviewView(ctx)

                    val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                    cameraProviderFuture.addListener({
                        val cameraProvider = cameraProviderFuture.get()

                        val preview = Preview.Builder().build().also {
                            it.setSurfaceProvider(previewView.surfaceProvider)
                        }

                        // BoofCV QR detector - handles high-version QR codes (v25-40)
                        // Pure Java, no Google dependencies, proven on dense cryptographic payloads
                        val detector: QrCodeDetector<GrayU8> = FactoryFiducial.qrcode(null, GrayU8::class.java)
                        android.util.Log.d("BoofCV", "Detector initialized: ${detector.javaClass.name}")

                        val imageAnalysis = ImageAnalysis.Builder()
                            .setTargetResolution(android.util.Size(1280, 720))
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()

                        var frameCount = 0
                        imageAnalysis.setAnalyzer(Executors.newSingleThreadExecutor()) { imageProxy ->
                            if (!hasScanned) {
                                frameCount++
                                val shouldLog = frameCount <= 5 || frameCount % 30 == 0
                                try {
                                    val bitmap = imageProxy.toBitmap()
                                    val gray = ConvertBitmap.bitmapToGray(bitmap, null as GrayU8?, null)

                                    if (shouldLog) {
                                        // Comprehensive diagnostics
                                        var minPx = 255
                                        var maxPx = 0
                                        var sum = 0L
                                        for (y in 0 until gray.height step 100) {
                                            for (x in 0 until gray.width step 100) {
                                                val px = gray.get(x, y)
                                                if (px < minPx) minPx = px
                                                if (px > maxPx) maxPx = px
                                                sum += px
                                            }
                                        }
                                        val samples = (gray.width / 100) * (gray.height / 100)
                                        val avgPx = if (samples > 0) sum / samples else 0
                                        android.util.Log.d("BoofCV", "Frame #$frameCount: ${bitmap.width}x${bitmap.height} config=${bitmap.config}, Gray=${gray.width}x${gray.height} min=$minPx max=$maxPx avg=$avgPx")
                                    }

                                    // Detect QR codes
                                    detector.process(gray)

                                    val detections = detector.getDetections()
                                    val failures = detector.getFailures()
                                    if (shouldLog) {
                                        android.util.Log.d("BoofCV", "  Detections: ${detections.size}, Failures: ${failures?.size ?: 0}")
                                    }

                                    for (qr in detections) {
                                        val value = qr.message
                                        if (value != null && !hasScanned) {
                                            android.util.Log.d("BoofCV", "QR DECODED: ${value.take(60)}...")

                                            // Check if this is a UR fragment (ur:bytes/...)
                                            if (value.lowercase().startsWith("ur:")) {
                                                // Feed to UR decoder
                                                try {
                                                    urDecoder.receivePart(value)
                                                    scanProgress = urDecoder.estimatedPercentComplete.toFloat()
                                                    android.util.Log.d("UR", "Progress: ${(scanProgress * 100).toInt()}%")

                                                    // Check if decoding is complete
                                                    val result = urDecoder.result
                                                    if (result != null && result.type == ResultType.SUCCESS) {
                                                        val bytes = result.ur.toBytes()
                                                        android.util.Log.d("UR", "UR decode complete: ${bytes.size} bytes")
                                                        hasScanned = true
                                                        val hello = ContactHello.fromBytes(bytes)
                                                        if (hello != null) {
                                                            onScanned(hello)
                                                        } else {
                                                            hasScanned = false
                                                            android.util.Log.e("UR", "Failed to parse ContactHello from UR bytes")
                                                        }
                                                    }
                                                } catch (e: Exception) {
                                                    android.util.Log.e("UR", "UR decode error: ${e.message}")
                                                }
                                            } else {
                                                // Legacy single-frame format (yours: or yoursz:)
                                                hasScanned = true
                                                parseQRCode(value)?.let { hello ->
                                                    onScanned(hello)
                                                } ?: run {
                                                    hasScanned = false
                                                }
                                            }
                                        }
                                    }
                                } catch (e: Exception) {
                                    if (shouldLog) {
                                        android.util.Log.e("BoofCV", "Error: ${e.message}", e)
                                    }
                                } finally {
                                    imageProxy.close()
                                }
                            } else {
                                imageProxy.close()
                            }
                        }

                        try {
                            cameraProvider.unbindAll()
                            cameraProvider.bindToLifecycle(
                                lifecycleOwner,
                                CameraSelector.DEFAULT_BACK_CAMERA,
                                preview,
                                imageAnalysis
                            )
                        } catch (e: Exception) {
                            onError("Camera error: ${e.message}")
                        }
                    }, ContextCompat.getMainExecutor(ctx))

                    previewView
                },
                modifier = Modifier.fillMaxSize()
            )

            // Scan overlay - square frame
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(48.dp),
                contentAlignment = Alignment.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(250.dp)
                        .border(2.dp, YoursColors.Primary)
                )
            }
        }

        // Bottom bar - pure black background
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(YoursColors.Background)
                .padding(24.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Show progress if scanning UR frames
                if (scanProgress > 0f) {
                    Text(
                        text = "RECEIVING UR FRAMES",
                        color = YoursColors.Primary,
                        fontSize = 11.sp,
                        letterSpacing = 2.sp
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    // Progress bar
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .background(YoursColors.GrayDim)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth(scanProgress)
                                .height(4.dp)
                                .background(YoursColors.Primary)
                        )
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "${(scanProgress * 100).toInt()}%",
                        color = YoursColors.Gray,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                } else {
                    Text(
                        text = "POINT AT THEIR QR CODE",
                        color = YoursColors.OnBackgroundMuted,
                        fontSize = 11.sp,
                        letterSpacing = 2.sp
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .border(1.dp, YoursColors.GrayDim)
                        .clickable { onShowMyCode() }
                        .padding(horizontal = 24.dp, vertical = 12.dp)
                ) {
                    Text(
                        text = "[SHOW MY CODE]",
                        color = YoursColors.Gray,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 1.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun NameThemContent(
    theirName: String,
    onNameChosen: (String) -> Unit
) {
    var petname by remember { mutableStateOf(theirName) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "THEY CALL THEMSELVES",
            color = YoursColors.OnBackgroundMuted,
            fontSize = 10.sp,
            letterSpacing = 2.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = theirName.uppercase(),
            color = YoursColors.OnBackground,
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 3.sp
        )

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "WHAT DO YOU WANT TO CALL THEM?",
            color = YoursColors.OnBackgroundMuted,
            fontSize = 10.sp,
            letterSpacing = 2.sp
        )

        Spacer(modifier = Modifier.height(16.dp))

        BasicTextField(
            value = petname,
            onValueChange = { petname = it },
            textStyle = TextStyle(
                color = YoursColors.OnBackground,
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
                letterSpacing = 2.sp
            ),
            singleLine = true,
            cursorBrush = SolidColor(YoursColors.Primary),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Words,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (petname.isNotBlank()) {
                        onNameChosen(petname.trim())
                    }
                }
            ),
            decorationBox = { innerTextField ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(YoursColors.Surface)
                        .border(1.dp, YoursColors.GrayDim)
                        .padding(20.dp),
                    contentAlignment = Alignment.Center
                ) {
                    innerTextField()
                }
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "This is your private name for them",
            color = YoursColors.Gray,
            fontSize = 10.sp
        )

        Spacer(modifier = Modifier.height(48.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(if (petname.isNotBlank()) YoursColors.Primary else YoursColors.GrayDim)
                .clickable(enabled = petname.isNotBlank()) { onNameChosen(petname.trim()) }
                .padding(vertical = 14.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "[CONNECT]",
                color = if (petname.isNotBlank()) YoursColors.Background else YoursColors.Gray,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 1.sp
            )
        }
    }
}

@Composable
private fun ConnectedContent(
    petname: String,
    onDone: () -> Unit
) {
    LaunchedEffect(Unit) {
        delay(2500)
        onDone()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Checkmark in square
        Box(
            modifier = Modifier
                .size(64.dp)
                .border(2.dp, YoursColors.Primary),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "✓",
                color = YoursColors.Primary,
                fontSize = 32.sp
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "CONNECTED",
            color = YoursColors.Primary,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 2.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = petname.uppercase(),
            color = YoursColors.OnBackground,
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 3.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = "is now in your contacts",
            color = YoursColors.OnBackgroundMuted,
            fontSize = 12.sp
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "E2EE SECURED",
            color = YoursColors.Gray,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            letterSpacing = 1.sp
        )
    }
}

@Composable
private fun ErrorContent(
    message: String,
    onRetry: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Something went wrong",
            style = MaterialTheme.typography.headlineSmall,
            color = YoursColors.Error
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            color = YoursColors.OnBackgroundMuted,
            textAlign = TextAlign.Center
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Button(
            onClick = onRetry,
            colors = ButtonDefaults.buttonColors(
                containerColor = YoursColors.Primary
            )
        ) {
            Text("Try again")
        }
    }
}

// ============================================================================
// QR CODE HELPERS - UR 2.0 (Uniform Resources) with Fountain Codes
// ============================================================================

/**
 * UR 2.0 animated QR configuration.
 *
 * Uses fountain codes (Luby Transform) for rateless encoding:
 * - Frames can be captured in any order
 * - Decoding completes with ~5-10% redundancy
 * - Each QR is ~250 bytes (Version 10-12) - easy to scan
 *
 * For ~1,400 byte payload: 5-7 source fragments, 1-3 second transfer at 12 FPS
 */
private const val UR_FRAGMENT_SIZE = 100       // bytes per fragment → ~220 chars → Version 9-10 QR
private const val UR_FRAME_DELAY_MS = 83L      // ~12 FPS
private const val UR_MIN_FRAGMENT_LEN = 10     // Hummingbird param
private const val UR_FIRST_SEQ_NUM = 0L        // Start from first fragment (Long)

/**
 * Create a UREncoder for the contact hello payload.
 * Returns encoder that generates unlimited fountain-coded frames.
 */
private fun createUREncoder(hello: ContactHello): UREncoder? {
    return try {
        val rawBytes = hello.toBytes()
        android.util.Log.d("UR", "Creating UR from ${rawBytes.size} bytes")

        // Create UR with "bytes" type (generic binary data)
        val ur = UR.fromBytes(rawBytes)

        // Create encoder: maxFragmentLen=250, minFragmentLen=10, firstSeqNum=0
        val encoder = UREncoder(ur, UR_FRAGMENT_SIZE, UR_MIN_FRAGMENT_LEN, UR_FIRST_SEQ_NUM)

        android.util.Log.d("UR", "UREncoder created, seqLen=${encoder.seqLen}")
        encoder
    } catch (e: Exception) {
        android.util.Log.e("UR", "Failed to create UREncoder: ${e.message}", e)
        null
    }
}

/**
 * Generate a plain black-on-white QR code for a UR fragment.
 * Uses L error correction since fountain codes provide redundancy.
 */
private fun generateURQRCode(urFragment: String): Bitmap? {
    return try {
        val content = urFragment.uppercase()
        android.util.Log.d("UR", "Generating QR (${content.length} chars)")

        val hints = java.util.Hashtable<EncodeHintType, Any>()
        hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.L
        hints[EncodeHintType.MARGIN] = 2

        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, 512, 512, hints)
        val width = bitMatrix.width
        val height = bitMatrix.height

        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
        bitmap
    } catch (e: Exception) {
        android.util.Log.e("UR", "QR generation failed: ${e.message}")
        null
    }
}

/**
 * Generate a branded QR code with the [stc] logo in the center.
 * (Legacy single-frame version - kept for reference)
 *
 * Features:
 * - Error correction HIGH (30%) to allow logo overlay
 * - Ember/gold color scheme on dark background
 * - Rounded dot modules instead of squares
 * - Centered logo (yours_logo.png)
 */
private var lastQrError: String? = null

private fun generateBrandedQRCode(
    hello: ContactHello,
    context: android.content.Context
): Bitmap? {
    lastQrError = null
    return try {
        // Serialize and compress contact data
        val rawBytes = hello.toBytes()

        // Compress with GZIP to reduce size
        val compressedBytes = java.io.ByteArrayOutputStream().use { baos ->
            java.util.zip.GZIPOutputStream(baos).use { gzip ->
                gzip.write(rawBytes)
            }
            baos.toByteArray()
        }

        val data = Base64.encodeToString(compressedBytes, Base64.NO_WRAP)
        val content = "yoursz:$data"  // 'z' indicates compressed

        android.util.Log.d("QRGen", "Payload: ${rawBytes.size}B → compressed: ${compressedBytes.size}B → encoded: ${content.length} chars")

        // Use M error correction (15%) - balance between capacity and branding space
        val hints = java.util.Hashtable<EncodeHintType, Any>()
        hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.M
        hints[EncodeHintType.MARGIN] = 1
        hints[EncodeHintType.CHARACTER_SET] = "UTF-8"

        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, 512, 512, hints)

        android.util.Log.d("QRGen", "BitMatrix generated: ${bitMatrix.width}x${bitMatrix.height}")

        val width = bitMatrix.width
        val height = bitMatrix.height

        // Create bitmap with ARGB for transparency support
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)

        // Background: dark (matches app theme)
        val bgColor = 0xFF0A0A0B.toInt()
        canvas.drawColor(bgColor)

        // QR module colors: ember/gold on dark
        val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFE8B866.toInt() // Ember gold
            style = Paint.Style.FILL
        }

        // Calculate module size and center exclusion zone for branding
        val moduleSize = width.toFloat() / bitMatrix.width
        val centerX = width / 2f
        val centerY = height / 2f
        val logoZoneRadius = width * 0.10f // 10% radius for M error correction (~15%)

        // Draw QR modules as rounded dots
        val dotRadius = moduleSize * 0.4f

        for (x in 0 until bitMatrix.width) {
            for (y in 0 until bitMatrix.height) {
                if (bitMatrix[x, y]) {
                    val pixelX = x * moduleSize + moduleSize / 2
                    val pixelY = y * moduleSize + moduleSize / 2

                    // Skip center zone (for logo)
                    val distFromCenter = kotlin.math.sqrt(
                        (pixelX - centerX) * (pixelX - centerX) +
                        (pixelY - centerY) * (pixelY - centerY)
                    )

                    if (distFromCenter > logoZoneRadius) {
                        canvas.drawCircle(pixelX, pixelY, dotRadius, dotPaint)
                    }
                }
            }
        }

        // Draw position detection patterns (the three corners) as solid squares
        // These need to be recognizable for scanning
        drawPositionPattern(canvas, 0f, 0f, moduleSize, dotPaint)
        drawPositionPattern(canvas, (bitMatrix.width - 7) * moduleSize, 0f, moduleSize, dotPaint)
        drawPositionPattern(canvas, 0f, (bitMatrix.height - 7) * moduleSize, moduleSize, dotPaint)

        // Draw [stc] text in center - compact for M error correction
        val textSize = width * 0.07f
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFE8B866.toInt() // Ember gold
            this.textSize = textSize
            textAlign = Paint.Align.CENTER
            typeface = android.graphics.Typeface.create(
                android.graphics.Typeface.MONOSPACE,
                android.graphics.Typeface.BOLD
            )
        }

        // Draw dark background circle for text
        val textBgRadius = width * 0.08f
        val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF0A0A0B.toInt() // Dark background
            style = Paint.Style.FILL
        }
        canvas.drawCircle(centerX, centerY, textBgRadius, bgPaint)

        // Draw border circle
        val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFE8B866.toInt() // Ember gold
            style = Paint.Style.STROKE
            strokeWidth = 2f
        }
        canvas.drawCircle(centerX, centerY, textBgRadius, borderPaint)

        // Draw [stc] text centered
        val textY = centerY + textSize * 0.35f
        canvas.drawText("[stc]", centerX, textY, textPaint)

        bitmap
    } catch (e: Exception) {
        lastQrError = "${e.javaClass.simpleName}: ${e.message}"
        null
    }
}

/**
 * Draw a position detection pattern (finder pattern) at the given position.
 * These are the three large squares in QR code corners.
 * Uses SHARP corners - required for reliable scanner detection.
 */
private fun drawPositionPattern(
    canvas: Canvas,
    x: Float,
    y: Float,
    moduleSize: Float,
    paint: Paint
) {
    val size7 = 7 * moduleSize
    val size5 = 5 * moduleSize
    val size3 = 3 * moduleSize

    // Finder patterns need dark-light-dark contrast for scanners to detect
    val darkPaint = Paint().apply {
        color = 0xFF000000.toInt() // Pure black for maximum contrast
        style = Paint.Style.FILL
    }
    val lightPaint = Paint().apply {
        color = 0xFFFFFFFF.toInt() // Pure white for maximum contrast
        style = Paint.Style.FILL
    }

    // Clear area first (remove any underlying dots)
    canvas.drawRect(x, y, x + size7, y + size7, lightPaint)

    // Outer square (7x7) - BLACK - sharp corners
    canvas.drawRect(x, y, x + size7, y + size7, darkPaint)

    // Middle ring (5x5) - WHITE - sharp corners
    canvas.drawRect(
        x + moduleSize, y + moduleSize,
        x + moduleSize + size5, y + moduleSize + size5,
        lightPaint
    )

    // Center square (3x3) - BLACK - sharp corners
    canvas.drawRect(
        x + 2 * moduleSize, y + 2 * moduleSize,
        x + 2 * moduleSize + size3, y + 2 * moduleSize + size3,
        darkPaint
    )
}

// Legacy function for compatibility
private fun generateQRCode(hello: ContactHello): Bitmap? {
    return try {
        val data = Base64.encodeToString(hello.toBytes(), Base64.NO_WRAP)
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode("yours:$data", BarcodeFormat.QR_CODE, 512, 512)

        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }

        bitmap
    } catch (e: Exception) {
        null
    }
}

private fun parseQRCode(data: String): ContactHello? {
    return try {
        when {
            data.startsWith("yoursz:") -> {
                // Compressed format
                val base64 = data.removePrefix("yoursz:")
                val compressedBytes = Base64.decode(base64, Base64.NO_WRAP)
                // Decompress with GZIP
                val bytes = java.util.zip.GZIPInputStream(
                    java.io.ByteArrayInputStream(compressedBytes)
                ).use { it.readBytes() }
                ContactHello.fromBytes(bytes)
            }
            data.startsWith("yours:") -> {
                // Uncompressed format (legacy)
                val base64 = data.removePrefix("yours:")
                val bytes = Base64.decode(base64, Base64.NO_WRAP)
                ContactHello.fromBytes(bytes)
            }
            else -> null
        }
    } catch (e: Exception) {
        android.util.Log.e("QRParse", "Failed to parse QR: ${e.message}")
        null
    }
}
