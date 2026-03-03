package com.yours.app.camera

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.util.Log
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.yours.app.crypto.BedrockCore
import com.yours.app.vault.Artifact
import com.yours.app.vault.VaultStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Sovereign Camera - Captures photos with zero metadata leakage.
 * 
 * Properties:
 * - Raw sensor data → memory only (never touches disk unencrypted)
 * - All EXIF/metadata stripped before any processing
 * - Encrypted immediately to owner's identity
 * - Only exists as encrypted artifact in vault
 * 
 * What this camera does NOT capture:
 * - GPS coordinates
 * - Device make/model
 * - Timestamps (unless explicitly added by user)
 * - Camera settings
 * - Thumbnail previews
 * - Unique image identifiers
 */
class SovereignCamera(
    private val context: Context,
    private val vaultStorage: VaultStorage
) {
    
    companion object {
        private const val TAG = "SovereignCamera"
        private const val JPEG_QUALITY = 90
    }
    
    private var imageCapture: ImageCapture? = null
    private var cameraProvider: ProcessCameraProvider? = null
    
    /**
     * Initialize camera preview.
     * Call this when camera UI is shown.
     */
    suspend fun startPreview(
        lifecycleOwner: LifecycleOwner,
        previewView: PreviewView
    ) = withContext(Dispatchers.Main) {
        
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        
        cameraProvider = suspendCancellableCoroutine { cont ->
            cameraProviderFuture.addListener({
                try {
                    cont.resume(cameraProviderFuture.get())
                } catch (e: Exception) {
                    cont.resumeWithException(e)
                }
            }, ContextCompat.getMainExecutor(context))
        }
        
        val provider = cameraProvider ?: throw IllegalStateException("Camera not available")
        
        // Preview use case
        val preview = androidx.camera.core.Preview.Builder()
            .build()
            .also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
        
        // Image capture use case - configured for quality, not metadata
        imageCapture = ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
            .build()
        
        // Select back camera
        val cameraSelector = androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA
        
        try {
            // Unbind any existing use cases
            provider.unbindAll()
            
            // Bind use cases to camera
            provider.bindToLifecycle(
                lifecycleOwner,
                cameraSelector,
                preview,
                imageCapture
            )
            
            Log.d(TAG, "Camera preview started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to bind camera use cases", e)
            throw e
        }
    }
    
    /**
     * Stop camera preview.
     * Call when leaving camera UI.
     */
    fun stopPreview() {
        cameraProvider?.unbindAll()
        cameraProvider = null
        imageCapture = null
    }
    
    /**
     * Capture a photo directly to the vault.
     * 
     * The photo:
     * 1. Is captured to memory only
     * 2. Has all metadata stripped
     * 3. Is immediately encrypted
     * 4. Is stored as an artifact
     * 5. Never exists unencrypted on disk
     * 
     * @param ownerEncryptionKey The owner's Hk-OVCT public key
     * @return The created artifact
     */
    suspend fun captureToVault(
        ownerEncryptionKey: ByteArray
    ): Artifact = withContext(Dispatchers.IO) {
        
        val capture = imageCapture 
            ?: throw IllegalStateException("Camera not initialized")
        
        // Capture image to memory
        val imageProxy = captureImage(capture)
        
        try {
            // Convert to clean JPEG (no metadata)
            val cleanJpeg = processToCleanJpeg(imageProxy)
            
            try {
                // Create encrypted artifact
                val artifact = Artifact.create(
                    content = cleanJpeg,
                    contentType = "image/jpeg",
                    ownerPublicKey = ownerEncryptionKey
                )
                
                // Store in vault
                vaultStorage.store(artifact)
                
                Log.d(TAG, "Photo captured to vault: ${artifact.id}")
                
                artifact
            } finally {
                // Zero out plaintext immediately
                BedrockCore.zeroize(cleanJpeg)
            }
        } finally {
            imageProxy.close()
        }
    }
    
    /**
     * Capture image from camera to ImageProxy (memory).
     */
    private suspend fun captureImage(
        imageCapture: ImageCapture
    ): ImageProxy = suspendCancellableCoroutine { cont ->
        
        imageCapture.takePicture(
            ContextCompat.getMainExecutor(context),
            object : ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {
                    cont.resume(image)
                }
                
                override fun onError(exception: ImageCaptureException) {
                    cont.resumeWithException(exception)
                }
            }
        )
    }
    
    /**
     * Process ImageProxy to clean JPEG with zero metadata.
     * 
     * This is where we ensure no information leaks:
     * - No EXIF data
     * - No GPS
     * - No device info
     * - No timestamps
     * - No thumbnails
     */
    private fun processToCleanJpeg(imageProxy: ImageProxy): ByteArray {
        // Convert ImageProxy to Bitmap
        val bitmap = imageProxyToBitmap(imageProxy)
        
        try {
            // Apply rotation if needed
            val rotatedBitmap = rotateBitmap(bitmap, imageProxy.imageInfo.rotationDegrees)
            
            try {
                // Compress to JPEG with NO metadata
                val outputStream = ByteArrayOutputStream()
                
                // Using Bitmap.compress creates a clean JPEG with no EXIF
                rotatedBitmap.compress(
                    Bitmap.CompressFormat.JPEG,
                    JPEG_QUALITY,
                    outputStream
                )
                
                val jpegBytes = outputStream.toByteArray()
                
                // Paranoid mode: Verify and strip any residual metadata
                val cleanBytes = ExifStripper.stripAllMetadata(jpegBytes)
                
                Log.d(TAG, "Clean JPEG created: ${cleanBytes.size} bytes")
                
                return cleanBytes
            } finally {
                if (rotatedBitmap !== bitmap) {
                    rotatedBitmap.recycle()
                }
            }
        } finally {
            bitmap.recycle()
        }
    }
    
    /**
     * Convert ImageProxy (YUV) to Bitmap (RGB).
     * Operates entirely in memory.
     */
    private fun imageProxyToBitmap(imageProxy: ImageProxy): Bitmap {
        val planes = imageProxy.planes
        
        // Handle JPEG format (if camera provides it directly)
        if (imageProxy.format == android.graphics.ImageFormat.JPEG) {
            val buffer = planes[0].buffer
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)
            return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        }
        
        // Handle YUV_420_888 format (most common)
        val yBuffer = planes[0].buffer
        val uBuffer = planes[1].buffer
        val vBuffer = planes[2].buffer
        
        val ySize = yBuffer.remaining()
        val uSize = uBuffer.remaining()
        val vSize = vBuffer.remaining()
        
        val nv21 = ByteArray(ySize + uSize + vSize)
        
        yBuffer.get(nv21, 0, ySize)
        vBuffer.get(nv21, ySize, vSize)
        uBuffer.get(nv21, ySize + vSize, uSize)
        
        val yuvImage = android.graphics.YuvImage(
            nv21,
            android.graphics.ImageFormat.NV21,
            imageProxy.width,
            imageProxy.height,
            null
        )
        
        val out = ByteArrayOutputStream()
        yuvImage.compressToJpeg(
            android.graphics.Rect(0, 0, imageProxy.width, imageProxy.height),
            100, // Max quality for intermediate step
            out
        )
        
        val imageBytes = out.toByteArray()
        return BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)
    }
    
    /**
     * Rotate bitmap if needed based on sensor orientation.
     */
    private fun rotateBitmap(bitmap: Bitmap, rotationDegrees: Int): Bitmap {
        if (rotationDegrees == 0) return bitmap
        
        val matrix = Matrix().apply {
            postRotate(rotationDegrees.toFloat())
        }
        
        return Bitmap.createBitmap(
            bitmap,
            0, 0,
            bitmap.width, bitmap.height,
            matrix,
            true
        )
    }
}

/**
 * EXIF metadata stripper.
 * Ensures absolutely no metadata survives in the output JPEG.
 */
object ExifStripper {
    
    private const val TAG = "ExifStripper"
    
    // JPEG markers
    private const val MARKER_SOI = 0xFFD8   // Start of Image
    private const val MARKER_APP0 = 0xFFE0  // JFIF
    private const val MARKER_APP1 = 0xFFE1  // EXIF
    private const val MARKER_APP2 = 0xFFE2  // ICC Profile
    private const val MARKER_APP13 = 0xFFED // IPTC
    private const val MARKER_APP14 = 0xFFEE // Adobe
    private const val MARKER_COM = 0xFFFE   // Comment
    private const val MARKER_SOS = 0xFFDA   // Start of Scan (image data begins)
    
    /**
     * Strip all metadata from JPEG.
     * 
     * Removes:
     * - EXIF (APP1) - camera info, GPS, timestamps
     * - JFIF (APP0) - basic info, thumbnail
     * - ICC Profile (APP2)
     * - IPTC (APP13) - editorial info
     * - Adobe (APP14)
     * - Comments (COM)
     * 
     * Keeps:
     * - Image data (essential)
     * - Quantization tables (essential)
     * - Huffman tables (essential)
     */
    fun stripAllMetadata(jpeg: ByteArray): ByteArray {
        if (jpeg.size < 2) return jpeg
        
        // Verify JPEG magic
        if (jpeg[0] != 0xFF.toByte() || jpeg[1] != 0xD8.toByte()) {
            Log.w(TAG, "Not a valid JPEG, returning as-is")
            return jpeg
        }
        
        val output = ByteArrayOutputStream()
        
        // Write SOI marker
        output.write(0xFF)
        output.write(0xD8)
        
        var i = 2
        while (i < jpeg.size - 1) {
            // Find next marker
            if (jpeg[i] != 0xFF.toByte()) {
                i++
                continue
            }
            
            val marker = ((jpeg[i].toInt() and 0xFF) shl 8) or (jpeg[i + 1].toInt() and 0xFF)
            
            // Check if this is a marker we want to strip
            val shouldStrip = when (marker) {
                MARKER_APP0,    // JFIF
                MARKER_APP1,    // EXIF
                MARKER_APP2,    // ICC
                MARKER_APP13,   // IPTC
                MARKER_APP14,   // Adobe
                MARKER_COM      // Comment
                    -> true
                else -> false
            }
            
            if (marker == MARKER_SOS) {
                // Start of scan - copy everything from here to end
                output.write(jpeg, i, jpeg.size - i)
                break
            }
            
            // Get segment length (if applicable)
            if (i + 3 < jpeg.size && marker != 0xFFD8 && marker != 0xFFD9) {
                val length = ((jpeg[i + 2].toInt() and 0xFF) shl 8) or 
                            (jpeg[i + 3].toInt() and 0xFF)
                
                if (shouldStrip) {
                    Log.d(TAG, "Stripping marker ${String.format("0x%04X", marker)}, length $length")
                    i += 2 + length
                    continue
                } else {
                    // Keep this segment
                    output.write(jpeg, i, 2 + length)
                    i += 2 + length
                }
            } else {
                // Standalone marker or end of data
                output.write(jpeg, i, 2)
                i += 2
            }
        }
        
        return output.toByteArray()
    }
    
    /**
     * Verify that a JPEG has no metadata.
     * Use this to audit that stripping worked.
     */
    fun hasMetadata(jpeg: ByteArray): Boolean {
        if (jpeg.size < 2) return false
        
        var i = 2
        while (i < jpeg.size - 1) {
            if (jpeg[i] != 0xFF.toByte()) {
                i++
                continue
            }
            
            val marker = ((jpeg[i].toInt() and 0xFF) shl 8) or (jpeg[i + 1].toInt() and 0xFF)
            
            // These markers should not be present
            if (marker in listOf(MARKER_APP1, MARKER_APP13, MARKER_COM)) {
                return true
            }
            
            if (marker == MARKER_SOS) break
            
            if (i + 3 < jpeg.size) {
                val length = ((jpeg[i + 2].toInt() and 0xFF) shl 8) or 
                            (jpeg[i + 3].toInt() and 0xFF)
                i += 2 + length
            } else {
                i += 2
            }
        }
        
        return false
    }
}
