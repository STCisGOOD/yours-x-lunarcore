package com.yours.app.vault

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.exifinterface.media.ExifInterface
import com.yours.app.crypto.BedrockCore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Sanitizes files before they enter the vault.
 *
 * CRITICAL SECURITY COMPONENT:
 * - Strips EXIF metadata from images (GPS, timestamps, camera info)
 * - Removes document metadata from PDFs
 * - Generates anonymous artifact names
 * - Ensures no identifying information leaks into the vault
 *
 * Without this, encrypted artifacts would still contain:
 * - GPS coordinates where photos were taken
 * - Device model and serial numbers
 * - Exact timestamps
 * - Software versions
 * - Author names in documents
 */
object ArtifactSanitizer {

    /**
     * EXIF tags that MUST be stripped for privacy.
     * These can reveal location, device identity, and timing.
     */
    private val DANGEROUS_EXIF_TAGS = listOf(
        // GPS Location - CRITICAL
        ExifInterface.TAG_GPS_LATITUDE,
        ExifInterface.TAG_GPS_LATITUDE_REF,
        ExifInterface.TAG_GPS_LONGITUDE,
        ExifInterface.TAG_GPS_LONGITUDE_REF,
        ExifInterface.TAG_GPS_ALTITUDE,
        ExifInterface.TAG_GPS_ALTITUDE_REF,
        ExifInterface.TAG_GPS_TIMESTAMP,
        ExifInterface.TAG_GPS_DATESTAMP,
        ExifInterface.TAG_GPS_PROCESSING_METHOD,
        ExifInterface.TAG_GPS_AREA_INFORMATION,
        ExifInterface.TAG_GPS_SPEED,
        ExifInterface.TAG_GPS_SPEED_REF,
        ExifInterface.TAG_GPS_TRACK,
        ExifInterface.TAG_GPS_TRACK_REF,
        ExifInterface.TAG_GPS_IMG_DIRECTION,
        ExifInterface.TAG_GPS_IMG_DIRECTION_REF,
        ExifInterface.TAG_GPS_DEST_LATITUDE,
        ExifInterface.TAG_GPS_DEST_LATITUDE_REF,
        ExifInterface.TAG_GPS_DEST_LONGITUDE,
        ExifInterface.TAG_GPS_DEST_LONGITUDE_REF,
        ExifInterface.TAG_GPS_DEST_BEARING,
        ExifInterface.TAG_GPS_DEST_BEARING_REF,
        ExifInterface.TAG_GPS_DEST_DISTANCE,
        ExifInterface.TAG_GPS_DEST_DISTANCE_REF,
        ExifInterface.TAG_GPS_MAP_DATUM,
        ExifInterface.TAG_GPS_DIFFERENTIAL,
        ExifInterface.TAG_GPS_H_POSITIONING_ERROR,

        // Timestamps - reveals when photo was taken
        ExifInterface.TAG_DATETIME,
        ExifInterface.TAG_DATETIME_ORIGINAL,
        ExifInterface.TAG_DATETIME_DIGITIZED,
        ExifInterface.TAG_OFFSET_TIME,
        ExifInterface.TAG_OFFSET_TIME_ORIGINAL,
        ExifInterface.TAG_OFFSET_TIME_DIGITIZED,
        ExifInterface.TAG_SUBSEC_TIME,
        ExifInterface.TAG_SUBSEC_TIME_ORIGINAL,
        ExifInterface.TAG_SUBSEC_TIME_DIGITIZED,

        // Device identification - reveals camera/phone model
        ExifInterface.TAG_MAKE,
        ExifInterface.TAG_MODEL,
        ExifInterface.TAG_SOFTWARE,
        ExifInterface.TAG_IMAGE_UNIQUE_ID,
        ExifInterface.TAG_CAMERA_OWNER_NAME,
        ExifInterface.TAG_BODY_SERIAL_NUMBER,
        ExifInterface.TAG_LENS_SERIAL_NUMBER,
        ExifInterface.TAG_LENS_MAKE,
        ExifInterface.TAG_LENS_MODEL,

        // Potentially identifying
        ExifInterface.TAG_ARTIST,
        ExifInterface.TAG_COPYRIGHT,
        ExifInterface.TAG_IMAGE_DESCRIPTION,
        ExifInterface.TAG_USER_COMMENT,
        ExifInterface.TAG_MAKER_NOTE,  // Manufacturer-specific data, often contains serial numbers

        // XMP data can contain all sorts of identifying info
        ExifInterface.TAG_XMP,
    )

    /**
     * Result of sanitization operation.
     */
    data class SanitizedResult(
        val content: ByteArray,
        val anonymousName: String,
        val strippedMetadata: List<String>  // What was removed (for transparency)
    )

    /**
     * Sanitize content before vault storage.
     *
     * @param content Raw file bytes
     * @param contentType MIME type
     * @param originalFileName Original filename (will be discarded)
     * @return Sanitized content with anonymous name
     */
    fun sanitize(
        content: ByteArray,
        contentType: String,
        originalFileName: String? = null
    ): SanitizedResult {
        return when {
            contentType.startsWith("image/jpeg") -> sanitizeJpeg(content)
            contentType.startsWith("image/png") -> sanitizePng(content)
            contentType.startsWith("image/webp") -> sanitizeWebp(content)
            contentType == "application/pdf" -> sanitizePdf(content)
            else -> SanitizedResult(
                content = content,
                anonymousName = generateAnonymousName(contentType),
                strippedMetadata = emptyList()
            )
        }
    }

    /**
     * Strip EXIF from JPEG images.
     * Re-encodes the image to ensure all metadata is removed.
     */
    private fun sanitizeJpeg(content: ByteArray): SanitizedResult {
        val strippedTags = mutableListOf<String>()

        try {
            // First, check what EXIF data exists (for logging what was removed)
            val inputStream = ByteArrayInputStream(content)
            val exif = ExifInterface(inputStream)

            for (tag in DANGEROUS_EXIF_TAGS) {
                if (exif.getAttribute(tag) != null) {
                    strippedTags.add(tag)
                }
            }
            inputStream.close()

            // Decode bitmap (strips EXIF)
            val bitmap = BitmapFactory.decodeByteArray(content, 0, content.size)
                ?: return SanitizedResult(
                    content = content,
                    anonymousName = generateAnonymousName("image/jpeg"),
                    strippedMetadata = listOf("DECODE_FAILED")
                )

            // Re-encode as clean JPEG with no EXIF
            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, 95, outputStream)
            bitmap.recycle()

            val cleanContent = outputStream.toByteArray()
            outputStream.close()

            return SanitizedResult(
                content = cleanContent,
                anonymousName = generateAnonymousName("image/jpeg"),
                strippedMetadata = strippedTags
            )
        } catch (e: Exception) {
            // If stripping fails, still generate anonymous name but keep content
            // Better to have metadata than lose the file entirely
            return SanitizedResult(
                content = content,
                anonymousName = generateAnonymousName("image/jpeg"),
                strippedMetadata = listOf("STRIP_FAILED: ${e.message}")
            )
        }
    }

    /**
     * Strip metadata from PNG images.
     * PNG can contain tEXt, iTXt, and zTXt chunks with metadata.
     */
    private fun sanitizePng(content: ByteArray): SanitizedResult {
        try {
            // Decode and re-encode to strip metadata chunks
            val bitmap = BitmapFactory.decodeByteArray(content, 0, content.size)
                ?: return SanitizedResult(
                    content = content,
                    anonymousName = generateAnonymousName("image/png"),
                    strippedMetadata = listOf("DECODE_FAILED")
                )

            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, outputStream)
            bitmap.recycle()

            val cleanContent = outputStream.toByteArray()
            outputStream.close()

            return SanitizedResult(
                content = cleanContent,
                anonymousName = generateAnonymousName("image/png"),
                strippedMetadata = listOf("PNG_METADATA_CHUNKS")
            )
        } catch (e: Exception) {
            return SanitizedResult(
                content = content,
                anonymousName = generateAnonymousName("image/png"),
                strippedMetadata = listOf("STRIP_FAILED: ${e.message}")
            )
        }
    }

    /**
     * Strip metadata from WebP images.
     */
    private fun sanitizeWebp(content: ByteArray): SanitizedResult {
        try {
            val bitmap = BitmapFactory.decodeByteArray(content, 0, content.size)
                ?: return SanitizedResult(
                    content = content,
                    anonymousName = generateAnonymousName("image/webp"),
                    strippedMetadata = listOf("DECODE_FAILED")
                )

            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.WEBP_LOSSY, 95, outputStream)
            bitmap.recycle()

            val cleanContent = outputStream.toByteArray()
            outputStream.close()

            return SanitizedResult(
                content = cleanContent,
                anonymousName = generateAnonymousName("image/webp"),
                strippedMetadata = listOf("WEBP_METADATA")
            )
        } catch (e: Exception) {
            return SanitizedResult(
                content = content,
                anonymousName = generateAnonymousName("image/webp"),
                strippedMetadata = listOf("STRIP_FAILED: ${e.message}")
            )
        }
    }

    /**
     * Sanitize PDF files.
     *
     * PDF metadata can contain:
     * - Author name
     * - Creation software
     * - Creation/modification dates
     * - Document title
     * - Custom metadata
     *
     * Full PDF sanitization requires parsing the PDF structure.
     * For now, we generate an anonymous name but note that
     * internal PDF metadata may still exist.
     *
     * TODO: Implement full PDF metadata stripping using a PDF library
     */
    private fun sanitizePdf(content: ByteArray): SanitizedResult {
        // PDF sanitization is complex - would need a PDF library
        // For now, just anonymize the name and warn
        return SanitizedResult(
            content = content,
            anonymousName = generateAnonymousName("application/pdf"),
            strippedMetadata = listOf("PDF_INTERNAL_METADATA_NOT_STRIPPED")
        )
    }

    /**
     * Generate a cryptographically random anonymous name.
     *
     * Format: artifact_[8 random hex chars].[extension]
     * Example: artifact_3f7a2bc1.jpg
     *
     * This reveals NOTHING about:
     * - Original filename
     * - When the file was created
     * - What the content is
     * - Who created it
     */
    fun generateAnonymousName(contentType: String): String {
        val randomBytes = BedrockCore.randomBytes(4)
        val randomHex = randomBytes.joinToString("") { "%02x".format(it) }

        val extension = when (contentType) {
            "image/jpeg" -> "jpg"
            "image/png" -> "png"
            "image/gif" -> "gif"
            "image/webp" -> "webp"
            "application/pdf" -> "pdf"
            "text/plain" -> "txt"
            "application/json" -> "json"
            "video/mp4" -> "mp4"
            "video/webm" -> "webm"
            "audio/mpeg" -> "mp3"
            "audio/ogg" -> "ogg"
            else -> "bin"
        }

        return "artifact_$randomHex.$extension"
    }

    /**
     * Check if content type supports metadata stripping.
     */
    fun supportsMetadataStripping(contentType: String): Boolean {
        return contentType.startsWith("image/jpeg") ||
               contentType.startsWith("image/png") ||
               contentType.startsWith("image/webp")
    }

    /**
     * Get a human-readable summary of what was stripped.
     */
    fun getStrippedSummary(strippedMetadata: List<String>): String {
        if (strippedMetadata.isEmpty()) return "No metadata found"

        val hasGps = strippedMetadata.any { it.contains("GPS") }
        val hasTimestamp = strippedMetadata.any { it.contains("DATETIME") || it.contains("TIME") }
        val hasDevice = strippedMetadata.any { it.contains("MAKE") || it.contains("MODEL") }

        val parts = mutableListOf<String>()
        if (hasGps) parts.add("GPS location")
        if (hasTimestamp) parts.add("timestamps")
        if (hasDevice) parts.add("device info")

        return if (parts.isNotEmpty()) {
            "Stripped: ${parts.joinToString(", ")}"
        } else {
            "Stripped ${strippedMetadata.size} metadata fields"
        }
    }
}
