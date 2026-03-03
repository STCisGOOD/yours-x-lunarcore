package com.yours.app.vault

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.Contact
import com.yours.app.mesh.MeshCoreManager
import com.yours.app.mesh.MeshConnectionState
import com.yours.app.messaging.LunarSessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.Inflater
import java.util.zip.InflaterOutputStream

/**
 * ArtifactSharingManager - Secure artifact sharing via multiple channels.
 *
 * Sharing Methods:
 * 1. MeshCore Transport - Direct P2P over LoRa mesh (most secure)
 * 2. External Apps - Encrypted export via Android share sheet
 * 3. QR Code - For small artifacts (< 2KB compressed)
 * 4. NFC - Tap-to-share for proximity transfer
 *
 * Security Model:
 * - All external shares are encrypted with recipient's public key
 * - QR/NFC include verification hash for integrity
 * - MeshCore uses end-to-end encrypted sessions
 * - Plaintext NEVER leaves the device unencrypted
 */
class ArtifactSharingManager(
    private val context: Context,
    private val meshManager: MeshCoreManager?,
    private val sessionManager: LunarSessionManager?
) {

    companion object {
        private const val TAG = "ArtifactSharingManager"

        // QR code limits
        private const val QR_MAX_BYTES = 2048  // Max compressed size for QR
        private const val QR_VERSION = 0x01
        private const val QR_SIZE = 512        // QR image size in pixels

        // NFC limits
        private const val NFC_MAX_BYTES = 4096  // NDEF max practical size

        // Chunk size for mesh transfer
        private const val MESH_CHUNK_SIZE = 200  // LoRa MTU is ~237 bytes

        // Share protocol version
        private const val SHARE_PROTOCOL_VERSION: Byte = 0x01

        // Share type markers
        private const val SHARE_TYPE_FULL: Byte = 0x01      // Complete artifact
        private const val SHARE_TYPE_REFERENCE: Byte = 0x02  // Reference to fetch later
        private const val SHARE_TYPE_CHUNKED: Byte = 0x03    // Multi-part transfer
    }

    /**
     * Current share operation state.
     */
    sealed class ShareState {
        object Idle : ShareState()
        object Preparing : ShareState()
        data class Ready(val method: ShareMethod, val data: Any) : ShareState()
        data class Transferring(val progress: Float, val method: ShareMethod) : ShareState()
        data class Completed(val method: ShareMethod) : ShareState()
        data class Failed(val error: String, val method: ShareMethod) : ShareState()
    }

    /**
     * Available sharing methods.
     */
    enum class ShareMethod {
        MESH_DIRECT,    // Via MeshCore LoRa network
        EXTERNAL_APP,   // Via Android share intent
        QR_CODE,        // Via QR code display
        NFC             // Via NFC tap
    }

    private val _shareState = MutableStateFlow<ShareState>(ShareState.Idle)
    val shareState: StateFlow<ShareState> = _shareState

    /**
     * Check which sharing methods are available for an artifact.
     *
     * @param decryptedSize Size of decrypted artifact in bytes
     * @return Set of available sharing methods
     */
    fun getAvailableMethods(decryptedSize: Int): Set<ShareMethod> {
        val methods = mutableSetOf<ShareMethod>()

        // External app sharing is always available
        methods.add(ShareMethod.EXTERNAL_APP)

        // MeshCore if connected
        if (meshManager?.connectionState?.value == MeshConnectionState.CONNECTED) {
            methods.add(ShareMethod.MESH_DIRECT)
        }

        // QR code for small artifacts only
        val estimatedCompressedSize = estimateCompressedSize(decryptedSize)
        if (estimatedCompressedSize <= QR_MAX_BYTES) {
            methods.add(ShareMethod.QR_CODE)
        }

        // NFC if available and artifact fits
        val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        if (nfcAdapter != null && nfcAdapter.isEnabled && estimatedCompressedSize <= NFC_MAX_BYTES) {
            methods.add(ShareMethod.NFC)
        }

        return methods
    }

    // ========================================================================
    // MESHCORE TRANSPORT SHARING
    // ========================================================================

    /**
     * Share artifact via MeshCore transport to a contact.
     *
     * Uses the established LunarSession for end-to-end encryption.
     * Supports chunked transfer for large files.
     *
     * @param artifact The artifact to share
     * @param decryptedContent The decrypted content bytes
     * @param recipient The contact to share with
     * @param ourSecretKey Our X25519 session private key (32 bytes) for Double Ratchet
     */
    suspend fun shareViaMesh(
        artifact: Artifact,
        decryptedContent: ByteArray,
        recipient: Contact,
        ourSecretKey: ByteArray
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            _shareState.value = ShareState.Preparing

            // Verify mesh connection
            if (meshManager?.connectionState?.value != MeshConnectionState.CONNECTED) {
                _shareState.value = ShareState.Failed("MeshCore not connected", ShareMethod.MESH_DIRECT)
                return@withContext Result.failure(Exception("MeshCore not connected"))
            }

            // Get or create session with recipient
            val sessionMgr = sessionManager
                ?: return@withContext Result.failure(Exception("Session manager not available"))

            val (session, handshake) = sessionMgr.getOrCreateSession(recipient, ourSecretKey)

            // If new session, send handshake first
            if (handshake != null) {
                val handshakeResult = meshManager.sendEncryptedMessage(
                    recipient.encryptionPublicKey,
                    handshake
                )
                if (handshakeResult.isFailure) {
                    _shareState.value = ShareState.Failed(
                        "Failed to establish session",
                        ShareMethod.MESH_DIRECT
                    )
                    return@withContext Result.failure(Exception("Failed to establish session"))
                }
            }

            // Prepare transfer payload
            val payload = prepareTransferPayload(artifact, decryptedContent)

            // Check if chunking is needed
            if (payload.size <= MESH_CHUNK_SIZE) {
                // Single packet transfer
                _shareState.value = ShareState.Transferring(0.5f, ShareMethod.MESH_DIRECT)

                val encrypted = sessionMgr.encrypt(recipient.did, payload)
                val result = meshManager.sendEncryptedMessage(
                    recipient.encryptionPublicKey,
                    encrypted
                )

                BedrockCore.zeroize(payload)

                if (result.isSuccess) {
                    _shareState.value = ShareState.Completed(ShareMethod.MESH_DIRECT)
                    Result.success(Unit)
                } else {
                    _shareState.value = ShareState.Failed(
                        result.exceptionOrNull()?.message ?: "Transfer failed",
                        ShareMethod.MESH_DIRECT
                    )
                    Result.failure(result.exceptionOrNull() ?: Exception("Transfer failed"))
                }
            } else {
                // Chunked transfer
                val result = sendChunkedMesh(payload, recipient, sessionMgr)
                BedrockCore.zeroize(payload)
                result
            }
        } catch (e: Exception) {
            _shareState.value = ShareState.Failed(e.message ?: "Unknown error", ShareMethod.MESH_DIRECT)
            Result.failure(e)
        }
    }

    /**
     * Send large artifact in chunks over mesh.
     */
    private suspend fun sendChunkedMesh(
        payload: ByteArray,
        recipient: Contact,
        sessionMgr: LunarSessionManager
    ): Result<Unit> {
        val totalChunks = (payload.size + MESH_CHUNK_SIZE - 1) / MESH_CHUNK_SIZE
        val transferId = BedrockCore.randomBytes(8)

        for (i in 0 until totalChunks) {
            val start = i * MESH_CHUNK_SIZE
            val end = minOf(start + MESH_CHUNK_SIZE, payload.size)
            val chunkData = payload.copyOfRange(start, end)

            // Create chunk header
            val chunk = createChunkPacket(
                transferId = transferId,
                chunkIndex = i,
                totalChunks = totalChunks,
                data = chunkData
            )

            // Encrypt and send
            val encrypted = sessionMgr.encrypt(recipient.did, chunk)
            val result = meshManager!!.sendEncryptedMessage(
                recipient.encryptionPublicKey,
                encrypted
            )

            BedrockCore.zeroize(chunkData)
            BedrockCore.zeroize(chunk)

            if (result.isFailure) {
                _shareState.value = ShareState.Failed(
                    "Chunk $i failed: ${result.exceptionOrNull()?.message}",
                    ShareMethod.MESH_DIRECT
                )
                return Result.failure(result.exceptionOrNull() ?: Exception("Chunk transfer failed"))
            }

            // Update progress
            _shareState.value = ShareState.Transferring(
                (i + 1).toFloat() / totalChunks,
                ShareMethod.MESH_DIRECT
            )
        }

        BedrockCore.zeroize(transferId)
        _shareState.value = ShareState.Completed(ShareMethod.MESH_DIRECT)
        return Result.success(Unit)
    }

    /**
     * Create a chunk packet for multi-part transfer.
     */
    private fun createChunkPacket(
        transferId: ByteArray,
        chunkIndex: Int,
        totalChunks: Int,
        data: ByteArray
    ): ByteArray {
        // Format: [type: 1] [transfer_id: 8] [chunk_idx: 2] [total: 2] [data_len: 2] [data]
        val packet = ByteArray(1 + 8 + 2 + 2 + 2 + data.size)
        var offset = 0

        packet[offset++] = SHARE_TYPE_CHUNKED

        System.arraycopy(transferId, 0, packet, offset, 8)
        offset += 8

        packet[offset++] = (chunkIndex shr 8).toByte()
        packet[offset++] = chunkIndex.toByte()

        packet[offset++] = (totalChunks shr 8).toByte()
        packet[offset++] = totalChunks.toByte()

        packet[offset++] = (data.size shr 8).toByte()
        packet[offset++] = data.size.toByte()

        System.arraycopy(data, 0, packet, offset, data.size)

        return packet
    }

    // ========================================================================
    // EXTERNAL APP SHARING (Encrypted)
    // ========================================================================

    /**
     * Share artifact via Android share intent with encryption.
     *
     * Creates a temporary encrypted file that can be shared to other apps.
     * The recipient needs the decryption key (shared out-of-band or via ContactHello).
     *
     * @param artifact The artifact to share
     * @param decryptedContent The decrypted content bytes
     * @param recipientPublicKey Recipient's Hk-OVCT public key for encryption
     * @return Share intent ready to start
     */
    suspend fun prepareExternalShare(
        artifact: Artifact,
        decryptedContent: ByteArray,
        recipientPublicKey: ByteArray
    ): Intent = withContext(Dispatchers.IO) {
        _shareState.value = ShareState.Preparing

        try {
            // Re-encrypt for recipient
            val encryptedForRecipient = BedrockCore.hkovctEncrypt(recipientPublicKey, decryptedContent)

            // Create share package with metadata
            val sharePackage = createSharePackage(artifact, encryptedForRecipient)

            // Write to temporary file in cache directory
            val cacheDir = File(context.cacheDir, "shares")
            cacheDir.mkdirs()

            val fileName = "${artifact.id}.yours"
            val shareFile = File(cacheDir, fileName)
            shareFile.writeBytes(sharePackage)

            // Get content URI via FileProvider
            val contentUri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                shareFile
            )

            // Clean up encrypted data
            BedrockCore.zeroize(encryptedForRecipient)
            BedrockCore.zeroize(sharePackage)

            // Create share intent
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_SUBJECT, artifact.metadata.name ?: "Encrypted Artifact")
                putExtra(
                    Intent.EXTRA_TEXT,
                    "Encrypted artifact from Yours. " +
                    "Open with Yours app to decrypt."
                )
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            _shareState.value = ShareState.Ready(ShareMethod.EXTERNAL_APP, shareIntent)

            Intent.createChooser(shareIntent, "Share encrypted artifact via...")

        } catch (e: Exception) {
            _shareState.value = ShareState.Failed(e.message ?: "Failed to prepare share", ShareMethod.EXTERNAL_APP)
            throw e
        }
    }

    /**
     * Create a share package containing encrypted artifact and metadata.
     */
    private fun createSharePackage(artifact: Artifact, encryptedContent: ByteArray): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Magic bytes: "YOURS" (5 bytes)
        buffer.addAll("YOURS".toByteArray(StandardCharsets.UTF_8).toList())

        // Version
        buffer.add(SHARE_PROTOCOL_VERSION)

        // Share type
        buffer.add(SHARE_TYPE_FULL)

        // Content hash (for verification)
        buffer.addAll(artifact.contentHash.toList())

        // Content type length + content type
        val contentTypeBytes = artifact.contentType.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(contentTypeBytes.size).toList())
        buffer.addAll(contentTypeBytes.toList())

        // Metadata name (optional)
        val nameBytes = (artifact.metadata.name ?: "").toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(nameBytes.size).toList())
        buffer.addAll(nameBytes.toList())

        // Timestamp
        buffer.addAll(longToBytes(artifact.createdAt).toList())

        // Encrypted content length + content
        buffer.addAll(intToBytes(encryptedContent.size).toList())
        buffer.addAll(encryptedContent.toList())

        // Signature placeholder (for future: sign with sender's key)
        buffer.addAll(ByteArray(64).toList())

        return buffer.toByteArray()
    }

    // ========================================================================
    // QR CODE SHARING
    // ========================================================================

    /**
     * Generate QR code for sharing a small artifact.
     *
     * Only works for artifacts that compress to under 2KB.
     *
     * @param artifact The artifact to share
     * @param decryptedContent The decrypted content bytes
     * @param recipientPublicKey Recipient's public key for encryption
     * @return Bitmap of QR code, or null if too large
     */
    suspend fun generateQRCode(
        artifact: Artifact,
        decryptedContent: ByteArray,
        recipientPublicKey: ByteArray
    ): Bitmap? = withContext(Dispatchers.IO) {
        _shareState.value = ShareState.Preparing

        try {
            // Compress content
            val compressed = compress(decryptedContent)

            if (compressed.size > QR_MAX_BYTES) {
                BedrockCore.zeroize(compressed)
                _shareState.value = ShareState.Failed(
                    "Artifact too large for QR (${compressed.size} > $QR_MAX_BYTES bytes)",
                    ShareMethod.QR_CODE
                )
                return@withContext null
            }

            // Encrypt for recipient
            val encrypted = BedrockCore.hkovctEncrypt(recipientPublicKey, compressed)
            BedrockCore.zeroize(compressed)

            // Create QR payload
            val qrPayload = createQRPayload(artifact, encrypted)
            BedrockCore.zeroize(encrypted)

            // Base64 encode for QR
            val base64 = android.util.Base64.encodeToString(
                qrPayload,
                android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE
            )
            BedrockCore.zeroize(qrPayload)

            // Generate QR bitmap
            val writer = QRCodeWriter()
            val hints = mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.MARGIN to 2
            )

            val bitMatrix = writer.encode(
                "yours://$base64",
                BarcodeFormat.QR_CODE,
                QR_SIZE,
                QR_SIZE,
                hints
            )

            val bitmap = Bitmap.createBitmap(QR_SIZE, QR_SIZE, Bitmap.Config.ARGB_8888)
            for (x in 0 until QR_SIZE) {
                for (y in 0 until QR_SIZE) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }

            _shareState.value = ShareState.Ready(ShareMethod.QR_CODE, bitmap)
            bitmap

        } catch (e: Exception) {
            _shareState.value = ShareState.Failed(
                e.message ?: "Failed to generate QR",
                ShareMethod.QR_CODE
            )
            null
        }
    }

    /**
     * Create payload for QR code.
     */
    private fun createQRPayload(artifact: Artifact, encryptedContent: ByteArray): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Version
        buffer.add(QR_VERSION.toByte())

        // Content hash (first 8 bytes for verification)
        buffer.addAll(artifact.contentHash.take(8))

        // Content type (compressed to single byte)
        buffer.add(contentTypeToCode(artifact.contentType))

        // Encrypted content
        buffer.addAll(encryptedContent.toList())

        return buffer.toByteArray()
    }

    /**
     * Parse QR code payload.
     *
     * @param qrData Base64-decoded QR payload
     * @param recipientSecretKey Recipient's secret key for decryption
     * @return Pair of (contentType, decryptedContent) or null on failure
     */
    fun parseQRPayload(
        qrData: ByteArray,
        recipientSecretKey: ByteArray
    ): Pair<String, ByteArray>? {
        if (qrData.size < 10) return null

        var offset = 0

        // Version
        val version = qrData[offset++]
        if (version != QR_VERSION.toByte()) return null

        // Content hash prefix (for future verification)
        val hashPrefix = qrData.copyOfRange(offset, offset + 8)
        offset += 8

        // Content type
        val contentType = codeToContentType(qrData[offset++])

        // Encrypted content
        val encrypted = qrData.copyOfRange(offset, qrData.size)

        // Decrypt
        val decrypted = BedrockCore.hkovctDecrypt(recipientSecretKey, encrypted)
            ?: return null

        // Decompress
        val decompressed = decompress(decrypted)
        BedrockCore.zeroize(decrypted)

        return if (decompressed != null) {
            Pair(contentType, decompressed)
        } else {
            null
        }
    }

    // ========================================================================
    // NFC SHARING
    // ========================================================================

    /**
     * Prepare NFC message for sharing.
     *
     * @param artifact The artifact to share
     * @param decryptedContent The decrypted content bytes
     * @param recipientPublicKey Recipient's public key for encryption
     * @return NDEF message ready for NFC transmission, or null if too large
     */
    suspend fun prepareNFCMessage(
        artifact: Artifact,
        decryptedContent: ByteArray,
        recipientPublicKey: ByteArray
    ): NdefMessage? = withContext(Dispatchers.IO) {
        _shareState.value = ShareState.Preparing

        try {
            // Compress content
            val compressed = compress(decryptedContent)

            if (compressed.size > NFC_MAX_BYTES) {
                BedrockCore.zeroize(compressed)
                _shareState.value = ShareState.Failed(
                    "Artifact too large for NFC (${compressed.size} > $NFC_MAX_BYTES bytes)",
                    ShareMethod.NFC
                )
                return@withContext null
            }

            // Encrypt for recipient
            val encrypted = BedrockCore.hkovctEncrypt(recipientPublicKey, compressed)
            BedrockCore.zeroize(compressed)

            // Create NFC payload (same format as QR for consistency)
            val payload = createQRPayload(artifact, encrypted)
            BedrockCore.zeroize(encrypted)

            // Create NDEF message with external type
            val ndefRecord = NdefRecord.createExternal(
                "com.yours.app",
                "artifact",
                payload
            )

            val message = NdefMessage(arrayOf(ndefRecord))

            _shareState.value = ShareState.Ready(ShareMethod.NFC, message)
            message

        } catch (e: Exception) {
            _shareState.value = ShareState.Failed(
                e.message ?: "Failed to prepare NFC",
                ShareMethod.NFC
            )
            null
        }
    }

    /**
     * Write NDEF message to NFC tag.
     *
     * @param tag The NFC tag to write to
     * @param message The NDEF message to write
     * @return Result indicating success or failure
     */
    suspend fun writeToNFCTag(tag: Tag, message: NdefMessage): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            _shareState.value = ShareState.Transferring(0.5f, ShareMethod.NFC)

            // Try NDEF first (already formatted tag)
            val ndef = Ndef.get(tag)
            if (ndef != null) {
                ndef.connect()
                try {
                    if (!ndef.isWritable) {
                        _shareState.value = ShareState.Failed("Tag is read-only", ShareMethod.NFC)
                        return@withContext Result.failure(Exception("Tag is read-only"))
                    }

                    val maxSize = ndef.maxSize
                    val messageSize = message.toByteArray().size

                    if (messageSize > maxSize) {
                        _shareState.value = ShareState.Failed(
                            "Message too large ($messageSize > $maxSize bytes)",
                            ShareMethod.NFC
                        )
                        return@withContext Result.failure(Exception("Message too large for tag"))
                    }

                    ndef.writeNdefMessage(message)
                    _shareState.value = ShareState.Completed(ShareMethod.NFC)
                    return@withContext Result.success(Unit)
                } finally {
                    ndef.close()
                }
            }

            // Try NdefFormatable (unformatted tag)
            val ndefFormatable = NdefFormatable.get(tag)
            if (ndefFormatable != null) {
                ndefFormatable.connect()
                try {
                    ndefFormatable.format(message)
                    _shareState.value = ShareState.Completed(ShareMethod.NFC)
                    return@withContext Result.success(Unit)
                } finally {
                    ndefFormatable.close()
                }
            }

            _shareState.value = ShareState.Failed("Tag not compatible", ShareMethod.NFC)
            Result.failure(Exception("Tag not NDEF compatible"))

        } catch (e: Exception) {
            _shareState.value = ShareState.Failed(e.message ?: "NFC write failed", ShareMethod.NFC)
            Result.failure(e)
        }
    }

    /**
     * Parse received NFC NDEF message.
     *
     * @param message The received NDEF message
     * @param recipientSecretKey Recipient's secret key for decryption
     * @return Pair of (contentType, decryptedContent) or null on failure
     */
    fun parseNFCMessage(
        message: NdefMessage,
        recipientSecretKey: ByteArray
    ): Pair<String, ByteArray>? {
        for (record in message.records) {
            // Check for our external type
            val type = String(record.type, StandardCharsets.UTF_8)
            if (type == "artifact") {
                return parseQRPayload(record.payload, recipientSecretKey)
            }
        }
        return null
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * Reset share state to idle.
     */
    fun reset() {
        _shareState.value = ShareState.Idle
    }

    /**
     * Prepare the transfer payload for mesh sharing.
     */
    private fun prepareTransferPayload(artifact: Artifact, decryptedContent: ByteArray): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Type marker
        buffer.add(SHARE_TYPE_FULL)

        // Content hash
        buffer.addAll(artifact.contentHash.toList())

        // Content type
        val contentTypeBytes = artifact.contentType.toByteArray(StandardCharsets.UTF_8)
        buffer.add(contentTypeBytes.size.toByte())
        buffer.addAll(contentTypeBytes.toList())

        // Metadata name (truncated to 64 chars)
        val nameBytes = (artifact.metadata.name ?: "").take(64).toByteArray(StandardCharsets.UTF_8)
        buffer.add(nameBytes.size.toByte())
        buffer.addAll(nameBytes.toList())

        // Compressed content
        val compressed = compress(decryptedContent)
        buffer.addAll(intToBytes(compressed.size).toList())
        buffer.addAll(compressed.toList())
        BedrockCore.zeroize(compressed)

        return buffer.toByteArray()
    }

    /**
     * Compress data using DEFLATE.
     */
    private fun compress(data: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        DeflaterOutputStream(output, deflater).use { it.write(data) }
        return output.toByteArray()
    }

    /**
     * Decompress DEFLATE data.
     */
    private fun decompress(data: ByteArray): ByteArray? {
        return try {
            val output = ByteArrayOutputStream()
            val inflater = Inflater()
            InflaterOutputStream(output, inflater).use { it.write(data) }
            output.toByteArray()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Estimate compressed size (rough heuristic).
     */
    private fun estimateCompressedSize(originalSize: Int): Int {
        // Images typically compress to 85-95% of original
        // Text compresses to 10-40%
        // Assume worst case of 90% for safety
        return (originalSize * 0.9).toInt()
    }

    /**
     * Map content type to single byte code for compact representation.
     */
    private fun contentTypeToCode(contentType: String): Byte {
        return when (contentType) {
            "image/jpeg" -> 0x01
            "image/png" -> 0x02
            "image/gif" -> 0x03
            "image/webp" -> 0x04
            "application/pdf" -> 0x10
            "text/plain" -> 0x20
            "application/json" -> 0x21
            "video/mp4" -> 0x30
            "audio/mpeg" -> 0x40
            else -> 0x00  // Unknown
        }
    }

    /**
     * Map byte code back to content type.
     */
    private fun codeToContentType(code: Byte): String {
        return when (code.toInt()) {
            0x01 -> "image/jpeg"
            0x02 -> "image/png"
            0x03 -> "image/gif"
            0x04 -> "image/webp"
            0x10 -> "application/pdf"
            0x20 -> "text/plain"
            0x21 -> "application/json"
            0x30 -> "video/mp4"
            0x40 -> "audio/mpeg"
            else -> "application/octet-stream"
        }
    }

    // ========================================================================
    // BYTE CONVERSION HELPERS
    // ========================================================================

    private fun intToBytes(value: Int): ByteArray {
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }

    private fun longToBytes(value: Long): ByteArray {
        return byteArrayOf(
            (value shr 56).toByte(),
            (value shr 48).toByte(),
            (value shr 40).toByte(),
            (value shr 32).toByte(),
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }
}
