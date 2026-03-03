package com.yours.app.vault

import android.content.Context
import android.util.Log
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Encrypted vault storage for artifacts.
 * 
 * All artifacts are stored as encrypted blobs.
 * The index (list of artifacts) is also encrypted.
 * Nothing is readable without the owner's keys.
 */
class VaultStorage(private val context: Context) {
    
    companion object {
        private const val TAG = "VaultStorage"
        private const val VAULT_DIR = "vault"
        private const val INDEX_FILE = "index.yours"
        private const val ARTIFACT_EXTENSION = ".own"
    }
    
    private val vaultDir: File
        get() = File(context.filesDir, VAULT_DIR).also { it.mkdirs() }
    
    private val indexFile: File
        get() = File(vaultDir, INDEX_FILE)
    
    private val mutex = Mutex()
    
    // In-memory cache of artifact metadata (not content)
    private val _artifacts = MutableStateFlow<List<ArtifactEntry>>(emptyList())
    val artifacts: Flow<List<ArtifactEntry>> = _artifacts.asStateFlow()
    
    /**
     * Lightweight artifact entry for listing.
     * Does not contain encrypted content (loaded on demand).
     */
    data class ArtifactEntry(
        val id: String,
        val contentType: String,
        val createdAt: Long,
        val metadata: ArtifactMetadata,
        val sizeBytes: Long
    )
    
    /**
     * Initialize vault storage.
     * Call after identity is unlocked.
     * 
     * @param indexKey Key for encrypting/decrypting the index
     */
    suspend fun initialize(indexKey: ByteArray) = withContext(Dispatchers.IO) {
        mutex.withLock {
            loadIndex(indexKey)
        }
    }
    
    /**
     * Store an artifact in the vault.
     */
    suspend fun store(artifact: Artifact) = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Write encrypted artifact to file
            val artifactFile = File(vaultDir, "${artifact.id}$ARTIFACT_EXTENSION")
            val serialized = serializeArtifact(artifact)
            artifactFile.writeBytes(serialized)

            
            // Update index
            val entry = ArtifactEntry(
                id = artifact.id,
                contentType = artifact.contentType,
                createdAt = artifact.createdAt,
                metadata = artifact.metadata,
                sizeBytes = serialized.size.toLong()
            )
            
            _artifacts.value = _artifacts.value + entry
        }
    }
    
    /**
     * Load an artifact from the vault.
     * 
     * @param id Artifact ID
     * @return The artifact, or null if not found
     */
    suspend fun load(id: String): Artifact? = withContext(Dispatchers.IO) {
        mutex.withLock {
            val artifactFile = File(vaultDir, "$id$ARTIFACT_EXTENSION")
            if (!artifactFile.exists()) {
                return@withContext null
            }
            
            val serialized = artifactFile.readBytes()
            deserializeArtifact(serialized)
        }
    }
    
    /**
     * Rename an artifact in the vault.
     *
     * @param id Artifact ID
     * @param newName New name for the artifact
     * @return True if renamed successfully
     */
    suspend fun rename(id: String, newName: String): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            val artifactFile = File(vaultDir, "$id$ARTIFACT_EXTENSION")
            if (!artifactFile.exists()) {
                return@withContext false
            }

            try {
                // Load artifact
                val serialized = artifactFile.readBytes()
                val artifact = deserializeArtifact(serialized) ?: return@withContext false

                // Update metadata with new name
                val updatedMetadata = artifact.metadata.copy(name = newName)
                val updatedArtifact = artifact.copy(metadata = updatedMetadata)

                // Re-serialize and save
                val newSerialized = serializeArtifact(updatedArtifact)
                artifactFile.writeBytes(newSerialized)

                // Update index
                _artifacts.value = _artifacts.value.map { entry ->
                    if (entry.id == id) {
                        entry.copy(metadata = updatedMetadata)
                    } else {
                        entry
                    }
                }

                true
            } catch (e: Exception) {
                false
            }
        }
    }

    /**
     * Delete an artifact from the vault.
     * IMPORTANT: Only call this AFTER successful transfer.
     */
    suspend fun delete(id: String): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            val artifactFile = File(vaultDir, "$id$ARTIFACT_EXTENSION")
            
            if (artifactFile.exists()) {
                val size = artifactFile.length().toInt()
                // Pass 1: Zero fill
                artifactFile.writeBytes(ByteArray(size))
                // Pass 2: Random data
                artifactFile.writeBytes(BedrockCore.randomBytes(size))
                // Pass 3: Ones fill
                artifactFile.writeBytes(ByteArray(size) { 0xFF.toByte() })
                // Final pass: Random data before delete
                artifactFile.writeBytes(BedrockCore.randomBytes(size))
                artifactFile.delete()

                // Update index
                _artifacts.value = _artifacts.value.filter { it.id != id }

                true
            } else {
                false
            }
        }
    }
    
    /**
     * Get total vault size in bytes.
     */
    fun getTotalSize(): Long {
        return vaultDir.listFiles()
            ?.filter { it.extension == "own" }
            ?.sumOf { it.length() }
            ?: 0L
    }
    
    /**
     * Save the index (call periodically and on app close).
     */
    suspend fun saveIndex(indexKey: ByteArray) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val indexData = serializeIndex(_artifacts.value)
            val encrypted = BedrockCore.aesEncrypt(indexKey, indexData)
            indexFile.writeBytes(encrypted)
            BedrockCore.zeroize(indexData)
        }
    }
    
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================
    
    private fun loadIndex(indexKey: ByteArray) {
        if (!indexFile.exists()) {
            _artifacts.value = emptyList()
            return
        }
        
        try {
            val encrypted = indexFile.readBytes()
            val decrypted = BedrockCore.aesDecrypt(indexKey, encrypted)

            if (decrypted != null) {
                _artifacts.value = deserializeIndex(decrypted)
                BedrockCore.zeroize(decrypted)
            } else {
                _artifacts.value = emptyList()
            }
        } catch (e: Exception) {
            _artifacts.value = emptyList()
        }
    }
    
    private fun serializeArtifact(artifact: Artifact): ByteArray {
        // Format:
        // [version: 1] [id_len: 4] [id] [content_type_len: 4] [content_type]
        // [content_hash: 32] [created_at: 8] [owner_did_len: 4] [owner_did?]
        // [metadata_len: 4] [metadata] [encrypted_content_len: 4] [encrypted_content]
        
        val buffer = mutableListOf<Byte>()
        
        // Version
        buffer.add(0x01)
        
        // ID
        val idBytes = artifact.id.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(idBytes.size).toList())
        buffer.addAll(idBytes.toList())
        
        // Content type
        val contentTypeBytes = artifact.contentType.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(contentTypeBytes.size).toList())
        buffer.addAll(contentTypeBytes.toList())
        
        // Content hash
        buffer.addAll(artifact.contentHash.toList())
        
        // Created at
        buffer.addAll(longToBytes(artifact.createdAt).toList())
        
        // Owner DID
        if (artifact.ownerDid != null) {
            val ownerBytes = artifact.ownerDid.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(ownerBytes.size).toList())
            buffer.addAll(ownerBytes.toList())
        } else {
            buffer.addAll(intToBytes(0).toList())
        }
        
        // Metadata (simplified)
        val metadataBytes = serializeMetadata(artifact.metadata)
        buffer.addAll(intToBytes(metadataBytes.size).toList())
        buffer.addAll(metadataBytes.toList())
        
        // Encrypted content
        buffer.addAll(intToBytes(artifact.encryptedContent.size).toList())
        buffer.addAll(artifact.encryptedContent.toList())
        
        return buffer.toByteArray()
    }
    
    private fun deserializeArtifact(data: ByteArray): Artifact? {
        try {
            var offset = 0
            
            // Version
            val version = data[offset++]
            if (version != 0x01.toByte()) return null
            
            // ID
            val idLen = bytesToInt(data, offset)
            offset += 4
            val id = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
            offset += idLen
            
            // Content type
            val contentTypeLen = bytesToInt(data, offset)
            offset += 4
            val contentType = String(data.copyOfRange(offset, offset + contentTypeLen), StandardCharsets.UTF_8)
            offset += contentTypeLen
            
            // Content hash
            val contentHash = data.copyOfRange(offset, offset + 32)
            offset += 32
            
            // Created at
            val createdAt = bytesToLong(data, offset)
            offset += 8
            
            // Owner DID
            val ownerDidLen = bytesToInt(data, offset)
            offset += 4
            val ownerDid = if (ownerDidLen > 0) {
                String(data.copyOfRange(offset, offset + ownerDidLen), StandardCharsets.UTF_8)
            } else null
            offset += ownerDidLen
            
            // Metadata
            val metadataLen = bytesToInt(data, offset)
            offset += 4
            val metadata = deserializeMetadata(data.copyOfRange(offset, offset + metadataLen))
            offset += metadataLen
            
            // Encrypted content
            val encryptedLen = bytesToInt(data, offset)
            offset += 4
            val encryptedContent = data.copyOfRange(offset, offset + encryptedLen)
            
            return Artifact(
                id = id,
                contentHash = contentHash,
                contentType = contentType,
                encryptedContent = encryptedContent,
                ownerDid = ownerDid,
                createdAt = createdAt,
                metadata = metadata
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize artifact", e)
            return null
        }
    }
    
    private fun serializeIndex(entries: List<ArtifactEntry>): ByteArray {
        val buffer = mutableListOf<Byte>()
        
        // Version
        buffer.add(0x01)
        
        // Count
        buffer.addAll(intToBytes(entries.size).toList())
        
        for (entry in entries) {
            // ID
            val idBytes = entry.id.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(idBytes.size).toList())
            buffer.addAll(idBytes.toList())
            
            // Content type
            val typeBytes = entry.contentType.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(typeBytes.size).toList())
            buffer.addAll(typeBytes.toList())
            
            // Created at
            buffer.addAll(longToBytes(entry.createdAt).toList())
            
            // Size
            buffer.addAll(longToBytes(entry.sizeBytes).toList())
            
            // Metadata
            val metaBytes = serializeMetadata(entry.metadata)
            buffer.addAll(intToBytes(metaBytes.size).toList())
            buffer.addAll(metaBytes.toList())
        }
        
        return buffer.toByteArray()
    }
    
    private fun deserializeIndex(data: ByteArray): List<ArtifactEntry> {
        try {
            var offset = 0
            
            // Version
            val version = data[offset++]
            if (version != 0x01.toByte()) return emptyList()
            
            // Count
            val count = bytesToInt(data, offset)
            offset += 4
            
            val entries = mutableListOf<ArtifactEntry>()
            
            repeat(count) {
                // ID
                val idLen = bytesToInt(data, offset)
                offset += 4
                val id = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
                offset += idLen
                
                // Content type
                val typeLen = bytesToInt(data, offset)
                offset += 4
                val contentType = String(data.copyOfRange(offset, offset + typeLen), StandardCharsets.UTF_8)
                offset += typeLen
                
                // Created at
                val createdAt = bytesToLong(data, offset)
                offset += 8
                
                // Size
                val sizeBytes = bytesToLong(data, offset)
                offset += 8
                
                // Metadata
                val metaLen = bytesToInt(data, offset)
                offset += 4
                val metadata = deserializeMetadata(data.copyOfRange(offset, offset + metaLen))
                offset += metaLen
                
                entries.add(ArtifactEntry(
                    id = id,
                    contentType = contentType,
                    createdAt = createdAt,
                    metadata = metadata,
                    sizeBytes = sizeBytes
                ))
            }
            
            return entries
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize index", e)
            return emptyList()
        }
    }
    
    private fun serializeMetadata(metadata: ArtifactMetadata): ByteArray {
        // Simple JSON-like format
        val sb = StringBuilder()
        sb.append("{")
        metadata.name?.let { sb.append("\"name\":\"$it\",") }
        metadata.description?.let { sb.append("\"desc\":\"$it\",") }
        if (metadata.tags.isNotEmpty()) {
            sb.append("\"tags\":[${metadata.tags.joinToString(",") { "\"$it\"" }}]")
        }
        sb.append("}")
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }
    
    private fun deserializeMetadata(data: ByteArray): ArtifactMetadata {
        // Simplified parsing
        val str = String(data, StandardCharsets.UTF_8)
        var name: String? = null
        var description: String? = null
        val tags = mutableListOf<String>()
        
        // Very basic parsing (should use proper JSON in production)
        val nameMatch = Regex("\"name\":\"([^\"]+)\"").find(str)
        name = nameMatch?.groupValues?.get(1)
        
        val descMatch = Regex("\"desc\":\"([^\"]+)\"").find(str)
        description = descMatch?.groupValues?.get(1)
        
        return ArtifactMetadata(name, description, tags)
    }
    
    private fun intToBytes(value: Int): ByteArray {
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }
    
    private fun bytesToInt(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
               ((data[offset + 1].toInt() and 0xFF) shl 16) or
               ((data[offset + 2].toInt() and 0xFF) shl 8) or
               (data[offset + 3].toInt() and 0xFF)
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
    
    private fun bytesToLong(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 56) or
               ((data[offset + 1].toLong() and 0xFF) shl 48) or
               ((data[offset + 2].toLong() and 0xFF) shl 40) or
               ((data[offset + 3].toLong() and 0xFF) shl 32) or
               ((data[offset + 4].toLong() and 0xFF) shl 24) or
               ((data[offset + 5].toLong() and 0xFF) shl 16) or
               ((data[offset + 6].toLong() and 0xFF) shl 8) or
               (data[offset + 7].toLong() and 0xFF)
    }
}
