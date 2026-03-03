package com.yours.app.vault

import com.yours.app.crypto.BedrockCore
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * An Artifact is an encrypted, owned digital object.
 * 
 * Properties:
 * - Encrypted to owner's identity (Hk-OVCT)
 * - Content never exists unencrypted on disk
 * - Transferable to other identities
 * - Provenance tracked
 */
data class Artifact(
    val id: String,                      // Unique identifier
    val contentHash: ByteArray,          // SHA3-256 of plaintext
    val contentType: String,             // MIME type
    val encryptedContent: ByteArray,     // Hk-OVCT encrypted content
    val ownerDid: String?,               // Current owner's DID (null if self)
    val createdAt: Long,                 // When artifact was created
    val metadata: ArtifactMetadata       // Optional user-added metadata
) {
    
    /**
     * Decrypt this artifact.
     * 
     * @param ownerSecretKey The owner's Hk-OVCT secret key
     * @return Decrypted content, or null if decryption fails
     */
    fun decrypt(ownerSecretKey: ByteArray): ByteArray? {
        return BedrockCore.hkovctDecrypt(ownerSecretKey, encryptedContent)
    }
    
    /**
     * Get file extension based on content type.
     */
    fun getExtension(): String {
        return when (contentType) {
            "image/jpeg" -> "jpg"
            "image/png" -> "png"
            "image/gif" -> "gif"
            "image/webp" -> "webp"
            "application/pdf" -> "pdf"
            "text/plain" -> "txt"
            "application/json" -> "json"
            else -> "bin"
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Artifact) return false
        return id == other.id
    }
    
    override fun hashCode(): Int = id.hashCode()
    
    companion object {
        
        /**
         * Create a new artifact from plaintext content.
         * 
         * @param content The plaintext content
         * @param contentType MIME type
         * @param ownerPublicKey Owner's Hk-OVCT public key
         * @param metadata Optional metadata
         * @return New encrypted artifact
         */
        fun create(
            content: ByteArray,
            contentType: String,
            ownerPublicKey: ByteArray,
            metadata: ArtifactMetadata = ArtifactMetadata()
        ): Artifact {
            // Generate unique ID
            val id = UUID.randomUUID().toString()
            
            // Hash content for integrity
            val contentHash = BedrockCore.sha3_256(content)
            
            // Encrypt content to owner
            val encryptedContent = BedrockCore.hkovctEncrypt(ownerPublicKey, content)
            
            return Artifact(
                id = id,
                contentHash = contentHash,
                contentType = contentType,
                encryptedContent = encryptedContent,
                ownerDid = null, // Self-owned
                createdAt = System.currentTimeMillis(),
                metadata = metadata
            )
        }
        
        /**
         * Re-encrypt artifact for transfer to new owner.
         * 
         * @param artifact The artifact to transfer
         * @param currentOwnerSecretKey Current owner's secret key (to decrypt)
         * @param newOwnerPublicKey New owner's public key (to encrypt)
         * @param newOwnerDid New owner's DID
         * @return New artifact encrypted to new owner, or null if decryption fails
         */
        fun transferTo(
            artifact: Artifact,
            currentOwnerSecretKey: ByteArray,
            newOwnerPublicKey: ByteArray,
            newOwnerDid: String
        ): Artifact? {
            // Decrypt with current owner's key
            val plaintext = artifact.decrypt(currentOwnerSecretKey) ?: return null
            
            try {
                // Verify content integrity
                val hash = BedrockCore.sha3_256(plaintext)
                if (!hash.contentEquals(artifact.contentHash)) {
                    return null
                }
                
                // Re-encrypt to new owner
                val newEncrypted = BedrockCore.hkovctEncrypt(newOwnerPublicKey, plaintext)
                
                return Artifact(
                    id = artifact.id,
                    contentHash = artifact.contentHash,
                    contentType = artifact.contentType,
                    encryptedContent = newEncrypted,
                    ownerDid = newOwnerDid,
                    createdAt = artifact.createdAt,
                    metadata = artifact.metadata
                )
            } finally {
                // Zero out plaintext
                BedrockCore.zeroize(plaintext)
            }
        }
    }
}

/**
 * Optional user-provided metadata for an artifact.
 * This metadata is stored encrypted as part of the artifact.
 */
data class ArtifactMetadata(
    val name: String? = null,          // User-assigned name
    val description: String? = null,   // User-assigned description
    val tags: List<String> = emptyList()
)

/**
 * Thumbnail for artifact preview.
 * Generated on-demand, never persisted unencrypted.
 */
data class ArtifactThumbnail(
    val artifactId: String,
    val thumbnailData: ByteArray,      // Small preview image
    val width: Int,
    val height: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ArtifactThumbnail) return false
        return artifactId == other.artifactId
    }
    
    override fun hashCode(): Int = artifactId.hashCode()
}
