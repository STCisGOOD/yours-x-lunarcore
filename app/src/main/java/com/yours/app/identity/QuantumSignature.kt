package com.yours.app.identity

import com.yours.app.crypto.BedrockCore
import com.yours.app.crypto.SignatureType
import com.yours.app.crypto.VerificationResult
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Signature mode for contacts.
 *
 * Uses Ed25519 signatures which provide 128-bit classical security.
 * Post-quantum signatures (Dilithium) are not used due to:
 * - Size constraints on LoRa mesh networks (signatures would require 22+ packets)
 * - Real-time verification means quantum attacks require quantum computer at verification time
 * - Encryption layer (ML-KEM-768) already provides quantum resistance for confidentiality
 */
enum class SignatureMode {
    /**
     * Ed25519 signatures.
     * Security: 128-bit classical
     */
    ED25519;

    companion object {
        /**
         * Default mode for contacts.
         */
        fun default(): SignatureMode = ED25519

        /**
         * Deserialize from byte.
         */
        fun fromByte(value: Byte): SignatureMode = ED25519
    }

    /**
     * Serialize to byte.
     */
    fun toByte(): Byte = 0

    /**
     * Human-readable description.
     */
    fun description(): String = "Ed25519 Signature"

    /**
     * Security level description.
     */
    fun securityLevel(): String = "128-bit classical"
}

// Type alias for backward compatibility during migration
@Deprecated("Use SignatureMode instead", ReplaceWith("SignatureMode"))
typealias QuantumSignatureMode = SignatureMode

/**
 * Information about a contact's signature verification status.
 */
data class ContactSignatureInfo(
    /**
     * Whether the last verification succeeded.
     */
    val verified: Boolean,

    /**
     * When the signature was last verified (Unix timestamp).
     */
    val lastVerifiedAt: Long,

    /**
     * Any warnings about the signature.
     */
    val warning: String? = null,

    /**
     * Details about the verification.
     */
    val details: String? = null
) {
    /**
     * Security status for UI display.
     */
    val securityStatus: SecurityStatus
        get() = if (verified) SecurityStatus.VERIFIED else SecurityStatus.UNVERIFIED

    /**
     * User-friendly status message.
     */
    fun statusMessage(): String = when (securityStatus) {
        SecurityStatus.VERIFIED -> "Signature verified"
        SecurityStatus.UNVERIFIED -> "Signature not verified"
    }
}

/**
 * Security status levels for UI display.
 */
enum class SecurityStatus {
    /**
     * Signature verified successfully.
     */
    VERIFIED,

    /**
     * Signature not verified or verification failed.
     */
    UNVERIFIED;

    /**
     * Color hint for UI (returns a string identifier, not actual color).
     */
    fun colorHint(): String = when (this) {
        VERIFIED -> "success"
        UNVERIFIED -> "error"
    }

    /**
     * Icon hint for UI.
     */
    fun iconHint(): String = when (this) {
        VERIFIED -> "shield_check"
        UNVERIFIED -> "shield_alert"
    }
}

// Type alias for backward compatibility during migration
@Deprecated("Use SecurityStatus instead", ReplaceWith("SecurityStatus"))
typealias QuantumSecurityStatus = SecurityStatus

/**
 * Identity keys for signing and encryption.
 *
 * Contains Ed25519 for signing and HK-OVCT (ML-KEM-768) for encryption.
 * Encryption provides quantum resistance; signing uses classical Ed25519.
 */
data class IdentityKeys(
    /**
     * Ed25519 signing private key.
     */
    val signingPrivateKey: ByteArray,

    /**
     * Ed25519 signing public key.
     */
    val signingPublicKey: ByteArray,

    /**
     * HK-OVCT encryption private key (ML-KEM-768 based - quantum resistant).
     */
    val encryptionPrivateKey: ByteArray,

    /**
     * HK-OVCT encryption public key.
     */
    val encryptionPublicKey: ByteArray
) {
    /**
     * Serialize for encrypted storage.
     *
     * Format:
     * [version:1][sigPrivLen:4][sigPriv:N][sigPubLen:4][sigPub:N]
     * [encPrivLen:4][encPriv:N][encPubLen:4][encPub:N]
     */
    fun serialize(): ByteArray {
        val totalSize = 1 + // version
                4 + signingPrivateKey.size +
                4 + signingPublicKey.size +
                4 + encryptionPrivateKey.size +
                4 + encryptionPublicKey.size

        val buffer = ByteBuffer.allocate(totalSize)
        buffer.put(SERIALIZATION_VERSION)

        buffer.putInt(signingPrivateKey.size)
        buffer.put(signingPrivateKey)
        buffer.putInt(signingPublicKey.size)
        buffer.put(signingPublicKey)

        buffer.putInt(encryptionPrivateKey.size)
        buffer.put(encryptionPrivateKey)
        buffer.putInt(encryptionPublicKey.size)
        buffer.put(encryptionPublicKey)

        return buffer.array()
    }

    /**
     * Securely zeroize all private key material.
     */
    fun zeroize() {
        BedrockCore.zeroize(signingPrivateKey)
        BedrockCore.zeroize(encryptionPrivateKey)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityKeys) return false
        return signingPublicKey.contentEquals(other.signingPublicKey) &&
                encryptionPublicKey.contentEquals(other.encryptionPublicKey)
    }

    override fun hashCode(): Int {
        var result = signingPublicKey.contentHashCode()
        result = 31 * result + encryptionPublicKey.contentHashCode()
        return result
    }

    companion object {
        private const val SERIALIZATION_VERSION: Byte = 0x02

        /**
         * Deserialize from bytes.
         */
        fun deserialize(data: ByteArray): IdentityKeys? {
            if (data.isEmpty()) return null

            try {
                val buffer = ByteBuffer.wrap(data)

                val version = buffer.get()
                if (version != SERIALIZATION_VERSION) return null

                val sigPrivLen = buffer.int
                if (sigPrivLen < 0 || sigPrivLen > 128) return null
                val sigPriv = ByteArray(sigPrivLen)
                buffer.get(sigPriv)

                val sigPubLen = buffer.int
                if (sigPubLen < 0 || sigPubLen > 64) return null
                val sigPub = ByteArray(sigPubLen)
                buffer.get(sigPub)

                val encPrivLen = buffer.int
                if (encPrivLen < 0 || encPrivLen > 8192) return null
                val encPriv = ByteArray(encPrivLen)
                buffer.get(encPriv)

                val encPubLen = buffer.int
                if (encPubLen < 0 || encPubLen > 4096) return null
                val encPub = ByteArray(encPubLen)
                buffer.get(encPub)

                return IdentityKeys(
                    signingPrivateKey = sigPriv,
                    signingPublicKey = sigPub,
                    encryptionPrivateKey = encPriv,
                    encryptionPublicKey = encPub
                )
            } catch (e: Exception) {
                return null
            }
        }

        /**
         * Generate new identity keys.
         */
        fun generate(): IdentityKeys {
            // Generate Ed25519 keypair for signing
            val (sigPriv, sigPub) = BedrockCore.generateSigningKeypair()

            // Generate HK-OVCT keypair for encryption (quantum-resistant)
            val (encPriv, encPub) = BedrockCore.hkovctKeygen()

            return IdentityKeys(
                signingPrivateKey = sigPriv,
                signingPublicKey = sigPub,
                encryptionPrivateKey = encPriv,
                encryptionPublicKey = encPub
            )
        }
    }
}

// Type alias for backward compatibility during migration
@Deprecated("Use IdentityKeys instead", ReplaceWith("IdentityKeys"))
typealias HybridIdentityKeys = IdentityKeys

/**
 * Contact signing service.
 *
 * Provides methods for signing and verifying contact data using Ed25519 signatures.
 */
object ContactSigningService {

    /**
     * Domain separator for contact signatures.
     */
    private val CONTACT_SIG_DOMAIN = "yours-contact-signature-v2".toByteArray(StandardCharsets.UTF_8)

    /**
     * Sign contact hello data.
     *
     * @param signableData The data to sign (from ContactHello.getSignableData())
     * @param signingPrivateKey The signer's Ed25519 private key
     * @return The signature bytes (64 bytes Ed25519 signature)
     */
    fun signContactHello(
        signableData: ByteArray,
        signingPrivateKey: ByteArray
    ): ByteArray {
        // Add domain separation
        val domainedData = createDomainedData(signableData)

        return try {
            BedrockCore.sign(signingPrivateKey, domainedData)
        } finally {
            BedrockCore.zeroize(domainedData)
        }
    }

    /**
     * Verify a contact hello signature.
     *
     * @param signableData The data that was signed
     * @param signature The signature to verify (64 bytes Ed25519)
     * @param signingPublicKey The signer's Ed25519 public key
     * @return true if signature is valid
     */
    fun verifyContactHello(
        signableData: ByteArray,
        signature: ByteArray,
        signingPublicKey: ByteArray
    ): Boolean {
        // Add domain separation
        val domainedData = createDomainedData(signableData)

        return try {
            BedrockCore.verify(signingPublicKey, domainedData, signature)
        } finally {
            BedrockCore.zeroize(domainedData)
        }
    }

    /**
     * Create a ContactSignatureInfo from a verification result.
     */
    fun createSignatureInfo(verified: Boolean): ContactSignatureInfo {
        return ContactSignatureInfo(
            verified = verified,
            lastVerifiedAt = System.currentTimeMillis(),
            warning = if (!verified) "Signature verification failed" else null,
            details = if (verified) "Ed25519 signature verified" else null
        )
    }

    /**
     * Create domain-separated data for signing.
     */
    private fun createDomainedData(data: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(CONTACT_SIG_DOMAIN.size + 4 + data.size)
        buffer.put(CONTACT_SIG_DOMAIN)
        buffer.putInt(data.size)
        buffer.put(data)
        return buffer.array()
    }
}
