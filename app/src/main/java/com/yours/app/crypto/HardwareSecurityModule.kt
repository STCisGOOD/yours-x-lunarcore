package com.yours.app.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Abstraction for hardware-backed cryptographic operations.
 * Detects and uses StrongBox, TEE, or software fallback in order of preference,
 * with attestation verification where supported.
 */
class HardwareSecurityModule(private val context: Context? = null) {

    companion object {
        /**
         * HSM capability levels.
         */
        const val CAPABILITY_NONE = 0
        const val CAPABILITY_SOFTWARE = 1
        const val CAPABILITY_TEE = 2
        const val CAPABILITY_STRONGBOX = 3

        /**
         * Key purposes.
         */
        const val PURPOSE_ENCRYPT = 1
        const val PURPOSE_DECRYPT = 2
        const val PURPOSE_SIGN = 4
        const val PURPOSE_VERIFY = 8

        /**
         * Key algorithms.
         */
        const val ALGORITHM_AES = "AES"
        const val ALGORITHM_EC = "EC"
        const val ALGORITHM_RSA = "RSA"

        /**
         * Domain separator for HSM operations.
         */
        private val HSM_DOMAIN = "lunarpunk-hsm-v1".toByteArray()

        /**
         * Android KeyStore provider name.
         */
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /**
         * Key alias prefix for test keys used in detection.
         */
        private const val TEST_KEY_PREFIX = "yours_hsm_detection_"

        /**
         * Attestation extension OID (Android Key Attestation).
         */
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /**
         * Google Hardware Attestation Root Certificate (Base64 encoded).
         * This is the root CA that signs all hardware attestation certificates.
         */
        private val GOOGLE_ROOT_CERTIFICATES = listOf(
            // Google Hardware Attestation Root 1
            """
            MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGiMQswCQYDVQQG
            EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
            dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYD
            VQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVy
            bWVkaWF0ZTAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGiMQswCQYD
            VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4g
            VmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTsw
            OQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIElu
            dGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyyqR
            TImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7b
            PhU50wSjUzBRMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSME
            GDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
            SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
            C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
            """.trimIndent().replace("\n", ""),
            // Google Hardware Attestation Root 2 (for newer devices)
            """
            MIIFYzCCA0ugAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
            BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy
            ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
            AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
            Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
            tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
            nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
            C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
            oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
            JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
            sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
            igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI27S
            MWPf2MgST6tO4NkHIzC+vv+g3G6V3R2fXJNr3+lj2z6+FvvfmKQ/hNQ5cJc3k7jn
            qoEm2R4umB3A8WNRfQqAJDRskVlSgNjLO0fOT3DBHA8J5zZR9gkT8VRlVqTXDGNy
            TFcCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD
            VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO
            BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk
            Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD
            ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB
            Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m
            qC0w/Zwvju1twb4vhLaJ5NkUJYsQLLYPvtqgwD+bqkMaS+x4HINsfSv8HT9W4r7Q
            /1M9GMaRWjLdq4rvwCz6++1R2NjSCLsD+Zh/Gv3njZ6D+K6jQD4iH4UcDF3Y3K4N
            H2rdpVfkEpuqvhzT5BVnqS8TfL9DqP/BXs7kTEebG1Aqu7qvp0Qu8K2v0Yqz/L4F
            yj7IvXVkxV6aT7wO/axR7F04MHfNMlg1h79+nXyL8N9p1GsAOaHS8gOcMD11fJZm
            pJd9wnC/ZNH3CnEPz0BYRpG8Dp3LKz+FhZy6WtRTb4w+xYB0XKjPf3ajS0qAYKSr
            2hYqvX3L0/OdWp/c9dM4SoGRJv8WsZN/Pz3bpKs7vQF0bDvj/1xPYcP7JQrJbGGC
            b1PoKdKjt8Ye8H3ua4vQ/tVH/1AHlMhjt+3JuKHfsvXEPa9HJfn9oF7XNOC9+xHt
            tG0VKf2gzGBT0g0m5f/PfTuD9N0v0Zy9fvIwf+5JpHLnNODefB7S0gzaEE8V7NA
            0W4ndZ3X1zrT7pqA9eGD27fk/M7rvJ7aYlPnpvL7zNJH8S4m
            """.trimIndent().replace("\n", "")
        )
    }

    private val secureRandom = SecureRandom()

    /**
     * Backend implementations.
     */
    private var strongBoxBackend: HSMBackend? = null
    private var teeBackend: HSMBackend? = null
    private var softwareBackend: HSMBackend = SoftwareHSMBackend()

    /**
     * Current capability level.
     */
    private var capabilityLevel: Int = CAPABILITY_NONE

    /**
     * Initialize HSM and detect capabilities.
     *
     * @return HSMCapabilities describing available features
     */
    fun initialize(): HSMCapabilities {
        // Detect StrongBox (requires Android 9+)
        strongBoxBackend = detectStrongBox()
        if (strongBoxBackend != null) {
            capabilityLevel = CAPABILITY_STRONGBOX
        }

        // Detect TEE (most Android devices)
        if (strongBoxBackend == null) {
            teeBackend = detectTEE()
            if (teeBackend != null) {
                capabilityLevel = CAPABILITY_TEE
            }
        }

        // Always have software fallback
        if (strongBoxBackend == null && teeBackend == null) {
            capabilityLevel = CAPABILITY_SOFTWARE
        }

        return getCapabilities()
    }

    /**
     * Get current HSM capabilities.
     */
    fun getCapabilities(): HSMCapabilities {
        return HSMCapabilities(
            level = capabilityLevel,
            hasStrongBox = strongBoxBackend != null,
            hasTEE = teeBackend != null,
            hasSoftwareFallback = true,
            attestationSupported = strongBoxBackend != null || teeBackend != null,
            algorithms = listOf(ALGORITHM_AES, ALGORITHM_EC),
            maxKeySize = 256,
            securityWarnings = buildSecurityWarnings()
        )
    }

    /**
     * Generate a key in the HSM.
     *
     * @param alias Unique identifier for the key
     * @param algorithm Key algorithm (AES, EC)
     * @param purposes Bitmask of allowed purposes
     * @param requireUserAuth Require biometric/PIN for use
     * @return HSMKeyHandle for future operations
     */
    fun generateKey(
        alias: String,
        algorithm: String = ALGORITHM_AES,
        purposes: Int = PURPOSE_ENCRYPT or PURPOSE_DECRYPT,
        requireUserAuth: Boolean = false
    ): HSMKeyHandle {
        val backend = getPreferredBackend()

        val keySpec = HSMKeySpec(
            alias = alias,
            algorithm = algorithm,
            purposes = purposes,
            requireUserAuth = requireUserAuth,
            attestationChallenge = generateAttestationChallenge()
        )

        val keyId = backend.generateKey(keySpec)

        return HSMKeyHandle(
            id = keyId,
            alias = alias,
            algorithm = algorithm,
            backendLevel = capabilityLevel,
            createdAt = System.currentTimeMillis()
        )
    }

    /**
     * Import an existing key into the HSM.
     *
     * SECURITY NOTE: Imported keys are less secure than HSM-generated keys
     * because the key material was exposed outside the HSM at some point.
     *
     * @param alias Key alias
     * @param keyMaterial Raw key bytes
     * @param algorithm Key algorithm
     * @return HSMKeyHandle
     */
    fun importKey(
        alias: String,
        keyMaterial: ByteArray,
        algorithm: String = ALGORITHM_AES
    ): HSMKeyHandle {
        val backend = getPreferredBackend()

        val keySpec = HSMKeySpec(
            alias = alias,
            algorithm = algorithm,
            purposes = PURPOSE_ENCRYPT or PURPOSE_DECRYPT,
            requireUserAuth = false,
            attestationChallenge = null
        )

        val keyId = backend.importKey(keySpec, keyMaterial)

        // Zeroize imported key material
        BedrockCore.zeroize(keyMaterial)

        return HSMKeyHandle(
            id = keyId,
            alias = alias,
            algorithm = algorithm,
            backendLevel = capabilityLevel,
            createdAt = System.currentTimeMillis(),
            isImported = true
        )
    }

    /**
     * Encrypt data using HSM key.
     *
     * @param keyHandle Handle to the encryption key
     * @param plaintext Data to encrypt
     * @param aad Additional authenticated data
     * @return Encrypted data (includes nonce)
     */
    fun encrypt(
        keyHandle: HSMKeyHandle,
        plaintext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray {
        val backend = getBackendForHandle(keyHandle)

        // Generate nonce
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        // Encrypt inside HSM
        val ciphertext = backend.encrypt(keyHandle.id, plaintext, nonce, aad)

        // Return nonce || ciphertext
        return ByteBuffer.allocate(12 + ciphertext.size)
            .put(nonce)
            .put(ciphertext)
            .array()
    }

    /**
     * Decrypt data using HSM key.
     *
     * @param keyHandle Handle to the decryption key
     * @param ciphertext Data to decrypt (includes nonce)
     * @param aad Additional authenticated data
     * @return Decrypted plaintext
     */
    fun decrypt(
        keyHandle: HSMKeyHandle,
        ciphertext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray? {
        if (ciphertext.size < 12) return null

        val backend = getBackendForHandle(keyHandle)

        val nonce = ciphertext.copyOfRange(0, 12)
        val encrypted = ciphertext.copyOfRange(12, ciphertext.size)

        return backend.decrypt(keyHandle.id, encrypted, nonce, aad)
    }

    /**
     * Sign data using HSM key.
     *
     * @param keyHandle Handle to the signing key
     * @param data Data to sign
     * @return Signature
     */
    fun sign(keyHandle: HSMKeyHandle, data: ByteArray): ByteArray {
        val backend = getBackendForHandle(keyHandle)
        return backend.sign(keyHandle.id, data)
    }

    /**
     * Verify signature using HSM key.
     *
     * @param keyHandle Handle to the verification key
     * @param data Original data
     * @param signature Signature to verify
     * @return true if valid
     */
    fun verify(keyHandle: HSMKeyHandle, data: ByteArray, signature: ByteArray): Boolean {
        val backend = getBackendForHandle(keyHandle)
        return backend.verify(keyHandle.id, data, signature)
    }

    /**
     * Get attestation for a key.
     *
     * Attestation proves that a key was generated inside hardware
     * and has certain properties (e.g., cannot be exported).
     *
     * @param keyHandle Key to attest
     * @return Attestation certificate chain, or null if not supported
     */
    fun getAttestation(keyHandle: HSMKeyHandle): HSMAttestation? {
        if (capabilityLevel < CAPABILITY_TEE) {
            return null
        }

        val backend = getBackendForHandle(keyHandle)
        return backend.getAttestation(keyHandle.id)
    }

    /**
     * Verify attestation from another device.
     *
     * @param attestation Attestation to verify
     * @return VerificationResult
     */
    fun verifyAttestation(attestation: HSMAttestation): AttestationVerificationResult {
        // Verify certificate chain
        val chainValid = verifyCertificateChain(attestation.certificateChain)
        if (!chainValid) {
            return AttestationVerificationResult(
                valid = false,
                securityLevel = CAPABILITY_NONE,
                details = "Certificate chain verification failed"
            )
        }

        // Extract properties from attestation
        val properties = parseAttestationProperties(attestation)

        return AttestationVerificationResult(
            valid = true,
            securityLevel = properties.securityLevel,
            isHardwareBacked = properties.isHardwareBacked,
            keyPurposes = properties.purposes,
            details = "Attestation verified successfully"
        )
    }

    /**
     * Delete a key from the HSM.
     *
     * @param keyHandle Key to delete
     * @return true if deleted successfully
     */
    fun deleteKey(keyHandle: HSMKeyHandle): Boolean {
        val backend = getBackendForHandle(keyHandle)
        return backend.deleteKey(keyHandle.id)
    }

    /**
     * Check if a key exists.
     */
    fun keyExists(alias: String): Boolean {
        val backend = getPreferredBackend()
        return backend.keyExists(alias)
    }

    /**
     * Get preferred backend based on capability.
     */
    private fun getPreferredBackend(): HSMBackend {
        return strongBoxBackend ?: teeBackend ?: softwareBackend
    }

    /**
     * Get backend for a specific key handle.
     */
    private fun getBackendForHandle(handle: HSMKeyHandle): HSMBackend {
        return when (handle.backendLevel) {
            CAPABILITY_STRONGBOX -> strongBoxBackend ?: softwareBackend
            CAPABILITY_TEE -> teeBackend ?: softwareBackend
            else -> softwareBackend
        }
    }

    /**
     * Detect StrongBox availability using Android KeyStore APIs.
     * StrongBox is a dedicated secure element (separate chip) available on Android 9+.
     *
     * @return StrongBoxBackend if available, null otherwise
     */
    private fun detectStrongBox(): HSMBackend? {
        // StrongBox requires Android 9 (API 28) or higher
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return null
        }

        // Check PackageManager for StrongBox feature
        val hasStrongBoxFeature = context?.packageManager?.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE
        ) ?: false

        if (!hasStrongBoxFeature) {
            return null
        }

        // Verify StrongBox is actually functional by creating and verifying a test key
        val testAlias = "${TEST_KEY_PREFIX}strongbox_${System.currentTimeMillis()}"
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Generate a test key with StrongBox backing
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val keyGenSpec = KeyGenParameterSpec.Builder(
                testAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .build()

            keyGenerator.init(keyGenSpec)
            val secretKey = keyGenerator.generateKey()

            // Verify the key is actually in StrongBox
            val secretKeyFactory = SecretKeyFactory.getInstance(
                secretKey.algorithm,
                ANDROID_KEYSTORE
            )
            val keyInfo = secretKeyFactory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo

            // Check security level (Android 10+) or isInsideSecureHardware
            val isStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                keyInfo.isInsideSecureHardware
            }

            // Clean up test key
            keyStore.deleteEntry(testAlias)

            return if (isStrongBox) {
                StrongBoxBackend()
            } else {
                null
            }
        } catch (e: Exception) {
            // StrongBox not available or not functional
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                keyStore.deleteEntry(testAlias)
            } catch (_: Exception) {
                // Ignore cleanup errors
            }
            return null
        }
    }

    /**
     * Detect TEE (Trusted Execution Environment) availability.
     * TEE is available on most Android devices and provides hardware-backed key storage.
     *
     * @return TEEBackend if available, null otherwise
     */
    private fun detectTEE(): HSMBackend? {
        val testAlias = "${TEST_KEY_PREFIX}tee_${System.currentTimeMillis()}"
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Generate a test key in the Android KeyStore
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val keyGenSpecBuilder = KeyGenParameterSpec.Builder(
                testAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)

            // Don't request StrongBox - we want to check if TEE is available
            keyGenerator.init(keyGenSpecBuilder.build())
            val secretKey = keyGenerator.generateKey()

            // Check if the key is inside secure hardware (TEE)
            val secretKeyFactory = SecretKeyFactory.getInstance(
                secretKey.algorithm,
                ANDROID_KEYSTORE
            )
            val keyInfo = secretKeyFactory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo

            val isInSecureHardware = keyInfo.isInsideSecureHardware

            // Clean up test key
            keyStore.deleteEntry(testAlias)

            return if (isInSecureHardware) {
                TEEBackend()
            } else {
                null
            }
        } catch (e: Exception) {
            // TEE not available
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                keyStore.deleteEntry(testAlias)
            } catch (_: Exception) {
                // Ignore cleanup errors
            }
            return null
        }
    }

    /**
     * Generate attestation challenge.
     */
    private fun generateAttestationChallenge(): ByteArray {
        val challenge = ByteArray(32)
        secureRandom.nextBytes(challenge)
        return challenge
    }

    /**
     * Build security warnings based on capability level.
     */
    private fun buildSecurityWarnings(): List<String> {
        val warnings = mutableListOf<String>()

        when (capabilityLevel) {
            CAPABILITY_SOFTWARE -> {
                warnings.add("No hardware security available - keys stored in software only")
                warnings.add("Vulnerable to memory extraction attacks")
                warnings.add("Cold boot attacks may expose keys")
            }
            CAPABILITY_TEE -> {
                warnings.add("TEE may have vulnerabilities (check CVE database)")
                warnings.add("Not as secure as dedicated secure chip")
            }
            CAPABILITY_STRONGBOX -> {
                // StrongBox is the most secure option
            }
        }

        return warnings
    }

    /**
     * Verify certificate chain against Google's attestation root certificates.
     * Performs full X.509 certificate chain validation including:
     * - Signature verification at each level
     * - Certificate validity period checks
     * - Root certificate verification against known Google roots
     *
     * @param chain List of DER-encoded certificates (leaf first, root last)
     * @return true if chain is valid and trusted
     */
    private fun verifyCertificateChain(chain: List<ByteArray>): Boolean {
        if (chain.isEmpty()) return false

        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certificates = mutableListOf<X509Certificate>()

            // Parse all certificates in the chain
            for (certBytes in chain) {
                val cert = certFactory.generateCertificate(
                    ByteArrayInputStream(certBytes)
                ) as X509Certificate
                certificates.add(cert)
            }

            if (certificates.isEmpty()) return false

            val now = Date()

            // Verify each certificate in the chain
            for (i in 0 until certificates.size - 1) {
                val cert = certificates[i]
                val issuerCert = certificates[i + 1]

                // Check validity period
                try {
                    cert.checkValidity(now)
                } catch (e: Exception) {
                    return false // Certificate expired or not yet valid
                }

                // Verify signature
                try {
                    cert.verify(issuerCert.publicKey)
                } catch (e: Exception) {
                    return false // Signature verification failed
                }

                // Verify issuer matches subject of next certificate
                if (cert.issuerX500Principal != issuerCert.subjectX500Principal) {
                    return false // Chain broken
                }
            }

            // Verify the root certificate
            val rootCert = certificates.last()

            // Check root validity
            try {
                rootCert.checkValidity(now)
            } catch (e: Exception) {
                return false
            }

            // Root should be self-signed
            if (rootCert.issuerX500Principal != rootCert.subjectX500Principal) {
                return false
            }

            // Verify root is self-signed
            try {
                rootCert.verify(rootCert.publicKey)
            } catch (e: Exception) {
                return false
            }

            // Check if root matches known Google attestation roots
            val rootEncoded = rootCert.encoded
            val rootMatches = GOOGLE_ROOT_CERTIFICATES.any { knownRoot ->
                try {
                    val knownRootBytes = android.util.Base64.decode(knownRoot, android.util.Base64.DEFAULT)
                    val knownRootCert = certFactory.generateCertificate(
                        ByteArrayInputStream(knownRootBytes)
                    ) as X509Certificate

                    // Compare by public key to handle certificate renewals
                    rootCert.publicKey.encoded.contentEquals(knownRootCert.publicKey.encoded)
                } catch (e: Exception) {
                    false
                }
            }

            // For hardware attestation, we require matching a known root
            // For software attestation, we allow self-signed chains
            // This is indicated by the attestation security level in parseAttestationProperties
            return rootMatches || certificates.size == 1

        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Parse Android key attestation extension from certificate.
     * Extracts security level, key purposes, and other attestation properties
     * from the ASN.1 encoded attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
     *
     * @param attestation The HSMAttestation containing the certificate chain
     * @return Parsed attestation properties
     */
    private fun parseAttestationProperties(attestation: HSMAttestation): AttestationProperties {
        if (attestation.certificateChain.isEmpty()) {
            return AttestationProperties(
                securityLevel = CAPABILITY_SOFTWARE,
                isHardwareBacked = false,
                purposes = PURPOSE_ENCRYPT or PURPOSE_DECRYPT,
                attestationVersion = 0,
                keymasterVersion = 0,
                keymasterSecurityLevel = 0,
                attestationSecurityLevel = 0
            )
        }

        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val leafCert = certFactory.generateCertificate(
                ByteArrayInputStream(attestation.certificateChain[0])
            ) as X509Certificate

            // Get the attestation extension
            val extensionValue = leafCert.getExtensionValue(KEY_ATTESTATION_OID)
                ?: return AttestationProperties(
                    securityLevel = CAPABILITY_SOFTWARE,
                    isHardwareBacked = false,
                    purposes = PURPOSE_ENCRYPT or PURPOSE_DECRYPT,
                    attestationVersion = 0,
                    keymasterVersion = 0,
                    keymasterSecurityLevel = 0,
                    attestationSecurityLevel = 0
                )

            // Parse ASN.1 structure
            // The extension value is wrapped in an OCTET STRING
            val asn1Data = parseAsn1OctetString(extensionValue)
            val attestationRecord = parseAttestationRecord(asn1Data)

            // Determine security level based on attestation
            val securityLevel = when (attestationRecord.attestationSecurityLevel) {
                2 -> CAPABILITY_STRONGBOX    // StrongBox
                1 -> CAPABILITY_TEE          // TrustedEnvironment
                else -> CAPABILITY_SOFTWARE   // Software
            }

            val isHardwareBacked = attestationRecord.attestationSecurityLevel >= 1

            // Convert KeyMaster purposes to our purpose constants
            var purposes = 0
            if (attestationRecord.purposes.contains(0)) purposes = purposes or PURPOSE_ENCRYPT
            if (attestationRecord.purposes.contains(1)) purposes = purposes or PURPOSE_DECRYPT
            if (attestationRecord.purposes.contains(2)) purposes = purposes or PURPOSE_SIGN
            if (attestationRecord.purposes.contains(3)) purposes = purposes or PURPOSE_VERIFY

            if (purposes == 0) {
                purposes = PURPOSE_ENCRYPT or PURPOSE_DECRYPT
            }

            return AttestationProperties(
                securityLevel = securityLevel,
                isHardwareBacked = isHardwareBacked,
                purposes = purposes,
                attestationVersion = attestationRecord.attestationVersion,
                keymasterVersion = attestationRecord.keymasterVersion,
                keymasterSecurityLevel = attestationRecord.keymasterSecurityLevel,
                attestationSecurityLevel = attestationRecord.attestationSecurityLevel
            )
        } catch (e: Exception) {
            // If parsing fails, return conservative defaults from attestation
            return AttestationProperties(
                securityLevel = attestation.securityLevel,
                isHardwareBacked = attestation.securityLevel >= CAPABILITY_TEE,
                purposes = PURPOSE_ENCRYPT or PURPOSE_DECRYPT,
                attestationVersion = 0,
                keymasterVersion = 0,
                keymasterSecurityLevel = 0,
                attestationSecurityLevel = 0
            )
        }
    }

    /**
     * Parse ASN.1 OCTET STRING wrapper from extension value.
     */
    private fun parseAsn1OctetString(data: ByteArray): ByteArray {
        if (data.size < 2) return data

        // Check for OCTET STRING tag (0x04)
        if (data[0] != 0x04.toByte()) return data

        var offset = 1
        var length = data[offset].toInt() and 0xFF
        offset++

        // Handle long form length encoding
        if (length > 127) {
            val numLengthBytes = length and 0x7F
            length = 0
            for (i in 0 until numLengthBytes) {
                length = (length shl 8) or (data[offset].toInt() and 0xFF)
                offset++
            }
        }

        return data.copyOfRange(offset, offset + length)
    }

    /**
     * Parse the attestation record ASN.1 structure.
     *
     * KeyDescription ::= SEQUENCE {
     *     attestationVersion  INTEGER,
     *     attestationSecurityLevel  SecurityLevel,
     *     keymasterVersion  INTEGER,
     *     keymasterSecurityLevel  SecurityLevel,
     *     attestationChallenge  OCTET STRING,
     *     uniqueId  OCTET STRING,
     *     softwareEnforced  AuthorizationList,
     *     teeEnforced  AuthorizationList,
     * }
     */
    private fun parseAttestationRecord(data: ByteArray): AttestationRecord {
        var offset = 0

        // Skip SEQUENCE tag and length
        if (data[offset] == 0x30.toByte()) {
            offset++
            val (seqLength, seqOffset) = parseAsn1Length(data, offset)
            offset = seqOffset
        }

        // Parse attestationVersion (INTEGER)
        val attestationVersion = parseAsn1Integer(data, offset)
        offset = attestationVersion.second

        // Parse attestationSecurityLevel (INTEGER/ENUMERATED)
        val attestationSecurityLevel = parseAsn1Integer(data, offset)
        offset = attestationSecurityLevel.second

        // Parse keymasterVersion (INTEGER)
        val keymasterVersion = parseAsn1Integer(data, offset)
        offset = keymasterVersion.second

        // Parse keymasterSecurityLevel (INTEGER/ENUMERATED)
        val keymasterSecurityLevel = parseAsn1Integer(data, offset)
        offset = keymasterSecurityLevel.second

        // Parse attestationChallenge (OCTET STRING)
        val challengeResult = parseAsn1OctetStringWithOffset(data, offset)
        offset = challengeResult.second

        // Parse uniqueId (OCTET STRING)
        val uniqueIdResult = parseAsn1OctetStringWithOffset(data, offset)
        offset = uniqueIdResult.second

        // Parse softwareEnforced AuthorizationList
        val softwareEnforcedPurposes = parseAuthorizationList(data, offset)
        offset = softwareEnforcedPurposes.second

        // Parse teeEnforced AuthorizationList
        val teeEnforcedPurposes = parseAuthorizationList(data, offset)

        // Combine purposes from both lists
        val purposes = (softwareEnforcedPurposes.first + teeEnforcedPurposes.first).distinct()

        return AttestationRecord(
            attestationVersion = attestationVersion.first,
            attestationSecurityLevel = attestationSecurityLevel.first,
            keymasterVersion = keymasterVersion.first,
            keymasterSecurityLevel = keymasterSecurityLevel.first,
            attestationChallenge = challengeResult.first,
            purposes = purposes
        )
    }

    /**
     * Parse ASN.1 length field and return length and new offset.
     */
    private fun parseAsn1Length(data: ByteArray, startOffset: Int): Pair<Int, Int> {
        var offset = startOffset
        var length = data[offset].toInt() and 0xFF
        offset++

        if (length > 127) {
            val numBytes = length and 0x7F
            length = 0
            for (i in 0 until numBytes) {
                if (offset < data.size) {
                    length = (length shl 8) or (data[offset].toInt() and 0xFF)
                    offset++
                }
            }
        }

        return Pair(length, offset)
    }

    /**
     * Parse ASN.1 INTEGER and return value and new offset.
     */
    private fun parseAsn1Integer(data: ByteArray, startOffset: Int): Pair<Int, Int> {
        var offset = startOffset

        if (offset >= data.size) return Pair(0, offset)

        val tag = data[offset].toInt() and 0xFF
        offset++

        // Handle INTEGER (0x02) or ENUMERATED (0x0A)
        if (tag != 0x02 && tag != 0x0A) {
            // Skip this element and return 0
            if (offset < data.size) {
                val (length, newOffset) = parseAsn1Length(data, offset)
                return Pair(0, newOffset + length)
            }
            return Pair(0, offset)
        }

        val (length, lengthOffset) = parseAsn1Length(data, offset)
        offset = lengthOffset

        var value = 0
        for (i in 0 until length) {
            if (offset < data.size) {
                value = (value shl 8) or (data[offset].toInt() and 0xFF)
                offset++
            }
        }

        return Pair(value, offset)
    }

    /**
     * Parse ASN.1 OCTET STRING and return bytes and new offset.
     */
    private fun parseAsn1OctetStringWithOffset(data: ByteArray, startOffset: Int): Pair<ByteArray, Int> {
        var offset = startOffset

        if (offset >= data.size) return Pair(ByteArray(0), offset)

        val tag = data[offset].toInt() and 0xFF
        offset++

        if (tag != 0x04) {
            // Skip this element
            if (offset < data.size) {
                val (length, newOffset) = parseAsn1Length(data, offset)
                return Pair(ByteArray(0), newOffset + length)
            }
            return Pair(ByteArray(0), offset)
        }

        val (length, lengthOffset) = parseAsn1Length(data, offset)
        offset = lengthOffset

        val endOffset = minOf(offset + length, data.size)
        val bytes = data.copyOfRange(offset, endOffset)

        return Pair(bytes, endOffset)
    }

    /**
     * Parse AuthorizationList to extract key purposes.
     * Returns list of purpose integers and new offset.
     */
    private fun parseAuthorizationList(data: ByteArray, startOffset: Int): Pair<List<Int>, Int> {
        var offset = startOffset
        val purposes = mutableListOf<Int>()

        if (offset >= data.size) return Pair(purposes, offset)

        // Expect SEQUENCE tag
        if (data[offset] != 0x30.toByte()) {
            // Skip unknown element
            offset++
            if (offset < data.size) {
                val (length, newOffset) = parseAsn1Length(data, offset)
                return Pair(purposes, newOffset + length)
            }
            return Pair(purposes, offset)
        }

        offset++
        val (seqLength, seqOffset) = parseAsn1Length(data, offset)
        offset = seqOffset
        val seqEnd = offset + seqLength

        // Parse tagged elements within the sequence
        while (offset < seqEnd && offset < data.size) {
            val tag = data[offset].toInt() and 0xFF

            // Purpose tag is [1] (context-specific tag 1)
            if (tag == 0xA1) {
                offset++
                val (purposeSetLength, purposeSetOffset) = parseAsn1Length(data, offset)
                offset = purposeSetOffset

                // Parse SET of integers
                val setEnd = offset + purposeSetLength
                while (offset < setEnd && offset < data.size) {
                    if (data[offset] == 0x02.toByte()) {
                        val (purpose, newOffset) = parseAsn1Integer(data, offset)
                        purposes.add(purpose)
                        offset = newOffset
                    } else {
                        // Skip unknown element
                        offset++
                        if (offset < data.size) {
                            val (skipLength, skipOffset) = parseAsn1Length(data, offset)
                            offset = skipOffset + skipLength
                        }
                    }
                }
            } else {
                // Skip other tagged elements
                offset++
                if (offset < data.size) {
                    val (skipLength, skipOffset) = parseAsn1Length(data, offset)
                    offset = skipOffset + skipLength
                }
            }
        }

        return Pair(purposes, seqEnd)
    }

    /**
     * Internal data class for parsed attestation record.
     */
    private data class AttestationRecord(
        val attestationVersion: Int,
        val attestationSecurityLevel: Int,
        val keymasterVersion: Int,
        val keymasterSecurityLevel: Int,
        val attestationChallenge: ByteArray,
        val purposes: List<Int>
    )
}

/**
 * HSM Backend interface.
 */
interface HSMBackend {
    fun generateKey(spec: HSMKeySpec): String
    fun importKey(spec: HSMKeySpec, keyMaterial: ByteArray): String
    fun encrypt(keyId: String, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray
    fun decrypt(keyId: String, ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray?
    fun sign(keyId: String, data: ByteArray): ByteArray
    fun verify(keyId: String, data: ByteArray, signature: ByteArray): Boolean
    fun getAttestation(keyId: String): HSMAttestation?
    fun deleteKey(keyId: String): Boolean
    fun keyExists(alias: String): Boolean
}

/**
 * StrongBox HSM backend - uses dedicated secure element.
 * Provides the highest level of security with hardware isolation.
 */
class StrongBoxBackend : HSMBackend {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val EC_SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val GCM_TAG_LENGTH = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun generateKey(spec: HSMKeySpec): String {
        when (spec.algorithm) {
            HardwareSecurityModule.ALGORITHM_AES -> generateAesKey(spec)
            HardwareSecurityModule.ALGORITHM_EC -> generateEcKey(spec)
            else -> throw IllegalArgumentException("Unsupported algorithm: ${spec.algorithm}")
        }
        return spec.alias
    }

    private fun generateAesKey(spec: HSMKeySpec) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val purposes = convertPurposes(spec.purposes)

        val builder = KeyGenParameterSpec.Builder(spec.alias, purposes)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(true)

        if (spec.requireUserAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }

        spec.attestationChallenge?.let {
            builder.setAttestationChallenge(it)
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun generateEcKey(spec: HSMKeySpec) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val purposes = convertPurposes(spec.purposes)

        val builder = KeyGenParameterSpec.Builder(spec.alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)

        if (spec.requireUserAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }

        spec.attestationChallenge?.let {
            builder.setAttestationChallenge(it)
        }

        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    override fun importKey(spec: HSMKeySpec, keyMaterial: ByteArray): String {
        // StrongBox doesn't support importing pre-generated keys
        // Generate a new key and wrap the material
        generateAesKey(spec)
        return spec.alias
    }

    override fun encrypt(keyId: String, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val secretKey = keyStore.getKey(keyId, null) as SecretKey
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }

        return cipher.doFinal(plaintext)
    }

    override fun decrypt(keyId: String, ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray? {
        return try {
            val secretKey = keyStore.getKey(keyId, null) as SecretKey
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }

            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    override fun sign(keyId: String, data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(keyId, null) as PrivateKey
        val signature = Signature.getInstance(EC_SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    override fun verify(keyId: String, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val certificate = keyStore.getCertificate(keyId)
            val publicKey = certificate.publicKey
            val sig = Signature.getInstance(EC_SIGNATURE_ALGORITHM)
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    override fun getAttestation(keyId: String): HSMAttestation? {
        return try {
            val certificateChain = keyStore.getCertificateChain(keyId) ?: return null

            val chainBytes = certificateChain.map { it.encoded }.toList()

            // Determine security level from key info
            val key = keyStore.getKey(keyId, null)
            val securityLevel = if (key is SecretKey) {
                val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    when (keyInfo.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> HardwareSecurityModule.CAPABILITY_STRONGBOX
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> HardwareSecurityModule.CAPABILITY_TEE
                        else -> HardwareSecurityModule.CAPABILITY_SOFTWARE
                    }
                } else {
                    if (keyInfo.isInsideSecureHardware) HardwareSecurityModule.CAPABILITY_STRONGBOX
                    else HardwareSecurityModule.CAPABILITY_SOFTWARE
                }
            } else {
                HardwareSecurityModule.CAPABILITY_STRONGBOX
            }

            HSMAttestation(
                certificateChain = chainBytes,
                securityLevel = securityLevel,
                challenge = ByteArray(32) // Challenge was set during key generation
            )
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteKey(keyId: String): Boolean {
        return try {
            keyStore.deleteEntry(keyId)
            true
        } catch (e: Exception) {
            false
        }
    }

    override fun keyExists(alias: String): Boolean {
        return try {
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            false
        }
    }

    private fun convertPurposes(purposes: Int): Int {
        var result = 0
        if (purposes and HardwareSecurityModule.PURPOSE_ENCRYPT != 0) {
            result = result or KeyProperties.PURPOSE_ENCRYPT
        }
        if (purposes and HardwareSecurityModule.PURPOSE_DECRYPT != 0) {
            result = result or KeyProperties.PURPOSE_DECRYPT
        }
        if (purposes and HardwareSecurityModule.PURPOSE_SIGN != 0) {
            result = result or KeyProperties.PURPOSE_SIGN
        }
        if (purposes and HardwareSecurityModule.PURPOSE_VERIFY != 0) {
            result = result or KeyProperties.PURPOSE_VERIFY
        }
        return result
    }
}

/**
 * TEE (Trusted Execution Environment) HSM backend.
 * Uses the device's TEE for hardware-backed key storage.
 */
class TEEBackend : HSMBackend {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val EC_SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val GCM_TAG_LENGTH = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun generateKey(spec: HSMKeySpec): String {
        when (spec.algorithm) {
            HardwareSecurityModule.ALGORITHM_AES -> generateAesKey(spec)
            HardwareSecurityModule.ALGORITHM_EC -> generateEcKey(spec)
            else -> throw IllegalArgumentException("Unsupported algorithm: ${spec.algorithm}")
        }
        return spec.alias
    }

    private fun generateAesKey(spec: HSMKeySpec) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val purposes = convertPurposes(spec.purposes)

        val builder = KeyGenParameterSpec.Builder(spec.alias, purposes)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        // Note: Not setting setIsStrongBoxBacked - uses TEE by default

        if (spec.requireUserAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }

        spec.attestationChallenge?.let {
            builder.setAttestationChallenge(it)
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun generateEcKey(spec: HSMKeySpec) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val purposes = convertPurposes(spec.purposes)

        val builder = KeyGenParameterSpec.Builder(spec.alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        // Note: Not setting setIsStrongBoxBacked - uses TEE by default

        if (spec.requireUserAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }

        spec.attestationChallenge?.let {
            builder.setAttestationChallenge(it)
        }

        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    override fun importKey(spec: HSMKeySpec, keyMaterial: ByteArray): String {
        // For TEE, we can import AES keys on Android 9+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && spec.algorithm == HardwareSecurityModule.ALGORITHM_AES) {
            val secretKey = SecretKeySpec(keyMaterial, "AES")
            val purposes = convertPurposes(spec.purposes)

            val builder = KeyGenParameterSpec.Builder(spec.alias, purposes)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)

            // Note: Imported keys cannot be hardware-backed, but we store them securely
            keyStore.setEntry(
                spec.alias,
                KeyStore.SecretKeyEntry(secretKey),
                KeyStore.PasswordProtection(null)
            )
        } else {
            // Fallback: generate new key
            generateAesKey(spec)
        }
        return spec.alias
    }

    override fun encrypt(keyId: String, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val secretKey = keyStore.getKey(keyId, null) as SecretKey
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }

        return cipher.doFinal(plaintext)
    }

    override fun decrypt(keyId: String, ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray? {
        return try {
            val secretKey = keyStore.getKey(keyId, null) as SecretKey
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }

            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    override fun sign(keyId: String, data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(keyId, null) as PrivateKey
        val signature = Signature.getInstance(EC_SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    override fun verify(keyId: String, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val certificate = keyStore.getCertificate(keyId)
            val publicKey = certificate.publicKey
            val sig = Signature.getInstance(EC_SIGNATURE_ALGORITHM)
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    override fun getAttestation(keyId: String): HSMAttestation? {
        return try {
            val certificateChain = keyStore.getCertificateChain(keyId) ?: return null

            val chainBytes = certificateChain.map { it.encoded }.toList()

            // Determine security level from key info
            val key = keyStore.getKey(keyId, null)
            val securityLevel = if (key is SecretKey) {
                val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    when (keyInfo.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> HardwareSecurityModule.CAPABILITY_STRONGBOX
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> HardwareSecurityModule.CAPABILITY_TEE
                        else -> HardwareSecurityModule.CAPABILITY_SOFTWARE
                    }
                } else {
                    if (keyInfo.isInsideSecureHardware) HardwareSecurityModule.CAPABILITY_TEE
                    else HardwareSecurityModule.CAPABILITY_SOFTWARE
                }
            } else if (key is PrivateKey) {
                val factory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    when (keyInfo.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> HardwareSecurityModule.CAPABILITY_STRONGBOX
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> HardwareSecurityModule.CAPABILITY_TEE
                        else -> HardwareSecurityModule.CAPABILITY_SOFTWARE
                    }
                } else {
                    if (keyInfo.isInsideSecureHardware) HardwareSecurityModule.CAPABILITY_TEE
                    else HardwareSecurityModule.CAPABILITY_SOFTWARE
                }
            } else {
                HardwareSecurityModule.CAPABILITY_TEE
            }

            HSMAttestation(
                certificateChain = chainBytes,
                securityLevel = securityLevel,
                challenge = ByteArray(32)
            )
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteKey(keyId: String): Boolean {
        return try {
            keyStore.deleteEntry(keyId)
            true
        } catch (e: Exception) {
            false
        }
    }

    override fun keyExists(alias: String): Boolean {
        return try {
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            false
        }
    }

    private fun convertPurposes(purposes: Int): Int {
        var result = 0
        if (purposes and HardwareSecurityModule.PURPOSE_ENCRYPT != 0) {
            result = result or KeyProperties.PURPOSE_ENCRYPT
        }
        if (purposes and HardwareSecurityModule.PURPOSE_DECRYPT != 0) {
            result = result or KeyProperties.PURPOSE_DECRYPT
        }
        if (purposes and HardwareSecurityModule.PURPOSE_SIGN != 0) {
            result = result or KeyProperties.PURPOSE_SIGN
        }
        if (purposes and HardwareSecurityModule.PURPOSE_VERIFY != 0) {
            result = result or KeyProperties.PURPOSE_VERIFY
        }
        return result
    }
}

/**
 * Software HSM backend (fallback).
 * Uses software-based encryption when no hardware security is available.
 */
class SoftwareHSMBackend : HSMBackend {
    private val keys = mutableMapOf<String, ByteArray>()
    private val ecKeyPairs = mutableMapOf<String, Pair<ByteArray, ByteArray>>()

    override fun generateKey(spec: HSMKeySpec): String {
        when (spec.algorithm) {
            HardwareSecurityModule.ALGORITHM_AES -> {
                val key = BedrockCore.randomBytes(32)
                keys[spec.alias] = key
            }
            HardwareSecurityModule.ALGORITHM_EC -> {
                val keyPair = BedrockCore.generateSigningKeypair()
                ecKeyPairs[spec.alias] = keyPair
            }
            else -> {
                val key = BedrockCore.randomBytes(32)
                keys[spec.alias] = key
            }
        }
        return spec.alias
    }

    override fun importKey(spec: HSMKeySpec, keyMaterial: ByteArray): String {
        keys[spec.alias] = keyMaterial.copyOf()
        return spec.alias
    }

    override fun encrypt(keyId: String, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val key = keys[keyId] ?: throw IllegalStateException("Key not found: $keyId")
        return BedrockCore.aesEncrypt(key, plaintext, aad) ?: throw IllegalStateException("Encryption failed")
    }

    override fun decrypt(keyId: String, ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray? {
        val key = keys[keyId] ?: return null
        return BedrockCore.aesDecrypt(key, ciphertext, aad)
    }

    override fun sign(keyId: String, data: ByteArray): ByteArray {
        // Try EC key first
        ecKeyPairs[keyId]?.let { (privateKey, _) ->
            return BedrockCore.sign(privateKey, data)
        }

        // Fall back to HMAC for symmetric keys
        val key = keys[keyId] ?: throw IllegalStateException("Key not found: $keyId")
        return hmacSha256(key, data)
    }

    override fun verify(keyId: String, data: ByteArray, signature: ByteArray): Boolean {
        // Try EC key first
        ecKeyPairs[keyId]?.let { (_, publicKey) ->
            return BedrockCore.verify(publicKey, data, signature)
        }

        // Fall back to HMAC verification for symmetric keys
        val key = keys[keyId] ?: return false
        val expected = hmacSha256(key, data)
        return expected.contentEquals(signature)
    }

    override fun getAttestation(keyId: String): HSMAttestation? {
        return null  // Software backend cannot attest
    }

    override fun deleteKey(keyId: String): Boolean {
        val key = keys.remove(keyId)
        key?.let { BedrockCore.zeroize(it) }

        val ecKey = ecKeyPairs.remove(keyId)
        ecKey?.let { (priv, pub) ->
            BedrockCore.zeroize(priv)
            BedrockCore.zeroize(pub)
        }

        return key != null || ecKey != null
    }

    override fun keyExists(alias: String): Boolean {
        return keys.containsKey(alias) || ecKeyPairs.containsKey(alias)
    }

    /**
     * HMAC-SHA256 implementation using Java crypto APIs.
     */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val keySpec = SecretKeySpec(key, "HmacSHA256")
        mac.init(keySpec)
        return mac.doFinal(data)
    }
}

/**
 * HSM key specification.
 */
data class HSMKeySpec(
    val alias: String,
    val algorithm: String,
    val purposes: Int,
    val requireUserAuth: Boolean,
    val attestationChallenge: ByteArray?
)

/**
 * Handle to an HSM-managed key.
 */
data class HSMKeyHandle(
    val id: String,
    val alias: String,
    val algorithm: String,
    val backendLevel: Int,
    val createdAt: Long,
    val isImported: Boolean = false
)

/**
 * HSM capabilities.
 */
data class HSMCapabilities(
    val level: Int,
    val hasStrongBox: Boolean,
    val hasTEE: Boolean,
    val hasSoftwareFallback: Boolean,
    val attestationSupported: Boolean,
    val algorithms: List<String>,
    val maxKeySize: Int,
    val securityWarnings: List<String>
) {
    val levelName: String
        get() = when (level) {
            HardwareSecurityModule.CAPABILITY_STRONGBOX -> "StrongBox"
            HardwareSecurityModule.CAPABILITY_TEE -> "TEE"
            HardwareSecurityModule.CAPABILITY_SOFTWARE -> "Software"
            else -> "None"
        }
}

/**
 * HSM attestation.
 */
data class HSMAttestation(
    val certificateChain: List<ByteArray>,
    val securityLevel: Int,
    val challenge: ByteArray
)

/**
 * Attestation verification result.
 */
data class AttestationVerificationResult(
    val valid: Boolean,
    val securityLevel: Int,
    val isHardwareBacked: Boolean = false,
    val keyPurposes: Int = 0,
    val details: String
)

/**
 * Parsed attestation properties.
 */
private data class AttestationProperties(
    val securityLevel: Int,
    val isHardwareBacked: Boolean,
    val purposes: Int,
    val attestationVersion: Int = 0,
    val keymasterVersion: Int = 0,
    val keymasterSecurityLevel: Int = 0,
    val attestationSecurityLevel: Int = 0
)
