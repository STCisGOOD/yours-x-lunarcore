package com.yours.app.crypto

import android.util.Log
import java.security.SecureRandom

/**
 * JNI Bridge to Rust Bedrock cryptographic primitives.
 * 
 * This class provides the interface to:
 * - Hk-OVCT (post-quantum + SETH-hard encryption)
 * - Key derivation (Argon2id)
 * - Ed25519 signatures
 * - X25519 key agreement
 * - AES-256-GCM symmetric encryption
 */
object BedrockCore {
    
    private const val TAG = "BedrockCore"
    
    init {
        try {
            System.loadLibrary("bedrock_core")
        } catch (e: UnsatisfiedLinkError) {
            throw RuntimeException("Bedrock crypto library not available", e)
        }
    }
    
    // ========================================================================
    // KEY DERIVATION
    // ========================================================================
    
    /**
     * Derive master key from passphrase using Argon2id.
     * 
     * @param passphrase User's four words
     * @param salt Unique salt (stored with encrypted identity)
     * @return 32-byte master key
     */
    external fun deriveKey(passphrase: ByteArray, salt: ByteArray): ByteArray
    
    /**
     * Generate cryptographically secure random bytes.
     */
    fun randomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes
    }
    
    // ========================================================================
    // IDENTITY KEYS (Ed25519 + X25519)
    // ========================================================================
    
    /**
     * Generate Ed25519 signing keypair.
     * @return Pair of (privateKey: 64 bytes, publicKey: 32 bytes)
     */
    external fun generateSigningKeypair(): Pair<ByteArray, ByteArray>
    
    /**
     * Generate X25519 encryption keypair.
     * @return Pair of (privateKey: 32 bytes, publicKey: 32 bytes)
     */
    external fun generateEncryptionKeypair(): Pair<ByteArray, ByteArray>

    /**
     * Perform X25519 Diffie-Hellman key agreement.
     *
     * This is symmetric: DH(sk_A, pk_B) == DH(sk_B, pk_A)
     * Used for blinded hints where both parties need the same shared secret.
     *
     * @param secretKey Our 32-byte X25519 secret key
     * @param publicKey Their 32-byte X25519 public key
     * @return 32-byte shared secret, or null if invalid point (RFC 7748 Section 6.1)
     */
    external fun x25519DiffieHellman(secretKey: ByteArray, publicKey: ByteArray): ByteArray?

    /**
     * Compute X25519 public key from secret key.
     *
     * The public key is computed via scalar multiplication: pk = sk * G
     * where G is the X25519 base point.
     *
     * @param secretKey 32-byte X25519 secret key
     * @return 32-byte public key, or null on error
     */
    external fun x25519ComputePublicKey(secretKey: ByteArray): ByteArray?

    /**
     * Sign a message with Ed25519.
     */
    external fun sign(privateKey: ByteArray, message: ByteArray): ByteArray
    
    /**
     * Verify an Ed25519 signature.
     */
    external fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
    
    // ========================================================================
    // Hk-OVCT (Hinted k-OV Confidential Transfer)
    // ========================================================================
    
    /**
     * Generate Hk-OVCT keypair (wraps ML-KEM-768).
     * @return Pair of (secretKey, publicKey)
     */
    external fun hkovctKeygen(): Pair<ByteArray, ByteArray>
    
    /**
     * Encrypt data using Hk-OVCT.
     * 
     * @param recipientPublicKey Recipient's Hk-OVCT public key
     * @param plaintext Data to encrypt
     * @return Ciphertext (includes KEM ciphertext + encrypted bundle + encrypted data)
     */
    external fun hkovctEncrypt(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray
    
    /**
     * Decrypt Hk-OVCT ciphertext.
     * 
     * @param secretKey Your Hk-OVCT secret key
     * @param ciphertext The encrypted data
     * @return Plaintext, or null if decryption fails
     */
    external fun hkovctDecrypt(secretKey: ByteArray, ciphertext: ByteArray): ByteArray?
    
    // ========================================================================
    // AES-256-GCM (Local symmetric encryption)
    // ========================================================================
    
    /**
     * Encrypt with AES-256-GCM.
     * Generates random nonce internally.
     * 
     * @param key 32-byte key
     * @param plaintext Data to encrypt
     * @param associatedData Optional AAD for authentication
     * @return nonce (12 bytes) || ciphertext || tag (16 bytes)
     */
    external fun aesEncrypt(
        key: ByteArray, 
        plaintext: ByteArray, 
        associatedData: ByteArray = ByteArray(0)
    ): ByteArray
    
    /**
     * Decrypt AES-256-GCM.
     * 
     * @param key 32-byte key
     * @param ciphertext nonce || ciphertext || tag
     * @param associatedData Must match what was used in encryption
     * @return Plaintext, or null if authentication fails
     */
    external fun aesDecrypt(
        key: ByteArray, 
        ciphertext: ByteArray, 
        associatedData: ByteArray = ByteArray(0)
    ): ByteArray?
    
    // ========================================================================
    // HASHING
    // ========================================================================
    
    /**
     * SHA3-256 hash.
     */
    external fun sha3_256(data: ByteArray): ByteArray
    
    /**
     * HKDF-SHA3-256 key derivation.
     */
    external fun hkdf(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int
    ): ByteArray
    
    // ========================================================================
    // SHAMIR SECRET SHARING
    // ========================================================================
    
    /**
     * Split a secret into n shares requiring k to reconstruct.
     * 
     * @param secret The secret to split
     * @param n Total number of shares
     * @param k Threshold (minimum shares needed)
     * @return List of n shares
     */
    external fun shamirSplit(secret: ByteArray, n: Int, k: Int): List<ByteArray>
    
    /**
     * Reconstruct secret from shares.
     * 
     * @param shares At least k shares from shamirSplit
     * @return The original secret, or null if reconstruction fails
     */
    external fun shamirCombine(shares: List<ByteArray>): ByteArray?
    
    // ========================================================================
    // ANONYMOUS RECOVERY SYSTEM
    // ========================================================================

    /**
     * Set up anonymous recovery system.
     *
     * Splits identity seed into 7 shares (4 needed to recover).
     * Each share is committed with Pedersen commitments for ZKP verification.
     *
     * @param passphrase User's passphrase (e.g., "forest ember shadow river")
     * @return Array of:
     *   - [0]: identity_seed (32 bytes)
     *   - [1]: nullifier_secret (32 bytes)
     *   - [2..8]: serialized SharePackages for distribution
     */
    external fun setupRecovery(passphrase: ByteArray): Array<ByteArray>

    /**
     * Create proof to retrieve a share from a mesh node.
     *
     * Uses Schnorr proof to prove knowledge of blinding factor
     * without revealing it.
     *
     * @param passphrase User's passphrase
     * @param index Share index (1-7)
     * @param context Request context (node_id || timestamp)
     * @return Proof data: blinding_commitment (32) || proof (64)
     */
    external fun createRetrievalProof(
        passphrase: ByteArray,
        index: Int,
        context: ByteArray
    ): ByteArray

    /**
     * Verify retrieval proof (for mesh nodes).
     *
     * @param storedCommitment The blinding commitment stored with the share
     * @param proofData The proof from createRetrievalProof
     * @param context Must match what was used in proof creation
     */
    external fun verifyRetrievalProof(
        storedCommitment: ByteArray,
        proofData: ByteArray,
        context: ByteArray
    ): Boolean

    /**
     * Derive nullifier for dead man's switch check-in.
     *
     * Publish this each week to prove you're alive.
     * If you stop publishing, recovery may be triggered.
     *
     * @param passphrase User's passphrase
     * @return Nullifier (32 bytes) for current epoch
     */
    external fun deriveNullifier(passphrase: ByteArray): ByteArray

    /**
     * Derive nullifier for a specific epoch.
     *
     * @param nullifierSecret The nullifier secret (from setupRecovery)
     * @param epoch Epoch number (week since Unix epoch)
     */
    external fun deriveNullifierForEpoch(
        nullifierSecret: ByteArray,
        epoch: Long
    ): ByteArray

    /**
     * Get current epoch number (weeks since Unix epoch).
     */
    external fun currentEpoch(): Long

    /**
     * Decrypt a retrieved share package.
     *
     * @param passphrase User's passphrase
     * @param packageData Serialized SharePackage from node
     * @return Decoded share (33 bytes: x || y)
     */
    external fun decryptShare(
        passphrase: ByteArray,
        packageData: ByteArray
    ): ByteArray?

    /**
     * Reconstruct identity seed from recovered shares.
     *
     * @param shares At least 4 decoded shares
     * @return Reconstructed identity seed (32 bytes)
     */
    external fun reconstructIdentitySeed(
        shares: Array<ByteArray>
    ): ByteArray?

    /**
     * Derive identity keys from identity seed.
     *
     * Use this after recovery to regenerate all keys.
     *
     * @param identitySeed The reconstructed identity seed
     * @return Array of:
     *   - [0]: signing_private (32 bytes)
     *   - [1]: signing_public (32 bytes)
     *   - [2]: encryption_private (2400 bytes, ML-KEM-768)
     *   - [3]: encryption_public (1184 bytes, ML-KEM-768)
     */
    external fun deriveIdentityKeys(identitySeed: ByteArray): Array<ByteArray>?

    // ========================================================================
    // DEVICE BINDING (Gap Closure #1)
    // ========================================================================

    /**
     * Minimum passphrase requirement: 8 words = 88 bits entropy.
     * This defeats nation-state brute force attacks.
     */
    const val MIN_PASSPHRASE_WORDS = 8
    const val BITS_PER_WORD = 11
    const val MIN_ENTROPY_BITS = MIN_PASSPHRASE_WORDS * BITS_PER_WORD

    /**
     * Validate passphrase meets security requirements.
     *
     * @param passphrase UTF-8 encoded passphrase string
     * @return ByteArray of [valid, word_count, entropy_bits, error_code]
     *         error_code: 0=none, 1=empty, 2=too_short, 3=invalid_chars, 4=invalid_word
     */
    external fun validatePassphrase(passphrase: ByteArray): ByteArray

    /**
     * Derive device-bound key from passphrase and device secret.
     *
     * Uses Argon2id with 512MB memory (mobile) or 1GB (desktop).
     * Key is bound to this specific device - passphrase alone is insufficient.
     *
     * @param passphrase User's 8+ word passphrase
     * @param deviceSecret 32-byte device-specific secret
     * @param salt 32-byte random salt (stored with encrypted vault)
     * @return 64 bytes: identity_seed (32) || recovery_seed (32)
     */
    external fun deriveDeviceBoundKey(
        passphrase: ByteArray,
        deviceSecret: ByteArray,
        salt: ByteArray
    ): ByteArray?

    /**
     * Create device secret from hardware ID.
     *
     * Call this with Android's ANDROID_ID or hardware serial.
     * The secret is deterministic for the same hardware.
     *
     * @param hardwareId Device-specific identifier
     * @return 32-byte device secret
     */
    external fun createDeviceSecret(hardwareId: ByteArray): ByteArray

    // ========================================================================
    // DURESS VAULT (Gap Closure #2 - Plausible Deniability)
    // ========================================================================

    /**
     * Create dual vaults for plausible deniability.
     *
     * - Real vault: opened with normal passphrase
     * - Decoy vault: opened with passphrase + derived duress marker
     *
     * Under coercion, provide the duress passphrase to reveal
     * innocent-looking decoy content. Adversary cannot prove
     * real vault exists.
     *
     * SECURITY: The duress marker is derived from duressWord + deviceSecret,
     * making it unpredictable to attackers. The old hardcoded " duress" marker
     * was vulnerable to attackers trying common suffixes.
     *
     * @param passphrase Normal passphrase (NOT the duress version)
     * @param deviceSecret Device binding secret
     * @param duressWord User-chosen word for duress marker derivation
     * @param realIdentitySeed Actual identity seed
     * @param realMetadata Actual metadata to protect
     * @param decoyIdentitySeed Decoy identity seed
     * @param decoyMetadata Innocent-looking decoy data
     * @return Array of [realVault, decoyVault] (both encrypted)
     */
    external fun createDualVaults(
        passphrase: ByteArray,
        deviceSecret: ByteArray,
        duressWord: ByteArray,
        realIdentitySeed: ByteArray,
        realMetadata: ByteArray,
        decoyIdentitySeed: ByteArray,
        decoyMetadata: ByteArray
    ): Array<ByteArray>?

    /**
     * Decrypt vault with passphrase.
     *
     * Returns null if wrong passphrase (no error to avoid oracle).
     * Result tells you which vault type was opened.
     *
     * @param passphrase User's passphrase (normal or duress)
     * @param deviceSecret Device binding secret
     * @param encryptedVault The encrypted vault blob
     * @return ByteArray of [vault_type (1=real, 2=decoy), identity_seed (32), metadata...]
     *         or null if wrong passphrase
     */
    external fun decryptVault(
        passphrase: ByteArray,
        deviceSecret: ByteArray,
        encryptedVault: ByteArray
    ): ByteArray?

    /**
     * Check if a passphrase is a duress passphrase.
     *
     * The duress marker is derived from duressWord + deviceSecret,
     * and checked against the passphrase suffix.
     *
     * @param passphrase The passphrase to check
     * @param deviceSecret Device binding secret
     * @param duressWord User-chosen word for duress marker derivation
     * @return true if passphrase ends with the derived duress marker
     */
    external fun isDuressPassphrase(
        passphrase: ByteArray,
        deviceSecret: ByteArray,
        duressWord: ByteArray
    ): Boolean

    // ========================================================================
    // RING SIGNATURES (Gap Closure #3 - Anonymous Nullifiers)
    // ========================================================================

    /**
     * Generate keypair for ring signatures.
     *
     * @return Array of [privateKey (32), publicKey (32)]
     */
    external fun generateRingKeypair(): Array<ByteArray>

    /**
     * Create anonymous nullifier with ring signature.
     *
     * The nullifier proves you're part of the anonymity set (ring)
     * without revealing which member you are. Key images allow
     * detection of double-signing.
     *
     * @param nullifierSecret 32-byte secret from passphrase
     * @param signingKey 32-byte private key
     * @param ring Array of public keys (anonymity set, must include yours)
     * @param signerIndex Your index in the ring
     * @param epoch Current epoch number
     * @return Serialized anonymous nullifier
     */
    external fun createAnonymousNullifier(
        nullifierSecret: ByteArray,
        signingKey: ByteArray,
        ring: Array<ByteArray>,
        signerIndex: Int,
        epoch: Long
    ): ByteArray?

    /**
     * Verify anonymous nullifier.
     *
     * Checks that the ring signature is valid without
     * learning which ring member signed.
     */
    external fun verifyAnonymousNullifier(nullifierData: ByteArray): Boolean

    /**
     * Extract key image from anonymous nullifier.
     *
     * Key images are linkable - same signer produces same key image.
     * Used to detect if same identity published multiple nullifiers.
     */
    external fun extractKeyImage(nullifierData: ByteArray): ByteArray?

    /**
     * Check if two anonymous nullifiers are from the same signer.
     *
     * Compares key images - same key image means same signer,
     * even though you can't tell WHICH member of the ring.
     */
    external fun isSameSigner(nullifier1: ByteArray, nullifier2: ByteArray): Boolean

    // ========================================================================
    // COVER TRAFFIC (Anti-XKeyscore)
    // ========================================================================

    /**
     * Standard packet size for all traffic (256 bytes).
     * All messages are padded to this size for traffic analysis resistance.
     */
    external fun getCoverPacketSize(): Int

    /**
     * Maximum payload per packet after encryption overhead.
     */
    external fun getMaxPayloadSize(): Int

    /**
     * Create a cover traffic generator.
     *
     * @param seed 32-byte random seed (use SecureRandom)
     * @return Handle to native generator (pass to other cover traffic functions)
     */
    external fun createCoverTrafficGenerator(seed: ByteArray): Long

    /**
     * Destroy cover traffic generator and free memory.
     */
    external fun destroyCoverTrafficGenerator(handle: Long)

    /**
     * Pad and encrypt a message to fixed packet size.
     *
     * Real messages are indistinguishable from chaff to an observer
     * without the encryption key.
     *
     * @param handle Generator handle
     * @param key 32-byte encryption key
     * @param plaintext Message to send
     * @return 256-byte encrypted packet
     */
    external fun padMessage(handle: Long, key: ByteArray, plaintext: ByteArray): ByteArray?

    /**
     * Generate chaff packet (encrypted random garbage).
     *
     * Chaff is indistinguishable from real traffic. Send chaff
     * to mask activity patterns and defeat traffic analysis.
     *
     * @param handle Generator handle
     * @return 256-byte chaff packet
     */
    external fun generateChaff(handle: Long): ByteArray?

    /**
     * Decrypt and unpad a received packet.
     *
     * @param handle Generator handle
     * @param key 32-byte decryption key
     * @param packet 256-byte encrypted packet
     * @return [type, payload...] where type: 1=real, 2=chaff, 3=heartbeat, 4=ack
     *         Returns null if decryption fails
     */
    external fun unpadMessage(handle: Long, key: ByteArray, packet: ByteArray): ByteArray?

    /**
     * Get next send delay with random jitter.
     *
     * Use this to schedule your next transmission. Random delays
     * defeat timing correlation attacks.
     *
     * @param handle Generator handle
     * @return Delay in milliseconds
     */
    external fun nextSendDelay(handle: Long): Long

    /**
     * Check if we should send chaff right now.
     *
     * Call this when idle to determine if chaff should be sent
     * to maintain constant traffic pattern.
     *
     * @param handle Generator handle
     * @param currentTimeMs Current system time in milliseconds
     * @return true if chaff should be sent
     */
    external fun shouldSendChaff(handle: Long, currentTimeMs: Long): Boolean

    // ========================================================================
    // STEGANOGRAPHY (Hide in Plain Sight)
    // ========================================================================

    /**
     * Calculate steganographic capacity for an image.
     *
     * Use this to determine how much data can be hidden in an image
     * before attempting to embed.
     *
     * @param width Image width in pixels
     * @param height Image height in pixels
     * @param channels Color channels (3 for RGB, 4 for RGBA)
     * @return Maximum bytes that can be hidden
     */
    external fun stegoCapacity(width: Int, height: Int, channels: Int): Int

    /**
     * Embed encrypted data into image pixels.
     *
     * The output image is visually identical to the input - only LSBs are modified.
     * Data is encrypted before embedding, so extraction requires the correct key.
     *
     * Usage with Android Bitmap:
     * ```
     * val pixels = IntArray(width * height)
     * bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
     * val rgbaBytes = pixels.flatMap { listOf(
     *     (it shr 16 and 0xFF).toByte(),  // R
     *     (it shr 8 and 0xFF).toByte(),   // G
     *     (it and 0xFF).toByte(),         // B
     *     (it shr 24 and 0xFF).toByte()   // A
     * )}.toByteArray()
     * val stegBytes = BedrockCore.stegoEmbed(rgbaBytes, width, height, 4, key, data)
     * ```
     *
     * @param pixels Raw pixel data (RGB or RGBA, row-major order)
     * @param width Image width
     * @param height Image height
     * @param channels 3 for RGB, 4 for RGBA
     * @param key 32-byte encryption key
     * @param data Data to hide
     * @return Modified pixels with embedded data, or null on error
     */
    external fun stegoEmbed(
        pixels: ByteArray,
        width: Int,
        height: Int,
        channels: Int,
        key: ByteArray,
        data: ByteArray
    ): ByteArray?

    /**
     * Extract hidden data from image pixels.
     *
     * Requires the same key used during embedding.
     * Returns null if no hidden data found or wrong key.
     *
     * @param pixels Pixel data with embedded content
     * @param width Image width
     * @param height Image height
     * @param channels 3 for RGB, 4 for RGBA
     * @param key 32-byte decryption key
     * @return Extracted data, or null if extraction fails
     */
    external fun stegoExtract(
        pixels: ByteArray,
        width: Int,
        height: Int,
        channels: Int,
        key: ByteArray
    ): ByteArray?

    /**
     * Detect if image likely contains hidden data.
     *
     * Uses statistical analysis (chi-square on LSBs).
     * Not definitive - just a heuristic.
     *
     * @param pixels Raw pixel data
     * @param width Image width
     * @param height Image height
     * @param channels 3 for RGB, 4 for RGBA
     * @return Confidence score 0-100 (higher = more likely contains stego)
     */
    external fun stegoDetect(
        pixels: ByteArray,
        width: Int,
        height: Int,
        channels: Int
    ): Int

    // ========================================================================
    // ONION ROUTING (MeshCore - Bypass Internet)
    // ========================================================================

    /**
     * Node ID size for MeshCore routing.
     */
    external fun getOnionNodeIdSize(): Int

    /**
     * Maximum payload size for onion packets.
     */
    external fun getOnionMaxPayload(): Int

    /**
     * Minimum hops for meaningful anonymity.
     */
    external fun getOnionMinHops(): Int

    /**
     * Maximum hops allowed.
     */
    external fun getOnionMaxHops(): Int

    /**
     * Create an ANONYMOUS onion-routed packet with ENFORCED minimum hops.
     *
     * SECURITY: This function REQUIRES at least MIN_HOPS (2) relay nodes.
     * Returns null if you don't provide enough relays - this is intentional
     * to prevent accidental anonymity compromise.
     *
     * The message is encrypted in layers - each relay can only
     * see the next hop, not the final destination or content.
     * This provides anonymity even if some relays are compromised.
     *
     * For non-anonymous direct messaging, use createOnionPacketDirect().
     *
     * @param routeNodeIds Array of relay node IDs (8 bytes each) - MUST have at least 1 relay
     * @param routePublicKeys Array of relay X25519 public keys (32 bytes each)
     * @param destNodeId Destination node ID
     * @param destPublicKey Destination X25519 public key
     * @param payload Message to send (max 200 bytes)
     * @return Serialized onion packet, or null if route too short for anonymity
     */
    external fun createOnionPacket(
        routeNodeIds: Array<ByteArray>,
        routePublicKeys: Array<ByteArray>,
        destNodeId: ByteArray,
        destPublicKey: ByteArray,
        payload: ByteArray
    ): ByteArray?

    /**
     * Create a DIRECT (non-anonymous) packet to destination.
     *
     * WARNING: This provides NO ANONYMITY. The destination knows your identity.
     *
     * Only use for:
     * - Initial contact establishment where anonymity isn't needed
     * - Local mesh announcements
     * - When you WANT the recipient to know who you are
     *
     * For ANONYMOUS messaging, ALWAYS use createOnionPacket() instead.
     *
     * @param destNodeId Destination node ID
     * @param destPublicKey Destination X25519 public key
     * @param payload Message to send
     * @return Serialized packet for transmission
     */
    external fun createOnionPacketDirect(
        destNodeId: ByteArray,
        destPublicKey: ByteArray,
        payload: ByteArray
    ): ByteArray?

    /**
     * Peel one layer from a received onion packet.
     *
     * Call this when your node receives an onion packet.
     * The result tells you whether to forward or deliver.
     *
     * @param packetData Received onion packet
     * @param privateKey Your node's X25519 private key
     * @return [type, data...] where:
     *         type=1: Relay - forward to next_hop_id (bytes 1-8), packet (bytes 9+)
     *         type=2: Destination - decrypted payload (bytes 1+)
     *         Returns null if decryption fails (not for you)
     */
    external fun peelOnionLayer(
        packetData: ByteArray,
        privateKey: ByteArray
    ): ByteArray?

    // ========================================================================
    // LUNAR HK-OVCT (Handle-Based Hedged Key Encapsulation)
    // ========================================================================
    //
    // LunarCore protocol's hedged KEM for LoRa mesh communication.
    // Secrets NEVER cross JNI boundary - Kotlin only gets handles.
    //
    // Security model:
    // - Hedged entropy: System RNG XOR deterministic XOR sensor data
    // - Dual-DH: Two independent DH operations for defense-in-depth
    // - Handle registry: Thread-safe storage, secrets stay in Rust memory
    //
    // Usage flow:
    // 1. lunarHkOvctKeygen() → (secretKey, publicKey)
    // 2. lunarHkOvctEncapsulate(pk, sk, entropy) → (ciphertext, handle)
    // 3. lunarHkOvctDeriveSessionKey(handle, context) → sessionKey
    // 4. lunarHkOvctDeleteSecret(handle) → cleanup when done
    // ========================================================================

    /**
     * Generate Lunar Hk-OVCT keypair (X25519).
     *
     * @return Pair of (secretKey: 32 bytes, publicKey: 32 bytes)
     *
     * SECURITY: Store secretKey encrypted with Argon2-derived key.
     */
    external fun lunarHkOvctKeygen(): Pair<ByteArray, ByteArray>

    /**
     * Encapsulate shared secret using hedged entropy.
     *
     * Combines three entropy sources via XOR:
     * 1. System RNG (may be backdoored)
     * 2. Deterministic from long-term keys (independent of RNG)
     * 3. External sensors (accelerometer, gyro, touch timing)
     *
     * Security: Shared secret is unpredictable if ANY source is good.
     *
     * @param recipientPk Recipient's 32-byte X25519 public key
     * @param senderSk Sender's 32-byte secret key (for hedging)
     * @param auxEntropy External entropy from sensors (use lunarCollectEntropy)
     * @return Pair of (ciphertext: 32 bytes, handle: Long) or null on error
     *
     * CRITICAL: Call lunarHkOvctDeleteSecret(handle) when session ends!
     */
    external fun lunarHkOvctEncapsulate(
        recipientPk: ByteArray,
        senderSk: ByteArray,
        auxEntropy: ByteArray
    ): Pair<ByteArray, Long>?

    /**
     * Decapsulate shared secret from ciphertext.
     *
     * @param ciphertext 32-byte ciphertext from encapsulation
     * @param recipientSk Recipient's 32-byte secret key
     * @return Handle for key derivation, or -1 on error
     *
     * CRITICAL: Call lunarHkOvctDeleteSecret(handle) when session ends!
     */
    external fun lunarHkOvctDecapsulate(
        ciphertext: ByteArray,
        recipientSk: ByteArray
    ): Long

    /**
     * Derive session key from stored shared secret.
     *
     * Different contexts produce different keys (domain separation).
     * Example contexts: "send", "recv", "handshake", "data"
     *
     * @param handle Secret handle from encapsulate/decapsulate
     * @param context Context bytes for domain separation
     * @return 32-byte derived key, or null if handle invalid
     */
    external fun lunarHkOvctDeriveSessionKey(
        handle: Long,
        context: ByteArray
    ): ByteArray?

    /**
     * Delete shared secret from registry.
     *
     * CRITICAL: Call this when session ends to zeroize memory.
     * Failing to call this leaks memory until process exit.
     *
     * @param handle Secret handle to delete
     * @return true if deleted, false if handle was invalid
     */
    external fun lunarHkOvctDeleteSecret(handle: Long): Boolean

    /**
     * Collect entropy from Android sensors for hedging.
     *
     * Hash sensor data into 32 bytes suitable for auxEntropy parameter.
     * Call with concatenated sensor readings:
     * - Accelerometer (x, y, z) over time
     * - Gyroscope readings
     * - Touch event coordinates and timestamps
     * - Any other available sensor data
     *
     * @param sensorData Raw sensor bytes (concatenate all sources)
     * @return 32-byte entropy suitable for lunarHkOvctEncapsulate
     */
    external fun lunarCollectEntropy(sensorData: ByteArray): ByteArray?

    // ========================================================================
    // LUNAR SESSION MANAGEMENT
    // ========================================================================
    //
    // Double Ratchet session management for forward secrecy and post-compromise
    // security over LoRa mesh. Sessions are stored in Rust and accessed via handles.
    //
    // Usage flow:
    // 1. Initiator: lunarSessionInitiate(ourSk, theirPk, entropy) → (handshake, hint, handle)
    // 2. Responder: lunarSessionRespond(ourSk, handshake) → (hint, handle)
    // 3. Both: lunarSessionEncrypt(handle, plaintext) → ciphertext
    // 4. Both: lunarSessionDecrypt(handle, ciphertext) → plaintext
    // 5. Cleanup: lunarSessionClose(handle)

    /**
     * Create a new session as initiator.
     *
     * @param ourSk Our 32-byte secret key
     * @param theirPk Their 32-byte public key
     * @param auxEntropy External entropy for hedging
     * @return Triple of (handshakePacket, sessionHint, sessionHandle), or null on error
     *
     * Send the handshake packet to the peer over the mesh.
     * The sessionHint is used for routing (4 bytes).
     */
    external fun lunarSessionInitiate(
        ourSk: ByteArray,
        theirPk: ByteArray,
        auxEntropy: ByteArray
    ): Triple<ByteArray, ByteArray, Long>?

    /**
     * Accept a handshake and create responding session.
     *
     * @param ourSk Our 32-byte secret key
     * @param handshakeBytes Handshake packet from initiator
     * @return Pair of (sessionHint, sessionHandle), or null on error
     */
    external fun lunarSessionRespond(
        ourSk: ByteArray,
        handshakeBytes: ByteArray
    ): Pair<ByteArray, Long>?

    /**
     * Encrypt a message using the session.
     *
     * @param sessionHandle Handle from lunarSessionInitiate/Respond
     * @param plaintext Message to encrypt
     * @return Encrypted ciphertext, or null on error
     */
    external fun lunarSessionEncrypt(
        sessionHandle: Long,
        plaintext: ByteArray
    ): ByteArray?

    /**
     * Decrypt a message using the session.
     *
     * @param sessionHandle Handle from lunarSessionInitiate/Respond
     * @param ciphertext Message to decrypt
     * @return Decrypted plaintext, or null on error
     */
    external fun lunarSessionDecrypt(
        sessionHandle: Long,
        ciphertext: ByteArray
    ): ByteArray?

    /**
     * Check if session should perform DH ratchet.
     *
     * Returns true if session has sent many messages or been active for a while.
     * When true, consider performing a key ratchet for post-compromise security.
     */
    external fun lunarSessionShouldRatchet(sessionHandle: Long): Boolean

    /**
     * Close a session and zeroize all keys.
     *
     * CRITICAL: Always call this when done to prevent key leakage.
     */
    external fun lunarSessionClose(sessionHandle: Long): Boolean

    // ========================================================================
    // LUNAR PACKET ENCODING
    // ========================================================================
    //
    // Packet encoding/decoding for LoRa mesh (237-byte MTU).
    // Packet types: Data (0), Handshake (1), Control (2), Cover (3)

    /**
     * Encode a data packet.
     *
     * @param nextHopHint 2-byte routing hint for next relay
     * @param sessionHint 4-byte session lookup hint
     * @param encryptedPayload Encrypted message data
     * @return Encoded packet bytes, or null on error
     */
    external fun lunarPacketEncodeData(
        nextHopHint: ByteArray,
        sessionHint: ByteArray,
        encryptedPayload: ByteArray
    ): ByteArray?

    /**
     * Decode a data packet.
     *
     * @param packetBytes Raw packet bytes
     * @return Triple of (nextHopHint, sessionHint, encryptedPayload), or null on error
     */
    external fun lunarPacketDecodeData(packetBytes: ByteArray): Triple<ByteArray, ByteArray, ByteArray>?

    /**
     * Get packet type.
     *
     * @param packetBytes Raw packet bytes
     * @return Packet type (0=Data, 1=Handshake, 2=Control, 3=Cover), or -1 on error
     */
    external fun lunarPacketGetType(packetBytes: ByteArray): Int

    /**
     * Generate a cover packet (chaff traffic).
     *
     * Cover packets are indistinguishable from data packets to external observers.
     *
     * @param size Size of random data (1-236 bytes)
     * @return Encoded cover packet, or null on error
     */
    external fun lunarPacketGenerateCover(size: Int): ByteArray?

    /**
     * Derive a 2-byte node hint from a public key.
     */
    external fun lunarDeriveNodeHint(publicKey: ByteArray): ByteArray?

    /**
     * Derive a 4-byte session hint from a session key.
     */
    external fun lunarDeriveSessionHint(sessionKey: ByteArray): ByteArray?

    // ========================================================================
    // LUNAR ROUTING
    // ========================================================================
    //
    // Node discovery, circuit construction, and path selection.
    // Routers are stored in Rust and accessed via handles.

    /**
     * Create a new Lunar router with a fresh identity.
     *
     * @return Router handle, or -1 on error
     */
    external fun lunarRouterCreate(): Long

    /**
     * Create a node announcement for broadcasting.
     *
     * @param routerHandle Router handle
     * @param region Optional region identifier (0 = none)
     * @param operator Optional operator identifier (0 = none)
     * @return Encoded announcement bytes, or null on error
     */
    external fun lunarRouterCreateAnnouncement(
        routerHandle: Long,
        region: Int,
        operator: Int
    ): ByteArray?

    /**
     * Process a received node announcement.
     *
     * @param routerHandle Router handle
     * @param announcementBytes Received announcement
     * @return true if valid and added, false otherwise
     */
    external fun lunarRouterProcessAnnouncement(
        routerHandle: Long,
        announcementBytes: ByteArray
    ): Boolean

    /**
     * Get router statistics.
     *
     * @param routerHandle Router handle
     * @return 20-byte array with stats (5 x u32 big-endian):
     *   [knownNodes, activeNodes, totalCircuits, readyCircuits, pendingBuilds]
     */
    external fun lunarRouterGetStats(routerHandle: Long): ByteArray?

    /**
     * Get our node's public hint.
     *
     * @param routerHandle Router handle
     * @return 2-byte hint, or null on error
     */
    external fun lunarRouterGetOurHint(routerHandle: Long): ByteArray?

    /**
     * Close a router and clean up resources.
     */
    external fun lunarRouterClose(routerHandle: Long): Boolean

    // ========================================================================
    // LUNAR CIRCUIT OPERATIONS (AES-256-GCM Onion Routing)
    // ========================================================================
    //
    // Circuit-based anonymous routing with path diversity.
    // Circuits are persistent tunnels (like Tor) that can send multiple messages.
    //
    // Flow:
    // 1. lunarRouterBuildCircuit() - Select path and create circuit
    // 2. lunarRouterEstablishCircuit() - Get handshakes for each hop
    // 3. [Send handshakes to each relay, get confirmations]
    // 4. lunarRouterConfirmHop() - Mark each hop as established
    // 5. lunarRouterWrapMessage() - Wrap messages through the circuit
    // 6. lunarRouterCloseCircuit() - Close when done or needs rotation

    /**
     * Build a new circuit with path selection criteria.
     *
     * @param routerHandle Router handle
     * @param minHops Minimum hops (0 = default MIN_CIRCUIT_HOPS = 3)
     * @param maxHops Maximum hops (0 = default MAX_CIRCUIT_HOPS = 5)
     * @param diverseRegions Require different regions for each hop
     * @param diverseOperators Require different operators for each hop
     * @param minReliability Minimum reliability score (0 = no minimum)
     * @return 8-byte circuit ID, or null on error
     */
    external fun lunarRouterBuildCircuit(
        routerHandle: Long,
        minHops: Int,
        maxHops: Int,
        diverseRegions: Boolean,
        diverseOperators: Boolean,
        minReliability: Int
    ): ByteArray?

    /**
     * Establish sessions with all hops in a circuit.
     *
     * Creates handshake packets for each relay. These must be sent
     * to the relays and confirmations received before the circuit is ready.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID from buildCircuit
     * @param auxEntropy Additional entropy for hedged key exchange
     * @return Encoded handshakes: [numHops(1), hop0Len(2), hop0Data, ...]
     */
    external fun lunarRouterEstablishCircuit(
        routerHandle: Long,
        circuitId: ByteArray,
        auxEntropy: ByteArray
    ): ByteArray?

    /**
     * Confirm that a circuit hop has been established.
     *
     * Call this after receiving confirmation from each relay.
     * When all hops are confirmed, the circuit becomes ready.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID
     * @param hopIndex Which hop (0 = entry relay)
     * @return true if successful
     */
    external fun lunarRouterConfirmHop(
        routerHandle: Long,
        circuitId: ByteArray,
        hopIndex: Int
    ): Boolean

    /**
     * Wrap a message through a circuit for anonymous transmission.
     *
     * The message is wrapped in multiple layers of AES-256-GCM encryption,
     * one for each hop. Each relay peels one layer and forwards.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID (must be Ready state)
     * @param payload Message to send
     * @param recipientHint 2-byte hint of final recipient
     * @return Onion-wrapped packet to send to entry relay
     */
    external fun lunarRouterWrapMessage(
        routerHandle: Long,
        circuitId: ByteArray,
        payload: ByteArray,
        recipientHint: ByteArray
    ): ByteArray?

    /**
     * Get the entry node hint for a circuit.
     *
     * The entry hint is needed to route the wrapped packet to the first hop.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID
     * @return 2-byte entry node hint
     */
    external fun lunarRouterGetEntryHint(
        routerHandle: Long,
        circuitId: ByteArray
    ): ByteArray?

    /**
     * Get circuit info.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID
     * @return 7 bytes: [state(1), hopCount(1), messageCount(4), needsRotation(1)]
     *         States: 0=Building, 1=Ready, 2=Closing, 3=Closed
     */
    external fun lunarRouterGetCircuitInfo(
        routerHandle: Long,
        circuitId: ByteArray
    ): ByteArray?

    /**
     * Close a specific circuit.
     *
     * @param routerHandle Router handle
     * @param circuitId 8-byte circuit ID
     * @return true if closed successfully
     */
    external fun lunarRouterCloseCircuit(
        routerHandle: Long,
        circuitId: ByteArray
    ): Boolean

    /**
     * Cleanup stale circuits.
     *
     * Closes circuits that need rotation (expired or message limit reached).
     *
     * @param routerHandle Router handle
     */
    external fun lunarRouterCleanup(routerHandle: Long)

    /**
     * Get or build a ready circuit.
     *
     * Returns an existing ready circuit if available, otherwise builds a new one.
     * This is the simplest way to get a circuit for sending.
     *
     * @param routerHandle Router handle
     * @param minHops Minimum hops (0 = default)
     * @return 8-byte circuit ID, or null if not enough nodes known
     */
    external fun lunarRouterGetOrBuildCircuit(
        routerHandle: Long,
        minHops: Int
    ): ByteArray?

    // ========================================================================
    // LUNAR ROUTER BBS+ AUTHENTICATION
    // ========================================================================

    /**
     * Add a trusted issuer to the router for BBS+ credential verification.
     *
     * @param routerHandle Router handle
     * @param issuerId 32-byte issuer identifier
     * @param issuerPublicKey Serialized IssuerPublicKey
     * @return true on success, false on error
     */
    external fun lunarRouterAddTrustedIssuer(
        routerHandle: Long,
        issuerId: ByteArray,
        issuerPublicKey: ByteArray
    ): Boolean

    /**
     * Remove a trusted issuer from the router (for revocation).
     *
     * @param routerHandle Router handle
     * @param issuerId 32-byte issuer identifier
     * @return true on success, false on error
     */
    external fun lunarRouterRemoveTrustedIssuer(
        routerHandle: Long,
        issuerId: ByteArray
    ): Boolean

    /**
     * Verify a BBS+ mesh access proof via the router.
     *
     * This checks:
     * 1. The proof is cryptographically valid
     * 2. The issuer is trusted by this router
     * 3. Rate limiting hasn't been exceeded
     *
     * @param routerHandle Router handle
     * @param proofBytes Serialized MeshAccessProof
     * @return Serialized VerifiedAccess (issuer_id:32 || access_level:1 || rate_token:32 || epoch:8)
     *         or null on error (invalid proof, untrusted issuer, or rate limited)
     */
    external fun lunarRouterVerifyAccessProof(
        routerHandle: Long,
        proofBytes: ByteArray
    ): ByteArray?

    /**
     * Register a node's verified access in the router.
     *
     * Call this after successfully verifying a BBS+ proof to authorize a node.
     *
     * @param routerHandle Router handle
     * @param nodeHint NODE_HINT_SIZE-byte node hint (4 bytes)
     * @param verifiedAccess Serialized VerifiedAccess from lunarRouterVerifyAccessProof
     * @return true on success, false on error
     */
    external fun lunarRouterRegisterNodeAccess(
        routerHandle: Long,
        nodeHint: ByteArray,
        verifiedAccess: ByteArray
    ): Boolean

    /**
     * Check if a node is authorized based on BBS+ authentication.
     *
     * @param routerHandle Router handle
     * @param nodeHint NODE_HINT_SIZE-byte node hint (4 bytes)
     * @return true if authorized, false otherwise
     */
    external fun lunarRouterIsNodeAuthorized(
        routerHandle: Long,
        nodeHint: ByteArray
    ): Boolean

    /**
     * Get the issuer ID from a MeshIssuer handle.
     *
     * @param issuerHandle Handle from meshIssuerCreate
     * @return 32-byte issuer ID, or null on error
     */
    external fun meshIssuerGetId(issuerHandle: Long): ByteArray?

    // ========================================================================
    // MESH CREDENTIALS (BBS+ Anonymous Access)
    // ========================================================================

    /**
     * Create a mesh issuer for issuing anonymous mesh access credentials.
     * @return Handle to issuer or -1 on error
     */
    external fun meshIssuerCreate(): Long

    /**
     * Issue a mesh access credential.
     * @param issuerHandle Handle from meshIssuerCreate
     * @param pubkeyCommitment 32-byte hash of user's public key
     * @param accessLevel 0=Basic, 1=Trusted, 2=Guardian
     * @return Serialized MeshCredential or null on error
     */
    external fun meshIssuerIssue(
        issuerHandle: Long,
        pubkeyCommitment: ByteArray,
        accessLevel: Int
    ): ByteArray?

    /**
     * Get issuer public key.
     * @param issuerHandle Handle from meshIssuerCreate
     * @return Serialized IssuerPublicKey or null on error
     */
    external fun meshIssuerGetPublicKey(issuerHandle: Long): ByteArray?

    /**
     * Create an anonymous mesh access proof from a credential.
     * @param credentialBytes Serialized MeshCredential
     * @param issuerPublicKey Serialized IssuerPublicKey
     * @param epoch Current epoch number
     * @return Serialized MeshAccessProof or null on error
     */
    external fun meshCredentialProve(
        credentialBytes: ByteArray,
        issuerPublicKey: ByteArray,
        epoch: Long
    ): ByteArray?

    /**
     * Verify a mesh access proof.
     * @param proofBytes Serialized MeshAccessProof
     * @param issuerPublicKey Serialized IssuerPublicKey
     * @return Verification result: (issuer_id:32 || access_level:1 || rate_token:32 || epoch:8) or null
     */
    external fun meshProofVerify(
        proofBytes: ByteArray,
        issuerPublicKey: ByteArray
    ): ByteArray?

    /**
     * Get current epoch number for rate limiting.
     */
    external fun meshGetCurrentEpoch(): Long

    /**
     * Access levels for mesh credentials.
     */
    object MeshAccessLevel {
        const val BASIC = 0      // Can relay, lower priority
        const val TRUSTED = 1    // Normal routing priority
        const val GUARDIAN = 2   // Highest priority, can issue credentials
    }

    // ========================================================================
    // MEMORY SAFETY
    // ========================================================================

    /**
     * Securely zero out a byte array.
     * Use this for any sensitive data (keys, plaintexts) when done.
     */
    external fun zeroize(data: ByteArray)

    /**
     * Kotlin extension for automatic zeroization.
     */
    inline fun <T> ByteArray.useAndZeroize(block: (ByteArray) -> T): T {
        return try {
            block(this)
        } finally {
            zeroize(this)
        }
    }
}
