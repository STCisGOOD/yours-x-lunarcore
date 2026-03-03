package com.yours.app.identity

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
 * A Contact is a relationship between two identities.
 *
 * Properties:
 * - Bidirectional: both parties consent
 * - Petnamed: you choose what to call them
 * - Cryptographically bound: backed by key exchange
 * - Encryption uses ML-KEM-768 (quantum-resistant)
 * - Signatures use Ed25519 (classical)
 */
data class Contact(
    val id: String,                      // Unique contact ID (local)
    val petname: String,                 // What YOU call them
    val did: String,                     // Their DID
    val encryptionPublicKey: ByteArray,  // Their HK-OVCT public key (ML-KEM-768 based)
    val signingPublicKey: ByteArray,     // Their Ed25519 public key
    val sessionPublicKey: ByteArray,     // Their X25519 public key (32 bytes, for Double Ratchet)
    val introducedBy: String?,           // Who introduced you (DID or null)
    val firstContact: Long,              // When relationship established
    val lastVerified: Long,              // Last successful key verification
    val trustLevel: TrustLevel           // guardian | contact | acquaintance
) {
    val initial: String
        get() = petname.firstOrNull()?.uppercase() ?: "?"

    /**
     * Get the security status of this contact.
     */
    val securityStatus: SecurityStatus
        get() = if (lastVerified > 0) SecurityStatus.VERIFIED else SecurityStatus.UNVERIFIED

    /**
     * Create a copy with updated verification timestamp.
     */
    fun withVerification(verifiedAt: Long = System.currentTimeMillis()): Contact = copy(
        lastVerified = verifiedAt
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Contact) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

enum class TrustLevel {
    ACQUAINTANCE,  // Someone you've connected with
    CONTACT,       // Someone you trust for transfers
    GUARDIAN       // Someone who holds a recovery share
}

/**
 * Contact exchange payload - shared via QR code or NFC.
 *
 * SECURITY: The signature field proves the QR was created by someone who
 * possesses the private key corresponding to signingPublicKey. Without this,
 * an attacker could create a QR with their own keys but someone else's name.
 *
 * Uses Ed25519 signatures (64 bytes) which fit easily in QR codes.
 * Encryption uses ML-KEM-768 (HK-OVCT) which is quantum-resistant.
 */
data class ContactHello(
    val did: String,
    val displayName: String,              // How they introduce themselves
    val encryptionPublicKey: ByteArray,   // HK-OVCT public key (ML-KEM-768 based)
    val signingPublicKey: ByteArray,      // Ed25519 public key
    val sessionPublicKey: ByteArray,      // X25519 public key (32 bytes, for Double Ratchet)
    val nonce: ByteArray,                 // For verification
    val timestamp: Long,
    val signature: ByteArray              // Ed25519 signature (64 bytes)
) {
    /**
     * Serialize to bytes for QR code.
     * Version 0x03 format - Ed25519 signatures + X25519 session key.
     */
    fun toBytes(): ByteArray {
        Log.d("ContactHello", "=== TO BYTES (QR generation) ===")
        Log.d("ContactHello", "sessionPublicKey.size=${sessionPublicKey.size} (expected 32)")
        Log.d("ContactHello", "encryptionPublicKey.size=${encryptionPublicKey.size} (expected 1184)")

        val buffer = mutableListOf<Byte>()

        // Version 0x03 - Ed25519 signed ContactHello with X25519 session key
        buffer.add(0x03.toByte())

        // DID
        val didBytes = did.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(didBytes.size).toList())
        buffer.addAll(didBytes.toList())

        // Display name
        val nameBytes = displayName.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(nameBytes.size).toList())
        buffer.addAll(nameBytes.toList())

        // Encryption key
        buffer.addAll(intToBytes(encryptionPublicKey.size).toList())
        buffer.addAll(encryptionPublicKey.toList())

        // Signing key (Ed25519)
        buffer.addAll(intToBytes(signingPublicKey.size).toList())
        buffer.addAll(signingPublicKey.toList())

        // Session key (X25519)
        buffer.addAll(intToBytes(sessionPublicKey.size).toList())
        buffer.addAll(sessionPublicKey.toList())

        // Nonce (32 bytes)
        buffer.addAll(nonce.toList())

        // Timestamp
        buffer.addAll(longToBytes(timestamp).toList())

        // Signature (64 bytes Ed25519)
        buffer.addAll(intToBytes(signature.size).toList())
        buffer.addAll(signature.toList())

        return buffer.toByteArray()
    }

    /**
     * Get the data that should be signed (everything except the signature itself).
     */
    fun getSignableData(): ByteArray {
        val buffer = mutableListOf<Byte>()

        val didBytes = did.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(didBytes.size).toList())
        buffer.addAll(didBytes.toList())

        val nameBytes = displayName.toByteArray(StandardCharsets.UTF_8)
        buffer.addAll(intToBytes(nameBytes.size).toList())
        buffer.addAll(nameBytes.toList())

        buffer.addAll(intToBytes(encryptionPublicKey.size).toList())
        buffer.addAll(encryptionPublicKey.toList())

        buffer.addAll(intToBytes(signingPublicKey.size).toList())
        buffer.addAll(signingPublicKey.toList())

        buffer.addAll(intToBytes(sessionPublicKey.size).toList())
        buffer.addAll(sessionPublicKey.toList())

        buffer.addAll(nonce.toList())
        buffer.addAll(longToBytes(timestamp).toList())

        return buffer.toByteArray()
    }

    companion object {
        // SECURITY AUDIT FIX #6: Maximum size limits to prevent OOM attacks
        private const val MAX_DID_LENGTH = 256
        private const val MAX_NAME_LENGTH = 128
        private const val MAX_KEY_LENGTH = 4096
        private const val MAX_SIGNATURE_LENGTH = 128  // Ed25519 signature is 64 bytes
        private const val MAX_TIMESTAMP_AGE_MS = 24 * 60 * 60 * 1000L  // 24 hours
        private const val MAX_TIMESTAMP_FUTURE_MS = 5 * 60 * 1000L     // 5 minutes

        /**
         * Safely read a length-prefixed field with bounds checking.
         * Returns null if bounds check fails.
         *
         * SECURITY AUDIT FIX #6: Prevents integer overflow and OOM attacks.
         */
        private fun safeReadLength(data: ByteArray, offset: Int, maxLength: Int): Int? {
            if (offset + 4 > data.size) return null
            val length = bytesToInt(data, offset)
            // Check for negative (overflow) or exceeds max or exceeds remaining data
            if (length < 0 || length > maxLength || offset + 4 + length > data.size) return null
            return length
        }

        fun fromBytes(data: ByteArray): ContactHello? {
            Log.d("ContactHello", "=== FROM BYTES (QR parsing) ===")
            Log.d("ContactHello", "data.size=${data.size}")
            try {
                // SECURITY AUDIT FIX #6: Minimum size check
                if (data.size < 1 + 4 + 4 + 4 + 4 + 4 + 32 + 8 + 4 + 64) {
                    Log.e("ContactHello", "Data too small: ${data.size} < minimum")
                    return null
                }

                var offset = 0

                // Version - 0x03 (with X25519 session key) or 0x02 (legacy)
                val version = data[offset++]
                val hasSessionKey = version == 0x03.toByte()
                Log.d("ContactHello", "version=0x${version.toString(16)}, hasSessionKey=$hasSessionKey")
                if (version != 0x03.toByte() && version != 0x02.toByte()) return null

                // DID - with bounds checking
                val didLen = safeReadLength(data, offset, MAX_DID_LENGTH) ?: return null
                offset += 4
                val did = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
                offset += didLen

                // Display name - with bounds checking
                val nameLen = safeReadLength(data, offset, MAX_NAME_LENGTH) ?: return null
                offset += 4
                val displayName = String(data.copyOfRange(offset, offset + nameLen), StandardCharsets.UTF_8)
                offset += nameLen

                // Encryption key - with bounds checking
                val encKeyLen = safeReadLength(data, offset, MAX_KEY_LENGTH) ?: return null
                offset += 4
                val encryptionPublicKey = data.copyOfRange(offset, offset + encKeyLen)
                offset += encKeyLen

                // Signing key (Ed25519) - with bounds checking
                val sigKeyLen = safeReadLength(data, offset, MAX_KEY_LENGTH) ?: return null
                offset += 4
                val signingPublicKey = data.copyOfRange(offset, offset + sigKeyLen)
                offset += sigKeyLen

                // Session key (X25519) - v0x03 only
                val sessionPublicKey = if (hasSessionKey) {
                    val sessKeyLen = safeReadLength(data, offset, MAX_KEY_LENGTH) ?: return null
                    Log.d("ContactHello", "sessKeyLen=$sessKeyLen")
                    offset += 4
                    val key = data.copyOfRange(offset, offset + sessKeyLen)
                    offset += sessKeyLen
                    key
                } else {
                    Log.w("ContactHello", "No session key in QR (v0x02)")
                    ByteArray(0)  // Legacy v0x02 doesn't have session key
                }

                Log.d("ContactHello", "Parsed: encryptionPublicKey.size=${encryptionPublicKey.size}, sessionPublicKey.size=${sessionPublicKey.size}")

                // Nonce - check remaining space
                if (offset + 32 + 8 > data.size) return null
                val nonce = data.copyOfRange(offset, offset + 32)
                offset += 32

                // Timestamp
                val timestamp = bytesToLong(data, offset)
                offset += 8

                // SECURITY AUDIT FIX: Validate timestamp to prevent replay attacks
                val now = System.currentTimeMillis()
                if (timestamp > now + MAX_TIMESTAMP_FUTURE_MS) return null  // Too far in future
                if (timestamp < now - MAX_TIMESTAMP_AGE_MS) return null     // Too old (stale)

                // Signature - with bounds checking
                val sigLen = safeReadLength(data, offset, MAX_SIGNATURE_LENGTH) ?: return null
                offset += 4
                if (offset + sigLen > data.size) return null
                val signature = data.copyOfRange(offset, offset + sigLen)

                // Build the ContactHello
                val hello = ContactHello(
                    did = did,
                    displayName = displayName,
                    encryptionPublicKey = encryptionPublicKey,
                    signingPublicKey = signingPublicKey,
                    sessionPublicKey = sessionPublicKey,
                    nonce = nonce,
                    timestamp = timestamp,
                    signature = signature
                )

                val signableData = hello.getSignableData()
                val verified = ContactSigningService.verifyContactHello(
                    signableData = signableData,
                    signature = signature,
                    signingPublicKey = signingPublicKey
                )

                Log.d("ContactHello", "Signature verified=$verified")
                if (verified) {
                    Log.d("ContactHello", "=== QR PARSE SUCCESS: sessionPublicKey.size=${hello.sessionPublicKey.size} ===")
                } else {
                    Log.e("ContactHello", "Signature verification FAILED")
                }
                return if (verified) hello else null

            } catch (e: Exception) {
                Log.e("ContactHello", "fromBytes exception: ${e.message}")
                return null
            }
        }

        private fun bytesToInt(data: ByteArray, offset: Int): Int {
            return ((data[offset].toInt() and 0xFF) shl 24) or
                   ((data[offset + 1].toInt() and 0xFF) shl 16) or
                   ((data[offset + 2].toInt() and 0xFF) shl 8) or
                   (data[offset + 3].toInt() and 0xFF)
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
}

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


/**
 * Manages contacts (your relationships).
 *
 * Encryption uses ML-KEM-768 (Hk-OVCT) for quantum resistance.
 * Signatures use Ed25519 for classical security (fits in QR/LoRa).
 */
class ContactManager(private val context: Context) {

    companion object {
        private const val TAG = "ContactManager"
        private const val CONTACTS_FILE = "contacts.yours"
        private const val CONTACTS_FILE_V2 = "contacts_v2.yours"
    }

    private val contactsFile: File
        get() = File(context.filesDir, CONTACTS_FILE)

    private val contactsFileV2: File
        get() = File(context.filesDir, CONTACTS_FILE_V2)

    private val mutex = Mutex()

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: Flow<List<Contact>> = _contacts.asStateFlow()

    /**
     * Initialize contacts storage.
     * @param encryptionKey Key for encrypting/decrypting contacts
     */
    suspend fun initialize(encryptionKey: ByteArray) = withContext(Dispatchers.IO) {
        mutex.withLock {
            loadContacts(encryptionKey)
        }
    }

    /**
     * Create your ContactHello for sharing via QR code.
     *
     * @param identity Your identity (public info)
     * @param signingPrivateKey Your Ed25519 private signing key
     * @return ContactHello ready for QR encoding
     */
    fun createHello(identity: Identity, signingPrivateKey: ByteArray): ContactHello {
        Log.d(TAG, "=== CREATE HELLO (for QR) ===")
        Log.d(TAG, "identity.sessionPublicKey.size=${identity.sessionPublicKey.size} (expected 32)")
        Log.d(TAG, "identity.encryptionPublicKey.size=${identity.encryptionPublicKey.size} (expected 1184)")

        val nonce = BedrockCore.randomBytes(32)
        val timestamp = System.currentTimeMillis()

        // Create unsigned hello first to get signable data
        val unsignedHello = ContactHello(
            did = identity.did,
            displayName = identity.name,
            encryptionPublicKey = identity.encryptionPublicKey,
            signingPublicKey = identity.signingPublicKey,
            sessionPublicKey = identity.sessionPublicKey,
            nonce = nonce,
            timestamp = timestamp,
            signature = ByteArray(0)
        )

        // Sign with Ed25519 to prove key ownership
        val signableData = unsignedHello.getSignableData()
        val signature = ContactSigningService.signContactHello(
            signableData = signableData,
            signingPrivateKey = signingPrivateKey
        )

        Log.d(TAG, "ContactHello created with sessionPublicKey.size=${unsignedHello.sessionPublicKey.size}")
        return unsignedHello.copy(signature = signature)
    }

    /**
     * Add a contact from their hello.
     *
     * @param hello Their ContactHello (from QR scan)
     * @param petname What you want to call them
     * @param encryptionKey Key for saving contacts
     */
    suspend fun addContact(
        hello: ContactHello,
        petname: String,
        encryptionKey: ByteArray
    ): Contact = withContext(Dispatchers.IO) {
        Log.d(TAG, "=== ADD CONTACT ===")
        Log.d(TAG, "hello.sessionPublicKey.size=${hello.sessionPublicKey.size} (expected 32)")
        Log.d(TAG, "hello.encryptionPublicKey.size=${hello.encryptionPublicKey.size} (expected 1184)")
        Log.d(TAG, "petname=$petname, did=${hello.did.take(30)}...")

        mutex.withLock {
            val contact = Contact(
                id = java.util.UUID.randomUUID().toString(),
                petname = petname,
                did = hello.did,
                encryptionPublicKey = hello.encryptionPublicKey,
                signingPublicKey = hello.signingPublicKey,
                sessionPublicKey = hello.sessionPublicKey,
                introducedBy = null,
                firstContact = System.currentTimeMillis(),
                lastVerified = System.currentTimeMillis(),
                trustLevel = TrustLevel.CONTACT
            )

            Log.d(TAG, "Contact created: id=${contact.id}, sessionPublicKey.size=${contact.sessionPublicKey.size}")
            _contacts.value = _contacts.value + contact
            Log.d(TAG, "Contact list now has ${_contacts.value.size} contacts")
            saveContacts(encryptionKey)
            Log.d(TAG, "Contacts saved to disk")

            contact
        }
    }

    /**
     * Re-verify a contact and update their verification status.
     *
     * @param contactId The contact to verify
     * @param encryptionKey Key for saving contacts
     * @return ContactSignatureInfo with verification results
     */
    suspend fun verifyContact(
        contactId: String,
        encryptionKey: ByteArray
    ): ContactSignatureInfo? = withContext(Dispatchers.IO) {
        mutex.withLock {
            val contact = _contacts.value.find { it.id == contactId } ?: return@withLock null

            // Update contact with new verification timestamp
            val updatedContact = contact.withVerification(System.currentTimeMillis())

            _contacts.value = _contacts.value.map {
                if (it.id == contactId) updatedContact else it
            }
            saveContacts(encryptionKey)

            ContactSigningService.createSignatureInfo(verified = true)
        }
    }
    
    /**
     * Get all contacts (from cached list).
     * Call initialize() first to load contacts.
     */
    fun getContacts(encryptionKey: ByteArray): List<Contact> {
        Log.d(TAG, "=== GET CONTACTS ===")
        Log.d(TAG, "_contacts.value.size=${_contacts.value.size}")
        Log.d(TAG, "contactsFileV2.exists()=${contactsFileV2.exists()}, contactsFile.exists()=${contactsFile.exists()}")

        // If not initialized yet, try loading
        // Check both V2/V3 file AND V1 file for backwards compatibility
        if (_contacts.value.isEmpty() && (contactsFileV2.exists() || contactsFile.exists())) {
            Log.d(TAG, "Loading contacts from disk...")
            loadContacts(encryptionKey)
        }

        Log.d(TAG, "Returning ${_contacts.value.size} contacts")
        for (contact in _contacts.value) {
            Log.d(TAG, "  - ${contact.petname}: sessionPublicKey.size=${contact.sessionPublicKey.size}")
        }
        return _contacts.value
    }

    /**
     * Get contact by ID.
     */
    fun getContact(id: String): Contact? {
        return _contacts.value.find { it.id == id }
    }
    
    /**
     * Get contact by DID.
     */
    fun getContactByDid(did: String): Contact? {
        return _contacts.value.find { it.did == did }
    }
    
    /**
     * Update contact petname.
     */
    suspend fun updatePetname(
        contactId: String,
        newPetname: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            _contacts.value = _contacts.value.map { contact ->
                if (contact.id == contactId) {
                    contact.copy(petname = newPetname)
                } else {
                    contact
                }
            }
            saveContacts(encryptionKey)
        }
    }
    
    /**
     * Promote contact to guardian.
     */
    suspend fun promoteToGuardian(
        contactId: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            _contacts.value = _contacts.value.map { contact ->
                if (contact.id == contactId) {
                    contact.copy(trustLevel = TrustLevel.GUARDIAN)
                } else {
                    contact
                }
            }
            saveContacts(encryptionKey)
        }
    }
    
    /**
     * Get all guardians.
     */
    fun getGuardians(): List<Contact> {
        return _contacts.value.filter { it.trustLevel == TrustLevel.GUARDIAN }
    }
    
    /**
     * Remove a contact.
     */
    suspend fun removeContact(
        contactId: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            _contacts.value = _contacts.value.filter { it.id != contactId }
            saveContacts(encryptionKey)
        }
    }
    
    /**
     * Save contacts (encrypted).
     */
    suspend fun saveContacts(encryptionKey: ByteArray) = withContext(Dispatchers.IO) {
        val data = serializeContacts(_contacts.value)
        val encrypted = BedrockCore.aesEncrypt(encryptionKey, data)
        contactsFileV2.writeBytes(encrypted)
        BedrockCore.zeroize(data)
    }

    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    private fun loadContacts(encryptionKey: ByteArray) {
        Log.d(TAG, "=== LOAD CONTACTS FROM DISK ===")

        // Try v2/v3 format first
        if (contactsFileV2.exists()) {
            Log.d(TAG, "contactsFileV2 exists, trying to load...")
            try {
                val encrypted = contactsFileV2.readBytes()
                Log.d(TAG, "Read ${encrypted.size} encrypted bytes")
                val decrypted = BedrockCore.aesDecrypt(encryptionKey, encrypted)

                if (decrypted != null) {
                    Log.d(TAG, "Decrypted ${decrypted.size} bytes, deserializing...")
                    _contacts.value = deserializeContacts(decrypted)
                    Log.d(TAG, "Loaded ${_contacts.value.size} contacts from V2/V3 file")
                    for (contact in _contacts.value) {
                        Log.d(TAG, "  Loaded: ${contact.petname}, sessionPublicKey.size=${contact.sessionPublicKey.size}")
                    }
                    BedrockCore.zeroize(decrypted)
                    return
                } else {
                    Log.e(TAG, "Decryption returned null!")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load V2/V3 contacts: ${e.message}")
                // Fall through to try v1 format
            }
        }

        // Fall back to v1 format (legacy)
        if (contactsFile.exists()) {
            Log.d(TAG, "Trying V1 format...")
            try {
                val encrypted = contactsFile.readBytes()
                val decrypted = BedrockCore.aesDecrypt(encryptionKey, encrypted)

                if (decrypted != null) {
                    _contacts.value = deserializeContactsV1(decrypted)
                    Log.d(TAG, "Loaded ${_contacts.value.size} contacts from V1 file")
                    BedrockCore.zeroize(decrypted)
                } else {
                    Log.e(TAG, "V1 decryption returned null")
                    _contacts.value = emptyList()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load V1 contacts: ${e.message}")
                _contacts.value = emptyList()
            }
        } else {
            Log.d(TAG, "No contacts file exists yet")
            _contacts.value = emptyList()
        }
    }

    /**
     * Serialize contacts (v3 format - simplified).
     */
    private fun serializeContacts(contacts: List<Contact>): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Version 0x03
        buffer.add(0x03)

        // Count
        buffer.addAll(intToBytes(contacts.size).toList())

        for (contact in contacts) {
            // ID
            val idBytes = contact.id.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(idBytes.size).toList())
            buffer.addAll(idBytes.toList())

            // Petname
            val petnameBytes = contact.petname.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(petnameBytes.size).toList())
            buffer.addAll(petnameBytes.toList())

            // DID
            val didBytes = contact.did.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(didBytes.size).toList())
            buffer.addAll(didBytes.toList())

            // Encryption key (HK-OVCT/ML-KEM-768)
            buffer.addAll(intToBytes(contact.encryptionPublicKey.size).toList())
            buffer.addAll(contact.encryptionPublicKey.toList())

            // Signing key (Ed25519)
            buffer.addAll(intToBytes(contact.signingPublicKey.size).toList())
            buffer.addAll(contact.signingPublicKey.toList())

            // Session key (X25519 for Double Ratchet)
            buffer.addAll(intToBytes(contact.sessionPublicKey.size).toList())
            buffer.addAll(contact.sessionPublicKey.toList())

            // Introduced by
            if (contact.introducedBy != null) {
                val introBytes = contact.introducedBy.toByteArray(StandardCharsets.UTF_8)
                buffer.addAll(intToBytes(introBytes.size).toList())
                buffer.addAll(introBytes.toList())
            } else {
                buffer.addAll(intToBytes(0).toList())
            }

            // Timestamps
            buffer.addAll(longToBytes(contact.firstContact).toList())
            buffer.addAll(longToBytes(contact.lastVerified).toList())

            // Trust level
            buffer.add(contact.trustLevel.ordinal.toByte())
        }

        return buffer.toByteArray()
    }

    /**
     * Deserialize contacts (handles v2, v3 formats).
     */
    private fun deserializeContacts(data: ByteArray): List<Contact> {
        Log.d(TAG, "=== DESERIALIZE CONTACTS ===")
        Log.d(TAG, "data.size=${data.size}")
        try {
            if (data.size < 5) {
                Log.e(TAG, "Data too small: ${data.size}")
                return emptyList()
            }

            var offset = 0
            val version = data[offset++]
            Log.d(TAG, "Contact file version=0x${version.toString(16)}")

            return when (version.toInt()) {
                0x03 -> {
                    Log.d(TAG, "Using V3 deserializer")
                    deserializeV3(data, offset)
                }
                0x02 -> {
                    Log.d(TAG, "Using V2 deserializer")
                    deserializeV2Legacy(data, offset)
                }
                0x01 -> {
                    Log.d(TAG, "Using V1 deserializer")
                    deserializeContactsV1(data)
                }
                else -> {
                    Log.e(TAG, "Unknown version: 0x${version.toString(16)}")
                    emptyList()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "deserializeContacts exception: ${e.message}")
            return emptyList()
        }
    }

    /**
     * Deserialize v3 format (current).
     */
    private fun deserializeV3(data: ByteArray, startOffset: Int): List<Contact> {
        var offset = startOffset

        val count = bytesToInt(data, offset)
        offset += 4
        Log.d(TAG, "deserializeV3: count=$count")
        if (count < 0 || count > 10000) return emptyList()

        val contacts = mutableListOf<Contact>()

        repeat(count) {
            // ID
            if (offset + 4 > data.size) return emptyList()
            val idLen = bytesToInt(data, offset)
            if (idLen < 0 || idLen > 256 || offset + 4 + idLen > data.size) return emptyList()
            offset += 4
            val id = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
            offset += idLen

            // Petname
            if (offset + 4 > data.size) return emptyList()
            val petnameLen = bytesToInt(data, offset)
            if (petnameLen < 0 || petnameLen > 256 || offset + 4 + petnameLen > data.size) return emptyList()
            offset += 4
            val petname = String(data.copyOfRange(offset, offset + petnameLen), StandardCharsets.UTF_8)
            offset += petnameLen

            // DID
            if (offset + 4 > data.size) return emptyList()
            val didLen = bytesToInt(data, offset)
            if (didLen < 0 || didLen > 256 || offset + 4 + didLen > data.size) return emptyList()
            offset += 4
            val did = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
            offset += didLen

            // Encryption key
            if (offset + 4 > data.size) return emptyList()
            val encKeyLen = bytesToInt(data, offset)
            if (encKeyLen < 0 || encKeyLen > 4096 || offset + 4 + encKeyLen > data.size) return emptyList()
            offset += 4
            val encryptionKey = data.copyOfRange(offset, offset + encKeyLen)
            offset += encKeyLen

            // Signing key (Ed25519)
            if (offset + 4 > data.size) return emptyList()
            val sigKeyLen = bytesToInt(data, offset)
            if (sigKeyLen < 0 || sigKeyLen > 4096 || offset + 4 + sigKeyLen > data.size) return emptyList()
            offset += 4
            val signingKey = data.copyOfRange(offset, offset + sigKeyLen)
            offset += sigKeyLen

            // Session key (X25519 for Double Ratchet)
            if (offset + 4 > data.size) return emptyList()
            val sessionKeyLen = bytesToInt(data, offset)
            if (sessionKeyLen < 0 || sessionKeyLen > 4096 || offset + 4 + sessionKeyLen > data.size) return emptyList()
            offset += 4
            val sessionKey = data.copyOfRange(offset, offset + sessionKeyLen)
            offset += sessionKeyLen

            // Introduced by
            if (offset + 4 > data.size) return emptyList()
            val introLen = bytesToInt(data, offset)
            if (introLen < 0 || introLen > 256 || offset + 4 + introLen > data.size) return emptyList()
            offset += 4
            val introducedBy = if (introLen > 0) {
                String(data.copyOfRange(offset, offset + introLen), StandardCharsets.UTF_8)
            } else null
            offset += introLen

            // Timestamps
            if (offset + 8 + 8 + 1 > data.size) return emptyList()
            val firstContact = bytesToLong(data, offset)
            offset += 8
            val lastVerified = bytesToLong(data, offset)
            offset += 8

            // Trust level
            val trustLevelIndex = data[offset++].toInt() and 0xFF
            if (trustLevelIndex >= TrustLevel.entries.size) return emptyList()
            val trustLevel = TrustLevel.entries[trustLevelIndex]

            Log.d(TAG, "deserializeV3: petname=$petname, sessionKey.size=${sessionKey.size}, encryptionKey.size=${encryptionKey.size}")
            contacts.add(Contact(
                id = id,
                petname = petname,
                did = did,
                encryptionPublicKey = encryptionKey,
                signingPublicKey = signingKey,
                sessionPublicKey = sessionKey,
                introducedBy = introducedBy,
                firstContact = firstContact,
                lastVerified = lastVerified,
                trustLevel = trustLevel
            ))
        }

        Log.d(TAG, "deserializeV3: returning ${contacts.size} contacts")
        return contacts
    }

    /**
     * Deserialize v2 format (legacy with dilithium - fields ignored).
     */
    private fun deserializeV2Legacy(data: ByteArray, startOffset: Int): List<Contact> {
        var offset = startOffset

        val count = bytesToInt(data, offset)
        offset += 4
        if (count < 0 || count > 10000) return emptyList()

        val contacts = mutableListOf<Contact>()

        repeat(count) {
            // ID
            if (offset + 4 > data.size) return emptyList()
            val idLen = bytesToInt(data, offset)
            if (idLen < 0 || idLen > 256 || offset + 4 + idLen > data.size) return emptyList()
            offset += 4
            val id = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
            offset += idLen

            // Petname
            if (offset + 4 > data.size) return emptyList()
            val petnameLen = bytesToInt(data, offset)
            if (petnameLen < 0 || petnameLen > 256 || offset + 4 + petnameLen > data.size) return emptyList()
            offset += 4
            val petname = String(data.copyOfRange(offset, offset + petnameLen), StandardCharsets.UTF_8)
            offset += petnameLen

            // DID
            if (offset + 4 > data.size) return emptyList()
            val didLen = bytesToInt(data, offset)
            if (didLen < 0 || didLen > 256 || offset + 4 + didLen > data.size) return emptyList()
            offset += 4
            val did = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
            offset += didLen

            // Encryption key
            if (offset + 4 > data.size) return emptyList()
            val encKeyLen = bytesToInt(data, offset)
            if (encKeyLen < 0 || encKeyLen > 4096 || offset + 4 + encKeyLen > data.size) return emptyList()
            offset += 4
            val encryptionKey = data.copyOfRange(offset, offset + encKeyLen)
            offset += encKeyLen

            // Signing key (Ed25519)
            if (offset + 4 > data.size) return emptyList()
            val sigKeyLen = bytesToInt(data, offset)
            if (sigKeyLen < 0 || sigKeyLen > 4096 || offset + 4 + sigKeyLen > data.size) return emptyList()
            offset += 4
            val signingKey = data.copyOfRange(offset, offset + sigKeyLen)
            offset += sigKeyLen

            // Dilithium key (legacy - skip)
            if (offset + 4 > data.size) return emptyList()
            val dilithiumKeyLen = bytesToInt(data, offset)
            if (dilithiumKeyLen < 0 || dilithiumKeyLen > 4096 || offset + 4 + dilithiumKeyLen > data.size) return emptyList()
            offset += 4
            offset += dilithiumKeyLen  // Skip the dilithium key bytes

            // Introduced by
            if (offset + 4 > data.size) return emptyList()
            val introLen = bytesToInt(data, offset)
            if (introLen < 0 || introLen > 256 || offset + 4 + introLen > data.size) return emptyList()
            offset += 4
            val introducedBy = if (introLen > 0) {
                String(data.copyOfRange(offset, offset + introLen), StandardCharsets.UTF_8)
            } else null
            offset += introLen

            // Timestamps
            if (offset + 8 + 8 + 1 + 1 + 1 > data.size) return emptyList()
            val firstContact = bytesToLong(data, offset)
            offset += 8
            val lastVerified = bytesToLong(data, offset)
            offset += 8

            // Trust level
            val trustLevelIndex = data[offset++].toInt() and 0xFF
            if (trustLevelIndex >= TrustLevel.entries.size) return emptyList()
            val trustLevel = TrustLevel.entries[trustLevelIndex]

            // Skip legacy fields (signature mode, last signature type)
            offset += 2

            contacts.add(Contact(
                id = id,
                petname = petname,
                did = did,
                encryptionPublicKey = encryptionKey,
                signingPublicKey = signingKey,
                sessionPublicKey = ByteArray(0),  // V2 doesn't have session keys
                introducedBy = introducedBy,
                firstContact = firstContact,
                lastVerified = lastVerified,
                trustLevel = trustLevel
            ))
        }

        return contacts
    }

    /**
     * Deserialize contacts from v1 format (legacy, no PQ keys).
     * SECURITY AUDIT FIX #13: Bounds checking in deserializer
     */
    private fun deserializeContactsV1(data: ByteArray): List<Contact> {
        try {
            // Minimum size check: version + count
            if (data.size < 5) return emptyList()

            var offset = 0

            // Version
            val version = data[offset++]
            if (version != 0x01.toByte()) return emptyList()

            // Count - validate reasonable range
            val count = bytesToInt(data, offset)
            offset += 4
            if (count < 0 || count > 10000) return emptyList()  // Sanity limit

            val contacts = mutableListOf<Contact>()

            repeat(count) {
                // ID - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val idLen = bytesToInt(data, offset)
                if (idLen < 0 || idLen > 256 || offset + 4 + idLen > data.size) return emptyList()
                offset += 4
                val id = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
                offset += idLen

                // Petname - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val petnameLen = bytesToInt(data, offset)
                if (petnameLen < 0 || petnameLen > 256 || offset + 4 + petnameLen > data.size) return emptyList()
                offset += 4
                val petname = String(data.copyOfRange(offset, offset + petnameLen), StandardCharsets.UTF_8)
                offset += petnameLen

                // DID - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val didLen = bytesToInt(data, offset)
                if (didLen < 0 || didLen > 256 || offset + 4 + didLen > data.size) return emptyList()
                offset += 4
                val did = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
                offset += didLen

                // Encryption key - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val encKeyLen = bytesToInt(data, offset)
                if (encKeyLen < 0 || encKeyLen > 4096 || offset + 4 + encKeyLen > data.size) return emptyList()
                offset += 4
                val encryptionKey = data.copyOfRange(offset, offset + encKeyLen)
                offset += encKeyLen

                // Signing key - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val sigKeyLen = bytesToInt(data, offset)
                if (sigKeyLen < 0 || sigKeyLen > 4096 || offset + 4 + sigKeyLen > data.size) return emptyList()
                offset += 4
                val signingKey = data.copyOfRange(offset, offset + sigKeyLen)
                offset += sigKeyLen

                // Introduced by - with bounds checking
                if (offset + 4 > data.size) return emptyList()
                val introLen = bytesToInt(data, offset)
                if (introLen < 0 || introLen > 256 || offset + 4 + introLen > data.size) return emptyList()
                offset += 4
                val introducedBy = if (introLen > 0) {
                    String(data.copyOfRange(offset, offset + introLen), StandardCharsets.UTF_8)
                } else null
                offset += introLen

                // Timestamps - check remaining space
                if (offset + 8 + 8 + 1 > data.size) return emptyList()
                val firstContact = bytesToLong(data, offset)
                offset += 8
                val lastVerified = bytesToLong(data, offset)
                offset += 8

                // Trust level - SECURITY FIX: Validate enum index before access
                val trustLevelIndex = data[offset++].toInt() and 0xFF
                if (trustLevelIndex >= TrustLevel.entries.size) return emptyList()
                val trustLevel = TrustLevel.entries[trustLevelIndex]

                contacts.add(Contact(
                    id = id,
                    petname = petname,
                    did = did,
                    encryptionPublicKey = encryptionKey,
                    signingPublicKey = signingKey,
                    sessionPublicKey = ByteArray(0),  // V1 doesn't have session keys
                    introducedBy = introducedBy,
                    firstContact = firstContact,
                    lastVerified = lastVerified,
                    trustLevel = trustLevel
                ))
            }

            return contacts
        } catch (e: Exception) {
            // SECURITY: Don't log exception details to prevent info leakage
            return emptyList()
        }
    }

    private fun bytesToInt(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
               ((data[offset + 1].toInt() and 0xFF) shl 16) or
               ((data[offset + 2].toInt() and 0xFF) shl 8) or
               (data[offset + 3].toInt() and 0xFF)
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
