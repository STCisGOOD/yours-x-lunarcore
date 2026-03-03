package com.yours.app.messaging

import com.yours.app.crypto.BedrockCore
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Message Types for LunarCore P2P Messaging
 *
 * All messages are:
 * - End-to-end encrypted with Double Ratchet (forward secrecy)
 * - Routed through onion layers (metadata protection)
 * - Padded to fixed size (traffic analysis resistance)
 */

/**
 * Delivery status of a message.
 */
enum class MessageStatus {
    PENDING,      // Not yet sent
    SENT,         // Transmitted over LoRa
    DELIVERED,    // ACK received from recipient
    READ,         // Read receipt received (optional)
    FAILED        // Send failed after retries
}

/**
 * Direction of message.
 */
enum class MessageDirection {
    OUTGOING,
    INCOMING
}

/**
 * A single message in a conversation.
 *
 * SECURITY:
 * - Content is stored encrypted at rest
 * - Session keys are never stored (only handles)
 * - Timestamps use local time (no server dependency)
 */
data class Message(
    val id: String,                          // UUID
    val threadId: String,                    // Contact ID (conversation)
    val direction: MessageDirection,
    val content: ByteArray,                  // UTF-8 text (decrypted)
    val timestamp: Long,                     // Local timestamp
    val status: MessageStatus,
    val sessionHint: ByteArray? = null,      // For routing
    val retryCount: Int = 0,
    val errorMessage: String? = null
) {
    /**
     * Get content as string.
     */
    val text: String
        get() = String(content, StandardCharsets.UTF_8)

    /**
     * Serialize for encrypted storage.
     */
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(
            1 +                     // version
            36 +                    // id (UUID string)
            36 +                    // threadId
            1 +                     // direction
            4 + content.size +      // content length + content
            8 +                     // timestamp
            1 +                     // status
            1 + (sessionHint?.size ?: 0) + // sessionHint present + data
            4 +                     // retryCount
            4 + (errorMessage?.toByteArray(StandardCharsets.UTF_8)?.size ?: 0)
        )

        buffer.put(0x01)  // version

        // ID (fixed 36 bytes for UUID)
        buffer.put(id.toByteArray(StandardCharsets.UTF_8).copyOf(36))

        // Thread ID
        buffer.put(threadId.toByteArray(StandardCharsets.UTF_8).copyOf(36))

        // Direction
        buffer.put(direction.ordinal.toByte())

        // Content
        buffer.putInt(content.size)
        buffer.put(content)

        // Timestamp
        buffer.putLong(timestamp)

        // Status
        buffer.put(status.ordinal.toByte())

        // Session hint
        if (sessionHint != null) {
            buffer.put(1.toByte())
            buffer.put(sessionHint)
        } else {
            buffer.put(0.toByte())
        }

        // Retry count
        buffer.putInt(retryCount)

        // Error message
        val errorBytes = errorMessage?.toByteArray(StandardCharsets.UTF_8)
        if (errorBytes != null) {
            buffer.putInt(errorBytes.size)
            buffer.put(errorBytes)
        } else {
            buffer.putInt(0)
        }

        return buffer.array().copyOf(buffer.position())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Message) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()

    companion object {
        private const val MAX_CONTENT_SIZE = 4096
        private const val MAX_ERROR_SIZE = 256

        /**
         * Create a new outgoing message.
         */
        fun create(threadId: String, text: String): Message {
            return Message(
                id = UUID.randomUUID().toString(),
                threadId = threadId,
                direction = MessageDirection.OUTGOING,
                content = text.toByteArray(StandardCharsets.UTF_8),
                timestamp = System.currentTimeMillis(),
                status = MessageStatus.PENDING
            )
        }

        /**
         * Create incoming message from decrypted payload.
         */
        fun incoming(
            threadId: String,
            content: ByteArray,
            sessionHint: ByteArray? = null
        ): Message {
            return Message(
                id = UUID.randomUUID().toString(),
                threadId = threadId,
                direction = MessageDirection.INCOMING,
                content = content,
                timestamp = System.currentTimeMillis(),
                status = MessageStatus.DELIVERED,
                sessionHint = sessionHint
            )
        }

        /**
         * Deserialize from bytes.
         */
        fun fromBytes(data: ByteArray): Message? {
            try {
                if (data.size < 1 + 36 + 36 + 1 + 4 + 8 + 1 + 1 + 4 + 4) return null

                val buffer = ByteBuffer.wrap(data)

                val version = buffer.get()
                if (version != 0x01.toByte()) return null

                // ID
                val idBytes = ByteArray(36)
                buffer.get(idBytes)
                val id = String(idBytes, StandardCharsets.UTF_8).trim()

                // Thread ID
                val threadIdBytes = ByteArray(36)
                buffer.get(threadIdBytes)
                val threadId = String(threadIdBytes, StandardCharsets.UTF_8).trim()

                // Direction
                val directionIndex = buffer.get().toInt() and 0xFF
                if (directionIndex >= MessageDirection.entries.size) return null
                val direction = MessageDirection.entries[directionIndex]

                // Content
                val contentLen = buffer.getInt()
                if (contentLen < 0 || contentLen > MAX_CONTENT_SIZE) return null
                if (buffer.remaining() < contentLen) return null
                val content = ByteArray(contentLen)
                buffer.get(content)

                // Timestamp
                val timestamp = buffer.getLong()

                // Status
                val statusIndex = buffer.get().toInt() and 0xFF
                if (statusIndex >= MessageStatus.entries.size) return null
                val status = MessageStatus.entries[statusIndex]

                // Session hint
                // MUST MATCH bedrock-core/src/lunar/packet.rs SESSION_HINT_SIZE (8 bytes)
                val hasSessionHint = buffer.get() == 1.toByte()
                val sessionHint = if (hasSessionHint) {
                    val hint = ByteArray(8)
                    if (buffer.remaining() < 8) return null
                    buffer.get(hint)
                    hint
                } else null

                // Retry count
                if (buffer.remaining() < 4) return null
                val retryCount = buffer.getInt()

                // Error message
                if (buffer.remaining() < 4) return null
                val errorLen = buffer.getInt()
                val errorMessage = if (errorLen > 0 && errorLen <= MAX_ERROR_SIZE) {
                    if (buffer.remaining() < errorLen) return null
                    val errorBytes = ByteArray(errorLen)
                    buffer.get(errorBytes)
                    String(errorBytes, StandardCharsets.UTF_8)
                } else null

                return Message(
                    id = id,
                    threadId = threadId,
                    direction = direction,
                    content = content,
                    timestamp = timestamp,
                    status = status,
                    sessionHint = sessionHint,
                    retryCount = retryCount,
                    errorMessage = errorMessage
                )
            } catch (e: Exception) {
                return null
            }
        }
    }
}

/**
 * A conversation thread with a contact.
 */
data class MessageThread(
    val contactId: String,                   // Contact ID
    val contactDid: String,                  // Contact's DID
    val contactPetname: String,              // How we call them
    val lastMessageTime: Long,               // Most recent message timestamp
    val lastMessagePreview: String,          // First 50 chars of last message
    val unreadCount: Int,                    // Unread incoming messages
    val sessionHandle: Long? = null          // Active Lunar session (null = needs handshake)
)

/**
 * Wire format for messages sent over LoRa mesh.
 *
 * Structure (after session encryption):
 * - Type (1 byte): 0x01 = text, 0x02 = ack, 0x03 = typing, 0x04 = read
 * - Payload (variable)
 * - Padding (to fixed size)
 *
 * SECURITY: All messages padded to PADDED_SIZE bytes to prevent length analysis.
 * An adversary cannot distinguish "ok" from a 200-character message.
 */
object MessageWireFormat {
    const val TYPE_TEXT: Byte = 0x01
    const val TYPE_ACK: Byte = 0x02
    const val TYPE_TYPING: Byte = 0x03
    const val TYPE_READ: Byte = 0x04

    /**
     * Fixed padded size for all wire messages.
     *
     * CALCULATION (MeshCore MAX_PACKET_PAYLOAD = 184 bytes):
     * - Wire payload: PADDED_SIZE bytes ............... 73 bytes
     * - Session encryption (Double Ratchet): .......... +36 bytes (8 counter + 12 nonce + 16 tag)
     * - Blinded hint: ................................. +4 bytes
     * - Onion layer: .................................. +62 bytes (32 pubkey + 12 nonce + 1 flag + 16 tag + 1 layer)
     * - Garlic bundling: .............................. +9 bytes (2 header + 7 clove header)
     * ─────────────────────────────────────────────────
     * TOTAL: 73 + 36 + 4 + 62 + 9 = 184 bytes ✓
     *
     * This enables garlic bundling (I2P-style traffic analysis resistance)
     * while fitting within the LoRa packet limit.
     *
     * Message capacity: ~73 characters (after wire format overhead for UUID etc.)
     */
    const val PADDED_SIZE = 73

    /**
     * Encode a text message for transmission.
     *
     * SECURITY FIX: Padded to fixed size to defeat length analysis.
     */
    fun encodeText(messageId: String, text: String): ByteArray {
        val textBytes = text.toByteArray(StandardCharsets.UTF_8)
        val idBytes = messageId.toByteArray(StandardCharsets.UTF_8)

        // Calculate actual content size
        val contentSize = 1 + 1 + idBytes.size + 2 + textBytes.size

        // Allocate fixed-size buffer
        val buffer = ByteBuffer.allocate(PADDED_SIZE)
        buffer.put(TYPE_TEXT)
        buffer.put(idBytes.size.toByte())
        buffer.put(idBytes)
        buffer.putShort(textBytes.size.toShort())
        buffer.put(textBytes)

        // SECURITY: Fill remaining space with random padding
        // Random padding prevents pattern analysis even on padding bytes
        if (buffer.position() < PADDED_SIZE) {
            val paddingSize = PADDED_SIZE - buffer.position()
            val padding = BedrockCore.randomBytes(paddingSize)
            buffer.put(padding)
        }

        return buffer.array()
    }

    /**
     * Encode an ACK for a received message.
     *
     * SECURITY FIX: Padded to fixed size - ACKs indistinguishable from messages.
     */
    fun encodeAck(messageId: String): ByteArray {
        val idBytes = messageId.toByteArray(StandardCharsets.UTF_8)

        val buffer = ByteBuffer.allocate(PADDED_SIZE)
        buffer.put(TYPE_ACK)
        buffer.put(idBytes.size.toByte())
        buffer.put(idBytes)

        // SECURITY: Random padding to fixed size
        if (buffer.position() < PADDED_SIZE) {
            val paddingSize = PADDED_SIZE - buffer.position()
            buffer.put(BedrockCore.randomBytes(paddingSize))
        }

        return buffer.array()
    }

    /**
     * Encode a read receipt.
     *
     * SECURITY FIX: Padded to fixed size.
     */
    fun encodeRead(messageId: String): ByteArray {
        val idBytes = messageId.toByteArray(StandardCharsets.UTF_8)

        val buffer = ByteBuffer.allocate(PADDED_SIZE)
        buffer.put(TYPE_READ)
        buffer.put(idBytes.size.toByte())
        buffer.put(idBytes)

        // SECURITY: Random padding to fixed size
        if (buffer.position() < PADDED_SIZE) {
            val paddingSize = PADDED_SIZE - buffer.position()
            buffer.put(BedrockCore.randomBytes(paddingSize))
        }

        return buffer.array()
    }

    /**
     * Decode a received wire message.
     *
     * @return Pair of (type, payload) or null if invalid
     */
    fun decode(data: ByteArray): Pair<Byte, ByteArray>? {
        if (data.isEmpty()) return null
        val type = data[0]
        val payload = data.copyOfRange(1, data.size)
        return Pair(type, payload)
    }

    /**
     * Parse a text message payload.
     *
     * @return Pair of (messageId, text) or null if invalid
     */
    fun parseText(payload: ByteArray): Pair<String, String>? {
        if (payload.size < 3) return null
        val idLen = payload[0].toInt() and 0xFF
        if (payload.size < 1 + idLen + 2) return null

        val messageId = String(payload.copyOfRange(1, 1 + idLen), StandardCharsets.UTF_8)

        val textLen = ((payload[1 + idLen].toInt() and 0xFF) shl 8) or
                      (payload[2 + idLen].toInt() and 0xFF)
        if (payload.size < 1 + idLen + 2 + textLen) return null

        val text = String(payload.copyOfRange(3 + idLen, 3 + idLen + textLen), StandardCharsets.UTF_8)
        return Pair(messageId, text)
    }

    /**
     * Parse an ACK payload.
     *
     * @return messageId or null if invalid
     */
    fun parseAck(payload: ByteArray): String? {
        if (payload.size < 1) return null
        val idLen = payload[0].toInt() and 0xFF
        if (payload.size < 1 + idLen) return null
        return String(payload.copyOfRange(1, 1 + idLen), StandardCharsets.UTF_8)
    }
}
