package com.yours.app.messaging

import android.content.Context
import com.yours.app.crypto.BedrockCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * MessageStorage - Encrypted storage for messages.
 *
 * Storage model:
 * - Messages stored per-thread (one file per contact)
 * - All files encrypted with master key (AES-256-GCM)
 * - Thread index stored separately for quick listing
 * - Messages loaded lazily per-thread
 *
 * SECURITY:
 * - All data encrypted at rest
 * - Keys never stored (derived from passphrase)
 * - Secure delete overwrites files before deletion
 */
class MessageStorage(private val context: Context) {

    companion object {
        private const val MESSAGES_DIR = "messages"
        private const val THREADS_INDEX = "threads.enc"
        private const val MAX_MESSAGES_PER_THREAD = 10000
        private const val MAX_PREVIEW_LENGTH = 50
    }

    private val messagesDir: File
        get() = File(context.filesDir, MESSAGES_DIR).also { it.mkdirs() }

    private val threadsIndexFile: File
        get() = File(context.filesDir, THREADS_INDEX)

    private val mutex = Mutex()

    private val _threads = MutableStateFlow<List<MessageThread>>(emptyList())
    val threads: Flow<List<MessageThread>> = _threads.asStateFlow()

    // Cache of loaded messages per thread
    private val messageCache = mutableMapOf<String, MutableList<Message>>()

    /**
     * Initialize storage and load thread index.
     */
    suspend fun initialize(encryptionKey: ByteArray) = withContext(Dispatchers.IO) {
        mutex.withLock {
            loadThreadIndex(encryptionKey)
        }
    }

    /**
     * Get all messages for a thread.
     */
    suspend fun getMessages(
        threadId: String,
        encryptionKey: ByteArray
    ): List<Message> = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Check cache first
            messageCache[threadId]?.let { return@withContext it.toList() }

            // Load from disk
            val messages = loadThreadMessages(threadId, encryptionKey)
            messageCache[threadId] = messages.toMutableList()
            messages
        }
    }

    /**
     * Add a message to a thread.
     */
    suspend fun addMessage(
        message: Message,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Get or create cached list
            val threadMessages = messageCache.getOrPut(message.threadId) {
                loadThreadMessages(message.threadId, encryptionKey).toMutableList()
            }

            // Add message
            threadMessages.add(message)

            // Enforce max messages limit
            while (threadMessages.size > MAX_MESSAGES_PER_THREAD) {
                threadMessages.removeAt(0)
            }

            // Save to disk
            saveThreadMessages(message.threadId, threadMessages, encryptionKey)

            // Update thread index
            updateThreadIndex(message, encryptionKey)
        }
    }

    /**
     * Update message status (e.g., SENT → DELIVERED).
     */
    suspend fun updateMessageStatus(
        threadId: String,
        messageId: String,
        status: MessageStatus,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val threadMessages = messageCache.getOrPut(threadId) {
                loadThreadMessages(threadId, encryptionKey).toMutableList()
            }

            val index = threadMessages.indexOfFirst { it.id == messageId }
            if (index >= 0) {
                threadMessages[index] = threadMessages[index].copy(status = status)
                saveThreadMessages(threadId, threadMessages, encryptionKey)
            }
        }
    }

    /**
     * Mark all messages in a thread as read.
     */
    suspend fun markThreadAsRead(
        threadId: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Update thread unread count
            _threads.value = _threads.value.map { thread ->
                if (thread.contactId == threadId) {
                    thread.copy(unreadCount = 0)
                } else {
                    thread
                }
            }
            saveThreadIndex(encryptionKey)
        }
    }

    /**
     * Create or update a thread entry.
     */
    suspend fun ensureThread(
        contactId: String,
        contactDid: String,
        contactPetname: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val existing = _threads.value.find { it.contactId == contactId }
            if (existing == null) {
                val newThread = MessageThread(
                    contactId = contactId,
                    contactDid = contactDid,
                    contactPetname = contactPetname,
                    lastMessageTime = 0,
                    lastMessagePreview = "",
                    unreadCount = 0
                )
                _threads.value = _threads.value + newThread
                saveThreadIndex(encryptionKey)
            }
        }
    }

    /**
     * Delete a thread and all its messages.
     */
    suspend fun deleteThread(
        threadId: String,
        encryptionKey: ByteArray
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Remove from cache
            messageCache.remove(threadId)

            // Secure delete message file
            val threadFile = File(messagesDir, "$threadId.enc")
            secureDeleteFile(threadFile)

            // Remove from index
            _threads.value = _threads.value.filter { it.contactId != threadId }
            saveThreadIndex(encryptionKey)
        }
    }

    /**
     * Wipe all messages (for panic wipe).
     */
    suspend fun wipeAll() = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Clear cache
            messageCache.clear()
            _threads.value = emptyList()

            // Secure delete all files
            messagesDir.listFiles()?.forEach { file ->
                secureDeleteFile(file)
            }
            secureDeleteFile(threadsIndexFile)
        }
    }

    /**
     * Get thread by contact ID.
     */
    fun getThread(contactId: String): MessageThread? {
        return _threads.value.find { it.contactId == contactId }
    }

    /**
     * Get thread by contact DID.
     */
    fun getThreadByDid(did: String): MessageThread? {
        return _threads.value.find { it.contactDid == did }
    }

    /**
     * Clear the in-memory message cache.
     *
     * SECURITY FIX: Call this on app lock to remove plaintext messages from RAM.
     * Messages remain encrypted on disk and will be decrypted on next access.
     *
     * This prevents memory forensics from extracting message content.
     */
    suspend fun clearCache() = withContext(Dispatchers.IO) {
        mutex.withLock {
            // Zeroize message content before clearing
            for ((_, messages) in messageCache) {
                for (message in messages) {
                    // Zeroize the content byte array
                    message.content.fill(0)
                }
            }
            messageCache.clear()
        }
    }

    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    private fun loadThreadIndex(encryptionKey: ByteArray) {
        if (!threadsIndexFile.exists()) {
            _threads.value = emptyList()
            return
        }

        try {
            val encrypted = threadsIndexFile.readBytes()
            val decrypted = BedrockCore.aesDecrypt(encryptionKey, encrypted)
            if (decrypted != null) {
                _threads.value = deserializeThreads(decrypted)
                BedrockCore.zeroize(decrypted)
            }
        } catch (e: Exception) {
            _threads.value = emptyList()
        }
    }

    private fun saveThreadIndex(encryptionKey: ByteArray) {
        val data = serializeThreads(_threads.value)
        val encrypted = BedrockCore.aesEncrypt(encryptionKey, data)
        threadsIndexFile.writeBytes(encrypted)
        BedrockCore.zeroize(data)
    }

    private fun loadThreadMessages(threadId: String, encryptionKey: ByteArray): List<Message> {
        val threadFile = File(messagesDir, "$threadId.enc")
        if (!threadFile.exists()) {
            return emptyList()
        }

        try {
            val encrypted = threadFile.readBytes()
            val decrypted = BedrockCore.aesDecrypt(encryptionKey, encrypted)
            if (decrypted != null) {
                val messages = deserializeMessages(decrypted)
                BedrockCore.zeroize(decrypted)
                return messages
            }
        } catch (e: Exception) {
            // Corrupted file - return empty
        }

        return emptyList()
    }

    private fun saveThreadMessages(threadId: String, messages: List<Message>, encryptionKey: ByteArray) {
        val threadFile = File(messagesDir, "$threadId.enc")
        val data = serializeMessages(messages)
        val encrypted = BedrockCore.aesEncrypt(encryptionKey, data)
        threadFile.writeBytes(encrypted)
        BedrockCore.zeroize(data)
    }

    private fun updateThreadIndex(message: Message, encryptionKey: ByteArray) {
        val isIncoming = message.direction == MessageDirection.INCOMING
        val preview = message.text.take(MAX_PREVIEW_LENGTH)

        _threads.value = _threads.value.map { thread ->
            if (thread.contactId == message.threadId) {
                thread.copy(
                    lastMessageTime = message.timestamp,
                    lastMessagePreview = preview,
                    unreadCount = if (isIncoming) thread.unreadCount + 1 else thread.unreadCount
                )
            } else {
                thread
            }
        }.sortedByDescending { it.lastMessageTime }

        saveThreadIndex(encryptionKey)
    }

    private fun serializeThreads(threads: List<MessageThread>): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Version
        buffer.add(0x01)

        // Count
        buffer.addAll(intToBytes(threads.size))

        for (thread in threads) {
            // Contact ID
            val idBytes = thread.contactId.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(idBytes.size))
            buffer.addAll(idBytes.toList())

            // Contact DID
            val didBytes = thread.contactDid.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(didBytes.size))
            buffer.addAll(didBytes.toList())

            // Petname
            val nameBytes = thread.contactPetname.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(nameBytes.size))
            buffer.addAll(nameBytes.toList())

            // Last message time
            buffer.addAll(longToBytes(thread.lastMessageTime))

            // Preview
            val previewBytes = thread.lastMessagePreview.toByteArray(StandardCharsets.UTF_8)
            buffer.addAll(intToBytes(previewBytes.size))
            buffer.addAll(previewBytes.toList())

            // Unread count
            buffer.addAll(intToBytes(thread.unreadCount))
        }

        return buffer.toByteArray()
    }

    private fun deserializeThreads(data: ByteArray): List<MessageThread> {
        try {
            if (data.size < 5) return emptyList()

            var offset = 0

            val version = data[offset++]
            if (version != 0x01.toByte()) return emptyList()

            val count = bytesToInt(data, offset)
            offset += 4
            if (count < 0 || count > 10000) return emptyList()

            val threads = mutableListOf<MessageThread>()

            repeat(count) {
                // Contact ID
                if (offset + 4 > data.size) return emptyList()
                val idLen = bytesToInt(data, offset)
                if (idLen < 0 || idLen > 256 || offset + 4 + idLen > data.size) return emptyList()
                offset += 4
                val contactId = String(data.copyOfRange(offset, offset + idLen), StandardCharsets.UTF_8)
                offset += idLen

                // Contact DID
                if (offset + 4 > data.size) return emptyList()
                val didLen = bytesToInt(data, offset)
                if (didLen < 0 || didLen > 256 || offset + 4 + didLen > data.size) return emptyList()
                offset += 4
                val contactDid = String(data.copyOfRange(offset, offset + didLen), StandardCharsets.UTF_8)
                offset += didLen

                // Petname
                if (offset + 4 > data.size) return emptyList()
                val nameLen = bytesToInt(data, offset)
                if (nameLen < 0 || nameLen > 256 || offset + 4 + nameLen > data.size) return emptyList()
                offset += 4
                val contactPetname = String(data.copyOfRange(offset, offset + nameLen), StandardCharsets.UTF_8)
                offset += nameLen

                // Last message time
                if (offset + 8 > data.size) return emptyList()
                val lastMessageTime = bytesToLong(data, offset)
                offset += 8

                // Preview
                if (offset + 4 > data.size) return emptyList()
                val previewLen = bytesToInt(data, offset)
                if (previewLen < 0 || previewLen > 256 || offset + 4 + previewLen > data.size) return emptyList()
                offset += 4
                val lastMessagePreview = String(data.copyOfRange(offset, offset + previewLen), StandardCharsets.UTF_8)
                offset += previewLen

                // Unread count
                if (offset + 4 > data.size) return emptyList()
                val unreadCount = bytesToInt(data, offset)
                offset += 4

                threads.add(MessageThread(
                    contactId = contactId,
                    contactDid = contactDid,
                    contactPetname = contactPetname,
                    lastMessageTime = lastMessageTime,
                    lastMessagePreview = lastMessagePreview,
                    unreadCount = unreadCount
                ))
            }

            return threads
        } catch (e: Exception) {
            return emptyList()
        }
    }

    private fun serializeMessages(messages: List<Message>): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Version
        buffer.add(0x01)

        // Count
        buffer.addAll(intToBytes(messages.size))

        for (message in messages) {
            val msgBytes = message.toBytes()
            buffer.addAll(intToBytes(msgBytes.size))
            buffer.addAll(msgBytes.toList())
        }

        return buffer.toByteArray()
    }

    private fun deserializeMessages(data: ByteArray): List<Message> {
        try {
            if (data.size < 5) return emptyList()

            var offset = 0

            val version = data[offset++]
            if (version != 0x01.toByte()) return emptyList()

            val count = bytesToInt(data, offset)
            offset += 4
            if (count < 0 || count > MAX_MESSAGES_PER_THREAD) return emptyList()

            val messages = mutableListOf<Message>()

            repeat(count) {
                if (offset + 4 > data.size) return messages

                val msgLen = bytesToInt(data, offset)
                if (msgLen < 0 || msgLen > 65536 || offset + 4 + msgLen > data.size) return messages
                offset += 4

                val msgBytes = data.copyOfRange(offset, offset + msgLen)
                offset += msgLen

                Message.fromBytes(msgBytes)?.let { messages.add(it) }
            }

            return messages
        } catch (e: Exception) {
            return emptyList()
        }
    }

    private fun secureDeleteFile(file: File) {
        if (!file.exists()) return
        try {
            val size = file.length().toInt().coerceAtLeast(32)
            // Overwrite with random data
            file.writeBytes(BedrockCore.randomBytes(size))
            // Overwrite with zeros
            file.writeBytes(ByteArray(size))
            // Delete
            file.delete()
        } catch (e: Exception) {
            file.delete()
        }
    }

    private fun intToBytes(value: Int): List<Byte> {
        return listOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }

    private fun longToBytes(value: Long): List<Byte> {
        return listOf(
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
