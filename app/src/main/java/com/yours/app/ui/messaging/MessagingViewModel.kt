package com.yours.app.ui.messaging

import android.content.Context
import android.view.MotionEvent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.yours.app.identity.Contact
import com.yours.app.identity.ContactManager
import com.yours.app.identity.IdentityManager
import com.yours.app.messaging.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.nio.ByteBuffer

/**
 * ViewModel for messaging screens.
 *
 * Encapsulates all messaging logic and provides reactive state for the UI.
 * Handles:
 * - Thread list management
 * - Conversation loading and real-time updates
 * - Message sending with full encryption pipeline
 * - Entropy collection from user interactions
 *
 * SECURITY:
 * - Collects entropy from touch events for hedged key exchange
 * - Manages MessageManager lifecycle
 * - Handles session establishment transparently
 */
class MessagingViewModel(
    private val context: Context,
    private val messageManager: MessageManager,
    private val contactManager: ContactManager,
    private val identityManager: IdentityManager
) : ViewModel() {

    // ========================================================================
    // STATE
    // ========================================================================

    private val _threads = MutableStateFlow<List<MessageThread>>(emptyList())
    val threads: StateFlow<List<MessageThread>> = _threads.asStateFlow()

    private val _currentContact = MutableStateFlow<Contact?>(null)
    val currentContact: StateFlow<Contact?> = _currentContact.asStateFlow()

    private val _currentMessages = MutableStateFlow<List<Message>>(emptyList())
    val currentMessages: StateFlow<List<Message>> = _currentMessages.asStateFlow()

    private val _isInitialized = MutableStateFlow(false)
    val isInitialized: StateFlow<Boolean> = _isInitialized.asStateFlow()

    private val _anonymityLevel = MutableStateFlow(AnonymityLevel.NONE)
    val anonymityLevel: StateFlow<AnonymityLevel> = _anonymityLevel.asStateFlow()

    private val _sendingState = MutableStateFlow<SendingState>(SendingState.Idle)
    val sendingState: StateFlow<SendingState> = _sendingState.asStateFlow()

    private val _events = MutableSharedFlow<MessagingUiEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<MessagingUiEvent> = _events.asSharedFlow()

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts.asStateFlow()

    // Entropy collection buffer for touch events
    private val entropyBuffer = mutableListOf<Byte>()
    private val entropyLock = Any()

    init {
        // Collect threads from MessageManager
        viewModelScope.launch {
            messageManager.threads.collect { threadList ->
                _threads.value = threadList
            }
        }

        // Collect message events for UI updates
        viewModelScope.launch {
            messageManager.events.collect { event ->
                handleMessageEvent(event)
            }
        }
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    /**
     * Initialize the messaging system.
     * Call this when the user unlocks the vault.
     */
    suspend fun initialize() {
        if (_isInitialized.value) return

        try {
            val masterKey = identityManager.getMasterKey()
            val unlockedKeys = identityManager.getUnlockedKeys()
            val identity = identityManager.getIdentity()

            if (unlockedKeys != null && identity != null) {
                messageManager.initialize(
                    encryptionKey = masterKey,
                    ourSecretKey = unlockedKeys.sessionPrivateKey,  // X25519 (32 bytes) for Double Ratchet
                    ourDid = identity.did,
                    ourPublicKey = identity.sessionPublicKey  // Pass for debug logging
                )
                _isInitialized.value = true
                _anonymityLevel.value = messageManager.getAnonymityLevel()

                // Load contacts
                _contacts.value = contactManager.getContacts(masterKey)
            }
        } catch (e: Exception) {
            _events.emit(MessagingUiEvent.Error("Failed to initialize messaging: ${e.message}"))
        }
    }

    /**
     * Refresh contacts list.
     */
    suspend fun refreshContacts() {
        try {
            val masterKey = identityManager.getMasterKey()
            _contacts.value = contactManager.getContacts(masterKey)
            _anonymityLevel.value = messageManager.getAnonymityLevel()
        } catch (e: Exception) {
            // Ignore
        }
    }

    // ========================================================================
    // CONVERSATION MANAGEMENT
    // ========================================================================

    /**
     * Open a conversation with a contact.
     */
    suspend fun openConversation(contact: Contact) {
        _currentContact.value = contact
        loadMessages(contact.id)
        markAsRead(contact.id)
    }

    /**
     * Open a conversation by thread.
     */
    suspend fun openConversation(thread: MessageThread) {
        val masterKey = identityManager.getMasterKey()
        val contact = contactManager.getContact(thread.contactId)
        if (contact != null) {
            openConversation(contact)
        }
    }

    /**
     * Close current conversation.
     */
    fun closeConversation() {
        _currentContact.value = null
        _currentMessages.value = emptyList()
    }

    /**
     * Load messages for a contact.
     */
    private suspend fun loadMessages(contactId: String) {
        try {
            val messages = messageManager.getMessages(contactId)
            _currentMessages.value = messages
        } catch (e: Exception) {
            _events.emit(MessagingUiEvent.Error("Failed to load messages: ${e.message}"))
        }
    }

    /**
     * Mark messages as read.
     */
    private suspend fun markAsRead(contactId: String) {
        try {
            messageManager.markAsRead(contactId)
        } catch (e: Exception) {
            // Ignore
        }
    }

    // ========================================================================
    // SENDING MESSAGES
    // ========================================================================

    /**
     * Send a message to the current contact.
     *
     * SECURITY: Messages are encrypted with Double Ratchet, then onion-routed
     * through multiple relays for metadata protection.
     */
    fun sendMessage(text: String) {
        val contact = _currentContact.value ?: return
        if (text.isBlank()) return

        _sendingState.value = SendingState.Sending

        viewModelScope.launch {
            try {
                // Send message through MessageManager
                // This handles: session establishment, encryption, onion routing, mesh transport
                val message = messageManager.sendMessage(contact, text)

                // Refresh message list
                loadMessages(contact.id)

                _sendingState.value = SendingState.Idle

            } catch (e: InsufficientRelaysException) {
                _sendingState.value = SendingState.Idle
                _events.emit(MessagingUiEvent.InsufficientRelays(
                    available = e.available,
                    required = e.required
                ))
            } catch (e: Exception) {
                _sendingState.value = SendingState.Idle
                _events.emit(MessagingUiEvent.Error("Failed to send: ${e.message}"))
            }
        }
    }

    /**
     * Send a message in direct mode (no onion routing).
     * SECURITY WARNING: Only use with explicit user consent.
     */
    fun sendMessageDirectMode(text: String) {
        val contact = _currentContact.value ?: return
        if (text.isBlank()) return

        _sendingState.value = SendingState.Sending

        viewModelScope.launch {
            try {
                // For now, fall back to normal sending
                val message = messageManager.sendMessage(contact, text)
                loadMessages(contact.id)
                _sendingState.value = SendingState.Idle
            } catch (e: Exception) {
                _sendingState.value = SendingState.Idle
                _events.emit(MessagingUiEvent.Error("Failed to send: ${e.message}"))
            }
        }
    }

    // ========================================================================
    // THREAD MANAGEMENT
    // ========================================================================

    /**
     * Delete a conversation thread.
     */
    fun deleteThread(contactId: String) {
        viewModelScope.launch {
            try {
                messageManager.deleteThread(contactId)
            } catch (e: Exception) {
                _events.emit(MessagingUiEvent.Error("Failed to delete thread: ${e.message}"))
            }
        }
    }

    // ========================================================================
    // EVENT HANDLING
    // ========================================================================

    private suspend fun handleMessageEvent(event: MessageEvent) {
        when (event) {
            is MessageEvent.Received -> {
                // Refresh messages if this is for current conversation
                if (event.message.threadId == _currentContact.value?.id) {
                    loadMessages(event.message.threadId)
                    markAsRead(event.message.threadId)
                }
                _events.emit(MessagingUiEvent.MessageReceived(
                    fromPetname = _threads.value.find { it.contactId == event.message.threadId }?.contactPetname ?: "Unknown"
                ))
            }

            is MessageEvent.StatusChanged -> {
                // Refresh messages to show updated status
                _currentContact.value?.let { contact ->
                    loadMessages(contact.id)
                }
            }

            is MessageEvent.SessionEstablished -> {
                _events.emit(MessagingUiEvent.SessionEstablished)
            }

            is MessageEvent.InsufficientRelays -> {
                _events.emit(MessagingUiEvent.InsufficientRelays(
                    available = event.available,
                    required = event.required
                ))
            }

            is MessageEvent.ReducedAnonymity -> {
                _events.emit(MessagingUiEvent.ReducedAnonymity(
                    contactCount = event.contactCount,
                    requiredCount = event.requiredCount
                ))
            }

            is MessageEvent.DirectModeWarning -> {
                _events.emit(MessagingUiEvent.DirectModeWarning)
            }

            is MessageEvent.Error -> {
                _events.emit(MessagingUiEvent.Error(event.error))
            }

            is MessageEvent.AckTimeout -> {
                _events.emit(MessagingUiEvent.DeliveryTimeout(event.messageId))
            }

            is MessageEvent.ReplayDetected -> {
                _events.emit(MessagingUiEvent.ReplayDetected)
            }

            else -> { /* Ignore other events */ }
        }
    }

    // ========================================================================
    // ENTROPY COLLECTION
    // ========================================================================

    /**
     * Collect entropy from touch events.
     *
     * SECURITY: Touch events provide high-quality entropy for hedged key exchange.
     * Even if the system RNG is compromised, touch timing and coordinates
     * provide unpredictable entropy that hardens session establishment.
     *
     * Call this from touch event handlers in the UI.
     */
    fun collectTouchEntropy(event: MotionEvent) {
        synchronized(entropyLock) {
            // Extract entropy from touch coordinates and timing
            val x = event.x
            val y = event.y
            val time = event.eventTime
            val pressure = event.pressure

            // Convert floats to bytes
            val xBits = java.lang.Float.floatToIntBits(x)
            val yBits = java.lang.Float.floatToIntBits(y)
            val pressureBits = java.lang.Float.floatToIntBits(pressure)

            // Add low bits (most entropy)
            entropyBuffer.add((xBits and 0xFF).toByte())
            entropyBuffer.add((yBits and 0xFF).toByte())
            entropyBuffer.add((time and 0xFF).toByte())
            entropyBuffer.add(((time shr 8) and 0xFF).toByte())
            entropyBuffer.add((pressureBits and 0xFF).toByte())

            // Keep buffer bounded
            while (entropyBuffer.size > 512) {
                entropyBuffer.removeAt(0)
            }
        }
    }

    /**
     * Collect entropy from keyboard input.
     *
     * SECURITY: Key timing provides entropy even if the actual text is predictable.
     */
    fun collectKeyboardEntropy() {
        synchronized(entropyLock) {
            val nanos = System.nanoTime()
            entropyBuffer.add((nanos and 0xFF).toByte())
            entropyBuffer.add(((nanos shr 8) and 0xFF).toByte())
            entropyBuffer.add(((nanos shr 16) and 0xFF).toByte())
            entropyBuffer.add(((nanos shr 24) and 0xFF).toByte())

            while (entropyBuffer.size > 512) {
                entropyBuffer.removeAt(0)
            }
        }
    }

    /**
     * Get collected entropy for session establishment.
     * Called internally by MessageManager during session creation.
     */
    internal fun getCollectedEntropy(): ByteArray {
        synchronized(entropyLock) {
            return entropyBuffer.toByteArray()
        }
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================

    override fun onCleared() {
        super.onCleared()
        // NOTE: Do NOT call messageManager.lock() here!
        //
        // closes ALL Double Ratchet sessions. This caused a critical bug:
        // - User sends message from S23 → creates INITIATOR session
        // - User navigates away or activity recreates → ViewModel.onCleared()
        // - lock() closes S23's session for S9
        // - S9's reply arrives → S23 has no session → message can't be decrypted!
        //
        // Sessions should ONLY be closed on:
        // 1. Explicit app lock (panic button, manual lock)
        // 2. Auto-lock timer expiry (handled in MainActivity)
        // 3. User explicit logout/wipe
        //
        // ViewModel cleanup is a normal lifecycle event that should NOT destroy
        // cryptographic sessions - the user is still using the app!
    }

    // ========================================================================
    // FACTORY
    // ========================================================================

    class Factory(
        private val context: Context,
        private val messageManager: MessageManager,
        private val contactManager: ContactManager,
        private val identityManager: IdentityManager
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(MessagingViewModel::class.java)) {
                return MessagingViewModel(
                    context = context,
                    messageManager = messageManager,
                    contactManager = contactManager,
                    identityManager = identityManager
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}

/**
 * State for message sending.
 */
sealed class SendingState {
    object Idle : SendingState()
    object Sending : SendingState()
}

/**
 * UI events from messaging system.
 */
sealed class MessagingUiEvent {
    data class Error(val message: String) : MessagingUiEvent()
    data class MessageReceived(val fromPetname: String) : MessagingUiEvent()
    object SessionEstablished : MessagingUiEvent()
    data class InsufficientRelays(val available: Int, val required: Int) : MessagingUiEvent()
    data class ReducedAnonymity(val contactCount: Int, val requiredCount: Int) : MessagingUiEvent()
    object DirectModeWarning : MessagingUiEvent()
    data class DeliveryTimeout(val messageId: String) : MessagingUiEvent()
    object ReplayDetected : MessagingUiEvent()
}
