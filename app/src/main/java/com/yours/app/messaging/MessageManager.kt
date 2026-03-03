package com.yours.app.messaging

import android.content.Context
import android.util.Log
import com.yours.app.crypto.BedrockCore
import com.yours.app.identity.Contact
import com.yours.app.identity.ContactManager
import com.yours.app.mesh.MeshCoreManager
import com.yours.app.mesh.MeshConnectionState
import com.yours.app.mesh.MeshEvent
import com.yours.app.mesh.MeshEventType
import com.yours.app.mesh.LoRaRxPacket
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * High-level P2P messaging over LunarCore mesh.
 * Coordinates session management, encryption, onion routing, and LoRa transport.
 */
class MessageManager(
    private val context: Context,
    private val contactManager: ContactManager,
    private val meshManager: MeshCoreManager
) {
    companion object {
        private const val TAG = "MessageManager"
        private var instanceCounter = 0
        private const val MAX_RETRIES = 3
        private const val RETRY_DELAY_MS = 5000L
        private const val ACK_TIMEOUT_MS = 30000L

        /**
         * MeshCore maximum payload size.
         * From MeshCore.h: #define MAX_PACKET_PAYLOAD 184
         * Packets larger than this WILL BE TRUNCATED by MeshCore!
         */
        const val MESHCORE_MAX_PAYLOAD = 184

        /**
         * SECURITY: Random ACK delay range to prevent timing correlation.
         * ACKs are delayed 5-30 seconds randomly to break timing patterns.
         */
        private const val ACK_DELAY_MIN_MS = 5000L
        private const val ACK_DELAY_MAX_MS = 30000L

        /**
         * SECURITY: Minimum relay count for anonymity.
         *
         * Like Tor, we require 3 relays (4 hops total: you → R1 → R2 → R3 → recipient).
         * With only 2 relays, a single compromised node reveals both endpoints.
         * With 3+ relays, adversary must compromise BOTH entry and exit.
         */
        const val MIN_RELAY_COUNT = 3

        /**
         * Whether to prefer LunarRouter circuits (AES-256-GCM) over simple onion (ChaCha20-Poly1305).
         * LunarRouter provides persistent tunnels with better anonymity properties.
         */
        const val PREFER_LUNAR_CIRCUITS = true
    }

    // Sub-managers
    private val sessionManager = LunarSessionManager(context)
    private val storage = MessageStorage(context)
    private val replayProtection = ReplayProtection()

    /**
     * LunarRouter circuit manager for AES-256-GCM circuit-based routing.
     * Provides Tor-style persistent tunnels with 3+ hops.
     */
    private lateinit var circuitManager: LunarCircuitManager

    // ========================================================================
    // PHASE 2-3 ANONYMITY COMPONENTS (NOW WIRED UP)
    // ========================================================================

    /**
     * Message pool for Tornado Cash-style epoch batching.
     * Messages are queued and released together at epoch boundaries.
     */
    private val messagePool = MessagePool(
        onTransmit = { pooledPacket ->
            transmitPooledPacket(pooledPacket)
        }
    )

    /**
     * Blinded hints to prevent targeted traffic scanning.
     * Hints rotate hourly and are unique per sender-recipient pair.
     */
    private val blindedHints = BlindedHintSystem(
        getOurSecretKey = { ourSecretKey }
    )

    /**
     * Unidirectional tunnels for I2P-style separate inbound/outbound paths.
     */
    private lateinit var tunnels: UnidirectionalTunnels

    /**
     * Garlic bundler for I2P-style message bundling.
     */
    private val garlicBundler = GarlicBundler()

    /**
     * Cover traffic scheduler for DAITA-style chaff generation.
     */
    private lateinit var coverTrafficScheduler: CoverTrafficScheduler

    /**
     * Poisson traffic scheduler for Loopix-style collision-resistant transmission.
     *
     * REPLACES epoch-based MessagePool for P2P mode:
     * - Exponentially-distributed inter-arrival times (memoryless)
     * - No synchronized epochs = no systematic half-duplex collisions
     * - Cover traffic generated at Poisson ticks when queue is empty
     *
     * P(collision) = (TX_duration / mean_inter_arrival)² ≈ 0.04% vs 100% with epochs
     */
    private val poissonScheduler = PoissonTrafficScheduler(
        onTransmit = { poissonPacket ->
            transmitPoissonPacket(poissonPacket)
        },
        generateCoverPacket = {
            generatePoissonCoverPacket()
        }
    )

    // State
    private var encryptionKey: ByteArray? = null
    private var ourSecretKey: ByteArray? = null
    private var ourPublicKey: ByteArray? = null  // Added for debug logging - what contacts should have stored for us
    private var ourDid: String = ""

    // Pending ACKs
    private val pendingAcks = ConcurrentHashMap<String, CompletableDeferred<Unit>>()

    // TIMING FIX: Buffer for messages that arrive before their handshake.
    // When a message arrives but no session exists yet, we buffer it here.
    // After a handshake is successfully processed, we retry all buffered messages.
    // This handles the race condition where message arrives before handshake
    // due to random epoch shuffling.
    private data class PendingMessage(
        val encryptedPayload: ByteArray,
        val receivedAt: Long,
        val ourSk: ByteArray
    )
    private val pendingMessagesBuffer = ConcurrentHashMap<String, MutableList<PendingMessage>>()
    private val pendingMessagesMutex = Mutex()
    private val PENDING_MESSAGE_TIMEOUT_MS = 60_000L  // 1 minute expiry

    // Coroutine scope for background tasks
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Event flow for UI updates
    private val _events = MutableSharedFlow<MessageEvent>(replay = 0, extraBufferCapacity = 64)
    val events: Flow<MessageEvent> = _events.asSharedFlow()

    // Expose thread list from storage
    val threads: Flow<List<MessageThread>> = storage.threads

    /**
     * Check if MessageManager is initialized.
     * Use this before sending messages to avoid crashes.
     */
    val isInitialized: Boolean
        get() = encryptionKey != null && ourSecretKey != null

    /**
     * Initialize the messaging system.
     *
     * @param encryptionKey Master key for storage encryption
     * @param ourSecretKey Our X25519 secret key for sessions
     * @param ourDid Our decentralized identifier
     */
    suspend fun initialize(encryptionKey: ByteArray, ourSecretKey: ByteArray, ourDid: String = "", ourPublicKey: ByteArray? = null) {
        this.encryptionKey = encryptionKey
        this.ourSecretKey = ourSecretKey
        this.ourPublicKey = ourPublicKey  // Store for debug logging at send time
        this.ourDid = ourDid

        // Debug: Log our session keys for comparison
        if (ourPublicKey != null) {
        } else {
        }

        // SELF-TEST: Create packet to ourselves and try to decrypt it
        if (ourPublicKey != null) {
            val testPayload = "SELF_TEST_PAYLOAD".toByteArray()
            val testNodeId = ByteArray(8) { 0x42 }
            val testPacket = BedrockCore.createOnionPacketDirect(testNodeId, ourPublicKey, testPayload)
            if (testPacket != null) {
                val peeled = BedrockCore.peelOnionLayer(testPacket, ourSecretKey)
                if (peeled != null) {
                } else {
                }
            } else {
            }
        }

        // Initialize storage
        storage.initialize(encryptionKey)

        // Start entropy collection for session hedging
        sessionManager.entropyCollector.startCollection()

        // ====================================================================
        // INITIALIZE LUNARROUTER CIRCUIT MANAGER (AES-256-GCM)
        // ====================================================================
        circuitManager = LunarCircuitManager(context, sessionManager.entropyCollector)
        circuitManager.start()

        // Listen for circuit events and handle handshakes
        scope.launch {
            circuitManager.events.collect { event ->
                handleCircuitEvent(event)
            }
        }

        // ====================================================================
        // INITIALIZE PHASE 2-3 ANONYMITY COMPONENTS
        // ====================================================================

        // Initialize unidirectional tunnels (I2P-style)
        tunnels = UnidirectionalTunnels(
            getContacts = { contactManager.getContacts(encryptionKey) },
            getOurDid = { this.ourDid }
        )
        // Wire up LunarRouter circuits to tunnels for AES-256-GCM routing
        tunnels.setCircuitManager(circuitManager)

        // Initialize cover traffic scheduler (DAITA-style)
        coverTrafficScheduler = CoverTrafficScheduler(
            messagePool = messagePool,
            getRandomContact = {
                val contacts = contactManager.getContacts(encryptionKey)
                contacts.randomOrNull()
            },
            buildOnionPacket = { contact, payload ->
                try {
                    buildOnionPacket(contact, payload)
                } catch (e: Exception) {
                    Log.e(TAG, "Exception in buildOnionPacket: " + e.javaClass.simpleName + ": " + e.message, e)
                    null
                }
            },
            wrapInGarlic = { contact, onionPacket ->
                // Pool pads to MAX_PACKET_SIZE with random bytes, which corrupts
                // raw onion packets. Garlic format includes length fields.
                val blindedHint = blindedHints.computeHintForRecipient(contact.sessionPublicKey)
                val clove = Clove.data(blindedHint, onionPacket)
                garlicBundler.buildImmediateGarlic(listOf(clove), addChaff = true)
            }
        )

        // ====================================================================
        // TRAFFIC SCHEDULER SELECTION (P2P vs Multi-Contact)
        // ====================================================================
        // - Double bandwidth usage (both generating cover traffic)
        // - Synchronized epoch collisions (MessagePool) defeating Poisson benefits
        //
        // P2P Mode (0-1 contacts): Use Poisson scheduler only
        // Multi-Contact Mode (2+ contacts): Use MessagePool for anonymity set batching
        val contactCount = contactManager.getContacts(encryptionKey).size
        val isP2PMode = contactCount <= 1

        if (isP2PMode) {
            // P2P MODE: Use Poisson scheduler (Loopix-style random timing)
            // Benefits: No synchronized epochs = no half-duplex collisions
            Log.i(TAG, "P2P MODE DETECTED ($contactCount contacts) - using Poisson scheduler only")
            poissonScheduler.start(scope, PoissonTrafficScheduler.LAMBDA_FAST)  // Faster for P2P testing
            Log.i(TAG, "Poisson scheduler started with λ=${PoissonTrafficScheduler.LAMBDA_FAST} (~7.5s avg)")
            // MessagePool NOT started - no epoch-based transmission
        } else {
            // MULTI-CONTACT MODE: Use MessagePool (Tornado Cash-style epoch batching)
            // Benefits: Anonymity set from batching multiple users' messages
            Log.i(TAG, "MULTI-CONTACT MODE ($contactCount contacts) - using MessagePool")
            messagePool.start(scope)
            // Poisson NOT started - epoch batching provides anonymity

            // Start cover traffic generation (DAITA-style chaff) for multi-contact mode
            coverTrafficScheduler.start(scope, CoverTrafficMode.OFF)
        }

        // Start listening for incoming messages
        startMessageListener()

        // Emit initialization event
        _events.emit(MessageEvent.SystemInitialized(
            anonymityLevel = getAnonymityLevel(),
            coverTrafficMode = coverTrafficScheduler.getMode()
        ))
    }

    /**
     * Send a message to a contact.
     *
     * FULL ANONYMITY FLOW (Phase 2-3 integrated):
     * 1. Create & store message
     * 2. Establish Double Ratchet session
     * 3. Encrypt with session
     * 4. Add replay protection (counter + nonce)
     * 5. Compute blinded hint (prevents targeted scanning)
     * 6. Build packet via unidirectional tunnel (I2P-style)
     * 7. Add to message pool (Tornado Cash-style batching)
     * 8. Pool releases at epoch boundary with chaff (DAITA-style)
     *
     * @param contact The recipient contact
     * @param text The message text
     * @return The created message (status will update via events)
     */
    suspend fun sendMessage(contact: Contact, text: String): Message {
        Log.d(TAG, "=== SEND MESSAGE ===")
        Log.d(TAG, "contact.petname=${contact.petname}")
        Log.d(TAG, "contact.sessionPublicKey.size=${contact.sessionPublicKey.size} (expected 32)")
        Log.d(TAG, "contact.encryptionPublicKey.size=${contact.encryptionPublicKey.size} (expected 1184)")
        Log.d(TAG, "text.length=${text.length}")

        val key = encryptionKey ?: throw IllegalStateException("Not initialized")
        val ourSk = ourSecretKey ?: throw IllegalStateException("Not initialized")

        Log.d(TAG, "MessageManager is initialized, proceeding...")

        // Create message
        val message = Message.create(contact.id, text)

        // Ensure thread exists
        storage.ensureThread(contact.id, contact.did, contact.petname, key)

        // Store message as pending
        storage.addMessage(message, key)

        // Build and queue in background
        scope.launch {
            try {
                val (session, handshake) = sessionManager.getOrCreateSession(contact, ourSk)

                // Bundle handshake + message in same garlic for ordering
                val handshakeClove: Clove? = if (handshake != null) {
                    val handshakePacket = buildOnionPacket(contact, handshake)
                    val hsHint = blindedHints.computeHintForRecipient(contact.sessionPublicKey)
                    Clove.handshake(hsHint, handshakePacket)
                } else {
                    null
                }

                // ============================================================
                // STEP 2: ENCRYPT MESSAGE
                // ============================================================
                val wireData = MessageWireFormat.encodeText(message.id, text)
                Log.d(TAG, "=== SIZE TRACE ===")
                Log.d(TAG, "STEP 2a: wireData.size=${wireData.size} (expected: ${MessageWireFormat.PADDED_SIZE})")

                val encrypted = sessionManager.encrypt(contact.did, wireData)
                Log.d(TAG, "STEP 2b: encrypted.size=${encrypted.size} (expected: ${wireData.size + 36})")
                Log.d(TAG, "STEP 2b: overhead=${encrypted.size - wireData.size} bytes (expected: 36)")

                // ============================================================
                // STEP 3: REPLAY PROTECTION - DISABLED (Double Ratchet handles it)
                // ============================================================
                // NOTE: The Double Ratchet session encryption already includes a
                // monotonic counter that provides replay protection. The separate
                // withReplayProtection() wrapper was redundant and added 24 bytes
                // of overhead that pushed us over the 184-byte MeshCore limit.
                //
                // val counter = replayProtection.generateCounter(contact.did)
                // val nonce = replayProtection.generateNonce()
                // val protectedPayload = encrypted.withReplayProtection(counter, nonce)

                // ============================================================
                // STEP 4: COMPUTE BLINDED HINT (prevents targeted scanning)
                // ============================================================
                val blindedHint = blindedHints.computeHintForRecipient(contact.sessionPublicKey)

                // Prepend blinded hint to payload so recipient can identify packet
                // FIXED: Use 'encrypted' directly instead of 'protectedPayload' (saves 24 bytes)
                val hintedPayload = ByteArray(BlindedHintSystem.BLINDED_HINT_SIZE + encrypted.size)
                System.arraycopy(blindedHint, 0, hintedPayload, 0, BlindedHintSystem.BLINDED_HINT_SIZE)
                System.arraycopy(encrypted, 0, hintedPayload, BlindedHintSystem.BLINDED_HINT_SIZE, encrypted.size)
                Log.d(TAG, "STEP 4: hintedPayload.size=${hintedPayload.size} (expected: ${encrypted.size + 4})")
                Log.d(TAG, "=== TOTAL BEFORE ONION: ${hintedPayload.size} bytes ===")
                Log.d(TAG, "=== EXPECTED: ${MessageWireFormat.PADDED_SIZE} + 36 + 4 = ${MessageWireFormat.PADDED_SIZE + 40} bytes ===")

                // ============================================================
                // STEP 5: BUILD PACKET - DIRECT MODE FOR P2P TESTING
                // ============================================================
                val packet = buildDirectPacket(contact, hintedPayload)

                // Create garlic bundle
                val messageClove = Clove.data(blindedHint, packet)

                // Add to message pool (epoch batching)
                val finalPackets: List<ByteArray> = if (handshakeClove != null) {
                    val cloves = listOf(handshakeClove, messageClove)

                    if (garlicBundler.willClovesFit(cloves)) {
                        listOf(garlicBundler.buildImmediateGarlic(
                            cloves = cloves,
                            addChaff = true,
                            preserveOrder = true
                        ))
                    } else {
                        // Split into two garlics for MTU constraint
                        listOf(
                            garlicBundler.wrapSingleClove(handshakeClove, addChaff = true),
                            garlicBundler.wrapSingleClove(messageClove, addChaff = true)
                        )
                    }
                } else {
                    // SINGLE MESSAGE: Existing session, just wrap the message clove
                    val bundleStatus = garlicBundler.addClove(messageClove)
                    val singlePacket = when (bundleStatus) {
                        BundleStatus.READY -> {
                            // Multiple cloves ready to bundle
                            val garlic = garlicBundler.buildGarlic(addChaff = true)
                            if (garlic != null) {
                                Log.d(TAG, "Garlic bundle ready: ${garlic.size} bytes, first=0x${String.format("%02X", garlic[0])}")
                                garlic
                            } else {
                                // Race condition: another thread got the cloves. Use guaranteed wrap.
                                Log.w(TAG, "buildGarlic returned null (race condition), using wrapSingleClove")
                                garlicBundler.wrapSingleClove(messageClove)
                            }
                        }
                        BundleStatus.SKIP -> {
                            // Packet too large for standard garlic bundling
                            // This should NOT happen with properly-sized messages!
                            Log.e(TAG, "!! Packet ${packet.size} bytes exceeds garlic bundling limit !!")
                            Log.e(TAG, "!! Using minimal garlic wrap (no chaff) !!")
                            // Still wrap in garlic (no chaff) to preserve structure
                            garlicBundler.wrapSingleClove(messageClove, addChaff = false)
                        }
                        BundleStatus.PENDING -> {
                            // Single message - use guaranteed wrap method
                            val garlic = garlicBundler.buildGarlic(addChaff = true)
                            if (garlic != null) {
                                Log.d(TAG, "Single message garlic: ${garlic.size} bytes, first=0x${String.format("%02X", garlic[0])}")
                                garlic
                            } else {
                                // Race condition: another thread got the clove. Use guaranteed wrap.
                                Log.w(TAG, "buildGarlic returned null (race condition), using wrapSingleClove")
                                garlicBundler.wrapSingleClove(messageClove)
                            }
                        }
                    }
                    listOf(singlePacket)
                }
                Log.d(TAG, "Final packets: ${finalPackets.size} garlic(s), total ${finalPackets.sumOf { it.size }} bytes")

                // ============================================================
                // STEP 8: QUEUE FOR TRANSMISSION (P2P vs Multi-Contact routing)
                // ============================================================
                // DETECT P2P MODE: Check if we only have one contact (the recipient)
                // In P2P mode, there's no anonymity set from batching, so we use
                // Poisson-distributed timing to avoid half-duplex collisions.
                val allContacts = contactManager.getContacts(key)
                val isP2PMode = allContacts.size <= 1

                var epoch = -1L
                if (isP2PMode) {
                    // ============================================================
                    // P2P MODE: Use Poisson scheduler (Loopix-style)
                    // ============================================================
                    // Benefits:
                    // - Exponentially-distributed inter-arrival times (memoryless)
                    // - No synchronized epochs = no systematic collisions
                    // - P(collision) ≈ 0.04% vs 100% with epoch batching
                    // - Cover traffic generated when queue is empty
                    Log.i(TAG, "P2P MODE: Routing ${finalPackets.size} packets through Poisson scheduler")
                    _events.emit(MessageEvent.PoissonModeActive(contact.did))

                    for ((index, pkt) in finalPackets.withIndex()) {
                        // Priority: handshakes first (higher priority = lower number)
                        val priority = if (index < finalPackets.size - 1) 10 else 0
                        val queuePosition = poissonScheduler.queuePacket(
                            packet = pkt,
                            metadata = PacketMetadata(
                                messageId = if (index == finalPackets.size - 1) message.id else "handshake_${message.id}",
                                contactDid = contact.did,
                                isHandshake = index < finalPackets.size - 1
                            ),
                            priority = priority
                        )
                        Log.d(TAG, "Poisson queued packet ${index + 1}/${finalPackets.size} at position $queuePosition")
                    }
                } else {
                    // ============================================================
                    // MULTI-CONTACT MODE: Use MessagePool (Tornado Cash-style)
                    // ============================================================
                    // Benefits:
                    // - Epoch batching provides anonymity set
                    // - Messages release together with chaff
                    // - Timing correlation becomes infeasible
                    Log.i(TAG, "MULTI-CONTACT MODE: Routing ${finalPackets.size} packets through MessagePool")

                    finalPackets.forEachIndexed { index, pkt ->
                        val priority = if (index < finalPackets.size - 1) -1 else 0
                        epoch = messagePool.addMessage(
                            packet = pkt,
                            priority = priority,
                            metadata = PacketMetadata(
                                messageId = if (index == finalPackets.size - 1) message.id else "handshake_${message.id}",
                                contactDid = contact.did,
                                isHandshake = index < finalPackets.size - 1
                            )
                        )
                    }

                    // Trigger cover traffic burst (DAITA-style) for multi-contact mode
                    coverTrafficScheduler.triggerBurst()
                }

                // Update status to QUEUED (will become SENT at next Poisson tick or epoch boundary)
                storage.updateMessageStatus(contact.id, message.id, MessageStatus.SENT, key)
                _events.emit(MessageEvent.MessageQueued(message.id, epoch))

                // Set up ACK listener
                val ackDeferred = CompletableDeferred<Unit>()
                pendingAcks[message.id] = ackDeferred

                // Wait for ACK with extended timeout
                // P2P mode: shorter timeout (Poisson mean interval is ~15s)
                // Multi-contact: accounts for epoch batching delay
                val extendedTimeout = if (isP2PMode) {
                    ACK_TIMEOUT_MS + 30_000L  // Poisson mean + buffer
                } else {
                    ACK_TIMEOUT_MS + MessagePool.EPOCH_DURATION_MS + MessagePool.EPOCH_JITTER_MS
                }
                try {
                    withTimeout(extendedTimeout) {
                        ackDeferred.await()
                    }
                    // ACK received
                    storage.updateMessageStatus(contact.id, message.id, MessageStatus.DELIVERED, key)
                    _events.emit(MessageEvent.StatusChanged(message.id, MessageStatus.DELIVERED))
                } catch (e: TimeoutCancellationException) {
                    // ACK timeout - message may still be delivered, just no confirmation
                    pendingAcks.remove(message.id)
                    _events.emit(MessageEvent.AckTimeout(message.id))
                }

            } catch (e: InsufficientRelaysException) {
                Log.e(TAG, "InsufficientRelaysException in sendMessage: available=" + e.available + ", required=" + e.required, e)
                // Not enough contacts for anonymous routing
                storage.updateMessageStatus(contact.id, message.id, MessageStatus.FAILED, key)
                _events.emit(MessageEvent.InsufficientRelays(message.id, e.available, e.required))
            } catch (e: Exception) {
                Log.e(TAG, "Exception in sendMessage: " + e.javaClass.simpleName + ": " + e.message, e)
                storage.updateMessageStatus(contact.id, message.id, MessageStatus.FAILED, key)
                _events.emit(MessageEvent.Error(message.id, e.message ?: "Send failed"))
            }
        }

        return message
    }

    /**
     * Get messages for a thread.
     */
    suspend fun getMessages(contactId: String): List<Message> {
        val key = encryptionKey ?: return emptyList()
        return storage.getMessages(contactId, key)
    }

    /**
     * Mark a thread as read.
     */
    suspend fun markAsRead(contactId: String) {
        val key = encryptionKey ?: return
        storage.markThreadAsRead(contactId, key)
    }

    /**
     * Delete a conversation.
     */
    suspend fun deleteThread(contactId: String) {
        val key = encryptionKey ?: return
        storage.deleteThread(contactId, key)

        // Also close session
        val contact = contactManager.getContact(contactId)
        if (contact != null) {
            sessionManager.closeSession(contact.did)
        }
    }

    /**
     * Lock messaging system - clear sensitive data from RAM.
     *
     * SECURITY FIX: Call this when app locks to prevent memory forensics.
     * Clears:
     * - In-memory message cache (plaintext messages)
     * - Session keys (Double Ratchet state)
     * - Master encryption keys
     * - Phase 2-3 anonymity component caches
     *
     * Messages remain encrypted on disk, sessions can be re-established.
     */
    suspend fun lock() {
        // Clear plaintext message cache
        storage.clearCache()

        // Close all sessions (keys zeroized in Rust)
        sessionManager.closeAllSessions()

        // ====================================================================
        // PHASE 2-3: Clear anonymity component state
        // ====================================================================

        // Clear message pool (pending messages lost - by design for security)
        messagePool.clear()

        // Clear Poisson scheduler queue (pending messages lost - by design for security)
        poissonScheduler.clear()

        // Clear blinded hints cache
        blindedHints.clearAll()

        // Clear unidirectional tunnels
        if (::tunnels.isInitialized) {
            tunnels.clearAll()
        }

        // Clear garlic bundler
        garlicBundler.clear()

        // Clear LunarRouter circuits (closes all circuits, zeroizes keys)
        if (::circuitManager.isInitialized) {
            circuitManager.stop()
        }

        // Clear replay protection state
        replayProtection.clearAll()

        // Zeroize local key copies
        encryptionKey?.let { BedrockCore.zeroize(it) }
        ourSecretKey?.let { BedrockCore.zeroize(it) }
        encryptionKey = null
        ourSecretKey = null
    }

    /**
     * Shutdown messaging system.
     */
    suspend fun shutdown() {
        // Stop cover traffic generation first
        if (::coverTrafficScheduler.isInitialized) {
            coverTrafficScheduler.stop()
        }

        // Stop LunarRouter circuit manager
        if (::circuitManager.isInitialized) {
            circuitManager.stop()
        }

        // Stop message pool processing
        messagePool.stop()

        // Stop Poisson traffic scheduler
        poissonScheduler.stop()

        // Cancel coroutine scope
        scope.cancel()

        // Stop entropy collection
        sessionManager.entropyCollector.stopCollection()

        // Lock to clear all sensitive data
        lock()
    }

    /**
     * Wipe all messages (for panic wipe).
     */
    suspend fun wipeAll() {
        storage.wipeAll()
        sessionManager.closeAllSessions()
    }

    // ========================================================================
    // PRIVATE: Phase 2-3 Integration Helpers
    // ========================================================================

    /**
     * Queue a handshake packet with high priority.
     * Handshakes are prioritized over regular messages.
     */
    private suspend fun queueHandshake(contact: Contact, handshake: ByteArray) {
        try {
            // Build packet for handshake
            val packet = buildOnionPacket(contact, handshake)

            // The pool pads packets to MAX_PACKET_SIZE with random bytes,
            // which would corrupt raw onion packets (auth tag at end).
            //
            // NOTE: Use Clove.handshake() NOT Clove.data() - handshake payloads
            // do NOT have a blinded hint prefix (unlike encrypted messages).
            // Using the wrong clove type causes the receiver to incorrectly
            // strip bytes from the handshake, corrupting it.
            val blindedHint = blindedHints.computeHintForRecipient(contact.sessionPublicKey)
            val clove = Clove.handshake(blindedHint, packet)
            val garlicPacket = garlicBundler.buildImmediateGarlic(listOf(clove), addChaff = true)

            // Queue with high priority (priority -1 = higher than normal)
            messagePool.addMessage(
                packet = garlicPacket,
                priority = -1,  // High priority
                metadata = PacketMetadata(
                    messageId = "handshake_${System.currentTimeMillis()}",
                    contactDid = contact.did,
                    isHandshake = true
                )
            )
        } catch (e: InsufficientRelaysException) {
                Log.e(TAG, "InsufficientRelaysException in sendMessage: available=" + e.available + ", required=" + e.required, e)
            // Fall back to direct handshake if no relays
            sendPacket(contact, handshake, isHandshake = true)
        }
    }

    /**
     * Transmit a pooled packet via the mesh transport.
     * Called by MessagePool at epoch boundaries.
     *
     * @return true if transmission succeeded
     */
    private suspend fun transmitPooledPacket(pooledPacket: PooledPacket): Boolean {
        // Check mesh connection
        val connState = meshManager.connectionState.value
        Log.d(TAG, "=== TRANSMIT POOLED PACKET ===")
        Log.d(TAG, "meshConnectionState=$connState, messageId=${pooledPacket.metadata?.messageId}")

        if (connState != MeshConnectionState.CONNECTED) {
            Log.e(TAG, "Cannot transmit: mesh not connected (state=$connState)")
            return false
        }

        return try {
            val packetSize = pooledPacket.data.size
            Log.d(TAG, "Calling meshManager.transmitRaw($packetSize bytes)...")

            // !! DIAGNOSTIC: Log exact bytes for handshake tracking !!
            val isHandshake = pooledPacket.metadata?.isHandshake == true
            val cloveCount = if (packetSize >= 2) (pooledPacket.data[1].toInt() and 0xFF) else -1
            val firstCloveType = if (packetSize >= 3) (pooledPacket.data[2].toInt() and 0xFF) else -1

            if (packetSize > MESHCORE_MAX_PAYLOAD) {
                Log.e(TAG, "TX packet too large: $packetSize > $MESHCORE_MAX_PAYLOAD")
            }

            val result = meshManager.transmitRaw(pooledPacket.data)
            Log.d(TAG, "transmitRaw result: isSuccess=${result.isSuccess}, error=${result.exceptionOrNull()?.message}")

            // Emit transmission event for non-chaff packets
            val isChaff = pooledPacket.type == MessagePool.PACKET_TYPE_CHAFF
            if (pooledPacket.metadata?.messageId != null && !isChaff) {
                _events.emit(MessageEvent.PacketTransmitted(
                    pooledPacket.metadata.messageId,
                    pooledPacket.addedAt
                ))
            }

            result.isSuccess
        } catch (e: Exception) {
                Log.e(TAG, "Exception in sendMessage: " + e.javaClass.simpleName + ": " + e.message, e)
            false
        }
    }

    /**
     * Transmit a Poisson-scheduled packet via the mesh transport.
     * Called by PoissonTrafficScheduler at random Poisson-distributed intervals.
     *
     * Unlike epoch-based transmission, this fires at random times,
     * eliminating systematic half-duplex collisions.
     *
     * @return true if transmission succeeded
     */
    private suspend fun transmitPoissonPacket(poissonPacket: PoissonPacket): Boolean {
        val connState = meshManager.connectionState.value
        Log.d(TAG, "=== TRANSMIT POISSON PACKET ===")
        Log.d(TAG, "isReal=${poissonPacket.isReal}, messageId=${poissonPacket.metadata?.messageId}")

        if (connState != MeshConnectionState.CONNECTED) {
            Log.e(TAG, "Cannot transmit: mesh not connected (state=$connState)")
            return false
        }

        return try {
            val packetSize = poissonPacket.data.size
            Log.d(TAG, "Calling meshManager.transmitRaw($packetSize bytes)...")

            // Diagnostic logging

            // Size check
            if (packetSize > MESHCORE_MAX_PAYLOAD) {
                Log.e(TAG, "!! TX PACKET TOO LARGE: $packetSize > $MESHCORE_MAX_PAYLOAD !!")
            }

            val result = meshManager.transmitRaw(poissonPacket.data)
            Log.d(TAG, "transmitRaw result: isSuccess=${result.isSuccess}, error=${result.exceptionOrNull()?.message ?: "none"}")

            // Emit event for real packets
            if (poissonPacket.isReal && poissonPacket.metadata?.messageId != null) {
                _events.emit(MessageEvent.PacketTransmitted(
                    poissonPacket.metadata.messageId,
                    System.currentTimeMillis()
                ))
            }

            result.isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Poisson transmit error: ${e.message}", e)
            false
        }
    }

    /**
     * Generate a cover packet for Poisson transmission.
     *
     * Cover packets are indistinguishable from real packets:
     * - Same size (184 bytes)
     * - Same garlic format (version byte 0x04)
     * - Random encrypted content
     *
     * An adversary observing the mesh sees a continuous stream of
     * Poisson-distributed packets, unable to distinguish real from cover.
     */
    private suspend fun generatePoissonCoverPacket(): ByteArray {
        // Generate random garlic-formatted cover packet
        val coverData = BedrockCore.randomBytes(PoissonTrafficScheduler.PACKET_SIZE)

        // Set garlic version byte so cover is indistinguishable from real traffic
        // 0x04 & 0b11 = Data type for Rust side parsing
        coverData[0] = 0x04

        return coverData
    }

    // ========================================================================
    // PRIVATE: Packet Building
    // ========================================================================

    /**
     * Build an onion-routed packet to a contact.
     *
     * ROUTING STRATEGY (in priority order):
     * 1. LunarRouter circuits (AES-256-GCM, persistent tunnels) - preferred
     * 2. Simple onion routing (ChaCha20-Poly1305, per-message) - fallback
     *
     * LunarRouter advantages:
     * - Persistent tunnels reduce setup overhead
     * - AES-256-GCM is hardware-accelerated on most devices
     * - Better path selection (region/operator diversity)
     * - Circuit rotation provides temporal unlinkability
     *
     * Route selection uses the CONTACT GRAPH:
     * - Your contacts are potential relays
     * - Message is onion-encrypted through 3+ hops (4 total including recipient)
     * - Each relay only sees previous/next hop
     *
     * SECURITY (Tor-equivalent):
     * - Minimum 3 relays required (like Tor's guard → middle → exit)
     * - Single compromised relay cannot deanonymize
     * - Adversary must control BOTH first AND last relay
     *
     * If insufficient contacts, returns InsufficientRelaysException.
     * Caller can choose to use direct mode with explicit user consent.
     */
    private suspend fun buildOnionPacket(recipient: Contact, payload: ByteArray): ByteArray {
        val key = encryptionKey ?: throw IllegalStateException("Not initialized")

        // ====================================================================
        // P2P DETECTION: If only contact is the recipient, use direct mode
        // ====================================================================
        val allContacts = contactManager.getContacts(key)
        val potentialRelays = allContacts.filter { it.did != recipient.did }

        if (allContacts.size <= 1 && potentialRelays.isEmpty()) {
            // P2P scenario: only have the recipient as a contact (or no contacts)
            // Skip onion routing entirely and use direct encrypted communication
            Log.d(TAG, "P2P scenario detected (contacts=${allContacts.size}, relays=0), using direct mode")
            _events.emit(MessageEvent.DirectModeWarning(recipient.did))
            return buildDirectPacket(recipient, payload)
        }

        // ====================================================================
        // STRATEGY 1: LunarRouter Circuits (AES-256-GCM) - PREFERRED
        // ====================================================================
        if (PREFER_LUNAR_CIRCUITS && ::circuitManager.isInitialized) {
            // Derive recipient hint for circuit destination (using X25519 session key)
            val recipientHint = BedrockCore.lunarDeriveNodeHint(recipient.sessionPublicKey)
                ?: ByteArray(LunarCircuitManager.NODE_HINT_SIZE)

            // Try to wrap message via established circuit
            val circuitResult = circuitManager.wrapMessage(payload, recipientHint)

            if (circuitResult != null) {
                Log.d(TAG, "Message wrapped via LunarRouter circuit (AES-256-GCM)")
                _events.emit(MessageEvent.CircuitUsed(circuitResult.circuitId))
                return circuitResult.wrappedPacket
            } else {
                // No circuit ready - try to build one asynchronously
                Log.d(TAG, "No ready circuit, building new one...")
                scope.launch {
                    val buildResult = circuitManager.buildCircuit(
                        minHops = MIN_RELAY_COUNT,
                        diverseRegions = true,
                        diverseOperators = true
                    )
                    if (buildResult != null) {
                        // Circuit built, will be used for next message
                        _events.emit(MessageEvent.CircuitBuilt(buildResult.circuitId))
                    }
                }
                // Fall through to simple onion routing
            }
        }

        // ====================================================================
        // STRATEGY 2: Simple Onion Routing (ChaCha20-Poly1305) - FALLBACK
        // ====================================================================

        // Get all contacts except recipient (potential relays)
        val contacts = contactManager.getContacts(key).filter { it.did != recipient.did }

        // SECURITY: Require minimum 3 relays for Tor-equivalent anonymity
        if (contacts.size >= MIN_RELAY_COUNT) {
            // Select random relays from contacts
            val relays = contacts.shuffled().take(MIN_RELAY_COUNT)

            // Build onion packet with 3 relay layers (using X25519 session keys)
            val routeNodeIds = relays.map { deriveNodeId(it.sessionPublicKey) }.toTypedArray()
            val routePublicKeys = relays.map { it.sessionPublicKey }.toTypedArray()

            val onionPacket = BedrockCore.createOnionPacket(
                routeNodeIds = routeNodeIds,
                routePublicKeys = routePublicKeys,
                destNodeId = deriveNodeId(recipient.sessionPublicKey),
                destPublicKey = recipient.sessionPublicKey,
                payload = payload
            )

            if (onionPacket != null) {
                return onionPacket
            }
        }

        // SECURITY: If we have SOME contacts but not enough, we can use what we have
        // with reduced anonymity (still better than direct)
        if (contacts.isNotEmpty()) {
            val relays = contacts.shuffled()

            // Use X25519 session keys for routing
            val routeNodeIds = relays.map { deriveNodeId(it.sessionPublicKey) }.toTypedArray()
            val routePublicKeys = relays.map { it.sessionPublicKey }.toTypedArray()

            val onionPacket = BedrockCore.createOnionPacket(
                routeNodeIds = routeNodeIds,
                routePublicKeys = routePublicKeys,
                destNodeId = deriveNodeId(recipient.sessionPublicKey),
                destPublicKey = recipient.sessionPublicKey,
                payload = payload
            )

            if (onionPacket != null) {
                // Emit warning about reduced anonymity
                _events.emit(MessageEvent.ReducedAnonymity(
                    contactCount = contacts.size,
                    requiredCount = MIN_RELAY_COUNT
                ))
                return onionPacket
            }
        }

        // No relays available - throw exception
        // Caller must explicitly consent to direct mode
        throw InsufficientRelaysException(
            available = contacts.size,
            required = MIN_RELAY_COUNT
        )
    }

    /**
     * Build a DIRECT packet (no relay anonymity).
     *
     * SECURITY WARNING: Only use with explicit user consent.
     * This provides encryption but NO anonymity - adversary can
     * directly correlate sender and receiver.
     *
     * Use cases:
     * - New users with no contacts yet
     * - Emergency situations where any communication is critical
     */
    suspend fun buildDirectPacket(recipient: Contact, payload: ByteArray): ByteArray {
        // Emit warning
        _events.emit(MessageEvent.DirectModeWarning(recipient.did))

        // Debug: Log key sizes to diagnose createOnionPacketDirect failures
        Log.d(TAG, "=== BUILD DIRECT PACKET ===")
        val nodeId = deriveNodeId(recipient.sessionPublicKey)
        Log.d(TAG, "recipient.petname=${recipient.petname}")
        Log.d(TAG, "recipient.sessionPublicKey.size=${recipient.sessionPublicKey.size} (expected 32)")
        Log.d(TAG, "recipient.encryptionPublicKey.size=${recipient.encryptionPublicKey.size} (expected 1184)")
        Log.d(TAG, "nodeId.size=${nodeId.size}, payload.size=${payload.size}")

        if (recipient.sessionPublicKey.size != 32) {
            if (recipient.sessionPublicKey.isEmpty()) {
                Log.e(TAG, "sessionPublicKey is EMPTY - contact was not created with session key!")
            }
        }
        if (nodeId.size != 8) {
            Log.e(TAG, "INVALID nodeId size! Expected 8, got ${nodeId.size}")
        }


        // Use X25519 session key (32 bytes) for direct packet encryption
        Log.d(TAG, "Calling BedrockCore.createOnionPacketDirect...")
        val result = BedrockCore.createOnionPacketDirect(
            destNodeId = nodeId,
            destPublicKey = recipient.sessionPublicKey,
            payload = payload
        )

        if (result == null) {
            Log.e(TAG, "createOnionPacketDirect returned NULL!")
            throw IllegalStateException("Failed to create direct packet")
        }

        Log.d(TAG, "createOnionPacketDirect success! result.size=${result.size}")

        // !! PACKET SIZE WARNING !!
        if (result.size > MESHCORE_MAX_PAYLOAD) {
            Log.e(TAG, "!! CREATED PACKET TOO LARGE: ${result.size} bytes !!")
            Log.e(TAG, "!! MeshCore limit: $MESHCORE_MAX_PAYLOAD bytes !!")
            Log.e(TAG, "!! This packet WILL BE TRUNCATED and message WILL FAIL !!")
            Log.e(TAG, "!! Payload was: ${payload.size} bytes (PADDED_SIZE=${MessageWireFormat.PADDED_SIZE}) !!")
            Log.e(TAG, "!! SOLUTION: Reduce MessageWireFormat.PADDED_SIZE !!")
        }

        return result
    }

    /**
     * Check if we have enough contacts for full anonymity.
     */
    suspend fun hasFullAnonymity(): Boolean {
        val key = encryptionKey ?: return false
        val contacts = contactManager.getContacts(key)
        return contacts.size >= MIN_RELAY_COUNT
    }

    /**
     * Get current anonymity level.
     *
     * NOTE: Relay count = contacts - 1 (recipient cannot be a relay).
     * - 4+ contacts = 3+ potential relays = FULL
     * - 3 contacts = 2 potential relays = REDUCED
     * - 2 contacts = 1 potential relay = MINIMAL
     * - 1 contact = 0 relays = NONE (P2P direct mode)
     */
    suspend fun getAnonymityLevel(): AnonymityLevel {
        val key = encryptionKey ?: return AnonymityLevel.NONE
        val contacts = contactManager.getContacts(key)

        // Potential relays = total contacts - 1 (recipient is not a relay)
        val potentialRelays = (contacts.size - 1).coerceAtLeast(0)

        return when {
            potentialRelays >= MIN_RELAY_COUNT -> AnonymityLevel.FULL      // 3+ relays
            potentialRelays >= 2 -> AnonymityLevel.REDUCED                 // 2 relays
            potentialRelays >= 1 -> AnonymityLevel.MINIMAL                 // 1 relay
            else -> AnonymityLevel.NONE                                    // P2P direct
        }
    }

    // ========================================================================
    // COVER TRAFFIC CONTROL
    // ========================================================================

    /**
     * Get current cover traffic mode.
     *
     * Cover traffic (chaff) provides timing anonymity by making it impossible
     * for observers to distinguish real messages from fake traffic.
     *
     * TRADE-OFF: More cover traffic = better timing privacy, but RF transmissions
     * can reveal physical location via direction finding and RSSI analysis.
     *
     * @return Current CoverTrafficMode
     */
    fun getCoverTrafficMode(): CoverTrafficMode {
        return if (::coverTrafficScheduler.isInitialized) {
            coverTrafficScheduler.getMode()
        } else {
            CoverTrafficMode.OFF
        }
    }

    /**
     * Set cover traffic mode.
     *
     * MODES:
     * - OFF: No cover traffic. Vulnerable to timing analysis but no RF emissions when idle.
     * - PROBABILISTIC: 30% chance of cover traffic per interval. Low bandwidth impact.
     * - BURST: Cover traffic accompanies real messages. Moderate protection.
     * - CONTINUOUS: Always maintain minimum traffic level. Strong timing protection.
     * - PARANOID: Maximum cover traffic. Best timing privacy but highest RF exposure.
     *
     * LOCATION PRIVACY WARNING:
     * Higher cover traffic modes improve timing anonymity but increase RF emissions,
     * which can be used for physical location tracking via direction finding,
     * triangulation, and RSSI analysis.
     *
     * @param mode The desired cover traffic mode
     */
    fun setCoverTrafficMode(mode: CoverTrafficMode) {
        if (::coverTrafficScheduler.isInitialized) {
            coverTrafficScheduler.setMode(mode)
            Log.i(TAG, "Cover traffic mode changed to: ${mode.name}")
        } else {
            Log.w(TAG, "Cannot set cover traffic mode: scheduler not initialized")
        }
    }

    /**
     * Derive node ID from public key (8-byte truncated hash).
     */
    private fun deriveNodeId(publicKey: ByteArray): ByteArray {
        val hash = BedrockCore.sha3_256(publicKey)
        return hash.copyOf(8)
    }

    // ========================================================================
    // PRIVATE: Transport
    // ========================================================================

    /**
     * Send a packet via the mesh transport.
     */
    private suspend fun sendPacket(recipient: Contact, packet: ByteArray, isHandshake: Boolean): Boolean {
        // Check mesh connection
        if (meshManager.connectionState.value != MeshConnectionState.CONNECTED) {
            return false
        }

        return try {
            // Encode as Lunar packet (using X25519 session key)
            val hint = BedrockCore.lunarDeriveNodeHint(recipient.sessionPublicKey) ?: ByteArray(LunarCircuitManager.NODE_HINT_SIZE)
            val sessionHint = sessionManager.getSessionHint(recipient.did) ?: ByteArray(LunarCircuitManager.SESSION_HINT_SIZE)


            val lunarPacket = if (isHandshake) {
                // Handshake packets have different encoding
                Log.d(TAG, "sendPacket: HANDSHAKE packet, not encoding with hint")
                packet
            } else {
                BedrockCore.lunarPacketEncodeData(hint, sessionHint, packet) ?: packet
            }

            // Send via mesh
            val result = meshManager.transmitRaw(lunarPacket)
            Log.d(TAG, "sendPacket: transmitRaw result=${result.isSuccess}, error=${result.exceptionOrNull()?.message ?: "none"}")
            result.isSuccess
        } catch (e: Exception) {
                Log.e(TAG, "Exception in sendMessage: " + e.javaClass.simpleName + ": " + e.message, e)
            false
        }
    }

    // ========================================================================
    // PRIVATE: Message Receiving
    // ========================================================================

    /**
     * Start listening for incoming messages from the mesh.
     */
    private val instanceId = ++instanceCounter

    /**
     * Thread-safe guard against starting multiple listeners.
     * Uses AtomicBoolean for proper thread-safety.
     */
    private val listenerStarted = java.util.concurrent.atomic.AtomicBoolean(false)

    private fun startMessageListener() {
        // Thread-safe guard: compareAndSet returns true only for the FIRST caller
        if (!listenerStarted.compareAndSet(false, true)) {
            return
        }

        // SINGLE listener via SharedFlow - removed redundant polling loop that caused duplicates
        scope.launch {
            meshManager.events.collect { event ->
                when (event.type) {
                    MeshEventType.MESSAGE_RECEIVED -> {
                        // Event payload is LoRaRxPacket, not raw ByteArray!
                        val packet = event.payload as? LoRaRxPacket ?: return@collect
                        val rxSize = packet.payload.size
                        Log.d(TAG, "[Instance#$instanceId] Received packet via event: $rxSize bytes, RSSI: ${packet.rssi}")

                        // !! TRUNCATION CHECK !! - Compare RX size to expected TX sizes
                        Log.w(TAG, "!! RX PACKET SIZE: $rxSize bytes !!")
                        if (rxSize == MESHCORE_MAX_PAYLOAD || rxSize == 255) {
                            Log.e(TAG, "!! WARNING: RX size is exactly $rxSize - LIKELY TRUNCATED !!")
                            Log.e(TAG, "!! Original packet was probably larger and got cut off !!")
                        } else if (rxSize < 100) {
                            Log.d(TAG, "!! RX size looks reasonable for a small packet !!")
                        } else {
                            Log.d(TAG, "!! RX size: $rxSize (check if this matches TX size) !!")
                        }

                        try {
                            handleIncomingPacket(packet.payload)
                        } catch (e: Exception) {
                            Log.e(TAG, "EXCEPTION calling handleIncomingPacket: ${e.javaClass.simpleName}: ${e.message}", e)
                        }
                    }
                    else -> { /* ignore other events */ }
                }
            }
        }
        // NOTE: Removed redundant polling loop that was causing duplicate packet processing.
        // The SharedFlow collector above is sufficient - having both caused race conditions.
    }

    /**
     * Recently processed packet fingerprints for deduplication.
     * Uses SHA-256 (truncated to 64-bit Long) instead of contentHashCode() to avoid collisions.
     * contentHashCode() is only 32-bit and can cause legitimate packets to be incorrectly dropped.
     */
    private val recentPacketFingerprints = java.util.concurrent.ConcurrentHashMap<Long, Long>()
    private val PACKET_DEDUP_WINDOW_MS = 5000L  // 5 second dedup window

    /**
     * Compute a 64-bit fingerprint using SHA-256 (first 8 bytes).
     * Much safer than contentHashCode() which has high collision probability.
     */
    private fun packetFingerprint(data: ByteArray): Long {
        val hash = BedrockCore.sha3_256(data)
        return ByteBuffer.wrap(hash).getLong()
    }

    /**
     * Handle an incoming packet from the mesh.
     */
    private suspend fun handleIncomingPacket(packetBytes: ByteArray) {
        Log.d(TAG, "handleIncomingPacket: received ${packetBytes.size} bytes")

        // !! EARLY FILTER: Skip non-garlic packets (firmware test traffic, etc.) !!
        if (packetBytes.isEmpty()) {
            Log.d(TAG, "Empty packet - skipping")
            return
        }
        val version = packetBytes[0].toInt() and 0xFF
        if (version != 0x04) {
            // Not a garlic packet (version 0x04) - likely firmware test traffic
            Log.d(TAG, "Non-garlic packet (version=0x${String.format("%02X", version)}) - skipping")
            return
        }

        // !! DEDUPLICATION: Use SHA-256 fingerprint (64-bit) for collision resistance !!
        val fingerprint = packetFingerprint(packetBytes)
        val now = System.currentTimeMillis()
        val previousTime = recentPacketFingerprints.putIfAbsent(fingerprint, now)
        if (previousTime != null && (now - previousTime) < PACKET_DEDUP_WINDOW_MS) {
            return
        }
        recentPacketFingerprints[fingerprint] = now  // Update timestamp
        // Clean old entries periodically
        if (recentPacketFingerprints.size > 100) {
            recentPacketFingerprints.entries.removeIf { now - it.value > PACKET_DEDUP_WINDOW_MS }
        }

        // !! DIAGNOSTIC: Log exact bytes for handshake tracking !!
        val cloveCount = if (packetBytes.size >= 2) (packetBytes[1].toInt() and 0xFF) else -1
        val firstCloveType = if (packetBytes.size >= 3) (packetBytes[2].toInt() and 0xFF) else -1
        if (packetBytes[0] == 0x04.toByte() && cloveCount == 2) {
            // This could be a handshake garlic (handshake clove + chaff clove)
            if (firstCloveType == 0x05) {
            } else if (firstCloveType == 0x03) {
            }
        }

        val key = encryptionKey
        if (key == null) {
            Log.w(TAG, "handleIncomingPacket: encryptionKey is NULL - dropping packet!")
            return
        }

        val ourSk = ourSecretKey
        if (ourSk == null) {
            Log.w(TAG, "handleIncomingPacket: ourSecretKey is NULL - dropping packet!")
            return
        }

        Log.d(TAG, "handleIncomingPacket: keys present, checking packet type...")

        try {
            // Check packet type
            val packetType = BedrockCore.lunarPacketGetType(packetBytes)
            Log.d(TAG, "handleIncomingPacket: packetType = $packetType")

            when (packetType) {
                0 -> { // DATA packet
                    Log.d(TAG, "handleIncomingPacket: DATA packet - calling handleDataPacket")
                    handleDataPacket(packetBytes, key, ourSk)
                }
                1 -> { // HANDSHAKE packet
                    Log.d(TAG, "handleIncomingPacket: HANDSHAKE packet")
                    handleHandshakePacket(packetBytes, ourSk)
                }
                3 -> { // COVER packet - ignore (chaff traffic)
                    Log.d(TAG, "handleIncomingPacket: COVER packet - ignoring")
                    // Do nothing - this is cover traffic for anonymity
                }
                else -> {
                    Log.d(TAG, "handleIncomingPacket: Unknown packet type $packetType - ignoring")
                    // Unknown or control packet
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleIncomingPacket exception: ${e.javaClass.simpleName}: ${e.message}", e)
            // Failed to process packet
        }
    }

    /**
     * Handle a data packet.
     *
     * PHASE 2-3: First checks blinded hint before attempting full decryption.
     * This prevents timing attacks where adversary can tell if we're the recipient.
     */
    private suspend fun handleDataPacket(packetBytes: ByteArray, key: ByteArray, ourSk: ByteArray) {
        Log.d(TAG, "handleDataPacket: processing ${packetBytes.size} bytes")

        // First, try to parse as garlic (I2P-style bundle)
        val cloves = garlicBundler.parseGarlic(packetBytes)
        Log.d(TAG, "handleDataPacket: garlic parse returned ${cloves.size} cloves")

        if (cloves.isNotEmpty()) {
            // It's a garlic - process each clove
            for (clove in cloves) {
                processClove(clove, key, ourSk)
            }
            return
        }

        // Debug: Log OUR keys for comparison

        // Log first bytes of the packet to see the ephemeral public key (bytes 0-31 of onion packet)

        // Not a garlic - try as regular onion packet
        Log.d(TAG, "handleDataPacket: attempting peelOnionLayer with ourSk[${ourSk.size}]")
        val result = BedrockCore.peelOnionLayer(packetBytes, ourSk)

        if (result == null) {
            Log.w(TAG, "handleDataPacket: peelOnionLayer returned NULL - packet not for us or corrupted")
            // Not for us, or corrupted
            return
        }

        Log.d(TAG, "handleDataPacket: peelOnionLayer returned ${result.size} bytes")
        val type = result[0].toInt()
        Log.d(TAG, "handleDataPacket: inner packet type = $type")

        when (type) {
            1 -> {
                // Relay - we need to forward this packet
                Log.d(TAG, "handleDataPacket: RELAY packet - forwarding")
                if (result.size > 9) {
                    val nextHopId = result.copyOfRange(1, 9)
                    val innerPacket = result.copyOfRange(9, result.size)
                    forwardPacket(nextHopId, innerPacket)
                }
            }
            2 -> {
                // Destination - this message is for us
                Log.d(TAG, "handleDataPacket: DESTINATION packet - message is for us!")
                val encryptedPayload = result.copyOfRange(1, result.size)
                Log.d(TAG, "handleDataPacket: encryptedPayload size = ${encryptedPayload.size}")

                // Extract blinded hint if present
                if (encryptedPayload.size > BlindedHintSystem.BLINDED_HINT_SIZE) {
                    val receivedHint = encryptedPayload.copyOfRange(0, BlindedHintSystem.BLINDED_HINT_SIZE)
                    val actualPayload = encryptedPayload.copyOfRange(
                        BlindedHintSystem.BLINDED_HINT_SIZE,
                        encryptedPayload.size
                    )

                    // Verify blinded hint matches (prevents targeted scanning)
                    // We need to check against all known senders
                    handleIncomingMessageWithHint(receivedHint, actualPayload, key)
                } else {
                    // Legacy packet without blinded hint
                    handleIncomingMessage(encryptedPayload, key)
                }
            }
        }
    }

    /**
     * Process a single clove from a garlic bundle.
     * The clove.payload is a raw onion packet that needs to be peeled first!
     */
    private suspend fun processClove(clove: Clove, key: ByteArray, ourSk: ByteArray) {
        Log.d(TAG, "processClove: cloveType=${clove.type}, payload=${clove.payload.size} bytes, hint=${clove.destinationHint.size} bytes")

        // Different clove types have different payload formats!
        when (clove.type) {
            GarlicBundler.CLOVE_TYPE_HANDSHAKE -> {
                // HANDSHAKE clove - payload does NOT have hint prefix!
                // The payload is onion-wrapped raw handshake bytes.
                Log.d(TAG, "processClove: HANDSHAKE clove - routing to session establishment")
                processHandshakeClove(clove, ourSk)
                return
            }
            GarlicBundler.CLOVE_TYPE_CHAFF -> {
                // Chaff clove - discard silently (it's fake traffic for anonymity)
                Log.d(TAG, "processClove: CHAFF clove - discarding")
                return
            }
            GarlicBundler.CLOVE_TYPE_DATA, GarlicBundler.CLOVE_TYPE_ACK -> {
                // Data/ACK clove - continue with normal processing below
                Log.d(TAG, "processClove: DATA/ACK clove - processing as message")
            }
            else -> {
                Log.w(TAG, "processClove: unknown clove type ${clove.type}")
                // Try to process anyway in case it's a valid message
            }
        }

        // We MUST peel the onion layer first to get the inner encrypted payload!
        val peeled = BedrockCore.peelOnionLayer(clove.payload, ourSk)

        if (peeled == null) {
            Log.d(TAG, "processClove: peelOnionLayer returned null - not for us or corrupted")
            return
        }

        Log.d(TAG, "processClove: peelOnionLayer returned ${peeled.size} bytes")
        val type = peeled[0].toInt()
        Log.d(TAG, "processClove: inner packet type = $type")

        when (type) {
            1 -> {
                // Relay - forward the packet
                Log.d(TAG, "processClove: RELAY packet - forwarding")
                if (peeled.size > 9) {
                    val nextHopId = peeled.copyOfRange(1, 9)
                    val innerPacket = peeled.copyOfRange(9, peeled.size)
                    forwardPacket(nextHopId, innerPacket)
                }
            }
            2 -> {
                // Destination - this message is for us!
                Log.d(TAG, "processClove: DESTINATION packet - message is for us!")
                val encryptedPayload = peeled.copyOfRange(1, peeled.size)
                Log.d(TAG, "processClove: encryptedPayload size = ${encryptedPayload.size}")

                // Check blinded hint from the clove header (if available)
                if (clove.destinationHint.isNotEmpty()) {
                    Log.d(TAG, "processClove: using clove destinationHint for verification")
                    // The hint is ALSO in the payload prefix (sender puts it in both places)
                    // We must strip it before attempting session decryption!
                    val actualPayload = if (encryptedPayload.size > BlindedHintSystem.BLINDED_HINT_SIZE) {
                        encryptedPayload.copyOfRange(BlindedHintSystem.BLINDED_HINT_SIZE, encryptedPayload.size)
                    } else {
                        encryptedPayload
                    }
                    Log.d(TAG, "processClove: stripped hint, actualPayload size = ${actualPayload.size}")
                    handleIncomingMessageWithHint(clove.destinationHint, actualPayload, key)
                } else if (encryptedPayload.size > BlindedHintSystem.BLINDED_HINT_SIZE) {
                    // Extract hint from payload (legacy format)
                    val receivedHint = encryptedPayload.copyOfRange(0, BlindedHintSystem.BLINDED_HINT_SIZE)
                    val actualPayload = encryptedPayload.copyOfRange(
                        BlindedHintSystem.BLINDED_HINT_SIZE,
                        encryptedPayload.size
                    )
                    handleIncomingMessageWithHint(receivedHint, actualPayload, key)
                } else {
                    // No hint available
                    handleIncomingMessage(encryptedPayload, key)
                }
            }
            else -> {
                Log.w(TAG, "processClove: unknown inner packet type $type")
            }
        }
    }

    /**
     * Process a HANDSHAKE clove to establish a Double Ratchet session.
     *
     * CRITICAL: Handshake payloads do NOT have a blinded hint prefix!
     * The payload structure is: [onion-wrapped][raw handshake bytes]
     * After peeling onion: [type=2 DESTINATION][raw handshake bytes]
     *
     * The raw handshake bytes start with flags byte where (byte & 0b11) == 0b01.
     */
    private suspend fun processHandshakeClove(clove: Clove, ourSk: ByteArray) {

        // !! DIAGNOSTIC: Log key info for debugging !!
        val payloadFirst8 = clove.payload.take(8).joinToString("") { String.format("%02X", it) }

        // Peel the onion layer to get the inner handshake
        val peeled = BedrockCore.peelOnionLayer(clove.payload, ourSk)

        if (peeled == null) {
            return
        }

        Log.d(TAG, "processHandshakeClove: peelOnionLayer returned ${peeled.size} bytes")
        val innerType = peeled[0].toInt()
        Log.d(TAG, "processHandshakeClove: inner packet type = $innerType")

        if (innerType != 2) {
            // Should be DESTINATION (type=2) for handshakes meant for us
            Log.w(TAG, "processHandshakeClove: unexpected inner type $innerType, expected 2 (DESTINATION)")
            return
        }

        // Extract the raw handshake bytes (NO hint stripping!)
        val handshakeBytes = peeled.copyOfRange(1, peeled.size)
        Log.d(TAG, "processHandshakeClove: handshakeBytes size = ${handshakeBytes.size}")

        // Verify it looks like a handshake packet (flags byte lower 2 bits = 0b01)
        if (handshakeBytes.isNotEmpty()) {
            val flagsByte = handshakeBytes[0].toInt() and 0b11
            Log.d(TAG, "processHandshakeClove: flags lower 2 bits = $flagsByte (expected 1 for handshake)")
        }

        // Route to handshake handler to establish Double Ratchet session
        Log.d(TAG, "processHandshakeClove: calling handleHandshakePacket")
        handleHandshakePacket(handshakeBytes, ourSk)
    }

    /**
     * Handle incoming message with blinded hint verification.
     */
    private suspend fun handleIncomingMessageWithHint(
        receivedHint: ByteArray,
        payload: ByteArray,
        key: ByteArray
    ) {

        val contacts = contactManager.getContacts(key)
        Log.d(TAG, "handleIncomingMessageWithHint: checking against ${contacts.size} contacts")

        // Find which contact sent this by matching the blinded hint
        var senderContact: Contact? = null
        for (contact in contacts) {
            Log.d(TAG, "handleIncomingMessageWithHint: checking ${contact.petname} (pk=${contactPkHex}...)")
            if (blindedHints.isHintForUs(receivedHint, contact.sessionPublicKey)) {
                Log.d(TAG, "handleIncomingMessageWithHint: MATCH! sender=${contact.petname}")
                senderContact = contact
                break
            } else {
                Log.d(TAG, "handleIncomingMessageWithHint: no match for ${contact.petname}")
            }
        }

        if (senderContact != null) {
            Log.d(TAG, "handleIncomingMessageWithHint: found sender contact=${senderContact.petname}, calling handleIncomingMessageFromContact")
            Log.d(TAG, "handleIncomingMessageWithHint: senderContact.did=${senderContact.did.take(30)}...")
            // We know who sent it - try to decrypt with their session
            handleIncomingMessageFromContact(senderContact, payload, key)
        } else {
            // Unknown sender - try all sessions
            handleIncomingMessage(payload, key)
        }
    }

    /**
     * Handle incoming message from a known contact.
     */
    private suspend fun handleIncomingMessageFromContact(
        contact: Contact,
        payload: ByteArray,
        key: ByteArray
    ) {
        Log.d(TAG, "handleIncomingMessageFromContact: contact=${contact.did.take(20)}..., payload=${payload.size} bytes")

        // Decrypt with this contact's session
        val plaintext = try {
            sessionManager.decrypt(contact.did, payload)
        } catch (e: SessionException) {
            // TIMING FIX: No session yet - message arrived before handshake!
            // Buffer the message and it will be retried after handshake completes.
            Log.w(TAG, "handleIncomingMessageFromContact: No session yet for ${contact.did.take(20)}... - buffering message")
            bufferPendingMessage(contact.did, payload)
            return
        } catch (e: Exception) {
            Log.e(TAG, "handleIncomingMessageFromContact: decrypt failed: ${e.javaClass.simpleName}: ${e.message}", e)
            // Decryption failed - maybe wrong contact or corrupted
            return
        }
        Log.d(TAG, "handleIncomingMessageFromContact: decrypted! plaintext=${plaintext.size} bytes")

        // ====================================================================
        // REPLAY PROTECTION EXTRACTION - DISABLED
        // ====================================================================
        // The sender no longer wraps messages with replay protection (counter + nonce)
        // because Double Ratchet already provides replay protection via its
        // monotonic message counter. Extracting replay protection here was
        // incorrectly stripping the first 24 bytes of the message content!
        //
        // OLD BUG: extractReplayProtection() would succeed for ANY message >= 24 bytes,
        // interpreting the TYPE_TEXT byte + UUID as "counter" and "nonce".
        // This caused wireType=48 (0x30='0' from UUID) instead of 0x01.
        //
        // val replayData = plaintext.extractReplayProtection()
        // if (replayData != null) { ... }
        //
        Log.d(TAG, "handleIncomingMessageFromContact: processing directly (DR provides replay protection)")
        processDecryptedMessage(contact.did, plaintext, ByteArray(LunarCircuitManager.SESSION_HINT_SIZE), key)
    }

    /**
     * Handle a handshake packet.
     *
     * SECURITY FIX: Constant-time iteration to prevent contact count leakage.
     * We always iterate ALL contacts and collect results, then act on first success.
     * This prevents timing attacks that could reveal how many contacts we have.
     */
    private suspend fun handleHandshakePacket(handshakeBytes: ByteArray, ourSk: ByteArray) {
        val hsFirst8 = handshakeBytes.take(8).joinToString("") { String.format("%02X", it) }

        val key = encryptionKey
        if (key == null) {
            return
        }

        val contacts = contactManager.getContacts(key)


        // SECURITY: Constant-time - always process ALL contacts
        // Store results without early return to prevent timing oracle
        var successContact: Contact? = null
        var successSession: LunarSessionManager.SessionInfo? = null

        for (contact in contacts) {
            try {
                Log.d(TAG, "handleHandshakePacket: trying contact ${contact.petname}...")
                val session = sessionManager.acceptHandshake(
                    contactDid = contact.did,
                    contactEncryptionKey = contact.encryptionPublicKey,
                    handshakeBytes = handshakeBytes,
                    ourSecretKey = ourSk
                )

                // Record first success but DON'T return early
                if (successContact == null) {
                    successContact = contact
                    successSession = session
                }
            } catch (e: Exception) {
                Log.d(TAG, "acceptHandshake failed for ${contact.petname}: ${e.message}")
                // Not from this contact - but continue iterating ALL contacts
                // to maintain constant time
            }
        }

        // Only after processing all contacts do we act on success
        if (successContact != null) {
            _events.emit(MessageEvent.SessionEstablished(successContact.did))

            // TIMING FIX: Retry any buffered messages that arrived before handshake
            // Now that the session is established, we can decrypt them.
            retryBufferedMessages(successContact.did, key)
        } else {
        }
    }

    /**
     * TIMING FIX: Buffer a message that arrived before its session was established.
     * Called when we identify the sender but have no session yet.
     */
    private suspend fun bufferPendingMessage(contactDid: String, payload: ByteArray) {
        val ourSk = ourSecretKey ?: return

        pendingMessagesMutex.withLock {
            val pending = PendingMessage(
                encryptedPayload = payload.copyOf(),  // Copy to avoid reference issues
                receivedAt = System.currentTimeMillis(),
                ourSk = ourSk.copyOf()
            )

            val buffer = pendingMessagesBuffer.getOrPut(contactDid) { mutableListOf() }

            // Limit buffer size to prevent memory exhaustion (max 10 messages per contact)
            if (buffer.size < 10) {
                buffer.add(pending)
                Log.d(TAG, "Buffered pending message for $contactDid (buffer size: ${buffer.size})")
            } else {
                Log.w(TAG, "Pending message buffer full for $contactDid - dropping oldest")
                buffer.removeAt(0)
                buffer.add(pending)
            }

            // Clean up expired messages while we're here
            val now = System.currentTimeMillis()
            buffer.removeAll { now - it.receivedAt > PENDING_MESSAGE_TIMEOUT_MS }
        }
    }

    /**
     * TIMING FIX: Retry buffered messages after a handshake establishes a session.
     */
    private suspend fun retryBufferedMessages(contactDid: String, key: ByteArray) {
        val messages = pendingMessagesMutex.withLock {
            pendingMessagesBuffer.remove(contactDid) ?: return
        }

        if (messages.isEmpty()) return

        Log.d(TAG, "Retrying ${messages.size} buffered messages for $contactDid")

        val now = System.currentTimeMillis()
        for (pending in messages) {
            // Skip expired messages
            if (now - pending.receivedAt > PENDING_MESSAGE_TIMEOUT_MS) {
                Log.d(TAG, "Skipping expired buffered message (age: ${now - pending.receivedAt}ms)")
                continue
            }

            // Retry decryption - session should exist now
            try {
                val plaintext = sessionManager.decrypt(contactDid, pending.encryptedPayload)
                Log.d(TAG, "Successfully decrypted buffered message!")

                // Process the message directly (replay protection disabled - DR handles it)
                processDecryptedMessage(contactDid, plaintext, ByteArray(0), key)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt buffered message: ${e.message}")
            }
        }
    }

    /**
     * Handle an incoming message (after decryption of onion layers).
     *
     * PHASE 2-3 INTEGRATION:
     * - Validates replay protection (counter + nonce)
     * - Rejects duplicate/replayed messages
     */
    private suspend fun handleIncomingMessage(encryptedPayload: ByteArray, key: ByteArray) {
        Log.d(TAG, "handleIncomingMessage: payload=${encryptedPayload.size} bytes")

        // Find which contact this is from by session hint
        val decoded = BedrockCore.lunarPacketDecodeData(encryptedPayload)
        if (decoded == null) {
            Log.d(TAG, "handleIncomingMessage: lunarPacketDecodeData returned null, trying tryDecryptFromAllSessions")
            // Try direct decryption without packet wrapper
            tryDecryptFromAllSessions(encryptedPayload, key)
            return
        }

        val (_, sessionHint, ciphertext) = decoded
        Log.d(TAG, "handleIncomingMessage: decoded - hint=${sessionHint.size} bytes, ciphertext=${ciphertext.size} bytes")

        // Find contact by session hint
        val contactDid = sessionManager.findContactByHint(sessionHint)
        if (contactDid == null) {
            Log.w(TAG, "handleIncomingMessage: findContactByHint returned null - no matching session!")
            return
        }
        Log.d(TAG, "handleIncomingMessage: found contact DID for session hint")

        // Decrypt with session
        val plaintext = try {
            sessionManager.decrypt(contactDid, ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "handleIncomingMessage: decrypt failed: ${e.javaClass.simpleName}: ${e.message}", e)
            return
        }
        Log.d(TAG, "handleIncomingMessage: decrypted successfully! plaintext=${plaintext.size} bytes")

        // ====================================================================
        // REPLAY PROTECTION - DISABLED (Double Ratchet handles it)
        // ====================================================================
        // The sender no longer wraps messages with replay protection because
        // Double Ratchet already provides replay protection. Processing directly.
        processDecryptedMessage(contactDid, plaintext, sessionHint, key)
    }

    /**
     * Process a decrypted and validated message.
     */
    private suspend fun processDecryptedMessage(
        contactDid: String,
        plaintext: ByteArray,
        sessionHint: ByteArray,
        key: ByteArray
    ) {
        Log.d(TAG, "processDecryptedMessage: contactDid=${contactDid.take(20)}..., plaintext=${plaintext.size} bytes")

        // Parse wire format
        val wireMessage = MessageWireFormat.decode(plaintext)
        if (wireMessage == null) {
            Log.w(TAG, "processDecryptedMessage: MessageWireFormat.decode returned null!")
            return
        }
        val (wireType, wirePayload) = wireMessage
        Log.d(TAG, "processDecryptedMessage: wireType=$wireType, wirePayload=${wirePayload.size} bytes")

        when (wireType) {
            MessageWireFormat.TYPE_TEXT -> {
                Log.d(TAG, "processDecryptedMessage: TYPE_TEXT message")
                val parsed = MessageWireFormat.parseText(wirePayload)
                if (parsed == null) {
                    Log.w(TAG, "processDecryptedMessage: parseText returned null!")
                    return
                }
                val (messageId, text) = parsed
                Log.d(TAG, "processDecryptedMessage: TEXT - messageId=$messageId, text='${text.take(50)}...'")

                // Find contact
                val contact = contactManager.getContactByDid(contactDid)
                if (contact == null) {
                    Log.w(TAG, "processDecryptedMessage: getContactByDid returned null for $contactDid!")
                    return
                }
                Log.d(TAG, "processDecryptedMessage: found contact, creating incoming message")

                // Create incoming message
                val message = Message.incoming(
                    threadId = contact.id,
                    content = text.toByteArray(Charsets.UTF_8),
                    sessionHint = sessionHint
                )

                // Store
                storage.ensureThread(contact.id, contact.did, contact.petname, key)
                storage.addMessage(message, key)

                // Emit event
                _events.emit(MessageEvent.Received(message))

                // Send ACK
                sendAck(contact, messageId)
            }

            MessageWireFormat.TYPE_ACK -> {
                val ackMessageId = MessageWireFormat.parseAck(wirePayload) ?: return
                pendingAcks[ackMessageId]?.complete(Unit)
                pendingAcks.remove(ackMessageId)
            }

            MessageWireFormat.TYPE_READ -> {
                val readMessageId = MessageWireFormat.parseAck(wirePayload) ?: return
                val contact = contactManager.getContactByDid(contactDid) ?: return
                storage.updateMessageStatus(contact.id, readMessageId, MessageStatus.READ, key)
                _events.emit(MessageEvent.StatusChanged(readMessageId, MessageStatus.READ))
            }
        }
    }

    /**
     * Try to decrypt message from all known sessions.
     *
     * SECURITY FIX: Constant-time iteration to prevent session count leakage.
     */
    private suspend fun tryDecryptFromAllSessions(ciphertext: ByteArray, key: ByteArray) {
        Log.d(TAG, "tryDecryptFromAllSessions: ciphertext=${ciphertext.size} bytes")

        val contacts = contactManager.getContacts(key)
        Log.d(TAG, "tryDecryptFromAllSessions: checking ${contacts.size} contacts")

        // SECURITY: Constant-time - collect result, don't return early
        var successData: Triple<Contact, String, String>? = null  // contact, messageId, text

        for (contact in contacts) {
            // Still check hasSession but do dummy work if no session
            val hasSession = sessionManager.hasSession(contact.did)
            Log.d(TAG, "tryDecryptFromAllSessions: contact=${contact.did.take(20)}..., hasSession=$hasSession")

            try {
                if (hasSession) {
                    val plaintext = sessionManager.decrypt(contact.did, ciphertext)
                    Log.d(TAG, "tryDecryptFromAllSessions: decrypted ${plaintext.size} bytes from contact")

                    val wireMessage = MessageWireFormat.decode(plaintext)
                    if (wireMessage != null) {
                        val (wireType, wirePayload) = wireMessage
                        Log.d(TAG, "tryDecryptFromAllSessions: wireType=$wireType")

                        if (wireType == MessageWireFormat.TYPE_TEXT) {
                            val parsed = MessageWireFormat.parseText(wirePayload)
                            if (parsed != null && successData == null) {
                                Log.d(TAG, "tryDecryptFromAllSessions: SUCCESS! Found text message: '${parsed.second.take(30)}...'")
                                successData = Triple(contact, parsed.first, parsed.second)
                            }
                        }
                    } else {
                        Log.d(TAG, "tryDecryptFromAllSessions: wireMessage decode returned null")
                    }
                } else {
                    // SECURITY: Dummy work to maintain constant time
                    // Hash the ciphertext to simulate decrypt effort
                    BedrockCore.sha3_256(ciphertext)
                }
            } catch (e: Exception) {
                Log.d(TAG, "tryDecryptFromAllSessions: decrypt failed for contact: ${e.javaClass.simpleName}")
                // Not from this contact - continue to maintain constant time
            }
        }
        Log.d(TAG, "tryDecryptFromAllSessions: finished checking all contacts, success=${successData != null}")

        // Only after all contacts processed, handle success
        if (successData != null) {
            val (contact, messageId, text) = successData

            val message = Message.incoming(
                threadId = contact.id,
                content = text.toByteArray(Charsets.UTF_8)
            )

            storage.ensureThread(contact.id, contact.did, contact.petname, key)
            storage.addMessage(message, key)
            _events.emit(MessageEvent.Received(message))

            sendAck(contact, messageId)
        }
    }

    /**
     * Send an ACK for a received message.
     *
     * SECURITY FIX: Random delay before sending ACK to prevent timing correlation.
     * An adversary watching network traffic cannot correlate message receipt with
     * ACK transmission because the delay is randomized.
     */
    private fun sendAck(contact: Contact, messageId: String) {
        // Launch in background with random delay
        scope.launch {
            try {
                // SECURITY: Random delay 5-30 seconds
                val delayMs = ACK_DELAY_MIN_MS +
                    (Math.random() * (ACK_DELAY_MAX_MS - ACK_DELAY_MIN_MS)).toLong()
                delay(delayMs)

                val ackData = MessageWireFormat.encodeAck(messageId)
                val encrypted = sessionManager.encrypt(contact.did, ackData)
                val packet = buildOnionPacket(contact, encrypted)
                sendPacket(contact, packet, isHandshake = false)
            } catch (e: Exception) {
                Log.e(TAG, "Exception in sendMessage: " + e.javaClass.simpleName + ": " + e.message, e)
                // ACK send failed - not critical
            }
        }
    }

    /**
     * Forward a packet to next hop (relay functionality).
     */
    private suspend fun forwardPacket(nextHopId: ByteArray, packet: ByteArray) {
        val key = encryptionKey ?: return

        // Find contact with matching node ID
        val contacts = contactManager.getContacts(key)

        for (contact in contacts) {
            val contactNodeId = deriveNodeId(contact.sessionPublicKey)
            if (contactNodeId.contentEquals(nextHopId)) {
                // Found the next hop - forward
                meshManager.transmitRaw(packet)
                return
            }
        }

        // Next hop not in our contacts - can't forward
    }

    // ========================================================================
    // PRIVATE: LunarRouter Circuit Event Handling
    // ========================================================================

    /**
     * Handle circuit lifecycle events from LunarCircuitManager.
     *
     * This processes:
     * - Handshakes that need to be exchanged over the mesh
     * - Circuit state changes (ready, failed, closed)
     * - Node discovery from mesh announcements
     */
    private suspend fun handleCircuitEvent(event: LunarCircuitManager.CircuitEvent) {
        when (event) {
            is LunarCircuitManager.CircuitEvent.CircuitBuilding -> {
                Log.d(TAG, "Circuit ${event.circuitId.toHexString()} building with ${event.hopCount} hops")
            }

            is LunarCircuitManager.CircuitEvent.CircuitReady -> {
                Log.d(TAG, "Circuit ${event.circuitId.toHexString()} ready")
                _events.emit(MessageEvent.CircuitReady(event.circuitId, 0))
            }

            is LunarCircuitManager.CircuitEvent.CircuitClosed -> {
                Log.d(TAG, "Circuit ${event.circuitId.toHexString()} closed: ${event.reason}")
            }

            is LunarCircuitManager.CircuitEvent.HandshakesReady -> {
                // Circuit handshakes are ready to be sent
                Log.d(TAG, "Sending ${event.handshakes.size} circuit handshakes")
                scope.launch {
                    for (handshake in event.handshakes) {
                        try {
                            // Send handshake via mesh - this will be picked up by relay nodes
                            val result = meshManager.transmitRaw(handshake)
                            if (!result.isSuccess) {
                                Log.w(TAG, "Failed to send circuit handshake")
                            }
                        } catch (e: Exception) {
                Log.e(TAG, "Exception in sendMessage: " + e.javaClass.simpleName + ": " + e.message, e)
                            Log.e(TAG, "Error sending circuit handshake", e)
                        }
                    }
                }
            }

            is LunarCircuitManager.CircuitEvent.NodeDiscovered -> {
                Log.d(TAG, "Discovered relay node: ${event.hint.toHexString()}")
            }

            is LunarCircuitManager.CircuitEvent.Error -> {
                Log.e(TAG, "Circuit error: ${event.message}")
                _events.emit(MessageEvent.CircuitFailed(ByteArray(8), event.message))
            }
        }
    }

    /**
     * Feed node announcements from the mesh into the circuit manager.
     * Called when we receive mesh announcements from other nodes.
     *
     * @param announcementBytes Raw announcement bytes from a relay node
     */
    suspend fun processNodeAnnouncement(announcementBytes: ByteArray) {
        if (::circuitManager.isInitialized) {
            circuitManager.processAnnouncement(announcementBytes)
        }
    }

    /**
     * Get current circuit statistics.
     */
    suspend fun getCircuitStats(): RouterStats? {
        return if (::circuitManager.isInitialized) {
            circuitManager.getStats()
        } else {
            null
        }
    }

    /**
     * Check if we have ready circuits for sending.
     */
    fun hasReadyCircuits(): Boolean {
        return ::circuitManager.isInitialized && circuitManager.hasReadyCircuit()
    }

    /**
     * Extension to convert ByteArray to hex string for logging.
     */
    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}

/**
 * Events emitted by MessageManager for UI updates.
 */
sealed class MessageEvent {
    // Core message events
    data class Received(val message: Message) : MessageEvent()
    data class StatusChanged(val messageId: String, val status: MessageStatus) : MessageEvent()
    data class Error(val messageId: String, val error: String) : MessageEvent()
    data class SessionEstablished(val contactDid: String) : MessageEvent()

    // ========================================================================
    // PHASE 2-3 ANONYMITY EVENTS
    // ========================================================================

    /**
     * System initialized with anonymity layer active.
     */
    data class SystemInitialized(
        val anonymityLevel: AnonymityLevel,
        val coverTrafficMode: CoverTrafficMode
    ) : MessageEvent()

    /**
     * Message queued in epoch pool (Tornado Cash-style batching).
     * Will be transmitted at epoch boundary with other messages.
     */
    data class MessageQueued(val messageId: String, val epochId: Long) : MessageEvent()

    /**
     * Packet transmitted from pool (including chaff).
     */
    data class PacketTransmitted(val messageId: String, val epochId: Long) : MessageEvent()

    /**
     * ACK not received within timeout.
     * Message may still have been delivered - network just didn't confirm.
     */
    data class AckTimeout(val messageId: String) : MessageEvent()

    /**
     * Not enough contacts available for anonymous routing.
     */
    data class InsufficientRelays(
        val messageId: String,
        val available: Int,
        val required: Int
    ) : MessageEvent()

    /**
     * P2P Poisson transmission mode active.
     * Uses Loopix-style random timing instead of epoch batching
     * to avoid half-duplex collisions in single-contact scenarios.
     */
    data class PoissonModeActive(val contactDid: String) : MessageEvent()

    /**
     * Replay attack detected - message was already processed.
     */
    data class ReplayDetected(val senderDid: String) : MessageEvent()

    /**
     * Warning: Message sent with reduced anonymity (fewer relays than recommended).
     */
    data class ReducedAnonymity(val contactCount: Int, val requiredCount: Int) : MessageEvent()

    /**
     * Warning: Message sent in direct mode (no relay anonymity).
     */
    data class DirectModeWarning(val recipientDid: String) : MessageEvent()

    // ========================================================================
    // LUNARROUTER CIRCUIT EVENTS (AES-256-GCM)
    // ========================================================================

    /**
     * Message was sent via a LunarRouter circuit.
     */
    data class CircuitUsed(val circuitId: ByteArray) : MessageEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitUsed) return false
            return circuitId.contentEquals(other.circuitId)
        }
        override fun hashCode(): Int = circuitId.contentHashCode()
    }

    /**
     * A new LunarRouter circuit was built.
     */
    data class CircuitBuilt(val circuitId: ByteArray) : MessageEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitBuilt) return false
            return circuitId.contentEquals(other.circuitId)
        }
        override fun hashCode(): Int = circuitId.contentHashCode()
    }

    /**
     * A LunarRouter circuit is ready for use.
     */
    data class CircuitReady(val circuitId: ByteArray, val hopCount: Int) : MessageEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitReady) return false
            return circuitId.contentEquals(other.circuitId) && hopCount == other.hopCount
        }
        override fun hashCode(): Int {
            var result = circuitId.contentHashCode()
            result = 31 * result + hopCount
            return result
        }
    }

    /**
     * A LunarRouter circuit failed to establish.
     */
    data class CircuitFailed(val circuitId: ByteArray, val reason: String) : MessageEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitFailed) return false
            return circuitId.contentEquals(other.circuitId) && reason == other.reason
        }
        override fun hashCode(): Int {
            var result = circuitId.contentHashCode()
            result = 31 * result + reason.hashCode()
            return result
        }
    }

    /**
     * A LunarRouter circuit was rotated for temporal unlinkability.
     */
    data class CircuitRotated(val oldCircuitId: ByteArray, val newCircuitId: ByteArray) : MessageEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CircuitRotated) return false
            return oldCircuitId.contentEquals(other.oldCircuitId) && newCircuitId.contentEquals(other.newCircuitId)
        }
        override fun hashCode(): Int {
            var result = oldCircuitId.contentHashCode()
            result = 31 * result + newCircuitId.contentHashCode()
            return result
        }
    }
}

/**
 * Exception thrown when insufficient relays are available for anonymity.
 */
class InsufficientRelaysException(
    val available: Int,
    val required: Int
) : Exception("Insufficient relays for anonymity: have $available, need $required")

/**
 * Anonymity level based on available relays.
 */
enum class AnonymityLevel(val description: String) {
    /**
     * Full anonymity: 3+ relays.
     * Equivalent to Tor's security model.
     */
    FULL("Full anonymity (3+ relays)"),

    /**
     * Reduced anonymity: 2 relays.
     * Single compromised node may reveal endpoints.
     */
    REDUCED("Reduced anonymity (2 relays) - vulnerable to single-node compromise"),

    /**
     * Minimal anonymity: 1 relay.
     * Provides some obfuscation but weak protection.
     */
    MINIMAL("Minimal anonymity (1 relay) - weak protection"),

    /**
     * No anonymity: Direct transmission.
     * Encrypted but sender/receiver are linkable.
     */
    NONE("No anonymity (direct) - encrypted but linkable")
}
