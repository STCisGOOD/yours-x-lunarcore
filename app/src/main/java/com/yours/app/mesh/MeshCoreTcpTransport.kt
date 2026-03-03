package com.yours.app.mesh

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.IOException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * MeshCore transport over TCP.
 *
 * Connects to MeshCore companion devices over WiFi. Useful for:
 * - Development/testing without USB cable
 * - MeshCore room servers
 * - meshcore-pi instances
 *
 * Note: TCP connection requires the phone and MeshCore device
 * to be on the same network. This is primarily for testing;
 * production use should prefer BLE or USB for true off-grid.
 *
 * ## Protocol Frame Format
 *
 * ```
 * +-------+------+--------+----------+------+
 * | MAGIC | TYPE | LENGTH |   DATA   |  CRC |
 * +-------+------+--------+----------+------+
 *   2B      1B     2B       0-65535B   2B
 * ```
 *
 * - MAGIC: 0x4D 0x43 ("MC" for MeshCore)
 * - TYPE: Frame type byte (see FrameType)
 * - LENGTH: Little-endian u16 (data length only)
 * - DATA: Type-specific payload
 * - CRC: CRC-16-CCITT over TYPE+LENGTH+DATA
 */
class MeshCoreTcpTransport : MeshCoreTransport {

    companion object {
        private const val TAG = "MeshCoreTcpTransport"

        // Protocol constants
        const val MAGIC_BYTE_1: Byte = 0x4D  // 'M'
        const val MAGIC_BYTE_2: Byte = 0x43  // 'C'

        const val HEADER_SIZE = 5  // MAGIC(2) + TYPE(1) + LENGTH(2)
        const val CRC_SIZE = 2
        const val MIN_FRAME_SIZE = HEADER_SIZE + CRC_SIZE
        const val MAX_DATA_SIZE = 65535

        // Timeouts
        const val RESPONSE_TIMEOUT_MS = 10000L
        const val READ_BUFFER_SIZE = 8192
    }

    /**
     * Frame types for MeshCore TCP protocol.
     */
    object FrameType {
        const val MESSAGE: Byte = 0x01
        const val ACK: Byte = 0x02
        const val DEVICE_INFO: Byte = 0x03
        const val CONTACTS: Byte = 0x04
        const val BATTERY: Byte = 0x05
        const val PING: Byte = 0x06
        const val PONG: Byte = 0x07
        const val REQUEST_DEVICE_INFO: Byte = 0x13
        const val REQUEST_CONTACTS: Byte = 0x14
        const val REQUEST_BATTERY: Byte = 0x15
    }

    private val _connectionState = MutableStateFlow(MeshConnectionState.DISCONNECTED)
    override val connectionState: StateFlow<MeshConnectionState> = _connectionState

    private val _events = MutableSharedFlow<MeshEvent>(replay = 0, extraBufferCapacity = 64)
    override val events: Flow<MeshEvent> = _events

    // TCP connection state
    private var socket: Socket? = null
    private var readJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Frame buffering for partial reads
    private val frameBuffer = mutableListOf<Byte>()
    private val bufferLock = Any()

    // Pending message ACKs
    private val pendingAcks = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()

    // Pending request responses
    private val pendingDeviceInfo = ConcurrentHashMap<Int, CompletableDeferred<DeviceInfo>>()
    private val pendingContacts = ConcurrentHashMap<Int, CompletableDeferred<List<MeshContact>>>()
    private val pendingBattery = ConcurrentHashMap<Int, CompletableDeferred<BatteryStatus>>()
    private val pendingPong = ConcurrentHashMap<Int, CompletableDeferred<Unit>>()

    // Sequence counter for requests
    @Volatile
    private var sequenceCounter = 0

    override suspend fun connect(connection: MeshConnection): Result<Unit> {
        if (connection !is MeshConnection.Tcp) {
            return Result.failure(IllegalArgumentException("Expected TCP connection"))
        }

        _connectionState.value = MeshConnectionState.CONNECTING

        return withContext(Dispatchers.IO) {
            try {
                socket = Socket(connection.host, connection.port).apply {
                    soTimeout = 0  // Non-blocking reads handled in coroutine
                    tcpNoDelay = true  // Disable Nagle's algorithm for lower latency
                    keepAlive = true
                }
                _connectionState.value = MeshConnectionState.CONNECTED
                _events.emit(MeshEvent(MeshEventType.CONNECTED))

                // Clear any stale buffer data
                synchronized(bufferLock) {
                    frameBuffer.clear()
                }

                // Start read loop
                startReadLoop()

                Result.success(Unit)
            } catch (e: IOException) {
                _connectionState.value = MeshConnectionState.ERROR
                _events.emit(MeshEvent(MeshEventType.CONNECTION_ERROR, e.message))
                Result.failure(e)
            }
        }
    }

    private fun startReadLoop() {
        readJob = scope.launch {
            val buffer = ByteArray(READ_BUFFER_SIZE)
            try {
                while (isActive && socket?.isConnected == true) {
                    val inputStream = socket?.getInputStream() ?: break
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        val data = buffer.copyOf(bytesRead)
                        processIncomingData(data)
                    } else if (bytesRead == -1) {
                        // Connection closed by remote
                        break
                    }
                }
            } catch (e: IOException) {
                if (isActive) {
                    _events.emit(MeshEvent(MeshEventType.ERROR, e.message))
                }
            } finally {
                if (_connectionState.value == MeshConnectionState.CONNECTED) {
                    _connectionState.value = MeshConnectionState.DISCONNECTED
                    _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
                }
            }
        }
    }

    /**
     * Process incoming data, handling frame buffering and parsing.
     */
    private suspend fun processIncomingData(data: ByteArray) {
        synchronized(bufferLock) {
            frameBuffer.addAll(data.toList())
        }

        // Extract and process complete frames
        while (true) {
            val frame = extractNextFrame() ?: break
            processFrame(frame)
        }
    }

    /**
     * Extract the next complete frame from the buffer.
     * Returns null if no complete frame is available.
     */
    private fun extractNextFrame(): ParsedFrame? {
        synchronized(bufferLock) {
            while (frameBuffer.size >= MIN_FRAME_SIZE) {
                // Find magic bytes
                val syncPos = findMagicBytes()
                if (syncPos < 0) {
                    // No magic bytes found, keep last byte (might be start of magic)
                    if (frameBuffer.size > 1) {
                        val last = frameBuffer.last()
                        frameBuffer.clear()
                        frameBuffer.add(last)
                    }
                    return null
                }

                // Discard garbage before magic bytes
                if (syncPos > 0) {
                    repeat(syncPos) { frameBuffer.removeAt(0) }
                }

                // Check if we have enough bytes for header
                if (frameBuffer.size < HEADER_SIZE) {
                    return null
                }

                // Parse header
                val frameType = frameBuffer[2]
                val dataLength = (frameBuffer[3].toInt() and 0xFF) or
                        ((frameBuffer[4].toInt() and 0xFF) shl 8)

                // Validate data length
                if (dataLength > MAX_DATA_SIZE) {
                    // Invalid length, skip magic and try again
                    frameBuffer.removeAt(0)
                    continue
                }

                val totalFrameSize = HEADER_SIZE + dataLength + CRC_SIZE

                // Check if we have the complete frame
                if (frameBuffer.size < totalFrameSize) {
                    return null
                }

                // Extract frame bytes
                val frameBytes = ByteArray(totalFrameSize) { frameBuffer[it] }

                // Verify CRC
                val receivedCrc = (frameBytes[totalFrameSize - 2].toInt() and 0xFF) or
                        ((frameBytes[totalFrameSize - 1].toInt() and 0xFF) shl 8)
                val calculatedCrc = calculateCrc16(frameBytes, 2, HEADER_SIZE - 2 + dataLength)

                if (receivedCrc != calculatedCrc) {
                    // CRC mismatch, skip magic and try again
                    frameBuffer.removeAt(0)
                    continue
                }

                // Extract data
                val frameData = if (dataLength > 0) {
                    frameBytes.copyOfRange(HEADER_SIZE, HEADER_SIZE + dataLength)
                } else {
                    ByteArray(0)
                }

                // Remove processed bytes from buffer
                repeat(totalFrameSize) { frameBuffer.removeAt(0) }

                return ParsedFrame(frameType, frameData)
            }

            return null
        }
    }

    /**
     * Find the position of magic bytes in the buffer.
     */
    private fun findMagicBytes(): Int {
        for (i in 0 until frameBuffer.size - 1) {
            if (frameBuffer[i] == MAGIC_BYTE_1 && frameBuffer[i + 1] == MAGIC_BYTE_2) {
                return i
            }
        }
        return -1
    }

    /**
     * Process a complete parsed frame.
     */
    private suspend fun processFrame(frame: ParsedFrame) {
        when (frame.type) {
            FrameType.MESSAGE -> processMessageFrame(frame.data)
            FrameType.ACK -> processAckFrame(frame.data)
            FrameType.DEVICE_INFO -> processDeviceInfoFrame(frame.data)
            FrameType.CONTACTS -> processContactsFrame(frame.data)
            FrameType.BATTERY -> processBatteryFrame(frame.data)
            FrameType.PING -> processPingFrame(frame.data)
            FrameType.PONG -> processPongFrame(frame.data)
            else -> {
                // Unknown frame type, ignore
            }
        }
    }

    /**
     * Process incoming message frame.
     *
     * Message frame data format:
     * [message_id: 16 bytes UUID][sender_pubkey: 32 bytes][content_length: 2 bytes][content: N bytes]
     */
    private suspend fun processMessageFrame(data: ByteArray) {
        if (data.size < 50) {  // 16 + 32 + 2 minimum
            _events.emit(MeshEvent(MeshEventType.ERROR, "Invalid message frame: too short"))
            return
        }

        val messageIdBytes = data.copyOfRange(0, 16)
        val messageId = bytesToUuid(messageIdBytes)
        val senderPubKey = data.copyOfRange(16, 48)
        val contentLength = (data[48].toInt() and 0xFF) or ((data[49].toInt() and 0xFF) shl 8)

        if (data.size < 50 + contentLength) {
            _events.emit(MeshEvent(MeshEventType.ERROR, "Invalid message frame: content truncated"))
            return
        }

        val content = data.copyOfRange(50, 50 + contentLength)

        val meshMessage = MeshMessage(
            from = senderPubKey,
            to = ByteArray(32),  // Will be filled by higher layer
            content = content,
            timestamp = System.currentTimeMillis(),
            messageId = messageId,
            isAcked = false
        )

        _events.emit(MeshEvent(MeshEventType.MESSAGE_RECEIVED, meshMessage))
    }

    /**
     * Process ACK frame.
     *
     * ACK frame data format:
     * [message_id: 16 bytes UUID][status: 1 byte (0=failed, 1=delivered, 2=read)]
     */
    private suspend fun processAckFrame(data: ByteArray) {
        if (data.size < 17) {
            return
        }

        val messageIdBytes = data.copyOfRange(0, 16)
        val messageId = bytesToUuid(messageIdBytes)
        val status = data[16].toInt() and 0xFF

        // Complete pending ACK
        pendingAcks[messageId]?.complete(status > 0)
        pendingAcks.remove(messageId)

        _events.emit(MeshEvent(MeshEventType.MESSAGE_ACK, Pair(messageId, status)))
    }

    /**
     * Process device info response frame.
     *
     * DeviceInfo frame data format:
     * [sequence: 2 bytes][node_id: 8 bytes][fw_version_len: 1 byte][fw_version: N bytes]
     * [hw_type_len: 1 byte][hw_type: N bytes][mesh_name_len: 1 byte][mesh_name: N bytes (optional)]
     */
    private suspend fun processDeviceInfoFrame(data: ByteArray) {
        if (data.size < 12) {
            return
        }

        val sequence = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
        val nodeId = data.copyOfRange(2, 10)

        var offset = 10

        // Firmware version
        val fwVersionLen = data[offset++].toInt() and 0xFF
        if (offset + fwVersionLen > data.size) return
        val firmwareVersion = String(data.copyOfRange(offset, offset + fwVersionLen), Charsets.UTF_8)
        offset += fwVersionLen

        // Hardware type
        if (offset >= data.size) return
        val hwTypeLen = data[offset++].toInt() and 0xFF
        if (offset + hwTypeLen > data.size) return
        val hardwareType = String(data.copyOfRange(offset, offset + hwTypeLen), Charsets.UTF_8)
        offset += hwTypeLen

        // Mesh name (optional)
        val meshName = if (offset < data.size) {
            val meshNameLen = data[offset++].toInt() and 0xFF
            if (meshNameLen > 0 && offset + meshNameLen <= data.size) {
                String(data.copyOfRange(offset, offset + meshNameLen), Charsets.UTF_8)
            } else {
                null
            }
        } else {
            null
        }

        val deviceInfo = DeviceInfo(
            nodeId = nodeId,
            firmwareVersion = firmwareVersion,
            hardwareType = hardwareType,
            meshName = meshName
        )

        // Complete pending request
        pendingDeviceInfo[sequence]?.complete(deviceInfo)
        pendingDeviceInfo.remove(sequence)

        _events.emit(MeshEvent(MeshEventType.DEVICE_INFO, deviceInfo))
    }

    /**
     * Process contacts response frame.
     *
     * Contacts frame data format:
     * [sequence: 2 bytes][contact_count: 2 bytes][contacts: N * contact_entry]
     *
     * Contact entry format:
     * [pubkey: 32 bytes][name_len: 1 byte][name: N bytes][last_seen: 8 bytes][signal: 1 byte (signed)]
     */
    private suspend fun processContactsFrame(data: ByteArray) {
        if (data.size < 4) {
            return
        }

        val sequence = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
        val contactCount = (data[2].toInt() and 0xFF) or ((data[3].toInt() and 0xFF) shl 8)

        val contacts = mutableListOf<MeshContact>()
        var offset = 4

        repeat(contactCount) {
            if (offset + 42 > data.size) return@repeat  // Minimum contact size: 32 + 1 + 0 + 8 + 1

            val publicKey = data.copyOfRange(offset, offset + 32)
            offset += 32

            val nameLen = data[offset++].toInt() and 0xFF
            val displayName = if (nameLen > 0 && offset + nameLen <= data.size) {
                val name = String(data.copyOfRange(offset, offset + nameLen), Charsets.UTF_8)
                offset += nameLen
                name
            } else {
                null
            }

            if (offset + 9 > data.size) return@repeat

            // Last seen timestamp (8 bytes, little-endian)
            val lastSeen = ByteBuffer.wrap(data.copyOfRange(offset, offset + 8))
                .order(ByteOrder.LITTLE_ENDIAN)
                .long
            offset += 8

            // Signal strength (signed byte, can be null if 0x7F)
            val signalByte = data[offset++].toInt()
            val signalStrength = if (signalByte == 0x7F) null else signalByte

            contacts.add(
                MeshContact(
                    publicKey = publicKey,
                    displayName = displayName,
                    lastSeen = lastSeen,
                    signalStrength = signalStrength
                )
            )
        }

        // Complete pending request
        pendingContacts[sequence]?.complete(contacts)
        pendingContacts.remove(sequence)

        // Emit individual contact events
        contacts.forEach { contact ->
            _events.emit(MeshEvent(MeshEventType.CONTACT_DISCOVERED, contact))
        }
    }

    /**
     * Process battery status response frame.
     *
     * Battery frame data format:
     * [sequence: 2 bytes][percentage: 1 byte][is_charging: 1 byte][voltage: 2 bytes (mV, little-endian)]
     */
    private suspend fun processBatteryFrame(data: ByteArray) {
        if (data.size < 6) {
            return
        }

        val sequence = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
        val percentage = data[2].toInt() and 0xFF
        val isCharging = data[3].toInt() != 0
        val voltageMv = (data[4].toInt() and 0xFF) or ((data[5].toInt() and 0xFF) shl 8)

        // Convert mV to V, null if 0 (unknown)
        val voltage = if (voltageMv > 0) voltageMv / 1000.0f else null

        val batteryStatus = BatteryStatus(
            percentage = percentage.coerceIn(0, 100),
            isCharging = isCharging,
            voltage = voltage
        )

        // Complete pending request
        pendingBattery[sequence]?.complete(batteryStatus)
        pendingBattery.remove(sequence)

        _events.emit(MeshEvent(MeshEventType.BATTERY_STATUS, batteryStatus))
    }

    /**
     * Process ping frame - respond with pong.
     *
     * Ping frame data format:
     * [sequence: 2 bytes][timestamp: 8 bytes]
     */
    private suspend fun processPingFrame(data: ByteArray) {
        if (data.size < 10) {
            return
        }

        // Respond with pong using the same data
        val pongFrame = buildFrame(FrameType.PONG, data)

        withContext(Dispatchers.IO) {
            try {
                socket?.getOutputStream()?.apply {
                    write(pongFrame)
                    flush()
                }
            } catch (e: IOException) {
                // Ignore pong send failures
            }
        }
    }

    /**
     * Process pong frame - complete pending ping.
     *
     * Pong frame data format:
     * [sequence: 2 bytes][timestamp: 8 bytes]
     */
    private suspend fun processPongFrame(data: ByteArray) {
        if (data.size < 2) {
            return
        }

        val sequence = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)

        pendingPong[sequence]?.complete(Unit)
        pendingPong.remove(sequence)
    }

    override suspend fun disconnect() {
        readJob?.cancel()
        readJob = null

        // Cancel all pending operations
        pendingAcks.values.forEach { it.cancel() }
        pendingAcks.clear()
        pendingDeviceInfo.values.forEach { it.cancel() }
        pendingDeviceInfo.clear()
        pendingContacts.values.forEach { it.cancel() }
        pendingContacts.clear()
        pendingBattery.values.forEach { it.cancel() }
        pendingBattery.clear()
        pendingPong.values.forEach { it.cancel() }
        pendingPong.clear()

        try {
            socket?.close()
        } catch (e: IOException) {
            // Ignore close errors
        }
        socket = null

        synchronized(bufferLock) {
            frameBuffer.clear()
        }

        _connectionState.value = MeshConnectionState.DISCONNECTED
        _events.emit(MeshEvent(MeshEventType.DISCONNECTED))
    }

    override suspend fun getDeviceInfo(): Result<DeviceInfo> {
        val s = socket ?: return Result.failure(IOException("Not connected"))

        return withContext(Dispatchers.IO) {
            try {
                val sequence = nextSequence()
                val deferred = CompletableDeferred<DeviceInfo>()
                pendingDeviceInfo[sequence] = deferred

                // Build and send request frame
                val requestData = ByteArray(2)
                requestData[0] = (sequence and 0xFF).toByte()
                requestData[1] = ((sequence shr 8) and 0xFF).toByte()

                val frame = buildFrame(FrameType.REQUEST_DEVICE_INFO, requestData)
                s.getOutputStream().write(frame)
                s.getOutputStream().flush()

                // Wait for response
                val deviceInfo = withTimeout(RESPONSE_TIMEOUT_MS) {
                    deferred.await()
                }

                Result.success(deviceInfo)
            } catch (e: TimeoutCancellationException) {
                Result.failure(IOException("Device info request timed out"))
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    override suspend fun getContacts(): Result<List<MeshContact>> {
        val s = socket ?: return Result.failure(IOException("Not connected"))

        return withContext(Dispatchers.IO) {
            try {
                val sequence = nextSequence()
                val deferred = CompletableDeferred<List<MeshContact>>()
                pendingContacts[sequence] = deferred

                // Build and send request frame
                val requestData = ByteArray(2)
                requestData[0] = (sequence and 0xFF).toByte()
                requestData[1] = ((sequence shr 8) and 0xFF).toByte()

                val frame = buildFrame(FrameType.REQUEST_CONTACTS, requestData)
                s.getOutputStream().write(frame)
                s.getOutputStream().flush()

                // Wait for response
                val contacts = withTimeout(RESPONSE_TIMEOUT_MS) {
                    deferred.await()
                }

                Result.success(contacts)
            } catch (e: TimeoutCancellationException) {
                Result.failure(IOException("Contacts request timed out"))
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    override suspend fun sendMessage(recipient: ByteArray, content: ByteArray): Result<String> {
        val s = socket ?: return Result.failure(IOException("Not connected"))

        return withContext(Dispatchers.IO) {
            try {
                val messageId = UUID.randomUUID().toString()
                val frame = buildMessageFrame(recipient, content, messageId)

                s.getOutputStream().write(frame)
                s.getOutputStream().flush()

                _events.emit(MeshEvent(MeshEventType.MESSAGE_SENT, messageId))
                Result.success(messageId)
            } catch (e: IOException) {
                _events.emit(MeshEvent(MeshEventType.MESSAGE_FAILED, e.message))
                Result.failure(e)
            }
        }
    }

    /**
     * Build a complete protocol frame with header and CRC.
     *
     * Frame format:
     * [MAGIC: 2B][TYPE: 1B][LENGTH: 2B][DATA: NB][CRC: 2B]
     */
    private fun buildFrame(type: Byte, data: ByteArray): ByteArray {
        val dataLength = data.size
        val frameSize = HEADER_SIZE + dataLength + CRC_SIZE
        val frame = ByteArray(frameSize)

        // Magic bytes
        frame[0] = MAGIC_BYTE_1
        frame[1] = MAGIC_BYTE_2

        // Frame type
        frame[2] = type

        // Data length (little-endian)
        frame[3] = (dataLength and 0xFF).toByte()
        frame[4] = ((dataLength shr 8) and 0xFF).toByte()

        // Data
        System.arraycopy(data, 0, frame, HEADER_SIZE, dataLength)

        // Calculate CRC over TYPE+LENGTH+DATA
        val crc = calculateCrc16(frame, 2, 3 + dataLength)
        frame[frameSize - 2] = (crc and 0xFF).toByte()
        frame[frameSize - 1] = ((crc shr 8) and 0xFF).toByte()

        return frame
    }

    /**
     * Build a message frame with proper protocol format.
     *
     * Message frame data format:
     * [message_id: 16 bytes UUID][recipient_pubkey: 32 bytes][content_length: 2 bytes][content: N bytes]
     */
    private fun buildMessageFrame(recipient: ByteArray, content: ByteArray, messageId: String): ByteArray {
        val messageIdBytes = uuidToBytes(messageId)
        val contentLength = content.size

        // Build message data payload
        val messageData = ByteArray(16 + 32 + 2 + contentLength)
        var offset = 0

        // Message ID (16 bytes)
        System.arraycopy(messageIdBytes, 0, messageData, offset, 16)
        offset += 16

        // Recipient public key (32 bytes, padded if necessary)
        val recipientPadded = if (recipient.size >= 32) {
            recipient.copyOfRange(0, 32)
        } else {
            ByteArray(32).also { System.arraycopy(recipient, 0, it, 0, recipient.size) }
        }
        System.arraycopy(recipientPadded, 0, messageData, offset, 32)
        offset += 32

        // Content length (2 bytes, little-endian)
        messageData[offset++] = (contentLength and 0xFF).toByte()
        messageData[offset++] = ((contentLength shr 8) and 0xFF).toByte()

        // Content
        System.arraycopy(content, 0, messageData, offset, contentLength)

        return buildFrame(FrameType.MESSAGE, messageData)
    }

    override suspend fun sendMessageWithRetry(
        recipient: ByteArray,
        content: ByteArray,
        maxRetries: Int,
        timeoutMs: Long
    ): Result<String> {
        var lastError: Throwable? = null

        repeat(maxRetries) { attempt ->
            val result = sendMessage(recipient, content)
            if (result.isSuccess) {
                val messageId = result.getOrThrow()

                // Wait for ACK
                val ackDeferred = CompletableDeferred<Boolean>()
                pendingAcks[messageId] = ackDeferred

                try {
                    val acked = withTimeout(timeoutMs) {
                        ackDeferred.await()
                    }
                    if (acked) {
                        return Result.success(messageId)
                    }
                } catch (e: TimeoutCancellationException) {
                    lastError = e
                } finally {
                    pendingAcks.remove(messageId)
                }

                // Exponential backoff before retry
                if (attempt < maxRetries - 1) {
                    delay(100L * (1 shl attempt))
                }
            } else {
                lastError = result.exceptionOrNull()
            }
        }

        return Result.failure(lastError ?: IOException("Send failed after $maxRetries attempts"))
    }

    override suspend fun getBatteryStatus(): Result<BatteryStatus> {
        val s = socket ?: return Result.failure(IOException("Not connected"))

        return withContext(Dispatchers.IO) {
            try {
                val sequence = nextSequence()
                val deferred = CompletableDeferred<BatteryStatus>()
                pendingBattery[sequence] = deferred

                // Build and send request frame
                val requestData = ByteArray(2)
                requestData[0] = (sequence and 0xFF).toByte()
                requestData[1] = ((sequence shr 8) and 0xFF).toByte()

                val frame = buildFrame(FrameType.REQUEST_BATTERY, requestData)
                s.getOutputStream().write(frame)
                s.getOutputStream().flush()

                // Wait for response
                val batteryStatus = withTimeout(RESPONSE_TIMEOUT_MS) {
                    deferred.await()
                }

                Result.success(batteryStatus)
            } catch (e: TimeoutCancellationException) {
                Result.failure(IOException("Battery status request timed out"))
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    /**
     * Send a ping to verify connection and measure latency.
     *
     * @return Round-trip time in milliseconds
     */
    suspend fun ping(): Result<Long> {
        val s = socket ?: return Result.failure(IOException("Not connected"))

        return withContext(Dispatchers.IO) {
            try {
                val sequence = nextSequence()
                val deferred = CompletableDeferred<Unit>()
                pendingPong[sequence] = deferred

                val timestamp = System.currentTimeMillis()

                // Build ping data: sequence + timestamp
                val pingData = ByteArray(10)
                pingData[0] = (sequence and 0xFF).toByte()
                pingData[1] = ((sequence shr 8) and 0xFF).toByte()

                // Timestamp (8 bytes, little-endian)
                for (i in 0 until 8) {
                    pingData[2 + i] = ((timestamp shr (i * 8)) and 0xFF).toByte()
                }

                val frame = buildFrame(FrameType.PING, pingData)
                s.getOutputStream().write(frame)
                s.getOutputStream().flush()

                // Wait for pong
                withTimeout(RESPONSE_TIMEOUT_MS) {
                    deferred.await()
                }

                val rtt = System.currentTimeMillis() - timestamp
                Result.success(rtt)
            } catch (e: TimeoutCancellationException) {
                Result.failure(IOException("Ping timed out"))
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    override fun isConnected(): Boolean = _connectionState.value == MeshConnectionState.CONNECTED

    /**
     * Get the next sequence number for requests.
     */
    private fun nextSequence(): Int {
        return (++sequenceCounter) and 0xFFFF
    }

    /**
     * Calculate CRC-16-CCITT checksum.
     */
    private fun calculateCrc16(data: ByteArray, offset: Int, length: Int): Int {
        var crc = 0xFFFF
        for (i in offset until offset + length) {
            crc = crc xor ((data[i].toInt() and 0xFF) shl 8)
            for (bit in 0 until 8) {
                crc = if ((crc and 0x8000) != 0) {
                    (crc shl 1) xor 0x1021
                } else {
                    crc shl 1
                }
                crc = crc and 0xFFFF
            }
        }
        return crc
    }

    /**
     * Convert UUID string to 16-byte array.
     */
    private fun uuidToBytes(uuidString: String): ByteArray {
        return try {
            val uuid = UUID.fromString(uuidString)
            val buffer = ByteBuffer.allocate(16)
            buffer.putLong(uuid.mostSignificantBits)
            buffer.putLong(uuid.leastSignificantBits)
            buffer.array()
        } catch (e: IllegalArgumentException) {
            // If not a valid UUID, hash the string
            val bytes = uuidString.toByteArray(Charsets.UTF_8)
            val result = ByteArray(16)
            for (i in bytes.indices) {
                result[i % 16] = (result[i % 16].toInt() xor bytes[i].toInt()).toByte()
            }
            result
        }
    }

    /**
     * Convert 16-byte array to UUID string.
     */
    private fun bytesToUuid(bytes: ByteArray): String {
        if (bytes.size < 16) {
            return UUID.randomUUID().toString()
        }
        val buffer = ByteBuffer.wrap(bytes)
        val mostSigBits = buffer.long
        val leastSigBits = buffer.long
        return UUID(mostSigBits, leastSigBits).toString()
    }

    /**
     * Internal class representing a parsed frame.
     */
    private data class ParsedFrame(
        val type: Byte,
        val data: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ParsedFrame) return false
            return type == other.type && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = type.toInt()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }
}
