package com.yours.app.mesh

/**
 * LoRa Serial Protocol
 *
 * Defines the framing protocol for USB/Serial communication between
 * Android and ESP32 with SX1262 LoRa transceiver.
 *
 * ## Frame Format
 *
 * ```
 * +------+------+--------+------+--------+-----+------+
 * | SYNC | LEN  |  CMD   | SEQ  |  DATA  | CRC | END  |
 * +------+------+--------+------+--------+-----+------+
 *   2B     2B     1B       1B    0-255B   2B    1B
 * ```
 *
 * - SYNC: 0xAA 0x55 (magic bytes)
 * - LEN: Little-endian u16 (data length only)
 * - CMD: Command byte
 * - SEQ: Sequence number (for matching responses)
 * - DATA: Command-specific payload
 * - CRC: CRC-16-CCITT over CMD+SEQ+DATA
 * - END: 0x0D (carriage return)
 */
object LoRaSerialProtocol {

    // Frame markers
    const val SYNC_BYTE_1: Byte = 0xAA.toByte()
    const val SYNC_BYTE_2: Byte = 0x55.toByte()
    const val END_BYTE: Byte = 0x0D.toByte()

    // Limits
    const val MAX_DATA_SIZE = 255
    const val MIN_FRAME_SIZE = 9  // SYNC(2) + LEN(2) + CMD(1) + SEQ(1) + CRC(2) + END(1)
    const val MAX_FRAME_SIZE = MIN_FRAME_SIZE + MAX_DATA_SIZE

    // Default baud rate
    const val DEFAULT_BAUD_RATE = 115200
}

/**
 * Command codes for the LoRa serial protocol.
 */
enum class LoRaCommand(val code: Byte) {
    // Heartbeat
    PING(0x01),
    PONG(0x02),

    // Configuration
    CONFIGURE(0x10),
    CONFIG_ACK(0x11),

    // Transmit
    TRANSMIT(0x20),
    TX_DONE(0x21),
    TX_ERROR(0x22),

    // Receive
    RECEIVE(0x30),

    // Statistics
    GET_STATS(0x40),
    STATS_RESPONSE(0x41),

    // Channel activity detection
    CAD(0x50),
    CAD_RESULT(0x51),

    // Device control
    RESET(0xF0.toByte()),
    VERSION(0xF1.toByte()),
    VERSION_RESPONSE(0xF2.toByte()),
    ERROR(0xFF.toByte());

    companion object {
        private val codeMap = entries.associateBy { it.code }
        fun fromCode(code: Byte): LoRaCommand? = codeMap[code]
    }
}

/**
 * A parsed protocol frame.
 */
data class LoRaFrame(
    val command: LoRaCommand,
    val sequence: Byte,
    val data: ByteArray
) {
    /**
     * Encode this frame to bytes.
     */
    fun encode(): ByteArray {
        val dataLen = data.size
        val frame = ByteArray(9 + dataLen)

        // Sync bytes
        frame[0] = LoRaSerialProtocol.SYNC_BYTE_1
        frame[1] = LoRaSerialProtocol.SYNC_BYTE_2

        // Length (little-endian u16)
        frame[2] = dataLen.toByte()
        frame[3] = (dataLen shr 8).toByte()

        // Command and sequence
        frame[4] = command.code
        frame[5] = sequence

        // Data
        System.arraycopy(data, 0, frame, 6, dataLen)

        // CRC-16 over cmd+seq+data
        val crc = crc16(frame, 4, 2 + dataLen)
        val crcOffset = 6 + dataLen
        frame[crcOffset] = crc.toByte()
        frame[crcOffset + 1] = (crc shr 8).toByte()

        // End byte
        frame[crcOffset + 2] = LoRaSerialProtocol.END_BYTE

        return frame
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LoRaFrame) return false
        return command == other.command &&
                sequence == other.sequence &&
                data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = command.hashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }

    companion object {
        /**
         * Decode a frame from bytes.
         *
         * @param bytes Raw frame bytes including sync, CRC, and end
         * @return Decoded frame or null if invalid
         */
        fun decode(bytes: ByteArray): LoRaFrame? {
            if (bytes.size < LoRaSerialProtocol.MIN_FRAME_SIZE) {
                return null
            }

            // Check sync bytes
            if (bytes[0] != LoRaSerialProtocol.SYNC_BYTE_1 ||
                bytes[1] != LoRaSerialProtocol.SYNC_BYTE_2
            ) {
                return null
            }

            // Get data length
            val dataLen = (bytes[2].toInt() and 0xFF) or
                    ((bytes[3].toInt() and 0xFF) shl 8)

            if (dataLen > LoRaSerialProtocol.MAX_DATA_SIZE) {
                return null
            }

            val expectedLen = LoRaSerialProtocol.MIN_FRAME_SIZE + dataLen
            if (bytes.size < expectedLen) {
                return null
            }

            // Check end byte
            if (bytes[expectedLen - 1] != LoRaSerialProtocol.END_BYTE) {
                return null
            }

            // Verify CRC
            val crcOffset = 6 + dataLen
            val receivedCrc = (bytes[crcOffset].toInt() and 0xFF) or
                    ((bytes[crcOffset + 1].toInt() and 0xFF) shl 8)
            val calculatedCrc = crc16(bytes, 4, 2 + dataLen)

            if (receivedCrc != calculatedCrc) {
                return null
            }

            // Parse command
            val command = LoRaCommand.fromCode(bytes[4]) ?: return null
            val sequence = bytes[5]
            val data = bytes.copyOfRange(6, 6 + dataLen)

            return LoRaFrame(command, sequence, data)
        }

        /**
         * Create a ping frame.
         */
        fun ping(sequence: Byte): LoRaFrame =
            LoRaFrame(LoRaCommand.PING, sequence, ByteArray(0))

        /**
         * Create a version query frame.
         */
        fun version(sequence: Byte): LoRaFrame =
            LoRaFrame(LoRaCommand.VERSION, sequence, ByteArray(0))

        /**
         * Create a CAD request frame.
         */
        fun cad(sequence: Byte): LoRaFrame =
            LoRaFrame(LoRaCommand.CAD, sequence, ByteArray(0))

        /**
         * Create a stats request frame.
         */
        fun getStats(sequence: Byte): LoRaFrame =
            LoRaFrame(LoRaCommand.GET_STATS, sequence, ByteArray(0))

        /**
         * Create a reset frame.
         */
        fun reset(sequence: Byte): LoRaFrame =
            LoRaFrame(LoRaCommand.RESET, sequence, ByteArray(0))

        /**
         * Create a transmit frame.
         */
        fun transmit(sequence: Byte, payload: ByteArray): LoRaFrame =
            LoRaFrame(LoRaCommand.TRANSMIT, sequence, payload)

        /**
         * Create a configure frame.
         *
         * @param frequencyHz Frequency in Hz (e.g., 915000000)
         * @param spreadingFactor SF 7-12
         * @param bandwidthKhz Bandwidth in kHz (125, 250, 500)
         * @param codingRate CR 1-4 for 4/5 to 4/8
         * @param txPowerDbm TX power in dBm
         * @param syncWord Sync word
         * @param preambleLength Preamble symbol count
         * @param crcEnabled Enable CRC
         * @param implicitHeader Use implicit header mode
         * @param ldro Enable Low Data Rate Optimization
         */
        fun configure(
            sequence: Byte,
            frequencyHz: Long,
            spreadingFactor: Int = 7,      // MeshCore USA/CA recommended
            bandwidthKhz: Int = 62,        // 62.5 kHz - MeshCore USA/CA recommended (rounded)
            codingRate: Int = 1,
            txPowerDbm: Int = 14,
            syncWord: Int = 0x12,          // Private network (Semtech docs)
            preambleLength: Int = 16,      // 16 symbol preamble
            crcEnabled: Boolean = true,
            implicitHeader: Boolean = false,
            ldro: Boolean = false
        ): LoRaFrame {
            val data = ByteArray(13)

            // Frequency (4 bytes, little-endian u32)
            data[0] = frequencyHz.toByte()
            data[1] = (frequencyHz shr 8).toByte()
            data[2] = (frequencyHz shr 16).toByte()
            data[3] = (frequencyHz shr 24).toByte()

            // Spreading factor (1 byte)
            data[4] = spreadingFactor.toByte()

            // Bandwidth in kHz (2 bytes, little-endian u16)
            data[5] = bandwidthKhz.toByte()
            data[6] = (bandwidthKhz shr 8).toByte()

            // Coding rate (1 byte)
            data[7] = codingRate.toByte()

            // TX power (1 byte)
            data[8] = txPowerDbm.toByte()

            // Sync word (1 byte)
            data[9] = syncWord.toByte()

            // Preamble length (2 bytes, little-endian u16)
            data[10] = preambleLength.toByte()
            data[11] = (preambleLength shr 8).toByte()

            // Flags (1 byte)
            var flags = 0
            if (crcEnabled) flags = flags or 0x01
            if (implicitHeader) flags = flags or 0x02
            if (ldro) flags = flags or 0x04
            data[12] = flags.toByte()

            return LoRaFrame(LoRaCommand.CONFIGURE, sequence, data)
        }
    }
}

/**
 * Parsed receive packet data from a RECEIVE frame.
 */
data class LoRaRxPacket(
    val rssi: Int,    // RSSI in dBm
    val snr: Int,     // SNR in dB
    val payload: ByteArray
) {
    companion object {
        /**
         * Parse a RECEIVE frame's data field.
         */
        fun fromFrameData(data: ByteArray): LoRaRxPacket? {
            if (data.size < 4) return null

            val rssi = (data[0].toInt() and 0xFF) or
                    ((data[1].toInt() and 0xFF) shl 8)
            // Sign-extend RSSI
            val signedRssi = if (rssi and 0x8000 != 0) rssi or 0xFFFF0000.toInt() else rssi

            val snr = data[2].toInt()  // Already signed

            val payload = data.copyOfRange(4, data.size)

            return LoRaRxPacket(signedRssi, snr, payload)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LoRaRxPacket) return false
        return rssi == other.rssi && snr == other.snr && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = rssi
        result = 31 * result + snr
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

/**
 * Streaming frame parser.
 *
 * Feed bytes as they arrive; completed frames are returned.
 */
class LoRaFrameParser {
    private val buffer = mutableListOf<Byte>()

    /**
     * Feed incoming bytes and extract any complete frames.
     */
    fun feed(bytes: ByteArray): List<LoRaFrame> {
        buffer.addAll(bytes.toList())
        return extractFrames()
    }

    /**
     * Clear the parser state.
     */
    fun reset() {
        buffer.clear()
    }

    private fun extractFrames(): List<LoRaFrame> {
        val frames = mutableListOf<LoRaFrame>()

        while (buffer.size >= LoRaSerialProtocol.MIN_FRAME_SIZE) {
            // Find sync bytes
            val syncPos = findSync()
            if (syncPos < 0) {
                // No sync found, keep last byte (might be start of sync)
                if (buffer.size > 1) {
                    val last = buffer.last()
                    buffer.clear()
                    buffer.add(last)
                }
                break
            }

            if (syncPos > 0) {
                // Discard garbage before sync
                repeat(syncPos) { buffer.removeAt(0) }
            }

            // Check if we have enough bytes for length field
            if (buffer.size < 4) break

            // Get data length
            val dataLen = (buffer[2].toInt() and 0xFF) or
                    ((buffer[3].toInt() and 0xFF) shl 8)

            if (dataLen > LoRaSerialProtocol.MAX_DATA_SIZE) {
                // Invalid length, skip sync and try again
                buffer.removeAt(0)
                continue
            }

            val frameLen = LoRaSerialProtocol.MIN_FRAME_SIZE + dataLen

            if (buffer.size < frameLen) {
                // Need more data
                break
            }

            // Extract frame bytes
            val frameBytes = ByteArray(frameLen) { buffer[it] }

            // Try to decode
            val frame = LoRaFrame.decode(frameBytes)
            if (frame != null) {
                frames.add(frame)
            }

            // Remove processed bytes
            repeat(frameLen) { buffer.removeAt(0) }
        }

        return frames
    }

    private fun findSync(): Int {
        for (i in 0 until buffer.size - 1) {
            if (buffer[i] == LoRaSerialProtocol.SYNC_BYTE_1 &&
                buffer[i + 1] == LoRaSerialProtocol.SYNC_BYTE_2
            ) {
                return i
            }
        }
        return -1
    }
}

/**
 * CRC-16-CCITT calculation.
 */
private fun crc16(data: ByteArray, offset: Int, length: Int): Int {
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
