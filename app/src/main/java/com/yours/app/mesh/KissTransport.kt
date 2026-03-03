package com.yours.app.mesh

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * KISS TNC Protocol Transport for RNode/Reticulum
 *
 * Implements the KISS (Keep It Simple, Stupid) serial protocol with
 * RNode-specific extensions for Reticulum network compatibility.
 *
 * ## KISS Frame Format
 * ```
 * ┌──────┬──────┬──────────────────────┬──────┐
 * │ FEND │ CMD  │ DATA (escaped)       │ FEND │
 * │ 0xC0 │      │ FESC=0xDB, etc       │ 0xC0 │
 * └──────┴──────┴──────────────────────┴──────┘
 * ```
 *
 * ## Escape Sequences
 * - FESC (0xDB) + TFEND (0xDC) = FEND (0xC0)
 * - FESC (0xDB) + TFESC (0xDD) = FESC (0xDB)
 *
 * Reference: https://github.com/markqvist/RNode_Firmware
 */
class KissTransport(
    private val inputStream: InputStream,
    private val outputStream: OutputStream
) {
    companion object {
        private const val TAG = "KissTransport"

        // KISS special bytes
        const val FEND: Byte = 0xC0.toByte()
        const val FESC: Byte = 0xDB.toByte()
        const val TFEND: Byte = 0xDC.toByte()
        const val TFESC: Byte = 0xDD.toByte()

        // Standard KISS commands
        const val CMD_DATA_FRAME: Byte = 0x00
        const val CMD_TX_DELAY: Byte = 0x01
        const val CMD_PERSISTENCE: Byte = 0x02
        const val CMD_SLOT_TIME: Byte = 0x03
        const val CMD_TX_TAIL: Byte = 0x04
        const val CMD_FULL_DUPLEX: Byte = 0x05
        const val CMD_SET_HARDWARE: Byte = 0x06
        const val CMD_RETURN: Byte = 0xFF.toByte()

        // RNode-specific commands
        const val RNODE_FREQUENCY: Byte = 0x01
        const val RNODE_BANDWIDTH: Byte = 0x02
        const val RNODE_TX_POWER: Byte = 0x03
        const val RNODE_SPREADING_FACTOR: Byte = 0x04
        const val RNODE_CODING_RATE: Byte = 0x05
        const val RNODE_RADIO_STATE: Byte = 0x06
        const val RNODE_RADIO_LOCK: Byte = 0x07
        const val RNODE_DETECT: Byte = 0x08
        const val RNODE_LEAVE: Byte = 0x0A
        const val RNODE_PROMISC: Byte = 0x0E
        const val RNODE_READY: Byte = 0x0F
        const val RNODE_STAT_RX: Byte = 0x21
        const val RNODE_STAT_TX: Byte = 0x22
        const val RNODE_STAT_RSSI: Byte = 0x23
        const val RNODE_STAT_SNR: Byte = 0x24
        const val RNODE_STAT_BATTERY: Byte = 0x25
        const val RNODE_FW_VERSION: Byte = 0x50
        const val RNODE_PROTOCOL_VERSION: Byte = 0x51
        const val RNODE_PLATFORM: Byte = 0x48
        const val RNODE_MCU: Byte = 0x49
        const val RNODE_BOARD: Byte = 0x4A
        const val RNODE_HW_SERIAL: Byte = 0x55
        const val RNODE_ERROR: Byte = 0x90.toByte()
        const val RNODE_INFO: Byte = 0xB0.toByte()
        const val RNODE_DATA_RSSI: Byte = 0xFE.toByte()

        // Maximum frame sizes
        const val MAX_DATA_SIZE = 512
        const val MAX_FRAME_SIZE = MAX_DATA_SIZE * 2 + 4
    }

    // Parsed KISS frames
    private val _frames = MutableSharedFlow<KissFrame>(
        replay = 0,
        extraBufferCapacity = 64
    )
    val frames: Flow<KissFrame> = _frames

    // Parser state
    private var receiveBuffer = ByteArray(MAX_FRAME_SIZE)
    private var bufferIndex = 0
    private var inFrame = false
    private var escape = false

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var readJob: Job? = null

    /**
     * Start the read loop to parse incoming KISS frames.
     */
    fun startReading() {
        readJob = scope.launch {
            val buffer = ByteArray(1024)
            try {
                while (isActive) {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        for (i in 0 until bytesRead) {
                            processByte(buffer[i])
                        }
                    } else if (bytesRead < 0) {
                        break // Stream closed
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Read error", e)
            }
        }
    }

    /**
     * Stop the read loop.
     */
    fun stopReading() {
        readJob?.cancel()
        readJob = null
    }

    /**
     * Close the transport.
     */
    fun close() {
        stopReading()
        scope.cancel()
        try {
            inputStream.close()
            outputStream.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing streams", e)
        }
    }

    /**
     * Process a single received byte through the KISS parser.
     */
    private suspend fun processByte(b: Byte) {
        when {
            b == FEND -> {
                if (inFrame && bufferIndex > 0) {
                    // End of frame
                    val frameData = receiveBuffer.copyOf(bufferIndex)
                    if (frameData.isNotEmpty()) {
                        val frame = parseFrame(frameData)
                        if (frame != null) {
                            _frames.emit(frame)
                        }
                    }
                }
                // Reset for next frame
                bufferIndex = 0
                inFrame = true
                escape = false
            }
            !inFrame -> {
                // Discard bytes outside of frame
            }
            b == FESC -> {
                escape = true
            }
            escape -> {
                val decoded = when (b) {
                    TFEND -> FEND
                    TFESC -> FESC
                    else -> b // Invalid escape, keep as-is
                }
                if (bufferIndex < receiveBuffer.size) {
                    receiveBuffer[bufferIndex++] = decoded
                }
                escape = false
            }
            else -> {
                if (bufferIndex < receiveBuffer.size) {
                    receiveBuffer[bufferIndex++] = b
                }
            }
        }
    }

    /**
     * Parse a completed frame buffer into a KissFrame.
     */
    private fun parseFrame(data: ByteArray): KissFrame? {
        if (data.isEmpty()) return null

        val command = data[0]
        val payload = if (data.size > 1) data.copyOfRange(1, data.size) else ByteArray(0)

        // Detect RNode extended commands (CMD_SET_HARDWARE with sub-command)
        return if (command == CMD_SET_HARDWARE && payload.isNotEmpty()) {
            val rnodeCmd = payload[0]
            val rnodeData = if (payload.size > 1) payload.copyOfRange(1, payload.size) else ByteArray(0)
            KissFrame.RNodeCommand(rnodeCmd, rnodeData)
        } else if (command == CMD_DATA_FRAME || (command.toInt() and 0x0F) == 0) {
            // Data frame (port in high nibble)
            val port = (command.toInt() shr 4) and 0x0F
            KissFrame.DataFrame(port, payload)
        } else {
            // Standard KISS command
            KissFrame.KissCommand(command, payload)
        }
    }

    /**
     * Encode and send a KISS frame.
     */
    @Synchronized
    fun sendFrame(frame: KissFrame) {
        val frameBytes = encodeFrame(frame)
        try {
            outputStream.write(frameBytes)
            outputStream.flush()
        } catch (e: Exception) {
            Log.e(TAG, "Write error", e)
        }
    }

    /**
     * Send raw data as a KISS data frame.
     */
    fun sendData(data: ByteArray, port: Int = 0) {
        sendFrame(KissFrame.DataFrame(port, data))
    }

    /**
     * Send an RNode command.
     */
    fun sendRNodeCommand(command: Byte, data: ByteArray = ByteArray(0)) {
        sendFrame(KissFrame.RNodeCommand(command, data))
    }

    /**
     * Encode a KissFrame to bytes for transmission.
     */
    private fun encodeFrame(frame: KissFrame): ByteArray {
        val output = mutableListOf<Byte>()
        output.add(FEND)

        when (frame) {
            is KissFrame.DataFrame -> {
                val cmd = ((frame.port and 0x0F) shl 4).toByte()
                output.add(cmd)
                escapeAndAdd(frame.data, output)
            }
            is KissFrame.KissCommand -> {
                output.add(frame.command)
                escapeAndAdd(frame.data, output)
            }
            is KissFrame.RNodeCommand -> {
                output.add(CMD_SET_HARDWARE)
                output.add(frame.command)
                escapeAndAdd(frame.data, output)
            }
        }

        output.add(FEND)
        return output.toByteArray()
    }

    /**
     * Escape special bytes and add to output list.
     */
    private fun escapeAndAdd(data: ByteArray, output: MutableList<Byte>) {
        for (b in data) {
            when (b) {
                FEND -> {
                    output.add(FESC)
                    output.add(TFEND)
                }
                FESC -> {
                    output.add(FESC)
                    output.add(TFESC)
                }
                else -> output.add(b)
            }
        }
    }

    // =========================================================================
    // RNode-Specific Commands
    // =========================================================================

    /**
     * Detect RNode device.
     */
    fun detectRNode() {
        sendRNodeCommand(RNODE_DETECT)
    }

    /**
     * Query RNode firmware version.
     */
    fun queryFirmwareVersion() {
        sendRNodeCommand(RNODE_FW_VERSION)
    }

    /**
     * Query RNode protocol version.
     */
    fun queryProtocolVersion() {
        sendRNodeCommand(RNODE_PROTOCOL_VERSION)
    }

    /**
     * Query RNode platform.
     */
    fun queryPlatform() {
        sendRNodeCommand(RNODE_PLATFORM)
    }

    /**
     * Query RNode board info.
     */
    fun queryBoard() {
        sendRNodeCommand(RNODE_BOARD)
    }

    /**
     * Query RNode hardware serial.
     */
    fun queryHardwareSerial() {
        sendRNodeCommand(RNODE_HW_SERIAL)
    }

    /**
     * Set radio frequency in Hz.
     */
    fun setFrequency(frequencyHz: Long) {
        val buffer = ByteBuffer.allocate(4)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(frequencyHz.toInt())
        sendRNodeCommand(RNODE_FREQUENCY, buffer.array())
    }

    /**
     * Set radio bandwidth in Hz.
     */
    fun setBandwidth(bandwidthHz: Long) {
        val buffer = ByteBuffer.allocate(4)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(bandwidthHz.toInt())
        sendRNodeCommand(RNODE_BANDWIDTH, buffer.array())
    }

    /**
     * Set TX power in dBm.
     */
    fun setTxPower(powerDbm: Int) {
        sendRNodeCommand(RNODE_TX_POWER, byteArrayOf(powerDbm.toByte()))
    }

    /**
     * Set spreading factor (7-12).
     */
    fun setSpreadingFactor(sf: Int) {
        sendRNodeCommand(RNODE_SPREADING_FACTOR, byteArrayOf(sf.toByte()))
    }

    /**
     * Set coding rate (5-8 for 4/5 to 4/8).
     */
    fun setCodingRate(cr: Int) {
        sendRNodeCommand(RNODE_CODING_RATE, byteArrayOf(cr.toByte()))
    }

    /**
     * Set radio state (true = on, false = off).
     */
    fun setRadioState(enabled: Boolean) {
        sendRNodeCommand(RNODE_RADIO_STATE, byteArrayOf(if (enabled) 0x01 else 0x00))
    }

    /**
     * Query RSSI.
     */
    fun queryRssi() {
        sendRNodeCommand(RNODE_STAT_RSSI)
    }

    /**
     * Query SNR.
     */
    fun querySnr() {
        sendRNodeCommand(RNODE_STAT_SNR)
    }

    /**
     * Query battery voltage.
     */
    fun queryBattery() {
        sendRNodeCommand(RNODE_STAT_BATTERY)
    }

    /**
     * Query RX statistics.
     */
    fun queryRxStats() {
        sendRNodeCommand(RNODE_STAT_RX)
    }

    /**
     * Query TX statistics.
     */
    fun queryTxStats() {
        sendRNodeCommand(RNODE_STAT_TX)
    }

    /**
     * Leave KISS mode.
     */
    fun leaveKissMode() {
        sendRNodeCommand(RNODE_LEAVE)
    }
}

/**
 * Parsed KISS frame.
 */
sealed class KissFrame {
    /**
     * Data frame for transmit/receive.
     */
    data class DataFrame(
        val port: Int,
        val data: ByteArray
    ) : KissFrame() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DataFrame) return false
            return port == other.port && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = port
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

    /**
     * Standard KISS command.
     */
    data class KissCommand(
        val command: Byte,
        val data: ByteArray = ByteArray(0)
    ) : KissFrame() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is KissCommand) return false
            return command == other.command && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = command.toInt()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

    /**
     * RNode-specific extended command.
     */
    data class RNodeCommand(
        val command: Byte,
        val data: ByteArray = ByteArray(0)
    ) : KissFrame() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RNodeCommand) return false
            return command == other.command && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = command.toInt()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }
}

/**
 * RNode device information.
 */
data class RNodeDeviceInfo(
    val firmwareVersion: String = "",
    val protocolVersion: Int = 0,
    val platform: Int = 0,
    val board: Int = 0,
    val mcu: Int = 0,
    val hardwareSerial: ByteArray = ByteArray(0)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RNodeDeviceInfo) return false
        return firmwareVersion == other.firmwareVersion &&
                protocolVersion == other.protocolVersion &&
                platform == other.platform &&
                board == other.board &&
                mcu == other.mcu &&
                hardwareSerial.contentEquals(other.hardwareSerial)
    }

    override fun hashCode(): Int {
        var result = firmwareVersion.hashCode()
        result = 31 * result + protocolVersion
        result = 31 * result + platform
        result = 31 * result + board
        result = 31 * result + mcu
        result = 31 * result + hardwareSerial.contentHashCode()
        return result
    }
}

/**
 * RNode radio configuration.
 */
data class RNodeRadioConfig(
    val frequencyHz: Long = 915_000_000,
    val bandwidthHz: Long = 125_000,
    val spreadingFactor: Int = 10,
    val codingRate: Int = 5,
    val txPowerDbm: Int = 17
)
