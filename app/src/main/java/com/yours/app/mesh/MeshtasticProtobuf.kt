package com.yours.app.mesh

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Manual Protocol Buffer encoding/decoding for Meshtastic messages.
 *
 * This implements the subset of Meshtastic protobufs needed for basic messaging.
 * Full protobuf support would require adding the protobuf-lite dependency and
 * generating classes from the .proto files.
 *
 * Reference: https://github.com/meshtastic/protobufs
 *
 * Protobuf wire format:
 * - Each field: (field_number << 3) | wire_type
 * - Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
 */
object MeshtasticProtobuf {

    // =========================================================================
    // WIRE TYPES
    // =========================================================================

    private const val WIRE_VARINT = 0
    private const val WIRE_64BIT = 1
    private const val WIRE_LENGTH_DELIMITED = 2
    private const val WIRE_32BIT = 5

    // =========================================================================
    // PORT NUMBERS (from portnums.proto)
    // =========================================================================

    object PortNum {
        const val UNKNOWN_APP = 0
        const val TEXT_MESSAGE_APP = 1
        const val REMOTE_HARDWARE_APP = 2
        const val POSITION_APP = 3
        const val NODEINFO_APP = 4
        const val ROUTING_APP = 5
        const val ADMIN_APP = 6
        const val TEXT_MESSAGE_COMPRESSED_APP = 7
        const val WAYPOINT_APP = 8
        const val AUDIO_APP = 9
        const val DETECTION_SENSOR_APP = 10
        const val REPLY_APP = 32
        const val IP_TUNNEL_APP = 33
        const val PAXCOUNTER_APP = 34
        const val SERIAL_APP = 64
        const val STORE_FORWARD_APP = 65
        const val RANGE_TEST_APP = 66
        const val TELEMETRY_APP = 67
        const val ZPS_APP = 68
        const val SIMULATOR_APP = 69
        const val TRACEROUTE_APP = 70
        const val NEIGHBORINFO_APP = 71
        const val ATAK_PLUGIN = 72
        const val MAP_REPORT_APP = 73
        const val PRIVATE_APP = 256
        const val ATAK_FORWARDER = 257
        const val MAX = 511
    }

    // =========================================================================
    // DATA CLASSES
    // =========================================================================

    /**
     * Decoded data payload within a MeshPacket.
     */
    data class Data(
        val portnum: Int = PortNum.UNKNOWN_APP,
        val payload: ByteArray = ByteArray(0),
        val wantResponse: Boolean = false,
        val dest: Long = 0,
        val source: Long = 0,
        val requestId: Long = 0,
        val replyId: Long = 0,
        val emoji: Long = 0
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Data) return false
            return portnum == other.portnum && payload.contentEquals(other.payload)
        }
        override fun hashCode(): Int = payload.contentHashCode()
    }

    /**
     * A mesh packet - the core message type.
     */
    data class MeshPacket(
        val from: Long = 0,
        val to: Long = 0,
        val channel: Int = 0,
        val decoded: Data? = null,
        val encrypted: ByteArray? = null,
        val id: Long = 0,
        val rxTime: Long = 0,
        val rxSnr: Float = 0f,
        val hopLimit: Int = 3,
        val wantAck: Boolean = false,
        val priority: Int = 0,
        val rxRssi: Int = 0,
        val delayed: Int = 0,
        val viaMqtt: Boolean = false,
        val hopStart: Int = 0
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is MeshPacket) return false
            return id == other.id
        }
        override fun hashCode(): Int = id.hashCode()
    }

    /**
     * User info for a node.
     */
    data class User(
        val id: String = "",
        val longName: String = "",
        val shortName: String = "",
        val macaddr: ByteArray = ByteArray(0),
        val hwModel: Int = 0,
        val isLicensed: Boolean = false,
        val role: Int = 0
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is User) return false
            return id == other.id
        }
        override fun hashCode(): Int = id.hashCode()
    }

    /**
     * Position info.
     */
    data class Position(
        val latitudeI: Int = 0,
        val longitudeI: Int = 0,
        val altitude: Int = 0,
        val time: Long = 0,
        val locationSource: Int = 0,
        val altitudeSource: Int = 0,
        val timestamp: Long = 0,
        val timestampMillisAdjust: Int = 0,
        val altitudeHae: Int = 0,
        val altitudeGeoidalSeparation: Int = 0,
        val pdop: Int = 0,
        val hdop: Int = 0,
        val vdop: Int = 0,
        val gpsAccuracy: Int = 0,
        val groundSpeed: Int = 0,
        val groundTrack: Int = 0,
        val fixQuality: Int = 0,
        val fixType: Int = 0,
        val satsInView: Int = 0,
        val sensorId: Int = 0,
        val nextUpdate: Int = 0,
        val seqNumber: Int = 0
    ) {
        val latitude: Double get() = latitudeI * 1e-7
        val longitude: Double get() = longitudeI * 1e-7
    }

    /**
     * Node info - describes a node in the mesh.
     */
    data class NodeInfo(
        val num: Long = 0,
        val user: User? = null,
        val position: Position? = null,
        val snr: Float = 0f,
        val lastHeard: Long = 0,
        val deviceMetrics: DeviceMetrics? = null,
        val channel: Int = 0,
        val viaMqtt: Boolean = false,
        val hopsAway: Int = 0,
        val isFavorite: Boolean = false
    )

    /**
     * Device metrics (battery, voltage, etc.)
     */
    data class DeviceMetrics(
        val batteryLevel: Int = 0,
        val voltage: Float = 0f,
        val channelUtilization: Float = 0f,
        val airUtilTx: Float = 0f,
        val uptimeSeconds: Long = 0
    )

    /**
     * My node info - info about the local node.
     */
    data class MyNodeInfo(
        val myNodeNum: Long = 0,
        val rebootCount: Int = 0,
        val minAppVersion: Int = 0,
        val messageTimeoutMsec: Int = 0,
        val firmwareVersion: String = "",
        val hasWifi: Boolean = false,
        val hasBluetooth: Boolean = false,
        val positionFlags: Int = 0,
        val hwModel: Int = 0,
        val hasRemoteHardware: Boolean = false
    )

    /**
     * ToRadio - message sent TO the Meshtastic device.
     */
    sealed class ToRadio {
        data class SendPacket(val packet: MeshPacket) : ToRadio()
        data class WantConfigId(val configId: Long) : ToRadio()
        object Disconnect : ToRadio()
    }

    /**
     * FromRadio - message received FROM the Meshtastic device.
     */
    sealed class FromRadio {
        data class Packet(val packet: MeshPacket) : FromRadio()
        data class MyInfo(val info: MyNodeInfo) : FromRadio()
        data class NodeInfoMsg(val info: NodeInfo) : FromRadio()
        data class ConfigComplete(val id: Long) : FromRadio()
        data class Rebooted(val rebooted: Boolean) : FromRadio()
        object Unknown : FromRadio()
    }

    // =========================================================================
    // ENCODING
    // =========================================================================

    /**
     * Encode a ToRadio message.
     */
    fun encodeToRadio(msg: ToRadio): ByteArray {
        val out = ByteArrayOutputStream()

        when (msg) {
            is ToRadio.SendPacket -> {
                // Field 1: packet (MeshPacket)
                val packetBytes = encodeMeshPacket(msg.packet)
                writeTag(out, 1, WIRE_LENGTH_DELIMITED)
                writeVarint(out, packetBytes.size.toLong())
                out.write(packetBytes)
            }
            is ToRadio.WantConfigId -> {
                // Field 3: want_config_id (uint32)
                writeTag(out, 3, WIRE_VARINT)
                writeVarint(out, msg.configId)
            }
            is ToRadio.Disconnect -> {
                // Field 4: disconnect (bool)
                writeTag(out, 4, WIRE_VARINT)
                writeVarint(out, 1)
            }
        }

        return out.toByteArray()
    }

    /**
     * Encode a MeshPacket.
     */
    fun encodeMeshPacket(packet: MeshPacket): ByteArray {
        val out = ByteArrayOutputStream()

        // Field 1: from (fixed32)
        if (packet.from != 0L) {
            writeTag(out, 1, WIRE_32BIT)
            writeFixed32(out, packet.from.toInt())
        }

        // Field 2: to (fixed32)
        if (packet.to != 0L) {
            writeTag(out, 2, WIRE_32BIT)
            writeFixed32(out, packet.to.toInt())
        }

        // Field 3: channel (uint32)
        if (packet.channel != 0) {
            writeTag(out, 3, WIRE_VARINT)
            writeVarint(out, packet.channel.toLong())
        }

        // Field 4: decoded (Data) - oneof payload_variant
        if (packet.decoded != null) {
            val dataBytes = encodeData(packet.decoded)
            writeTag(out, 4, WIRE_LENGTH_DELIMITED)
            writeVarint(out, dataBytes.size.toLong())
            out.write(dataBytes)
        }

        // Field 5: encrypted (bytes) - oneof payload_variant
        if (packet.encrypted != null && packet.decoded == null) {
            writeTag(out, 5, WIRE_LENGTH_DELIMITED)
            writeVarint(out, packet.encrypted.size.toLong())
            out.write(packet.encrypted)
        }

        // Field 6: id (fixed32)
        if (packet.id != 0L) {
            writeTag(out, 6, WIRE_32BIT)
            writeFixed32(out, packet.id.toInt())
        }

        // Field 7: rx_time (fixed32)
        if (packet.rxTime != 0L) {
            writeTag(out, 7, WIRE_32BIT)
            writeFixed32(out, packet.rxTime.toInt())
        }

        // Field 8: rx_snr (float)
        if (packet.rxSnr != 0f) {
            writeTag(out, 8, WIRE_32BIT)
            writeFloat(out, packet.rxSnr)
        }

        // Field 9: hop_limit (uint32)
        if (packet.hopLimit != 0) {
            writeTag(out, 9, WIRE_VARINT)
            writeVarint(out, packet.hopLimit.toLong())
        }

        // Field 10: want_ack (bool)
        if (packet.wantAck) {
            writeTag(out, 10, WIRE_VARINT)
            writeVarint(out, 1)
        }

        // Field 11: priority (enum)
        if (packet.priority != 0) {
            writeTag(out, 11, WIRE_VARINT)
            writeVarint(out, packet.priority.toLong())
        }

        // Field 12: rx_rssi (int32)
        if (packet.rxRssi != 0) {
            writeTag(out, 12, WIRE_VARINT)
            writeVarint(out, packet.rxRssi.toLong())
        }

        return out.toByteArray()
    }

    /**
     * Encode a Data message.
     */
    fun encodeData(data: Data): ByteArray {
        val out = ByteArrayOutputStream()

        // Field 1: portnum (enum)
        if (data.portnum != 0) {
            writeTag(out, 1, WIRE_VARINT)
            writeVarint(out, data.portnum.toLong())
        }

        // Field 2: payload (bytes)
        if (data.payload.isNotEmpty()) {
            writeTag(out, 2, WIRE_LENGTH_DELIMITED)
            writeVarint(out, data.payload.size.toLong())
            out.write(data.payload)
        }

        // Field 3: want_response (bool)
        if (data.wantResponse) {
            writeTag(out, 3, WIRE_VARINT)
            writeVarint(out, 1)
        }

        // Field 4: dest (fixed32)
        if (data.dest != 0L) {
            writeTag(out, 4, WIRE_32BIT)
            writeFixed32(out, data.dest.toInt())
        }

        // Field 5: source (fixed32)
        if (data.source != 0L) {
            writeTag(out, 5, WIRE_32BIT)
            writeFixed32(out, data.source.toInt())
        }

        // Field 6: request_id (fixed32)
        if (data.requestId != 0L) {
            writeTag(out, 6, WIRE_32BIT)
            writeFixed32(out, data.requestId.toInt())
        }

        return out.toByteArray()
    }

    // =========================================================================
    // DECODING
    // =========================================================================

    /**
     * Decode a FromRadio message.
     */
    fun decodeFromRadio(bytes: ByteArray): FromRadio {
        val input = ByteArrayInputStream(bytes)
        var packet: MeshPacket? = null
        var myInfo: MyNodeInfo? = null
        var nodeInfo: NodeInfo? = null
        var configCompleteId: Long? = null
        var rebooted: Boolean? = null

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> { // packet (MeshPacket)
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        packet = decodeMeshPacket(data)
                    }
                }
                2 -> { // my_info (MyNodeInfo)
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        myInfo = decodeMyNodeInfo(data)
                    }
                }
                3 -> { // node_info (NodeInfo)
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        nodeInfo = decodeNodeInfo(data)
                    }
                }
                5 -> { // config_complete_id (uint32)
                    if (wireType == WIRE_VARINT) {
                        configCompleteId = readVarint(input)
                    }
                }
                8 -> { // rebooted (bool)
                    if (wireType == WIRE_VARINT) {
                        rebooted = readVarint(input) != 0L
                    }
                }
                else -> skipField(input, wireType)
            }
        }

        return when {
            packet != null -> FromRadio.Packet(packet)
            myInfo != null -> FromRadio.MyInfo(myInfo)
            nodeInfo != null -> FromRadio.NodeInfoMsg(nodeInfo)
            configCompleteId != null -> FromRadio.ConfigComplete(configCompleteId)
            rebooted != null -> FromRadio.Rebooted(rebooted)
            else -> FromRadio.Unknown
        }
    }

    /**
     * Decode a MeshPacket.
     */
    fun decodeMeshPacket(bytes: ByteArray): MeshPacket {
        val input = ByteArrayInputStream(bytes)
        var from = 0L
        var to = 0L
        var channel = 0
        var decoded: Data? = null
        var encrypted: ByteArray? = null
        var id = 0L
        var rxTime = 0L
        var rxSnr = 0f
        var hopLimit = 3
        var wantAck = false
        var priority = 0
        var rxRssi = 0

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> from = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                2 -> to = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                3 -> channel = readVarint(input).toInt()
                4 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        decoded = decodeData(data)
                    }
                }
                5 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        encrypted = ByteArray(length)
                        input.read(encrypted)
                    }
                }
                6 -> id = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                7 -> rxTime = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                8 -> rxSnr = if (wireType == WIRE_32BIT) readFloat(input) else readVarint(input).toFloat()
                9 -> hopLimit = readVarint(input).toInt()
                10 -> wantAck = readVarint(input) != 0L
                11 -> priority = readVarint(input).toInt()
                12 -> rxRssi = readVarint(input).toInt()
                else -> skipField(input, wireType)
            }
        }

        return MeshPacket(
            from = from,
            to = to,
            channel = channel,
            decoded = decoded,
            encrypted = encrypted,
            id = id,
            rxTime = rxTime,
            rxSnr = rxSnr,
            hopLimit = hopLimit,
            wantAck = wantAck,
            priority = priority,
            rxRssi = rxRssi
        )
    }

    /**
     * Decode a Data message.
     */
    fun decodeData(bytes: ByteArray): Data {
        val input = ByteArrayInputStream(bytes)
        var portnum = 0
        var payload = ByteArray(0)
        var wantResponse = false
        var dest = 0L
        var source = 0L
        var requestId = 0L

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> portnum = readVarint(input).toInt()
                2 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        payload = ByteArray(length)
                        input.read(payload)
                    }
                }
                3 -> wantResponse = readVarint(input) != 0L
                4 -> dest = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                5 -> source = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                6 -> requestId = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                else -> skipField(input, wireType)
            }
        }

        return Data(
            portnum = portnum,
            payload = payload,
            wantResponse = wantResponse,
            dest = dest,
            source = source,
            requestId = requestId
        )
    }

    /**
     * Decode MyNodeInfo.
     */
    fun decodeMyNodeInfo(bytes: ByteArray): MyNodeInfo {
        val input = ByteArrayInputStream(bytes)
        var myNodeNum = 0L
        var rebootCount = 0
        var minAppVersion = 0
        var firmwareVersion = ""

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> myNodeNum = readVarint(input)
                8 -> rebootCount = readVarint(input).toInt()
                11 -> minAppVersion = readVarint(input).toInt()
                else -> skipField(input, wireType)
            }
        }

        return MyNodeInfo(
            myNodeNum = myNodeNum,
            rebootCount = rebootCount,
            minAppVersion = minAppVersion,
            firmwareVersion = firmwareVersion
        )
    }

    /**
     * Decode NodeInfo.
     */
    fun decodeNodeInfo(bytes: ByteArray): NodeInfo {
        val input = ByteArrayInputStream(bytes)
        var num = 0L
        var user: User? = null
        var position: Position? = null
        var snr = 0f
        var lastHeard = 0L
        var channel = 0

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> num = readVarint(input)
                2 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        user = decodeUser(data)
                    }
                }
                3 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        position = decodePosition(data)
                    }
                }
                4 -> snr = if (wireType == WIRE_32BIT) readFloat(input) else readVarint(input).toFloat()
                5 -> lastHeard = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                8 -> channel = readVarint(input).toInt()
                else -> skipField(input, wireType)
            }
        }

        return NodeInfo(
            num = num,
            user = user,
            position = position,
            snr = snr,
            lastHeard = lastHeard,
            channel = channel
        )
    }

    /**
     * Decode User.
     */
    fun decodeUser(bytes: ByteArray): User {
        val input = ByteArrayInputStream(bytes)
        var id = ""
        var longName = ""
        var shortName = ""
        var macaddr = ByteArray(0)
        var hwModel = 0
        var isLicensed = false
        var role = 0

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        id = String(data, Charsets.UTF_8)
                    }
                }
                2 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        longName = String(data, Charsets.UTF_8)
                    }
                }
                3 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        val data = ByteArray(length)
                        input.read(data)
                        shortName = String(data, Charsets.UTF_8)
                    }
                }
                4 -> {
                    if (wireType == WIRE_LENGTH_DELIMITED) {
                        val length = readVarint(input).toInt()
                        macaddr = ByteArray(length)
                        input.read(macaddr)
                    }
                }
                5 -> hwModel = readVarint(input).toInt()
                6 -> isLicensed = readVarint(input) != 0L
                7 -> role = readVarint(input).toInt()
                else -> skipField(input, wireType)
            }
        }

        return User(
            id = id,
            longName = longName,
            shortName = shortName,
            macaddr = macaddr,
            hwModel = hwModel,
            isLicensed = isLicensed,
            role = role
        )
    }

    /**
     * Decode Position.
     */
    fun decodePosition(bytes: ByteArray): Position {
        val input = ByteArrayInputStream(bytes)
        var latitudeI = 0
        var longitudeI = 0
        var altitude = 0
        var time = 0L

        while (input.available() > 0) {
            val tag = readTag(input) ?: break
            val fieldNumber = tag shr 3
            val wireType = tag and 0x07

            when (fieldNumber) {
                1 -> latitudeI = readVarint(input).toInt() // sfixed32 stored as varint in some versions
                2 -> longitudeI = readVarint(input).toInt()
                3 -> altitude = readVarint(input).toInt()
                4 -> time = if (wireType == WIRE_32BIT) readFixed32(input).toLong() and 0xFFFFFFFFL else readVarint(input)
                else -> skipField(input, wireType)
            }
        }

        return Position(
            latitudeI = latitudeI,
            longitudeI = longitudeI,
            altitude = altitude,
            time = time
        )
    }

    // =========================================================================
    // PRIMITIVE ENCODING/DECODING
    // =========================================================================

    private fun writeTag(out: ByteArrayOutputStream, fieldNumber: Int, wireType: Int) {
        writeVarint(out, ((fieldNumber shl 3) or wireType).toLong())
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (v and 0x7F.inv() != 0L) {
            out.write(((v.toInt() and 0x7F) or 0x80))
            v = v ushr 7
        }
        out.write(v.toInt() and 0x7F)
    }

    private fun writeFixed32(out: ByteArrayOutputStream, value: Int) {
        out.write(value and 0xFF)
        out.write((value shr 8) and 0xFF)
        out.write((value shr 16) and 0xFF)
        out.write((value shr 24) and 0xFF)
    }

    private fun writeFloat(out: ByteArrayOutputStream, value: Float) {
        writeFixed32(out, java.lang.Float.floatToIntBits(value))
    }

    private fun readTag(input: ByteArrayInputStream): Int? {
        if (input.available() <= 0) return null
        return readVarint(input).toInt()
    }

    private fun readVarint(input: ByteArrayInputStream): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = input.read()
            if (b == -1) break
            result = result or ((b.toLong() and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return result
    }

    private fun readFixed32(input: ByteArrayInputStream): Int {
        val b0 = input.read()
        val b1 = input.read()
        val b2 = input.read()
        val b3 = input.read()
        return (b0 and 0xFF) or
               ((b1 and 0xFF) shl 8) or
               ((b2 and 0xFF) shl 16) or
               ((b3 and 0xFF) shl 24)
    }

    private fun readFloat(input: ByteArrayInputStream): Float {
        return java.lang.Float.intBitsToFloat(readFixed32(input))
    }

    private fun skipField(input: ByteArrayInputStream, wireType: Int) {
        when (wireType) {
            WIRE_VARINT -> readVarint(input)
            WIRE_64BIT -> input.skip(8)
            WIRE_LENGTH_DELIMITED -> {
                val length = readVarint(input).toInt()
                input.skip(length.toLong())
            }
            WIRE_32BIT -> input.skip(4)
        }
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /**
     * Create a text message packet.
     */
    fun createTextMessage(
        text: String,
        to: Long = 0xFFFFFFFF, // Broadcast
        channel: Int = 0,
        wantAck: Boolean = true
    ): ToRadio {
        val data = Data(
            portnum = PortNum.TEXT_MESSAGE_APP,
            payload = text.toByteArray(Charsets.UTF_8),
            wantResponse = wantAck
        )

        val packet = MeshPacket(
            to = to,
            decoded = data,
            id = (System.currentTimeMillis() and 0xFFFFFFFF), // Use timestamp as ID
            channel = channel,
            wantAck = wantAck,
            hopLimit = 3
        )

        return ToRadio.SendPacket(packet)
    }

    /**
     * Create a private app message (for our encrypted payloads).
     */
    fun createPrivateMessage(
        payload: ByteArray,
        to: Long,
        channel: Int = 0,
        wantAck: Boolean = true
    ): ToRadio {
        val data = Data(
            portnum = PortNum.PRIVATE_APP,
            payload = payload,
            wantResponse = wantAck
        )

        val packet = MeshPacket(
            to = to,
            decoded = data,
            id = (System.currentTimeMillis() and 0xFFFFFFFF),
            channel = channel,
            wantAck = wantAck,
            hopLimit = 3
        )

        return ToRadio.SendPacket(packet)
    }

    /**
     * Request config from the device.
     */
    fun createWantConfig(configId: Long = 0): ToRadio {
        return ToRadio.WantConfigId(configId)
    }
}
