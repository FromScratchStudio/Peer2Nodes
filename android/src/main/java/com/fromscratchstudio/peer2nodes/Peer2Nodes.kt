package com.fromscratchstudio.peer2nodes

import java.time.Instant
import java.util.UUID

enum class PeerMessageType(val wireValue: String) {
    HELLO("HELLO"),
    HELLO_ACK("HELLO_ACK"),
    OFFER("OFFER"),
    ANSWER("ANSWER"),
    CANDIDATE("CANDIDATE"),
    DATA("DATA"),
    HEARTBEAT("HEARTBEAT"),
    GOODBYE("GOODBYE"),
    ERROR("ERROR");

    companion object {
        fun fromWireValue(value: String): PeerMessageType {
            return entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported messageType: $value")
        }
    }
}

enum class PeerCapability(val wireValue: String) {
    WEBRTC_DATA_CHANNEL("webrtc-data-channel"),
    WIFI_DIRECT("wifi-direct"),
    WIFI_AWARE("wifi-aware"),
    BLE_GATT("ble-gatt"),
    END_TO_END_ENCRYPTION("end-to-end-encryption"),
    FILE_TRANSFER("file-transfer"),
    STREAMING("streaming");

    companion object {
        fun fromWireValue(value: String): PeerCapability {
            return entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported capability: $value")
        }
    }
}

enum class PeerTransportKind(val wireValue: String) {
    WEBRTC("webrtc"),
    WIFI_DIRECT("wifi-direct"),
    WIFI_AWARE("wifi-aware"),
    BLE("ble");

    companion object {
        fun fromWireValue(value: String): PeerTransportKind {
            return entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported transport: $value")
        }
    }
}

enum class PeerPayloadEncoding(val wireValue: String) {
    JSON("json"),
    UTF8("utf8"),
    BASE64("base64"),
    BINARY("binary");

    companion object {
        fun fromWireValue(value: String): PeerPayloadEncoding {
            return entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported payload encoding: $value")
        }
    }
}

enum class PeerEncryptionMode(val wireValue: String) {
    NONE("none"),
    DTLS("dtls"),
    NOISE_XK("noise-xk"),
    TLS("tls");

    companion object {
        fun fromWireValue(value: String): PeerEncryptionMode {
            return entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported encryption mode: $value")
        }
    }
}

data class PeerNegotiation(
    val transport: PeerTransportKind,
    val sdp: String? = null,
    val candidate: String? = null
) {
    fun toProtocolMap(): Map<String, Any> = buildMap {
        put("transport", transport.wireValue)
        sdp?.let { put("sdp", it) }
        candidate?.let { put("candidate", it) }
    }

    companion object {
        fun fromProtocolMap(map: Map<String, Any?>): PeerNegotiation {
            return PeerNegotiation(
                transport = PeerTransportKind.fromWireValue(map.requireString("transport")),
                sdp = map.string("sdp"),
                candidate = map.string("candidate")
            )
        }
    }
}

data class PeerPayload(
    val contentType: String,
    val encoding: PeerPayloadEncoding,
    val body: String
) {
    fun toProtocolMap(): Map<String, Any> = mapOf(
        "contentType" to contentType,
        "encoding" to encoding.wireValue,
        "body" to body
    )

    companion object {
        fun fromProtocolMap(map: Map<String, Any?>): PeerPayload {
            return PeerPayload(
                contentType = map.requireString("contentType"),
                encoding = PeerPayloadEncoding.fromWireValue(map.requireString("encoding")),
                body = map.requireString("body")
            )
        }
    }
}

data class PeerSecurity(
    val encryption: PeerEncryptionMode,
    val signature: String? = null,
    val keyId: String? = null
) {
    fun toProtocolMap(): Map<String, Any> = buildMap {
        put("encryption", encryption.wireValue)
        signature?.let { put("signature", it) }
        keyId?.let { put("keyId", it) }
    }

    companion object {
        fun fromProtocolMap(map: Map<String, Any?>): PeerSecurity {
            return PeerSecurity(
                encryption = PeerEncryptionMode.fromWireValue(map.requireString("encryption")),
                signature = map.string("signature"),
                keyId = map.string("keyId")
            )
        }
    }
}

data class PeerFailure(
    val code: String,
    val message: String,
    val retryable: Boolean = false
) {
    fun toProtocolMap(): Map<String, Any> = mapOf(
        "code" to code,
        "message" to message,
        "retryable" to retryable
    )

    companion object {
        fun fromProtocolMap(map: Map<String, Any?>): PeerFailure {
            return PeerFailure(
                code = map.requireString("code"),
                message = map.requireString("message"),
                retryable = map.boolean("retryable") ?: false
            )
        }
    }
}

data class PeerEnvelope(
    val protocolVersion: String,
    val messageType: PeerMessageType,
    val sessionId: String,
    val sourceNodeId: String,
    val targetNodeId: String? = null,
    val timestamp: Instant,
    val sequence: Int,
    val capabilities: List<PeerCapability>? = null,
    val negotiation: PeerNegotiation? = null,
    val payload: PeerPayload? = null,
    val security: PeerSecurity? = null,
    val error: PeerFailure? = null
) {
    fun toProtocolMap(): Map<String, Any> = buildMap {
        put("protocolVersion", protocolVersion)
        put("messageType", messageType.wireValue)
        put("sessionId", sessionId)
        put("sourceNodeId", sourceNodeId)
        targetNodeId?.let { put("targetNodeId", it) }
        put("timestamp", timestamp.toString())
        put("sequence", sequence)
        capabilities?.let { put("capabilities", it.map(PeerCapability::wireValue)) }
        negotiation?.let { put("negotiation", it.toProtocolMap()) }
        payload?.let { put("payload", it.toProtocolMap()) }
        security?.let { put("security", it.toProtocolMap()) }
        error?.let { put("error", it.toProtocolMap()) }
    }

    companion object {
        fun fromProtocolMap(map: Map<String, Any?>): PeerEnvelope {
            return PeerEnvelope(
                protocolVersion = map.requireString("protocolVersion"),
                messageType = PeerMessageType.fromWireValue(map.requireString("messageType")),
                sessionId = map.requireString("sessionId"),
                sourceNodeId = map.requireString("sourceNodeId"),
                targetNodeId = map.string("targetNodeId"),
                timestamp = Instant.parse(map.requireString("timestamp")),
                sequence = map.requireInt("sequence"),
                capabilities = map.stringList("capabilities")?.map(PeerCapability::fromWireValue),
                negotiation = map.mapValue("negotiation")?.let(PeerNegotiation::fromProtocolMap),
                payload = map.mapValue("payload")?.let(PeerPayload::fromProtocolMap),
                security = map.mapValue("security")?.let(PeerSecurity::fromProtocolMap),
                error = map.mapValue("error")?.let(PeerFailure::fromProtocolMap)
            )
        }
    }
}

private fun Map<String, Any?>.string(key: String): String? = this[key] as? String

private fun Map<String, Any?>.requireString(key: String): String {
    return string(key) ?: throw IllegalArgumentException("Missing or invalid string field: $key")
}

private fun Map<String, Any?>.requireInt(key: String): Int {
    val value = this[key]
    return when (value) {
        is Int -> value
        is Long -> value.toInt()
        is Number -> value.toInt()
        is String -> value.toIntOrNull()
        else -> null
    } ?: throw IllegalArgumentException("Missing or invalid int field: $key")
}

private fun Map<String, Any?>.boolean(key: String): Boolean? = this[key] as? Boolean

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.mapValue(key: String): Map<String, Any?>? {
    return this[key] as? Map<String, Any?>
}

private fun Map<String, Any?>.stringList(key: String): List<String>? {
    val values = this[key] as? List<*> ?: return null
    return values.map {
        it as? String ?: throw IllegalArgumentException("Invalid string value in list field: $key")
    }
}

fun interface PeerTransportHandler {
    fun onEnvelope(envelope: PeerEnvelope)
}

interface PeerTransport {
    fun setMessageHandler(handler: PeerTransportHandler)
    fun start()
    fun stop()
    fun send(envelope: PeerEnvelope)
}

class LoopbackPeerTransport : PeerTransport {
    private var handler: PeerTransportHandler? = null
    private var remote: LoopbackPeerTransport? = null

    fun connect(remoteTransport: LoopbackPeerTransport) {
        remote = remoteTransport
    }

    override fun setMessageHandler(handler: PeerTransportHandler) {
        this.handler = handler
    }

    override fun start() = Unit

    override fun stop() = Unit

    override fun send(envelope: PeerEnvelope) {
        remote?.handler?.onEnvelope(envelope)
    }
}

class PeerNodeClient(
    val nodeId: String = UUID.randomUUID().toString(),
    private val protocolVersion: String = "1.0.0",
    private val capabilities: List<PeerCapability>,
    private val transport: PeerTransport,
    private val now: () -> Instant = { Instant.now() }
) {
    private data class SessionState(
        var targetNodeId: String?,
        var lastReceivedAt: Instant,
        var nextSequence: Int,
        var connected: Boolean
    )

    var onSessionOpened: ((String, String?) -> Unit)? = null
    var onData: ((PeerEnvelope) -> Unit)? = null
    var onFailure: ((PeerEnvelope) -> Unit)? = null
    var onSessionClosed: ((String) -> Unit)? = null

    private val sessions = mutableMapOf<String, SessionState>()

    fun start() {
        transport.setMessageHandler(PeerTransportHandler { envelope ->
            handleIncoming(envelope)
        })
        transport.start()
    }

    fun stop() {
        transport.stop()
        sessions.clear()
    }

    fun openSession(targetNodeId: String? = null): String {
        val sessionId = UUID.randomUUID().toString()
        sessions[sessionId] = SessionState(targetNodeId, now(), 1, false)
        transport.send(
            buildEnvelope(
                messageType = PeerMessageType.HELLO,
                sessionId = sessionId,
                targetNodeId = targetNodeId,
                capabilities = capabilities
            )
        )
        return sessionId
    }

    fun sendData(
        sessionId: String,
        body: String,
        targetNodeId: String? = null,
        contentType: String = "text/plain",
        encoding: PeerPayloadEncoding = PeerPayloadEncoding.UTF8
    ) {
        transport.send(
            buildEnvelope(
                messageType = PeerMessageType.DATA,
                sessionId = sessionId,
                targetNodeId = targetNodeId ?: sessions[sessionId]?.targetNodeId,
                payload = PeerPayload(contentType = contentType, encoding = encoding, body = body)
            )
        )
    }

    fun sendHeartbeat(sessionId: String, targetNodeId: String? = null) {
        transport.send(
            buildEnvelope(
                messageType = PeerMessageType.HEARTBEAT,
                sessionId = sessionId,
                targetNodeId = targetNodeId ?: sessions[sessionId]?.targetNodeId
            )
        )
    }

    fun disconnect(sessionId: String, targetNodeId: String? = null) {
        transport.send(
            buildEnvelope(
                messageType = PeerMessageType.GOODBYE,
                sessionId = sessionId,
                targetNodeId = targetNodeId ?: sessions[sessionId]?.targetNodeId
            )
        )
        sessions.remove(sessionId)
        onSessionClosed?.invoke(sessionId)
    }

    private fun handleIncoming(envelope: PeerEnvelope) {
        val state = sessions.getOrPut(envelope.sessionId) {
            SessionState(envelope.sourceNodeId, envelope.timestamp, envelope.sequence + 1, false)
        }
        state.targetNodeId = envelope.sourceNodeId
        state.lastReceivedAt = envelope.timestamp

        when (envelope.messageType) {
            PeerMessageType.HELLO -> {
                state.connected = true
                onSessionOpened?.invoke(envelope.sessionId, envelope.sourceNodeId)
                transport.send(
                    buildEnvelope(
                        messageType = PeerMessageType.HELLO_ACK,
                        sessionId = envelope.sessionId,
                        targetNodeId = envelope.sourceNodeId,
                        capabilities = capabilities
                    )
                )
            }
            PeerMessageType.HELLO_ACK -> {
                state.connected = true
                onSessionOpened?.invoke(envelope.sessionId, envelope.sourceNodeId)
            }
            PeerMessageType.DATA -> onData?.invoke(envelope)
            PeerMessageType.ERROR -> onFailure?.invoke(envelope)
            PeerMessageType.GOODBYE -> {
                sessions.remove(envelope.sessionId)
                onSessionClosed?.invoke(envelope.sessionId)
            }
            PeerMessageType.HEARTBEAT,
            PeerMessageType.OFFER,
            PeerMessageType.ANSWER,
            PeerMessageType.CANDIDATE -> Unit
        }
    }

    private fun buildEnvelope(
        messageType: PeerMessageType,
        sessionId: String,
        targetNodeId: String? = null,
        capabilities: List<PeerCapability>? = null,
        negotiation: PeerNegotiation? = null,
        payload: PeerPayload? = null,
        security: PeerSecurity? = null,
        error: PeerFailure? = null
    ): PeerEnvelope {
        return PeerEnvelope(
            protocolVersion = protocolVersion,
            messageType = messageType,
            sessionId = sessionId,
            sourceNodeId = nodeId,
            targetNodeId = targetNodeId,
            timestamp = now(),
            sequence = nextSequence(sessionId),
            capabilities = capabilities,
            negotiation = negotiation,
            payload = payload,
            security = security,
            error = error
        )
    }

    private fun nextSequence(sessionId: String): Int {
        val state = sessions.getOrPut(sessionId) {
            SessionState(targetNodeId = null, lastReceivedAt = now(), nextSequence = 1, connected = false)
        }
        val sequence = state.nextSequence
        state.nextSequence += 1
        return sequence
    }
}
