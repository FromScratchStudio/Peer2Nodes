package com.fromscratchstudio.peer2nodes

import java.time.Instant
import java.util.UUID

enum class PeerMessageType {
    HELLO,
    HELLO_ACK,
    OFFER,
    ANSWER,
    CANDIDATE,
    DATA,
    HEARTBEAT,
    GOODBYE,
    ERROR
}

enum class PeerCapability(val wireValue: String) {
    WEBRTC_DATA_CHANNEL("webrtc-data-channel"),
    WIFI_DIRECT("wifi-direct"),
    WIFI_AWARE("wifi-aware"),
    BLE_GATT("ble-gatt"),
    END_TO_END_ENCRYPTION("end-to-end-encryption"),
    FILE_TRANSFER("file-transfer"),
    STREAMING("streaming")
}

enum class PeerTransportKind(val wireValue: String) {
    WEBRTC("webrtc"),
    WIFI_DIRECT("wifi-direct"),
    WIFI_AWARE("wifi-aware"),
    BLE("ble")
}

enum class PeerPayloadEncoding {
    JSON,
    UTF8,
    BASE64,
    BINARY
}

enum class PeerEncryptionMode(val wireValue: String) {
    NONE("none"),
    DTLS("dtls"),
    NOISE_XK("noise-xk"),
    TLS("tls")
}

data class PeerNegotiation(
    val transport: PeerTransportKind,
    val sdp: String? = null,
    val candidate: String? = null
)

data class PeerPayload(
    val contentType: String,
    val encoding: PeerPayloadEncoding,
    val body: String
)

data class PeerSecurity(
    val encryption: PeerEncryptionMode,
    val signature: String? = null,
    val keyId: String? = null
)

data class PeerFailure(
    val code: String,
    val message: String,
    val retryable: Boolean = false
)

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
)

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
    val nodeId: String = UUID.randomUUID().toString().lowercase(),
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
        val sessionId = UUID.randomUUID().toString().lowercase()
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
            SessionState(targetNodeId = null, lastReceivedAt = now(), nextSequence = 0, connected = false)
        }
        val sequence = state.nextSequence
        state.nextSequence += 1
        return sequence
    }
}
