package com.fromscratchstudio.peer2nodes

enum class WebRTCSignalType {
    OFFER,
    ANSWER,
    CANDIDATE
}

data class WebRTCSignal(
    val sourceNodeId: String,
    val targetNodeId: String,
    val sessionId: String? = null,
    val type: WebRTCSignalType,
    val sdp: String? = null,
    val candidate: String? = null
)

fun interface WebRTCSignalHandler {
    fun onSignal(signal: WebRTCSignal)
}

interface WebRTCSignalingClient {
    fun start(handler: WebRTCSignalHandler)
    fun stop()
    fun send(signal: WebRTCSignal)
}

fun interface WebRTCDataHandler {
    fun onData(remoteNodeId: String, payload: ByteArray)
}

fun interface WebRTCIceCandidateHandler {
    fun onIceCandidate(remoteNodeId: String, candidate: String)
}

interface WebRTCEngine {
    fun setDataHandler(handler: WebRTCDataHandler)
    fun setIceCandidateHandler(handler: WebRTCIceCandidateHandler)
    fun start()
    fun stop()
    fun createOffer(remoteNodeId: String): String
    fun createAnswer(remoteNodeId: String, offerSdp: String): String
    fun applyAnswer(remoteNodeId: String, answerSdp: String)
    fun addIceCandidate(remoteNodeId: String, candidate: String)

    /**
     * Sends [payload] to [remoteNodeId] over the WebRTC data channel.
     *
     * **Buffering contract:** Implementations MUST buffer outbound data internally
     * until the underlying data channel reaches the OPEN state, then drain the
     * buffer. Throwing or silently dropping data before the channel is open is
     * not permitted — [WebRTCPeerTransport.send] may be called before the channel
     * is ready (e.g. for the initial HELLO frame) and relies on the engine to
     * handle that case transparently.
     */
    fun send(remoteNodeId: String, payload: ByteArray)
}

interface PeerEnvelopeCodec {
    fun encode(envelope: PeerEnvelope): ByteArray
    fun decode(payload: ByteArray): PeerEnvelope
}

class WebRTCPeerTransport(
    private val nodeId: String,
    private val signaling: WebRTCSignalingClient,
    private val engine: WebRTCEngine,
    private val codec: PeerEnvelopeCodec
) : PeerTransport {
    private var handler: PeerTransportHandler? = null
    private val announcedPeers = mutableSetOf<String>()
    private val sessionTargets = mutableMapOf<String, String>() // sessionId -> remoteNodeId
    var onTransportError: ((Throwable) -> Unit)? = null

    override fun setMessageHandler(handler: PeerTransportHandler) {
        this.handler = handler
    }

    override fun start() {
        engine.setDataHandler(WebRTCDataHandler { remoteNodeId, payload ->
            runCatching { codec.decode(payload) }
                .onSuccess { envelope ->
                    if (envelope.sessionId.isNotBlank()) {
                        sessionTargets[envelope.sessionId] = remoteNodeId
                    }
                    handler?.onEnvelope(envelope)
                }
                .onFailure { error ->
                    onTransportError?.invoke(error)
                }
        })

        engine.setIceCandidateHandler(WebRTCIceCandidateHandler { remoteNodeId, candidate ->
            runCatching {
                signaling.send(
                    WebRTCSignal(
                        sourceNodeId = nodeId,
                        targetNodeId = remoteNodeId,
                        type = WebRTCSignalType.CANDIDATE,
                        candidate = candidate
                    )
                )
            }.onFailure { error -> onTransportError?.invoke(error) }
        })

        signaling.start(WebRTCSignalHandler { signal ->
            handleIncomingSignal(signal)
        })
        engine.start()
    }

    override fun stop() {
        signaling.stop()
        engine.stop()
        announcedPeers.clear()
        sessionTargets.clear()
    }

    override fun send(envelope: PeerEnvelope) {
        val remoteNodeId = envelope.targetNodeId ?: sessionTargets[envelope.sessionId]
            ?: throw IllegalArgumentException("targetNodeId is required for WebRTC transport")

        sessionTargets[envelope.sessionId] = remoteNodeId
        ensureOfferSentIfNeeded(remoteNodeId = remoteNodeId, sessionId = envelope.sessionId)
        engine.send(remoteNodeId, codec.encode(envelope))
    }

    private fun ensureOfferSentIfNeeded(remoteNodeId: String, sessionId: String) {
        if (announcedPeers.contains(remoteNodeId)) return
        val offerSdp = engine.createOffer(remoteNodeId)
        signaling.send(
            WebRTCSignal(
                sourceNodeId = nodeId,
                targetNodeId = remoteNodeId,
                sessionId = sessionId,
                type = WebRTCSignalType.OFFER,
                sdp = offerSdp
            )
        )
        announcedPeers += remoteNodeId
    }

    private fun handleIncomingSignal(signal: WebRTCSignal) {
        if (signal.targetNodeId != nodeId) return
        signal.sessionId?.let { sessionTargets[it] = signal.sourceNodeId }

        when (signal.type) {
            WebRTCSignalType.OFFER -> {
                val offer = signal.sdp ?: return
                runCatching {
                    announcedPeers += signal.sourceNodeId
                    val answerSdp = engine.createAnswer(signal.sourceNodeId, offer)
                    signaling.send(
                        WebRTCSignal(
                            sourceNodeId = nodeId,
                            targetNodeId = signal.sourceNodeId,
                            sessionId = signal.sessionId,
                            type = WebRTCSignalType.ANSWER,
                            sdp = answerSdp
                        )
                    )
                }.onFailure { error -> onTransportError?.invoke(error) }
            }
            WebRTCSignalType.ANSWER -> {
                val answer = signal.sdp ?: return
                runCatching { engine.applyAnswer(signal.sourceNodeId, answer) }
                    .onFailure { error -> onTransportError?.invoke(error) }
            }
            WebRTCSignalType.CANDIDATE -> {
                val candidate = signal.candidate ?: return
                runCatching { engine.addIceCandidate(signal.sourceNodeId, candidate) }
                    .onFailure { error -> onTransportError?.invoke(error) }
            }
        }
    }
}
