import Foundation

public enum WebRTCSignalType: String, Codable {
    case offer
    case answer
    case candidate
}

public struct WebRTCSignal: Codable, Equatable {
    public let sourceNodeId: String
    public let targetNodeId: String
    public let sessionId: String?
    public let type: WebRTCSignalType
    public let sdp: String?
    public let candidate: String?

    public init(
        sourceNodeId: String,
        targetNodeId: String,
        sessionId: String? = nil,
        type: WebRTCSignalType,
        sdp: String? = nil,
        candidate: String? = nil
    ) {
        self.sourceNodeId = sourceNodeId
        self.targetNodeId = targetNodeId
        self.sessionId = sessionId
        self.type = type
        self.sdp = sdp
        self.candidate = candidate
    }
}

public protocol WebRTCSignalingClient: AnyObject {
    func start(onSignal: @escaping (WebRTCSignal) -> Void) throws
    func stop()
    func send(_ signal: WebRTCSignal) throws
}

public protocol WebRTCEngine: AnyObject {
    var onIceCandidate: ((String, String) -> Void)? { get set } // remoteNodeId, candidate
    var onData: ((String, Data) -> Void)? { get set } // remoteNodeId, payload

    func start() throws
    func stop()
    func createOffer(for remoteNodeId: String) throws -> String
    func createAnswer(for remoteNodeId: String, offerSdp: String) throws -> String
    func applyAnswer(_ sdp: String, from remoteNodeId: String) throws
    func addIceCandidate(_ candidate: String, from remoteNodeId: String) throws
    func send(_ data: Data, to remoteNodeId: String) throws
}

public final class WebRTCPeerTransport: PeerTransport {
    private let nodeId: String
    private let signaling: WebRTCSignalingClient
    private let engine: WebRTCEngine
    private var handler: ((PeerEnvelope) -> Void)?
    private var announcedPeers = Set<String>()
    private var sessionTargets: [String: String] = [:] // sessionId -> remoteNodeId

    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    public init(nodeId: String, signaling: WebRTCSignalingClient, engine: WebRTCEngine) {
        self.nodeId = nodeId
        self.signaling = signaling
        self.engine = engine
    }

    public func setMessageHandler(_ handler: @escaping (PeerEnvelope) -> Void) {
        self.handler = handler
    }

    public func start() throws {
        engine.onData = { [weak self] remoteNodeId, payload in
            guard let self else { return }
            do {
                let envelope = try self.decoder.decode(PeerEnvelope.self, from: payload)
                self.sessionTargets[envelope.sessionId] = remoteNodeId
                self.handler?(envelope)
            } catch {
                // malformed payload; ignored by design
            }
        }

        engine.onIceCandidate = { [weak self] remoteNodeId, candidate in
            guard let self else { return }
            try? self.signaling.send(
                WebRTCSignal(
                    sourceNodeId: self.nodeId,
                    targetNodeId: remoteNodeId,
                    type: .candidate,
                    candidate: candidate
                )
            )
        }

        try signaling.start { [weak self] signal in
            self?.handleIncomingSignal(signal)
        }
        try engine.start()
    }

    public func stop() {
        signaling.stop()
        engine.stop()
        announcedPeers.removeAll()
        sessionTargets.removeAll()
    }

    public func send(_ envelope: PeerEnvelope) throws {
        guard let remoteNodeId = envelope.targetNodeId ?? sessionTargets[envelope.sessionId] else {
            throw NSError(
                domain: "Peer2Nodes.WebRTCPeerTransport",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "targetNodeId is required for WebRTC transport"]
            )
        }
        sessionTargets[envelope.sessionId] = remoteNodeId
        try ensureOfferSentIfNeeded(to: remoteNodeId, sessionId: envelope.sessionId)
        let data = try encoder.encode(envelope)
        try engine.send(data, to: remoteNodeId)
    }

    private func ensureOfferSentIfNeeded(to remoteNodeId: String, sessionId: String) throws {
        if announcedPeers.contains(remoteNodeId) { return }
        announcedPeers.insert(remoteNodeId)
        let offerSdp = try engine.createOffer(for: remoteNodeId)
        try signaling.send(
            WebRTCSignal(
                sourceNodeId: nodeId,
                targetNodeId: remoteNodeId,
                sessionId: sessionId,
                type: .offer,
                sdp: offerSdp
            )
        )
    }

    private func handleIncomingSignal(_ signal: WebRTCSignal) {
        guard signal.targetNodeId == nodeId else { return }
        if let sessionId = signal.sessionId {
            sessionTargets[sessionId] = signal.sourceNodeId
        }

        do {
            switch signal.type {
            case .offer:
                guard let offerSdp = signal.sdp else { return }
                announcedPeers.insert(signal.sourceNodeId)
                let answerSdp = try engine.createAnswer(for: signal.sourceNodeId, offerSdp: offerSdp)
                try signaling.send(
                    WebRTCSignal(
                        sourceNodeId: nodeId,
                        targetNodeId: signal.sourceNodeId,
                        sessionId: signal.sessionId,
                        type: .answer,
                        sdp: answerSdp
                    )
                )
            case .answer:
                guard let answerSdp = signal.sdp else { return }
                try engine.applyAnswer(answerSdp, from: signal.sourceNodeId)
            case .candidate:
                guard let candidate = signal.candidate else { return }
                try engine.addIceCandidate(candidate, from: signal.sourceNodeId)
            }
        } catch {
            // Signaling/engine errors are intentionally swallowed at transport level.
        }
    }
}
