import Foundation

public enum PeerMessageType: String, Codable {
    case hello = "HELLO"
    case helloAck = "HELLO_ACK"
    case offer = "OFFER"
    case answer = "ANSWER"
    case candidate = "CANDIDATE"
    case data = "DATA"
    case heartbeat = "HEARTBEAT"
    case goodbye = "GOODBYE"
    case error = "ERROR"
}

public enum PeerCapability: String, Codable, CaseIterable {
    case webRTCDataChannel = "webrtc-data-channel"
    case wifiDirect = "wifi-direct"
    case wifiAware = "wifi-aware"
    case bleGatt = "ble-gatt"
    case endToEndEncryption = "end-to-end-encryption"
    case fileTransfer = "file-transfer"
    case streaming = "streaming"
}

public enum PeerTransportKind: String, Codable {
    case webrtc
    case wifiDirect = "wifi-direct"
    case wifiAware = "wifi-aware"
    case ble
}

public enum PeerPayloadEncoding: String, Codable {
    case json
    case utf8
    case base64
    case binary
}

public enum PeerEncryptionMode: String, Codable {
    case none
    case dtls
    case noiseXK = "noise-xk"
    case tls
}

public struct PeerNegotiation: Codable, Equatable {
    public let transport: PeerTransportKind
    public let sdp: String?
    public let candidate: String?

    public init(transport: PeerTransportKind, sdp: String? = nil, candidate: String? = nil) {
        self.transport = transport
        self.sdp = sdp
        self.candidate = candidate
    }
}

public struct PeerPayload: Codable, Equatable {
    public let contentType: String
    public let encoding: PeerPayloadEncoding
    public let body: String

    public init(contentType: String, encoding: PeerPayloadEncoding, body: String) {
        self.contentType = contentType
        self.encoding = encoding
        self.body = body
    }
}

public struct PeerSecurity: Codable, Equatable {
    public let encryption: PeerEncryptionMode
    public let signature: String?
    public let keyId: String?

    public init(encryption: PeerEncryptionMode, signature: String? = nil, keyId: String? = nil) {
        self.encryption = encryption
        self.signature = signature
        self.keyId = keyId
    }
}

public struct PeerFailure: Codable, Equatable {
    public let code: String
    public let message: String
    public let retryable: Bool

    public init(code: String, message: String, retryable: Bool = false) {
        self.code = code
        self.message = message
        self.retryable = retryable
    }
}

public struct PeerEnvelope: Codable, Equatable {
    public let protocolVersion: String
    public let messageType: PeerMessageType
    public let sessionId: String
    public let sourceNodeId: String
    public let targetNodeId: String?
    public let timestamp: Date
    public let sequence: Int
    public let capabilities: [PeerCapability]?
    public let negotiation: PeerNegotiation?
    public let payload: PeerPayload?
    public let security: PeerSecurity?
    public let error: PeerFailure?

    public init(
        protocolVersion: String,
        messageType: PeerMessageType,
        sessionId: String,
        sourceNodeId: String,
        targetNodeId: String? = nil,
        timestamp: Date,
        sequence: Int,
        capabilities: [PeerCapability]? = nil,
        negotiation: PeerNegotiation? = nil,
        payload: PeerPayload? = nil,
        security: PeerSecurity? = nil,
        error: PeerFailure? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageType = messageType
        self.sessionId = sessionId
        self.sourceNodeId = sourceNodeId
        self.targetNodeId = targetNodeId
        self.timestamp = timestamp
        self.sequence = sequence
        self.capabilities = capabilities
        self.negotiation = negotiation
        self.payload = payload
        self.security = security
        self.error = error
    }
}

public protocol PeerTransport: AnyObject {
    func setMessageHandler(_ handler: @escaping (PeerEnvelope) -> Void)
    func start() throws
    func stop()
    func send(_ envelope: PeerEnvelope) throws
}

public final class LoopbackPeerTransport: PeerTransport {
    private var handler: ((PeerEnvelope) -> Void)?
    private weak var remote: LoopbackPeerTransport?

    public init() {}

    public func connect(to remote: LoopbackPeerTransport) {
        self.remote = remote
    }

    public func setMessageHandler(_ handler: @escaping (PeerEnvelope) -> Void) {
        self.handler = handler
    }

    public func start() throws {}

    public func stop() {}

    public func send(_ envelope: PeerEnvelope) throws {
        remote?.handler?(envelope)
    }
}

public final class PeerNodeClient {
    private struct SessionState {
        var targetNodeId: String?
        var lastReceivedAt: Date
        var nextSequence: Int
        var connected: Bool
    }

    public let nodeId: String
    public let protocolVersion: String
    public let capabilities: [PeerCapability]

    public var onSessionOpened: ((String, String?) -> Void)?
    public var onData: ((PeerEnvelope) -> Void)?
    public var onFailure: ((PeerEnvelope) -> Void)?
    public var onSessionClosed: ((String) -> Void)?

    private let transport: PeerTransport
    private let dateProvider: () -> Date
    private var sessions: [String: SessionState] = [:]

    public init(
        nodeId: String = UUID().uuidString.lowercased(),
        protocolVersion: String = "1.0.0",
        capabilities: [PeerCapability],
        transport: PeerTransport,
        dateProvider: @escaping () -> Date = Date.init
    ) {
        self.nodeId = nodeId
        self.protocolVersion = protocolVersion
        self.capabilities = capabilities
        self.transport = transport
        self.dateProvider = dateProvider
    }

    public func start() throws {
        transport.setMessageHandler { [weak self] envelope in
            self?.handleIncoming(envelope)
        }
        try transport.start()
    }

    public func stop() {
        transport.stop()
        sessions.removeAll()
    }

    @discardableResult
    public func openSession(targetNodeId: String? = nil) throws -> String {
        let sessionId = UUID().uuidString.lowercased()
        sessions[sessionId] = SessionState(
            targetNodeId: targetNodeId,
            lastReceivedAt: dateProvider(),
            nextSequence: 1,
            connected: false
        )
        try transport.send(
            buildEnvelope(
                messageType: .hello,
                sessionId: sessionId,
                targetNodeId: targetNodeId,
                capabilities: capabilities
            )
        )
        return sessionId
    }

    public func sendData(
        sessionId: String,
        targetNodeId: String? = nil,
        contentType: String = "text/plain",
        encoding: PeerPayloadEncoding = .utf8,
        body: String
    ) throws {
        try transport.send(
            buildEnvelope(
                messageType: .data,
                sessionId: sessionId,
                targetNodeId: targetNodeId ?? sessions[sessionId]?.targetNodeId,
                payload: PeerPayload(contentType: contentType, encoding: encoding, body: body)
            )
        )
    }

    public func sendHeartbeat(sessionId: String, targetNodeId: String? = nil) throws {
        try transport.send(
            buildEnvelope(
                messageType: .heartbeat,
                sessionId: sessionId,
                targetNodeId: targetNodeId ?? sessions[sessionId]?.targetNodeId
            )
        )
    }

    public func disconnect(sessionId: String, targetNodeId: String? = nil) throws {
        try transport.send(
            buildEnvelope(
                messageType: .goodbye,
                sessionId: sessionId,
                targetNodeId: targetNodeId ?? sessions[sessionId]?.targetNodeId
            )
        )
        sessions.removeValue(forKey: sessionId)
        onSessionClosed?(sessionId)
    }

    public func encode(_ envelope: PeerEnvelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    public func decode(_ data: Data) throws -> PeerEnvelope {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(PeerEnvelope.self, from: data)
    }

    private func handleIncoming(_ envelope: PeerEnvelope) {
        if sessions[envelope.sessionId] == nil {
            sessions[envelope.sessionId] = SessionState(
                targetNodeId: envelope.sourceNodeId,
                lastReceivedAt: envelope.timestamp,
                nextSequence: envelope.sequence + 1,
                connected: false
            )
        }

        sessions[envelope.sessionId]?.targetNodeId = envelope.sourceNodeId
        sessions[envelope.sessionId]?.lastReceivedAt = envelope.timestamp

        switch envelope.messageType {
        case .hello:
            sessions[envelope.sessionId]?.connected = true
            onSessionOpened?(envelope.sessionId, envelope.sourceNodeId)
            do {
                try transport.send(
                    buildEnvelope(
                        messageType: .helloAck,
                        sessionId: envelope.sessionId,
                        targetNodeId: envelope.sourceNodeId,
                        capabilities: capabilities
                    )
                )
            } catch {}
        case .helloAck:
            sessions[envelope.sessionId]?.connected = true
            onSessionOpened?(envelope.sessionId, envelope.sourceNodeId)
        case .data:
            onData?(envelope)
        case .error:
            onFailure?(envelope)
        case .goodbye:
            sessions.removeValue(forKey: envelope.sessionId)
            onSessionClosed?(envelope.sessionId)
        case .heartbeat, .offer, .answer, .candidate:
            break
        }
    }

    private func buildEnvelope(
        messageType: PeerMessageType,
        sessionId: String,
        targetNodeId: String? = nil,
        capabilities: [PeerCapability]? = nil,
        negotiation: PeerNegotiation? = nil,
        payload: PeerPayload? = nil,
        security: PeerSecurity? = nil,
        error: PeerFailure? = nil
    ) -> PeerEnvelope {
        let sequence = nextSequence(for: sessionId)
        return PeerEnvelope(
            protocolVersion: protocolVersion,
            messageType: messageType,
            sessionId: sessionId,
            sourceNodeId: nodeId,
            targetNodeId: targetNodeId,
            timestamp: dateProvider(),
            sequence: sequence,
            capabilities: capabilities,
            negotiation: negotiation,
            payload: payload,
            security: security,
            error: error
        )
    }

    private func nextSequence(for sessionId: String) -> Int {
        var state = sessions[sessionId] ?? SessionState(
            targetNodeId: nil,
            lastReceivedAt: dateProvider(),
            nextSequence: 0,
            connected: false
        )
        let nextValue = state.nextSequence
        state.nextSequence += 1
        sessions[sessionId] = state
        return nextValue
    }
}
