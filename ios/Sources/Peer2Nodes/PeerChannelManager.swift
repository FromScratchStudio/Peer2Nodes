import CryptoKit
import Foundation

// MARK: - Internal content-type constants

private let ctKeyExchange  = "application/vnd.peer2nodes.key-exchange+json"
private let ctAuthResponse = "application/vnd.peer2nodes.auth-response+json"
private let ctAuthConfirm  = "application/vnd.peer2nodes.auth-confirm+json"
private let ctAck          = "application/vnd.peer2nodes.ack+json"
private let ctApp          = "application/vnd.peer2nodes.app+json"

// MARK: - ChannelStatus

public enum ChannelStatus: String {
    case authenticating = "AUTHENTICATING"
    case ready          = "READY"
    case closing        = "CLOSING"
    case closed         = "CLOSED"
    case error          = "ERROR"
}

// MARK: - PeerCryptoError

public enum PeerCryptoError: Error, LocalizedError {
    case noSessionKey(String)
    case invalidKeyFormat
    case decryptionFailed
    case noRemoteIdentityKey

    public var errorDescription: String? {
        switch self {
        case .noSessionKey(let s):  return "No session key for session \(s)"
        case .invalidKeyFormat:     return "Invalid key format"
        case .decryptionFailed:     return "AES-GCM decryption failed"
        case .noRemoteIdentityKey:  return "Remote identity key not registered"
        }
    }
}

// MARK: - PeerCryptoService
//
// Manages:
//  - A stable P-256 identity keypair (ECDSA/SHA-256) for mutual authentication
//  - Per-session symmetric keys (AES-256-GCM) derived via ephemeral P-256 ECDH + HKDF-SHA256
//
// Key format on the wire: DER/SPKI (91 bytes), base64-encoded. Canonical across all platforms.
// Signature format on the wire: DER ECDSA (70–72 bytes), base64-encoded.
// PeerCryptoAdapter converts between these canonical formats and CryptoKit's native
// x9.63 (keys) / P1363 (signatures) representations. See claude-adr.md §5.

public final class PeerCryptoService {

    private let identityPrivateKey: P256.Signing.PrivateKey

    private struct SessionData {
        var sharedKey:         SymmetricKey?
        var remoteIdentityKey: P256.Signing.PublicKey?
    }

    private var sessions: [String: SessionData] = [:]
    private let queue = DispatchQueue(label: "peer2nodes.crypto", attributes: .concurrent)

    public init() {
        identityPrivateKey = P256.Signing.PrivateKey()
    }

    // Canonical wire format: DER/SPKI for public keys, DER ECDSA for signatures.
    // PeerCryptoAdapter converts to/from CryptoKit's native x9.63 / P1363 formats.

    public var identityPublicKeyBase64: String {
        let x963 = identityPrivateKey.publicKey.x963Representation
        return (try? PeerCryptoAdapter.x963ToDerSpki(x963))?.base64EncodedString() ?? ""
    }

    public func generateEphemeralKeyPair() -> (publicKeyBase64: String, privateKey: P256.KeyAgreement.PrivateKey) {
        let priv  = P256.KeyAgreement.PrivateKey()
        let x963  = priv.publicKey.x963Representation
        let spki  = (try? PeerCryptoAdapter.x963ToDerSpki(x963)) ?? Data()
        return (spki.base64EncodedString(), priv)
    }

    public func deriveSessionKey(
        sessionId: String,
        localEphemeralPrivKey: P256.KeyAgreement.PrivateKey,
        remoteEphemeralPubBase64: String
    ) throws {
        guard let derData  = Data(base64Encoded: remoteEphemeralPubBase64) else {
            throw PeerCryptoError.invalidKeyFormat
        }
        // Accept both DER/SPKI (Android/Node.js) and x9.63 (older iOS) via normalisation
        let x963Data = Data(try PeerCryptoAdapter.normalizePublicKey(derData).dropFirst(26))
        let remotePub    = try P256.KeyAgreement.PublicKey(x963Representation: x963Data)
        let sharedSecret = try localEphemeralPrivKey.sharedSecretFromKeyAgreement(with: remotePub)
        let derived      = sharedSecret.hkdfDerivedSymmetricKey(
            using:           SHA256.self,
            salt:            Data(repeating: 0, count: 32),
            sharedInfo:      Data("peer2nodes-v1".utf8),
            outputByteCount: 32
        )
        queue.async(flags: .barrier) {
            var s = self.sessions[sessionId] ?? SessionData()
            s.sharedKey = derived
            self.sessions[sessionId] = s
        }
    }

    public func registerRemoteIdentityKey(sessionId: String, base64Key: String) throws {
        guard let rawData = Data(base64Encoded: base64Key) else {
            throw PeerCryptoError.invalidKeyFormat
        }
        // Accept both DER/SPKI and x9.63 via normalisation
        let x963Data  = Data(try PeerCryptoAdapter.normalizePublicKey(rawData).dropFirst(26))
        let remoteKey = try P256.Signing.PublicKey(x963Representation: x963Data)
        queue.async(flags: .barrier) {
            var s = self.sessions[sessionId] ?? SessionData()
            s.remoteIdentityKey = remoteKey
            self.sessions[sessionId] = s
        }
    }

    /// Signs a challenge. Returns a DER-encoded ECDSA signature (wire-canonical format).
    public func signChallenge(_ challengeBase64: String) throws -> String {
        guard let data = Data(base64Encoded: challengeBase64) else {
            throw PeerCryptoError.invalidKeyFormat
        }
        let digest    = SHA256.hash(data: data)
        let p1363Sig  = try identityPrivateKey.signature(for: digest)
        let derSig    = try PeerCryptoAdapter.p1363ToDer(p1363Sig.rawRepresentation)
        return derSig.base64EncodedString()
    }

    /// Verifies a challenge signature. Accepts DER-encoded ECDSA (wire-canonical).
    public func verifyChallengeSignature(
        sessionId:       String,
        challengeBase64: String,
        signatureBase64: String
    ) -> Bool {
        var remoteKey: P256.Signing.PublicKey?
        queue.sync { remoteKey = self.sessions[sessionId]?.remoteIdentityKey }
        guard let key           = remoteKey,
              let challengeData = Data(base64Encoded: challengeBase64),
              let derSigData    = Data(base64Encoded: signatureBase64),
              let p1363Data     = try? PeerCryptoAdapter.derToP1363(derSigData),
              let sig           = try? P256.Signing.ECDSASignature(rawRepresentation: p1363Data) else {
            return false
        }
        let digest = SHA256.hash(data: challengeData)
        return key.isValidSignature(sig, for: digest)
    }

    /// AES-256-GCM encrypt. Returns (ciphertext: base64, nonce: base64).
    public func encrypt(sessionId: String, plaintext: String) throws -> (ciphertext: String, nonce: String) {
        var key: SymmetricKey?
        queue.sync { key = self.sessions[sessionId]?.sharedKey }
        guard let symKey = key else { throw PeerCryptoError.noSessionKey(sessionId) }
        guard let plaintextData = plaintext.data(using: .utf8) else { throw PeerCryptoError.invalidKeyFormat }

        let sealedBox = try AES.GCM.seal(plaintextData, using: symKey)
        let combined  = sealedBox.ciphertext + sealedBox.tag
        let nonceData = sealedBox.nonce.withUnsafeBytes { Data($0) }
        return (combined.base64EncodedString(), nonceData.base64EncodedString())
    }

    /// AES-256-GCM decrypt. Throws on authentication failure.
    public func decrypt(sessionId: String, ciphertextBase64: String, nonceBase64: String) throws -> String {
        var key: SymmetricKey?
        queue.sync { key = self.sessions[sessionId]?.sharedKey }
        guard let symKey  = key                                     else { throw PeerCryptoError.noSessionKey(sessionId) }
        guard let combined = Data(base64Encoded: ciphertextBase64),
              let nonceData = Data(base64Encoded: nonceBase64)       else { throw PeerCryptoError.invalidKeyFormat }

        let tag        = combined.suffix(16)
        let ciphertext = combined.prefix(combined.count - 16)
        let nonce      = try AES.GCM.Nonce(data: nonceData)
        let sealedBox  = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plain      = try AES.GCM.open(sealedBox, using: symKey)
        guard let result = String(data: plain, encoding: .utf8) else { throw PeerCryptoError.decryptionFailed }
        return result
    }

    public func clearSession(_ sessionId: String) {
        queue.async(flags: .barrier) { self.sessions.removeValue(forKey: sessionId) }
    }
}

// MARK: - OutboundMessageQueueEntry

private struct QueueEntry {
    let sendFn:  () throws -> Void
    var retries: Int
    let resolve: (String) -> Void
    let reject:  (Error) -> Void
}

// MARK: - OutboundMessageQueue
//
// Tracks DATA messages that require an ACK and retries them on timeout.
// Thread-safe via a dedicated serial dispatch queue.

public final class OutboundMessageQueue {

    private var pending:        [String: QueueEntry] = [:]
    private let serialQueue     = DispatchQueue(label: "peer2nodes.ackqueue")
    private var timer:          DispatchSourceTimer?
    private let maxRetries:     Int
    private let retryInterval:  TimeInterval
    private let onRetry:        ((String, Int) -> Void)?
    private let onExpired:      ((String) -> Void)?

    public init(
        maxRetries:    Int          = 3,
        retryInterval: TimeInterval = 5.0,
        onRetry:       ((String, Int) -> Void)? = nil,
        onExpired:     ((String) -> Void)?      = nil
    ) {
        self.maxRetries    = maxRetries
        self.retryInterval = retryInterval
        self.onRetry       = onRetry
        self.onExpired     = onExpired
    }

    deinit { stop() }

    /// Enqueues a message for ACK tracking. Calls back resolve(messageId) on ACK or reject on expiry.
    public func enqueue(
        messageId: String,
        sendFn:    @escaping () throws -> Void,
        resolve:   @escaping (String) -> Void,
        reject:    @escaping (Error) -> Void
    ) {
        serialQueue.async {
            self.pending[messageId] = QueueEntry(sendFn: sendFn, retries: 0, resolve: resolve, reject: reject)
            self.ensureTimerRunning()
        }
    }

    public func acknowledge(_ messageId: String) {
        serialQueue.async {
            guard let entry = self.pending.removeValue(forKey: messageId) else { return }
            entry.resolve(messageId)
            if self.pending.isEmpty { self.stopTimer() }
        }
    }

    public func stop() {
        serialQueue.sync {
            self.stopTimer()
            for (id, entry) in self.pending {
                entry.reject(PeerChannelError.queueStopped(id))
            }
            self.pending.removeAll()
        }
    }

    public var pendingCount: Int {
        serialQueue.sync { pending.count }
    }

    private func ensureTimerRunning() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: serialQueue)
        t.schedule(deadline: .now() + retryInterval, repeating: retryInterval)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func stopTimer() {
        timer?.cancel()
        timer = nil
    }

    private func tick() {
        for (id, var entry) in pending {
            if entry.retries >= maxRetries {
                pending.removeValue(forKey: id)
                entry.reject(PeerChannelError.ackTimeout(id))
                onExpired?(id)
            } else {
                entry.retries += 1
                pending[id] = entry
                try? entry.sendFn()
                onRetry?(id, entry.retries)
            }
        }
        if pending.isEmpty { stopTimer() }
    }
}

// MARK: - PeerChannelError

public enum PeerChannelError: Error, LocalizedError {
    case channelNotReady(String)
    case authFailed(String)
    case ackTimeout(String)
    case queueStopped(String)

    public var errorDescription: String? {
        switch self {
        case .channelNotReady(let s): return "Channel \(s) is not ready"
        case .authFailed(let r):      return "Channel auth failed: \(r)"
        case .ackTimeout(let id):     return "Message \(id) not acknowledged"
        case .queueStopped(let id):   return "Queue stopped before message \(id) was acknowledged"
        }
    }
}

// MARK: - PeerChannelManager
//
// Sits above PeerNodeClient and provides:
//   - Mutual authentication via ECDH ephemeral key exchange + challenge-response signatures
//   - AES-256-GCM payload encryption / decryption
//   - ACK-tracked reliable message delivery with configurable retries
//
// Handshake per session:
//   Initiator → Responder : HELLO        (via PeerNodeClient.openSession)
//   Responder → Initiator : HELLO_ACK    (via PeerNodeClient)
//   Initiator → Responder : DATA key-exchange   { ephemeralPubKey, identityKey, challenge }
//   Responder → Initiator : DATA auth-response  { ephemeralPubKey, identityKey, challenge, sig(A_challenge) }
//   Initiator → Responder : DATA auth-confirm   { sig(B_challenge) }
//   — both sides now hold a derived AES-256-GCM session key, channel status → READY —

public final class PeerChannelManager {

    private struct ChannelState {
        var status:       ChannelStatus
        var remoteNodeId: String?
    }

    private struct PendingHandshake {
        var isInitiator:        Bool
        var ephemeralPrivKey:   P256.KeyAgreement.PrivateKey?
        var challenge:          String?
        var responderChallenge: String?
        var resolve:            ((String) -> Void)?
        var reject:             ((Error) -> Void)?
    }

    private let client:      PeerNodeClient
    private let crypto:      PeerCryptoService
    private let queue:       OutboundMessageQueue
    private let stateQueue   = DispatchQueue(label: "peer2nodes.channel", attributes: .concurrent)

    private var channels:   [String: ChannelState]     = [:]
    private var pending:    [String: PendingHandshake]  = [:]

    public var onChannelReady:        ((String, String?) -> Void)?
    public var onMessageReceived:     ((String, String, String) -> Void)?  // (sessionId, messageId, plaintext)
    public var onMessageAcknowledged: ((String, String) -> Void)?
    public var onChannelError:        ((String) -> Void)?
    public var onChannelClosed:       ((String) -> Void)?

    public init(
        client:        PeerNodeClient,
        cryptoService: PeerCryptoService?  = nil,
        queueOptions: (maxRetries: Int, retryInterval: TimeInterval)? = nil
    ) {
        self.client = client
        self.crypto = cryptoService ?? PeerCryptoService()
        self.queue  = OutboundMessageQueue(
            maxRetries:    queueOptions?.maxRetries    ?? 3,
            retryInterval: queueOptions?.retryInterval ?? 5.0,
            onExpired:     nil
        )

        self.client.onSessionOpened = { [weak self] sid, rid   in self?.handleSessionOpened(sid, remoteId: rid) }
        self.client.onData          = { [weak self] envelope    in self?.handleData(envelope) }
        self.client.onFailure       = { [weak self] envelope    in
            self?.onChannelError?(envelope.error?.message ?? "transport_error")
        }
        self.client.onSessionClosed = { [weak self] sid        in self?.handleSessionClosed(sid) }
    }

    public func start() throws { try client.start() }

    public func stop() {
        queue.stop()
        client.stop()
        stateQueue.async(flags: .barrier) {
            self.channels.removeAll()
            self.pending.removeAll()
        }
    }

    /// Opens an authenticated, encrypted channel. Calls resolve(sessionId) once mutual auth completes.
    public func openChannel(
        targetNodeId: String? = nil,
        resolve:      @escaping (String) -> Void,
        reject:       @escaping (Error)  -> Void
    ) {
        let (ephemeralPub, ephemeralPriv) = crypto.generateEphemeralKeyPair()
        let challenge = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).base64EncodedString() }

        guard let sessionId = try? client.openSession(targetNodeId: targetNodeId) else {
            reject(PeerChannelError.channelNotReady("failed to open session"))
            return
        }

        stateQueue.async(flags: .barrier) {
            self.channels[sessionId] = ChannelState(status: .authenticating, remoteNodeId: targetNodeId)
            self.pending[sessionId]  = PendingHandshake(
                isInitiator:      true,
                ephemeralPrivKey: ephemeralPriv,
                challenge:        challenge,
                resolve:          resolve,
                reject:           reject
            )
        }

        let body: [String: String] = [
            "ephemeralPubKey": ephemeralPub,
            "identityKey":     crypto.identityPublicKeyBase64,
            "challenge":       challenge,
        ]
        sendJSON(sessionId: sessionId, contentType: ctKeyExchange, body: body)
    }

    /// Sends an encrypted message. If requireAck, resolve/reject are called on ACK or expiry.
    public func sendMessage(
        sessionId:  String,
        plaintext:  String,
        requireAck: Bool = true,
        resolve:    ((String) -> Void)? = nil,
        reject:     ((Error)  -> Void)? = nil
    ) throws {
        var status: ChannelStatus?
        stateQueue.sync { status = self.channels[sessionId]?.status }
        guard status == .ready else { throw PeerChannelError.channelNotReady(sessionId) }

        let messageId = UUID().uuidString
        let (ciphertext, nonce) = try crypto.encrypt(sessionId: sessionId, plaintext: plaintext)

        let body: [String: Any] = [
            "messageId":  messageId,
            "ciphertext": ciphertext,
            "nonce":      nonce,
            "requireAck": requireAck,
        ]

        let sendFn: () throws -> Void = { [weak self] in
            self?.sendJSON(sessionId: sessionId, contentType: ctApp, body: body)
        }
        try sendFn()

        if requireAck, let res = resolve, let rej = reject {
            queue.enqueue(messageId: messageId, sendFn: sendFn, resolve: res, reject: rej)
        }
    }

    public func closeChannel(sessionId: String) {
        stateQueue.async(flags: .barrier) { self.channels[sessionId]?.status = .closing }
        try? client.disconnect(sessionId: sessionId)
    }

    public func channelStatus(for sessionId: String) -> ChannelStatus? {
        stateQueue.sync { channels[sessionId]?.status }
    }

    // MARK: - Private handlers

    private func handleSessionOpened(_ sessionId: String, remoteId: String?) {
        stateQueue.async(flags: .barrier) {
            if self.channels[sessionId] == nil {
                self.channels[sessionId] = ChannelState(status: .authenticating, remoteNodeId: remoteId)
            }
        }
    }

    private func handleData(_ envelope: PeerEnvelope) {
        guard let contentType = envelope.payload?.contentType else { return }
        let sid = envelope.sessionId

        switch contentType {
        case ctKeyExchange:  handleKeyExchange(sid, envelope: envelope)
        case ctAuthResponse: handleAuthResponse(sid, envelope: envelope)
        case ctAuthConfirm:  handleAuthConfirm(sid, envelope: envelope)
        case ctAck:          handleAck(sid, envelope: envelope)
        case ctApp:          handleAppMessage(sid, envelope: envelope)
        default:             break
        }
    }

    private func handleKeyExchange(_ sid: String, envelope: PeerEnvelope) {
        guard let bodyStr = envelope.payload?.body,
              let dict    = parseJSON(bodyStr) else { return }

        guard let remotePub      = dict["ephemeralPubKey"] as? String,
              let remoteIdentity = dict["identityKey"]     as? String,
              let theirChallenge = dict["challenge"]       as? String else { return }

        let (myPub, myPriv) = crypto.generateEphemeralKeyPair()
        try? crypto.registerRemoteIdentityKey(sessionId: sid, base64Key: remoteIdentity)
        try? crypto.deriveSessionKey(sessionId: sid, localEphemeralPrivKey: myPriv, remoteEphemeralPubBase64: remotePub)

        let myChallenge = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).base64EncodedString() }
        let sig         = (try? crypto.signChallenge(theirChallenge)) ?? ""

        stateQueue.async(flags: .barrier) {
            self.pending[sid] = PendingHandshake(
                isInitiator:        false,
                responderChallenge: myChallenge
            )
        }

        sendJSON(sessionId: sid, contentType: ctAuthResponse, body: [
            "ephemeralPubKey":   myPub,
            "identityKey":       crypto.identityPublicKeyBase64,
            "challenge":         myChallenge,
            "challengeResponse": sig,
        ] as [String: Any])
    }

    private func handleAuthResponse(_ sid: String, envelope: PeerEnvelope) {
        guard let bodyStr = envelope.payload?.body,
              let dict    = parseJSON(bodyStr) else { return }

        var p: PendingHandshake?
        stateQueue.sync { p = self.pending[sid] }
        guard let pending = p, pending.isInitiator else { return }

        guard let remotePub      = dict["ephemeralPubKey"]   as? String,
              let remoteIdentity = dict["identityKey"]        as? String,
              let theirChallenge = dict["challenge"]           as? String,
              let sig            = dict["challengeResponse"]  as? String else { return }

        try? crypto.registerRemoteIdentityKey(sessionId: sid, base64Key: remoteIdentity)

        guard let ourChallenge = pending.challenge,
              crypto.verifyChallengeSignature(sessionId: sid, challengeBase64: ourChallenge, signatureBase64: sig) else {
            failChannel(sid, reason: "auth_failed:invalid_challenge_response")
            return
        }

        guard let privKey = pending.ephemeralPrivKey else { return }
        try? crypto.deriveSessionKey(sessionId: sid, localEphemeralPrivKey: privKey, remoteEphemeralPubBase64: remotePub)

        let confirmSig = (try? crypto.signChallenge(theirChallenge)) ?? ""
        sendJSON(sessionId: sid, contentType: ctAuthConfirm, body: ["challengeResponse": confirmSig])

        setChannelReady(sid)
        pending.resolve?(sid)
        stateQueue.async(flags: .barrier) { self.pending.removeValue(forKey: sid) }
    }

    private func handleAuthConfirm(_ sid: String, envelope: PeerEnvelope) {
        guard let bodyStr = envelope.payload?.body,
              let dict    = parseJSON(bodyStr),
              let sig     = dict["challengeResponse"] as? String else { return }

        var p: PendingHandshake?
        stateQueue.sync { p = self.pending[sid] }
        guard let pending = p, !pending.isInitiator,
              let respChallenge = pending.responderChallenge else { return }

        guard crypto.verifyChallengeSignature(sessionId: sid, challengeBase64: respChallenge, signatureBase64: sig) else {
            failChannel(sid, reason: "auth_failed:invalid_auth_confirm")
            return
        }

        setChannelReady(sid)
        stateQueue.async(flags: .barrier) { self.pending.removeValue(forKey: sid) }
    }

    private func handleAppMessage(_ sid: String, envelope: PeerEnvelope) {
        var status: ChannelStatus?
        stateQueue.sync { status = self.channels[sid]?.status }
        guard status == .ready,
              let bodyStr    = envelope.payload?.body,
              let dict       = parseJSON(bodyStr),
              let messageId  = dict["messageId"]  as? String,
              let ciphertext = dict["ciphertext"] as? String,
              let nonce      = dict["nonce"]       as? String else { return }

        let requireAck = dict["requireAck"] as? Bool ?? false

        guard let plaintext = try? crypto.decrypt(sessionId: sid, ciphertextBase64: ciphertext, nonceBase64: nonce) else {
            onChannelError?("decrypt_failed:\(sid)")
            return
        }

        if requireAck {
            sendJSON(sessionId: sid, contentType: ctAck, body: ["messageId": messageId])
        }

        onMessageReceived?(sid, messageId, plaintext)
    }

    private func handleAck(_ sid: String, envelope: PeerEnvelope) {
        guard let bodyStr  = envelope.payload?.body,
              let dict      = parseJSON(bodyStr),
              let messageId = dict["messageId"] as? String else { return }
        queue.acknowledge(messageId)
        onMessageAcknowledged?(sid, messageId)
    }

    private func handleSessionClosed(_ sid: String) {
        stateQueue.async(flags: .barrier) { self.channels[sid]?.status = .closed }
        crypto.clearSession(sid)
        stateQueue.async(flags: .barrier) { self.pending.removeValue(forKey: sid) }
        onChannelClosed?(sid)
    }

    private func setChannelReady(_ sid: String) {
        var remoteId: String?
        stateQueue.async(flags: .barrier) {
            self.channels[sid]?.status = .ready
            remoteId = self.channels[sid]?.remoteNodeId
        }
        stateQueue.sync {}
        let rid = stateQueue.sync { self.channels[sid]?.remoteNodeId }
        onChannelReady?(sid, rid)
    }

    private func failChannel(_ sid: String, reason: String) {
        stateQueue.async(flags: .barrier) { self.channels[sid]?.status = .error }
        var p: PendingHandshake?
        stateQueue.sync { p = self.pending[sid] }
        p?.reject?(PeerChannelError.authFailed(reason))
        stateQueue.async(flags: .barrier) { self.pending.removeValue(forKey: sid) }
        crypto.clearSession(sid)
        onChannelError?(reason)
    }

    // MARK: - Helpers

    private func sendJSON(sessionId: String, contentType: String, body: Any) {
        guard let data   = try? JSONSerialization.data(withJSONObject: body),
              let string = String(data: data, encoding: .utf8) else { return }
        try? client.sendData(
            sessionId:   sessionId,
            contentType: contentType,
            encoding:    .json,
            body:        string
        )
    }

    private func parseJSON(_ string: String) -> [String: Any]? {
        guard let data = string.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

// MARK: - Data helper

private extension Data {
    init(randomBytes count: Int) {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        self = Data(bytes)
    }
}
