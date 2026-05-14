import XCTest
@testable import Peer2Nodes

// MARK: - Helpers

private func makePair() -> (managerA: PeerChannelManager, managerB: PeerChannelManager) {
    let tA = LoopbackPeerTransport()
    let tB = LoopbackPeerTransport()
    tA.connect(to: tB)
    tB.connect(to: tA)

    let caps: [PeerCapability] = [.endToEndEncryption, .webRTCDataChannel]
    let clientA = PeerNodeClient(capabilities: caps, transport: tA)
    let clientB = PeerNodeClient(capabilities: caps, transport: tB)
    return (PeerChannelManager(client: clientA), PeerChannelManager(client: clientB))
}

// MARK: - PeerCryptoServiceTests

final class PeerCryptoServiceTests: XCTestCase {

    func test_identityKeyIsStable() {
        let svc = PeerCryptoService()
        XCTAssertEqual(svc.identityPublicKeyBase64, svc.identityPublicKeyBase64)
        XCTAssertGreaterThan(svc.identityPublicKeyBase64.count, 50)
    }

    func test_ephemeralKeypairsAreDistinct() {
        let svc = PeerCryptoService()
        let kp1 = svc.generateEphemeralKeyPair()
        let kp2 = svc.generateEphemeralKeyPair()
        XCTAssertNotEqual(kp1.publicKeyBase64, kp2.publicKeyBase64)
    }

    func test_sharedKeyDerivation_encryptDecryptRoundTrip() throws {
        let svcA = PeerCryptoService()
        let svcB = PeerCryptoService()
        let kpA  = svcA.generateEphemeralKeyPair()
        let kpB  = svcB.generateEphemeralKeyPair()

        try svcA.deriveSessionKey(sessionId: "s1", localEphemeralPrivKey: kpA.privateKey, remoteEphemeralPubBase64: kpB.publicKeyBase64)
        try svcB.deriveSessionKey(sessionId: "s1", localEphemeralPrivKey: kpB.privateKey, remoteEphemeralPubBase64: kpA.publicKeyBase64)

        let (ciphertext, nonce) = try svcA.encrypt(sessionId: "s1", plaintext: "hello iOS")
        let plaintext           = try svcB.decrypt(sessionId: "s1", ciphertextBase64: ciphertext, nonceBase64: nonce)
        XCTAssertEqual(plaintext, "hello iOS")
    }

    func test_decryptFailsOnTamperedCiphertext() throws {
        let svcA = PeerCryptoService()
        let svcB = PeerCryptoService()
        let kpA  = svcA.generateEphemeralKeyPair()
        let kpB  = svcB.generateEphemeralKeyPair()
        try svcA.deriveSessionKey(sessionId: "s1", localEphemeralPrivKey: kpA.privateKey, remoteEphemeralPubBase64: kpB.publicKeyBase64)
        try svcB.deriveSessionKey(sessionId: "s1", localEphemeralPrivKey: kpB.privateKey, remoteEphemeralPubBase64: kpA.publicKeyBase64)

        let (ciphertext, nonce) = try svcA.encrypt(sessionId: "s1", plaintext: "secret")
        var tampered = Data(base64Encoded: ciphertext)!
        tampered[0]  ^= 0xff
        XCTAssertThrowsError(try svcB.decrypt(sessionId: "s1", ciphertextBase64: tampered.base64EncodedString(), nonceBase64: nonce))
    }

    func test_signVerifyRoundTrip() throws {
        let svcA      = PeerCryptoService()
        let svcB      = PeerCryptoService()
        let challenge = Data(randomBytes: 32).base64EncodedString()
        let sig       = try svcA.signChallenge(challenge)

        try svcB.registerRemoteIdentityKey(sessionId: "s1", base64Key: svcA.identityPublicKeyBase64)
        XCTAssertTrue(svcB.verifyChallengeSignature(sessionId: "s1", challengeBase64: challenge, signatureBase64: sig))
    }

    func test_verifyFailsWithWrongIdentityKey() throws {
        let svcA      = PeerCryptoService()
        let svcB      = PeerCryptoService()
        let svcC      = PeerCryptoService() // attacker
        let challenge = Data(randomBytes: 32).base64EncodedString()
        let sig       = try svcA.signChallenge(challenge)

        try svcB.registerRemoteIdentityKey(sessionId: "s1", base64Key: svcC.identityPublicKeyBase64)
        XCTAssertFalse(svcB.verifyChallengeSignature(sessionId: "s1", challengeBase64: challenge, signatureBase64: sig))
    }

    func test_clearSessionRemovesKey() throws {
        let svc = PeerCryptoService()
        let kp  = svc.generateEphemeralKeyPair()
        let svc2 = PeerCryptoService()
        let kp2  = svc2.generateEphemeralKeyPair()
        try svc.deriveSessionKey(sessionId: "s1", localEphemeralPrivKey: kp.privateKey, remoteEphemeralPubBase64: kp2.publicKeyBase64)
        let (ct, nonce) = try svc.encrypt(sessionId: "s1", plaintext: "data")
        svc.clearSession("s1")
        XCTAssertThrowsError(try svc.decrypt(sessionId: "s1", ciphertextBase64: ct, nonceBase64: nonce))
    }
}

// MARK: - PeerChannelManagerTests

final class PeerChannelManagerTests: XCTestCase {

    func test_openChannel_initiatorBecomesReady() throws {
        let (managerA, managerB) = makePair()
        try managerA.start()
        try managerB.start()

        let expectation = XCTestExpectation(description: "A channel ready")
        var resolvedId: String?

        managerA.openChannel(resolve: { sid in
            resolvedId = sid
            expectation.fulfill()
        }, reject: { _ in XCTFail("openChannel rejected") })

        wait(for: [expectation], timeout: 2.0)
        XCTAssertNotNil(resolvedId)
        XCTAssertEqual(managerA.channelStatus(for: resolvedId!), .ready)

        managerA.stop()
        managerB.stop()
    }

    func test_openChannel_responderFiresOnChannelReady() throws {
        let (managerA, managerB) = makePair()
        try managerA.start()
        try managerB.start()

        let expA = XCTestExpectation(description: "A ready")
        let expB = XCTestExpectation(description: "B ready")
        var sidA: String?
        var sidB: String?

        managerA.onChannelReady = { sid, _ in sidA = sid; expA.fulfill() }
        managerB.onChannelReady = { sid, _ in sidB = sid; expB.fulfill() }

        managerA.openChannel(resolve: { _ in }, reject: { _ in })
        wait(for: [expA, expB], timeout: 2.0)

        XCTAssertEqual(sidA, sidB)

        managerA.stop()
        managerB.stop()
    }

    func test_sendMessage_receivedAsPlaintext() throws {
        let (managerA, managerB) = makePair()
        try managerA.start()
        try managerB.start()

        let expReady = XCTestExpectation(description: "ready")
        let expMsg   = XCTestExpectation(description: "message received")
        var received: String?
        var sessionId: String?

        managerA.openChannel(resolve: { sid in
            sessionId = sid
            expReady.fulfill()
        }, reject: { _ in XCTFail() })
        wait(for: [expReady], timeout: 2.0)

        managerB.onMessageReceived = { _, _, text in
            received = text
            expMsg.fulfill()
        }

        try managerA.sendMessage(sessionId: sessionId!, plaintext: "secret payload", requireAck: false)
        wait(for: [expMsg], timeout: 2.0)

        XCTAssertEqual(received, "secret payload")

        managerA.stop()
        managerB.stop()
    }

    func test_ackTracking_resolveOnAck() throws {
        let (managerA, managerB) = makePair()
        try managerA.start()
        try managerB.start()

        let expReady = XCTestExpectation(description: "ready")
        let expAck   = XCTestExpectation(description: "ack")
        var sessionId: String?

        managerA.openChannel(resolve: { sid in sessionId = sid; expReady.fulfill() }, reject: { _ in XCTFail() })
        wait(for: [expReady], timeout: 2.0)
        managerB.onMessageReceived = { _, _, _ in }

        try managerA.sendMessage(sessionId: sessionId!, plaintext: "ack test", requireAck: true,
            resolve: { _ in expAck.fulfill() },
            reject:  { _ in XCTFail("ACK rejected") })

        wait(for: [expAck], timeout: 2.0)

        managerA.stop()
        managerB.stop()
    }

    func test_sendMessage_throwsOnNonReadyChannel() throws {
        let (managerA, _) = makePair()
        try managerA.start()
        XCTAssertThrowsError(try managerA.sendMessage(sessionId: "ghost", plaintext: "hi"))
        managerA.stop()
    }

    func test_closeChannel_statusBecomesClosedOnInitiator() throws {
        let (managerA, managerB) = makePair()
        try managerA.start()
        try managerB.start()

        let expReady = XCTestExpectation(description: "ready")
        let expClosed = XCTestExpectation(description: "closed")
        var sessionId: String?

        managerA.openChannel(resolve: { sid in sessionId = sid; expReady.fulfill() }, reject: { _ in XCTFail() })
        wait(for: [expReady], timeout: 2.0)

        managerA.onChannelClosed = { _ in expClosed.fulfill() }
        managerA.closeChannel(sessionId: sessionId!)
        wait(for: [expClosed], timeout: 2.0)

        XCTAssertEqual(managerA.channelStatus(for: sessionId!), .closed)

        managerA.stop()
        managerB.stop()
    }
}

// MARK: - Data helper

private extension Data {
    init(randomBytes count: Int) {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        self = Data(bytes)
    }

    func base64EncodedString() -> String {
        (self as NSData).base64EncodedString(options: [])
    }
}
