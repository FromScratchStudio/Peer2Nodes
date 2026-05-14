package com.fromscratchstudio.peer2nodes

import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

private fun makePair(): Pair<PeerChannelManager, PeerChannelManager> {
    val tA = LoopbackPeerTransport()
    val tB = LoopbackPeerTransport()
    tA.connect(tB)
    tB.connect(tA)

    val caps = listOf(PeerCapability.END_TO_END_ENCRYPTION, PeerCapability.WEBRTC_DATA_CHANNEL)
    val clientA = PeerNodeClient(capabilities = caps, transport = tA)
    val clientB = PeerNodeClient(capabilities = caps, transport = tB)
    return PeerChannelManager(clientA) to PeerChannelManager(clientB)
}

private fun await(latch: CountDownLatch, description: String) {
    assertTrue("Timed out waiting for: $description", latch.await(3, TimeUnit.SECONDS))
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerCryptoService tests
// ─────────────────────────────────────────────────────────────────────────────

class PeerCryptoServiceTest {

    @Test fun identityKeyIsStable() {
        val svc = PeerCryptoService()
        assertEquals(svc.identityPublicKeyBase64, svc.identityPublicKeyBase64)
        assertTrue(svc.identityPublicKeyBase64.isNotEmpty())
    }

    @Test fun ephemeralKeypairsAreDistinct() {
        val svc = PeerCryptoService()
        assertNotEquals(svc.generateEphemeralKeyPair().publicKeyBase64,
                        svc.generateEphemeralKeyPair().publicKeyBase64)
    }

    @Test fun sharedKeyDerivation_encryptDecryptRoundTrip() {
        val svcA = PeerCryptoService()
        val svcB = PeerCryptoService()
        val kpA  = svcA.generateEphemeralKeyPair()
        val kpB  = svcB.generateEphemeralKeyPair()

        svcA.deriveSessionKey("s1", kpA.privateKey, kpB.publicKeyBase64)
        svcB.deriveSessionKey("s1", kpB.privateKey, kpA.publicKeyBase64)

        val (ciphertext, nonce) = svcA.encrypt("s1", "hello Android")
        assertEquals("hello Android", svcB.decrypt("s1", ciphertext, nonce))
    }

    @Test(expected = Exception::class)
    fun decryptFailsOnTamperedCiphertext() {
        val svcA = PeerCryptoService()
        val svcB = PeerCryptoService()
        val kpA  = svcA.generateEphemeralKeyPair()
        val kpB  = svcB.generateEphemeralKeyPair()
        svcA.deriveSessionKey("s1", kpA.privateKey, kpB.publicKeyBase64)
        svcB.deriveSessionKey("s1", kpB.privateKey, kpA.publicKeyBase64)

        val (ciphertext, nonce) = svcA.encrypt("s1", "secret")
        val tampered = Base64.getDecoder().decode(ciphertext).also { it[0] = it[0].xor(0xff.toByte()) }
        svcB.decrypt("s1", Base64.getEncoder().encodeToString(tampered), nonce) // must throw
    }

    @Test fun signVerifyRoundTrip() {
        val svcA      = PeerCryptoService()
        val svcB      = PeerCryptoService()
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .let { Base64.getEncoder().encodeToString(it) }
        val sig       = svcA.signChallenge(challenge)

        svcB.registerRemoteIdentityKey("s1", svcA.identityPublicKeyBase64)
        assertTrue(svcB.verifyChallengeSignature("s1", challenge, sig))
    }

    @Test fun verifyFailsWithWrongIdentityKey() {
        val svcA      = PeerCryptoService()
        val svcB      = PeerCryptoService()
        val svcC      = PeerCryptoService() // attacker
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .let { Base64.getEncoder().encodeToString(it) }
        val sig       = svcA.signChallenge(challenge)

        svcB.registerRemoteIdentityKey("s1", svcC.identityPublicKeyBase64)
        assertFalse(svcB.verifyChallengeSignature("s1", challenge, sig))
    }

    @Test(expected = IllegalStateException::class)
    fun clearSessionRemovesKey_decryptThrows() {
        val svc  = PeerCryptoService()
        val svc2 = PeerCryptoService()
        val kp   = svc.generateEphemeralKeyPair()
        val kp2  = svc2.generateEphemeralKeyPair()
        svc.deriveSessionKey("s1", kp.privateKey, kp2.publicKeyBase64)
        val (ct, nonce) = svc.encrypt("s1", "data")
        svc.clearSession("s1")
        svc.decrypt("s1", ct, nonce) // must throw
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OutboundMessageQueue tests
// ─────────────────────────────────────────────────────────────────────────────

class OutboundMessageQueueTest {

    @Test fun resolvesOnAcknowledge() {
        val resolved = AtomicReference<String>()
        val latch = CountDownLatch(1)
        val q = OutboundMessageQueue(retryIntervalMs = 60_000L)

        q.enqueue("m1", sendFn = {}, resolve = { id -> resolved.set(id); latch.countDown() }, reject = {})
        q.acknowledge("m1")

        await(latch, "acknowledgement")
        assertEquals("m1", resolved.get())
        q.stop()
    }

    @Test fun stopRejectsAllPending() {
        val rejected = AtomicReference<Throwable>()
        val latch = CountDownLatch(1)
        val q = OutboundMessageQueue(retryIntervalMs = 60_000L)

        q.enqueue("m2", sendFn = {}, resolve = {}, reject = { e -> rejected.set(e); latch.countDown() })
        q.stop()

        await(latch, "rejection on stop")
        assertNotNull(rejected.get())
        assertTrue(rejected.get()!!.message!!.contains("stopped"))
    }

    @Test fun rejectsAfterMaxRetries() {
        val rejected = AtomicReference<Throwable>()
        val latch = CountDownLatch(1)
        val q = OutboundMessageQueue(maxRetries = 2, retryIntervalMs = 10L)

        q.enqueue("m3", sendFn = {}, resolve = {}, reject = { e -> rejected.set(e); latch.countDown() })

        await(latch, "expiry after retries")
        assertNotNull(rejected.get())
        q.stop()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerChannelManager tests
// ─────────────────────────────────────────────────────────────────────────────

class PeerChannelManagerTest {

    @Test fun openChannel_initiatorBecomesReady() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latch = CountDownLatch(1)
        val resolvedSid = AtomicReference<String>()

        managerA.openChannel(
            resolve = { sid -> resolvedSid.set(sid); latch.countDown() },
            reject  = { fail("rejected") }
        )

        await(latch, "channel ready")
        assertNotNull(resolvedSid.get())
        assertEquals(ChannelStatus.READY, managerA.channelStatus(resolvedSid.get()!!))

        managerA.stop(); managerB.stop()
    }

    @Test fun openChannel_responderFiresOnChannelReady() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latchA = CountDownLatch(1); val latchB = CountDownLatch(1)
        val sidA = AtomicReference<String>(); val sidB = AtomicReference<String>()
        managerA.onChannelReady = { sid, _ -> sidA.set(sid); latchA.countDown() }
        managerB.onChannelReady = { sid, _ -> sidB.set(sid); latchB.countDown() }

        managerA.openChannel(resolve = {}, reject = { fail("rejected") })

        await(latchA, "A ready"); await(latchB, "B ready")
        assertEquals(sidA.get(), sidB.get())

        managerA.stop(); managerB.stop()
    }

    @Test fun sendMessage_receivedAsPlaintext() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latchReady = CountDownLatch(1)
        val latchMsg   = CountDownLatch(1)
        val sidA       = AtomicReference<String>()
        val received   = AtomicReference<String>()

        managerA.openChannel(
            resolve = { sid -> sidA.set(sid); latchReady.countDown() },
            reject  = { fail("rejected") }
        )
        await(latchReady, "ready")
        managerB.onMessageReceived = { _, _, text -> received.set(text); latchMsg.countDown() }

        managerA.sendMessage(sessionId = sidA.get()!!, plaintext = "android secret", requireAck = false)
        await(latchMsg, "message received")
        assertEquals("android secret", received.get())

        managerA.stop(); managerB.stop()
    }

    @Test fun ackTracking_resolveOnAck() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latchReady = CountDownLatch(1)
        val latchAck   = CountDownLatch(1)
        val sidA       = AtomicReference<String>()

        managerA.openChannel(resolve = { sid -> sidA.set(sid); latchReady.countDown() }, reject = { fail() })
        await(latchReady, "ready")
        managerB.onMessageReceived = { _, _, _ -> }

        managerA.sendMessage(
            sessionId  = sidA.get()!!,
            plaintext  = "needs ack",
            requireAck = true,
            resolve    = { latchAck.countDown() },
            reject     = { fail("ack rejected") }
        )
        await(latchAck, "ack received")

        managerA.stop(); managerB.stop()
    }

    @Test fun bidirectionalMessaging() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latchReady = CountDownLatch(2)
        val latchA2B   = CountDownLatch(1)
        val latchB2A   = CountDownLatch(1)
        val sidA       = AtomicReference<String>(); val sidB = AtomicReference<String>()
        val recvB      = AtomicReference<String>(); val recvA = AtomicReference<String>()

        managerA.onChannelReady    = { sid, _ -> sidA.set(sid); latchReady.countDown() }
        managerB.onChannelReady    = { sid, _ -> sidB.set(sid); latchReady.countDown() }
        managerB.onMessageReceived = { _, _, t -> recvB.set(t); latchA2B.countDown() }
        managerA.onMessageReceived = { _, _, t -> recvA.set(t); latchB2A.countDown() }

        managerA.openChannel(resolve = {}, reject = { fail() })
        await(latchReady, "both ready")

        managerA.sendMessage(sidA.get()!!, "A→B", requireAck = false)
        await(latchA2B, "A→B received")
        managerB.sendMessage(sidB.get()!!, "B→A", requireAck = false)
        await(latchB2A, "B→A received")

        assertEquals("A→B", recvB.get())
        assertEquals("B→A", recvA.get())

        managerA.stop(); managerB.stop()
    }

    @Test(expected = IllegalStateException::class)
    fun sendMessage_throwsOnNonReadyChannel() {
        val (managerA, _) = makePair()
        managerA.start()
        managerA.sendMessage("ghost", "hi")
    }

    @Test fun tamperedAuthResponse_triggersChannelError() {
        val tA = LoopbackPeerTransport(); val tB = LoopbackPeerTransport()
        tA.connect(tB); tB.connect(tA)
        val caps = listOf(PeerCapability.END_TO_END_ENCRYPTION)
        val clientA = PeerNodeClient(capabilities = caps, transport = tA)
        val clientB = PeerNodeClient(capabilities = caps, transport = tB)
        val managerA = PeerChannelManager(clientA)
        val managerB = PeerChannelManager(clientB)

        // Intercept B's sendData to corrupt the challenge signature
        val origSend = clientB::sendData
        val interceptor = object : PeerNodeClient(capabilities = caps, transport = tB) {}
        // Since we can't easily monkey-patch in Kotlin, we test through a custom crypto service
        // that produces invalid signatures to verify the rejection path.
        val badCrypto = object : PeerCryptoService() {
            override fun signChallenge(challengeBase64: String): String {
                return Base64.getEncoder().encodeToString(ByteArray(64)) // all-zero = invalid sig
            }
        }
        val managerBBad = PeerChannelManager(clientB, cryptoService = badCrypto)
        managerA.start(); managerBBad.start()

        val latch = CountDownLatch(1)
        val error = AtomicReference<String>()
        managerA.onChannelError = { reason -> error.set(reason); latch.countDown() }

        var authFailed = false
        managerA.openChannel(
            resolve = {},
            reject  = { e -> authFailed = e.message?.contains("auth_failed") == true; latch.countDown() }
        )

        await(latch, "auth error")
        assertTrue("Expected auth failure", authFailed || error.get()?.contains("auth_failed") == true)

        managerA.stop(); managerBBad.stop()
    }

    @Test fun closeChannel_statusBecomesClosedOnInitiator() {
        val (managerA, managerB) = makePair()
        managerA.start(); managerB.start()

        val latchReady  = CountDownLatch(1)
        val latchClosed = CountDownLatch(1)
        val sidA        = AtomicReference<String>()

        managerA.openChannel(resolve = { sid -> sidA.set(sid); latchReady.countDown() }, reject = { fail() })
        await(latchReady, "ready")

        managerA.onChannelClosed = { latchClosed.countDown() }
        managerA.closeChannel(sidA.get()!!)
        await(latchClosed, "closed")

        assertEquals(ChannelStatus.CLOSED, managerA.channelStatus(sidA.get()!!))

        managerA.stop(); managerB.stop()
    }
}
