package com.fromscratchstudio.peer2nodes

import org.json.JSONObject
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.*
import javax.crypto.spec.*

// Internal content-type constants
private const val CT_KEY_EXCHANGE  = "application/vnd.peer2nodes.key-exchange+json"
private const val CT_AUTH_RESPONSE = "application/vnd.peer2nodes.auth-response+json"
private const val CT_AUTH_CONFIRM  = "application/vnd.peer2nodes.auth-confirm+json"
private const val CT_ACK           = "application/vnd.peer2nodes.ack+json"
private const val CT_APP           = "application/vnd.peer2nodes.app+json"

// ─────────────────────────────────────────────────────────────────────────────
// ChannelStatus
// ─────────────────────────────────────────────────────────────────────────────

enum class ChannelStatus { AUTHENTICATING, READY, CLOSING, CLOSED, ERROR }

// ─────────────────────────────────────────────────────────────────────────────
// PeerCryptoService
//
// Manages:
//  - A stable P-256 identity keypair (ECDSA / SHA256withECDSA) for mutual auth
//  - Per-session AES-256-GCM symmetric keys derived via ephemeral P-256 ECDH
//    and HKDF-SHA256 (manual extract-then-expand; avoids API 35 requirement)
//
// Key format on the wire: DER-encoded SubjectPublicKeyInfo, Base64 (standard).
// Signature format: DER-encoded ECDSA, Base64 (standard JCE output).
// Note: iOS uses x963/P1363 formats. A serialisation adapter is needed for
// heterogeneous (Android ↔ iOS) sessions. See claude-adr.md §5.
// ─────────────────────────────────────────────────────────────────────────────

class PeerCryptoService {

    private val identityKeyPair: KeyPair = KeyPairGenerator
        .getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private data class SessionData(
        var sharedKey:         ByteArray?    = null,
        var remoteIdentityKey: PublicKey?    = null
    )

    private val sessions = ConcurrentHashMap<String, SessionData>()

    /** DER/SPKI public key, Base64-encoded */
    val identityPublicKeyBase64: String
        get() = Base64.getEncoder().encodeToString(identityKeyPair.public.encoded)

    data class EphemeralKeyPair(val publicKeyBase64: String, val privateKey: PrivateKey)

    fun generateEphemeralKeyPair(): EphemeralKeyPair {
        val kp = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        return EphemeralKeyPair(
            publicKeyBase64 = Base64.getEncoder().encodeToString(kp.public.encoded),
            privateKey      = kp.private
        )
    }

    /**
     * Computes ECDH shared secret, then derives a 32-byte AES key via HKDF-SHA256.
     */
    fun deriveSessionKey(sessionId: String, localPrivKey: PrivateKey, remotePubBase64: String) {
        val remoteKeyDer    = Base64.getDecoder().decode(remotePubBase64)
        val remotePublicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(remoteKeyDer))

        val sharedSecret = KeyAgreement.getInstance("ECDH").run {
            init(localPrivKey)
            doPhase(remotePublicKey, true)
            generateSecret()
        }

        val derivedKey = hkdf(
            ikm  = sharedSecret,
            salt = ByteArray(32),
            info = "peer2nodes-v1".toByteArray(Charsets.UTF_8),
            len  = 32
        )

        sessions.compute(sessionId) { _, existing ->
            (existing ?: SessionData()).also { it.sharedKey = derivedKey }
        }
    }

    fun registerRemoteIdentityKey(sessionId: String, base64Key: String) {
        val keyDer    = Base64.getDecoder().decode(base64Key)
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keyDer))
        sessions.compute(sessionId) { _, existing ->
            (existing ?: SessionData()).also { it.remoteIdentityKey = publicKey }
        }
    }

    /** DER-encoded ECDSA-SHA256 signature over challenge bytes, Base64 */
    fun signChallenge(challengeBase64: String): String {
        val data      = Base64.getDecoder().decode(challengeBase64)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(identityKeyPair.private)
            update(data)
            sign()
        }
        return Base64.getEncoder().encodeToString(signature)
    }

    fun verifyChallengeSignature(sessionId: String, challengeBase64: String, signatureBase64: String): Boolean {
        val remoteKey = sessions[sessionId]?.remoteIdentityKey ?: return false
        return try {
            val data = Base64.getDecoder().decode(challengeBase64)
            val sig  = Base64.getDecoder().decode(signatureBase64)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(remoteKey)
                update(data)
                verify(sig)
            }
        } catch (_: Exception) { false }
    }

    /** AES-256-GCM encrypt. Returns Pair(ciphertext_base64, nonce_base64). */
    fun encrypt(sessionId: String, plaintext: String): Pair<String, String> {
        val key = sessions[sessionId]?.sharedKey
            ?: error("No session key for $sessionId")
        val nonce  = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        }
        val combined = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)) // ciphertext + tag appended by JCE
        return Pair(
            Base64.getEncoder().encodeToString(combined),
            Base64.getEncoder().encodeToString(nonce)
        )
    }

    /** AES-256-GCM decrypt. Throws on authentication failure (GCM tag mismatch). */
    fun decrypt(sessionId: String, ciphertextBase64: String, nonceBase64: String): String {
        val key    = sessions[sessionId]?.sharedKey ?: error("No session key for $sessionId")
        val nonce  = Base64.getDecoder().decode(nonceBase64)
        val combined = Base64.getDecoder().decode(ciphertextBase64)
        val plain  = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            doFinal(combined)
        }
        return String(plain, Charsets.UTF_8)
    }

    fun clearSession(sessionId: String) { sessions.remove(sessionId) }

    // ── HKDF-SHA256 (extract-then-expand, single block) ─────────────────────
    // Manual implementation avoids dependency on API 35's HKDFParameterSpec.

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // Extract
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // Expand — single T(1) block suffices for 32 bytes
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(0x01.toByte())
        return mac.doFinal().copyOf(len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OutboundMessageQueue
//
// Tracks DATA messages that require an ACK and retries on timeout.
// Thread-safe via ConcurrentHashMap + a single-thread ScheduledExecutorService.
// ─────────────────────────────────────────────────────────────────────────────

class OutboundMessageQueue(
    private val maxRetries:     Int  = 3,
    private val retryIntervalMs: Long = 5_000L,
    private val onRetry:  ((String, Int) -> Unit)? = null,
    private val onExpired: ((String) -> Unit)?      = null
) {
    private data class Entry(
        val sendFn:  () -> Unit,
        var retries: AtomicInteger = AtomicInteger(0),
        val resolve: (String) -> Unit,
        val reject:  (Throwable) -> Unit
    )

    private val pending   = ConcurrentHashMap<String, Entry>()
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    @Volatile private var future: java.util.concurrent.ScheduledFuture<*>? = null

    fun enqueue(
        messageId: String,
        sendFn:    () -> Unit,
        resolve:   (String) -> Unit,
        reject:    (Throwable) -> Unit
    ) {
        pending[messageId] = Entry(sendFn, AtomicInteger(0), resolve, reject)
        ensureTimerRunning()
    }

    fun acknowledge(messageId: String) {
        pending.remove(messageId)?.resolve?.invoke(messageId)
        if (pending.isEmpty()) cancelTimer()
    }

    val pendingCount: Int get() = pending.size

    fun stop() {
        cancelTimer()
        scheduler.shutdown()
        pending.forEach { (id, entry) ->
            entry.reject(IllegalStateException("Queue stopped before message $id was acknowledged"))
        }
        pending.clear()
    }

    @Synchronized private fun ensureTimerRunning() {
        if (future == null || future!!.isCancelled) {
            future = scheduler.scheduleAtFixedRate(
                ::tick, retryIntervalMs, retryIntervalMs, TimeUnit.MILLISECONDS
            )
        }
    }

    @Synchronized private fun cancelTimer() {
        future?.cancel(false)
        future = null
    }

    private fun tick() {
        val expired = mutableListOf<String>()
        val retry   = mutableListOf<String>()
        for ((id, entry) in pending) {
            if (entry.retries.get() >= maxRetries) expired += id else retry += id
        }
        expired.forEach { id ->
            pending.remove(id)?.let { e ->
                e.reject(IllegalStateException("Message $id not acknowledged after $maxRetries retries"))
                onExpired?.invoke(id)
            }
        }
        retry.forEach { id ->
            pending[id]?.let { e ->
                val n = e.retries.incrementAndGet()
                e.sendFn()
                onRetry?.invoke(id, n)
            }
        }
        if (pending.isEmpty()) cancelTimer()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerChannelManager
//
// Sits above PeerNodeClient and provides:
//   - Mutual authentication via ECDH ephemeral key exchange + challenge-response
//   - AES-256-GCM payload encryption / decryption
//   - ACK-tracked reliable message delivery with configurable retries
//
// Handshake per session:
//   Initiator → Responder : HELLO         (PeerNodeClient.openSession)
//   Responder → Initiator : HELLO_ACK     (PeerNodeClient auto)
//   Initiator → Responder : DATA key-exchange   { ephemeralPubKey, identityKey, challenge }
//   Responder → Initiator : DATA auth-response  { ephemeralPubKey, identityKey, challenge, sig }
//   Initiator → Responder : DATA auth-confirm   { challengeResponse }
//   — channel status → READY, AES-256-GCM key active on both sides —
// ─────────────────────────────────────────────────────────────────────────────

class PeerChannelManager(
    private val client:        PeerNodeClient,
    private val cryptoService: PeerCryptoService = PeerCryptoService(),
    private val queueOptions:  Pair<Int, Long>?  = null   // (maxRetries, retryIntervalMs)
) {
    private data class ChannelState(
        var status:       ChannelStatus,
        var remoteNodeId: String?
    )

    private data class PendingHandshake(
        val isInitiator:        Boolean,
        val ephemeralPrivKey:   PrivateKey?         = null,
        val challenge:          String?             = null,
        var responderChallenge: String?             = null,
        val resolve:            ((String) -> Unit)? = null,
        val reject:             ((Throwable) -> Unit)? = null
    )

    private val channels = ConcurrentHashMap<String, ChannelState>()
    private val pending  = ConcurrentHashMap<String, PendingHandshake>()
    private val queue    = OutboundMessageQueue(
        maxRetries      = queueOptions?.first  ?: 3,
        retryIntervalMs = queueOptions?.second ?: 5_000L,
        onExpired       = { id -> onChannelError?.invoke("ack_timeout:$id") }
    )

    var onChannelReady:        ((String, String?) -> Unit)? = null
    var onMessageReceived:     ((String, String, String) -> Unit)? = null  // (sessionId, messageId, plaintext)
    var onMessageAcknowledged: ((String, String) -> Unit)? = null
    var onChannelError:        ((String) -> Unit)?         = null
    var onChannelClosed:       ((String) -> Unit)?         = null

    init {
        client.onSessionOpened = { sid, rid  -> handleSessionOpened(sid, rid) }
        client.onData          = { env       -> handleData(env) }
        client.onFailure       = { env       -> onChannelError?.invoke(env.error?.message ?: "transport_error") }
        client.onSessionClosed = { sid       -> handleSessionClosed(sid) }
    }

    fun start() = client.start()
    fun stop()  { queue.stop(); client.stop(); channels.clear(); pending.clear() }

    /**
     * Opens an authenticated, encrypted channel. Calls resolve(sessionId) once mutual auth completes,
     * or reject(error) on failure.
     */
    fun openChannel(
        targetNodeId: String? = null,
        resolve: (String) -> Unit,
        reject:  (Throwable) -> Unit
    ) {
        val (ephemeralPub, ephemeralPriv) = cryptoService.generateEphemeralKeyPair()
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .let { Base64.getEncoder().encodeToString(it) }

        val sessionId = client.openSession(targetNodeId)
        channels[sessionId] = ChannelState(ChannelStatus.AUTHENTICATING, targetNodeId)
        pending[sessionId]  = PendingHandshake(
            isInitiator    = true,
            ephemeralPrivKey = ephemeralPriv,
            challenge      = challenge,
            resolve        = resolve,
            reject         = reject
        )

        sendJson(sessionId, CT_KEY_EXCHANGE, mapOf(
            "ephemeralPubKey" to ephemeralPub,
            "identityKey"     to cryptoService.identityPublicKeyBase64,
            "challenge"       to challenge
        ))
    }

    /**
     * Sends an encrypted message. When requireAck is true, resolve/reject are called
     * on ACK or expiry respectively.
     */
    fun sendMessage(
        sessionId:  String,
        plaintext:  String,
        requireAck: Boolean           = true,
        resolve:    ((String) -> Unit)? = null,
        reject:     ((Throwable) -> Unit)? = null
    ) {
        check(channels[sessionId]?.status == ChannelStatus.READY) {
            "Channel $sessionId is not ready (status: ${channels[sessionId]?.status})"
        }

        val messageId            = UUID.randomUUID().toString()
        val (ciphertext, nonce)  = cryptoService.encrypt(sessionId, plaintext)

        val body = mapOf(
            "messageId"  to messageId,
            "ciphertext" to ciphertext,
            "nonce"      to nonce,
            "requireAck" to requireAck
        )

        val sendFn: () -> Unit = { sendJson(sessionId, CT_APP, body) }
        sendFn()

        if (requireAck && resolve != null && reject != null) {
            queue.enqueue(messageId, sendFn, resolve, reject)
        }
    }

    fun closeChannel(sessionId: String) {
        channels[sessionId]?.status = ChannelStatus.CLOSING
        client.disconnect(sessionId)
    }

    fun channelStatus(sessionId: String): ChannelStatus? = channels[sessionId]?.status

    // ── Handlers ─────────────────────────────────────────────────────────────

    private fun handleSessionOpened(sessionId: String, remoteNodeId: String?) {
        channels.computeIfAbsent(sessionId) {
            ChannelState(ChannelStatus.AUTHENTICATING, remoteNodeId)
        }
    }

    private fun handleData(envelope: PeerEnvelope) {
        val contentType = envelope.payload?.contentType ?: return
        val sid         = envelope.sessionId
        when (contentType) {
            CT_KEY_EXCHANGE  -> handleKeyExchange(sid, envelope)
            CT_AUTH_RESPONSE -> handleAuthResponse(sid, envelope)
            CT_AUTH_CONFIRM  -> handleAuthConfirm(sid, envelope)
            CT_ACK           -> handleAck(sid, envelope)
            CT_APP           -> handleAppMessage(sid, envelope)
        }
    }

    private fun handleKeyExchange(sid: String, envelope: PeerEnvelope) {
        val body = envelope.payload?.body?.let { JSONObject(it) } ?: return
        val remotePub      = body.optString("ephemeralPubKey").takeIf { it.isNotEmpty() } ?: return
        val remoteIdentity = body.optString("identityKey").takeIf { it.isNotEmpty() } ?: return
        val theirChallenge = body.optString("challenge").takeIf { it.isNotEmpty() } ?: return

        cryptoService.registerRemoteIdentityKey(sid, remoteIdentity)
        val (myPub, myPriv) = cryptoService.generateEphemeralKeyPair()
        cryptoService.deriveSessionKey(sid, myPriv, remotePub)

        val myChallenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .let { Base64.getEncoder().encodeToString(it) }
        val sig = cryptoService.signChallenge(theirChallenge)

        pending[sid] = PendingHandshake(
            isInitiator        = false,
            responderChallenge = myChallenge
        )

        sendJson(sid, CT_AUTH_RESPONSE, mapOf(
            "ephemeralPubKey"   to myPub,
            "identityKey"       to cryptoService.identityPublicKeyBase64,
            "challenge"         to myChallenge,
            "challengeResponse" to sig
        ))
    }

    private fun handleAuthResponse(sid: String, envelope: PeerEnvelope) {
        val body    = envelope.payload?.body?.let { JSONObject(it) } ?: return
        val p       = pending[sid] ?: return
        if (!p.isInitiator) return

        val remotePub      = body.optString("ephemeralPubKey").takeIf { it.isNotEmpty() } ?: return
        val remoteIdentity = body.optString("identityKey").takeIf { it.isNotEmpty() } ?: return
        val theirChallenge = body.optString("challenge").takeIf { it.isNotEmpty() } ?: return
        val sig            = body.optString("challengeResponse").takeIf { it.isNotEmpty() } ?: return

        cryptoService.registerRemoteIdentityKey(sid, remoteIdentity)

        if (!cryptoService.verifyChallengeSignature(sid, p.challenge!!, sig)) {
            failChannel(sid, "auth_failed:invalid_challenge_response")
            return
        }

        cryptoService.deriveSessionKey(sid, p.ephemeralPrivKey!!, remotePub)
        val confirmSig = cryptoService.signChallenge(theirChallenge)

        sendJson(sid, CT_AUTH_CONFIRM, mapOf("challengeResponse" to confirmSig))
        setChannelReady(sid)
        p.resolve?.invoke(sid)
        pending.remove(sid)
    }

    private fun handleAuthConfirm(sid: String, envelope: PeerEnvelope) {
        val body = envelope.payload?.body?.let { JSONObject(it) } ?: return
        val sig  = body.optString("challengeResponse").takeIf { it.isNotEmpty() } ?: return
        val p    = pending[sid] ?: return
        if (p.isInitiator) return

        if (!cryptoService.verifyChallengeSignature(sid, p.responderChallenge!!, sig)) {
            failChannel(sid, "auth_failed:invalid_auth_confirm")
            return
        }

        setChannelReady(sid)
        pending.remove(sid)
    }

    private fun handleAppMessage(sid: String, envelope: PeerEnvelope) {
        if (channels[sid]?.status != ChannelStatus.READY) return
        val body       = envelope.payload?.body?.let { JSONObject(it) } ?: return
        val messageId  = body.optString("messageId").takeIf { it.isNotEmpty() } ?: return
        val ciphertext = body.optString("ciphertext").takeIf { it.isNotEmpty() } ?: return
        val nonce      = body.optString("nonce").takeIf { it.isNotEmpty() } ?: return
        val requireAck = body.optBoolean("requireAck", false)

        val plaintext = try {
            cryptoService.decrypt(sid, ciphertext, nonce)
        } catch (_: Exception) {
            onChannelError?.invoke("decrypt_failed:$sid")
            return
        }

        if (requireAck) sendJson(sid, CT_ACK, mapOf("messageId" to messageId))
        onMessageReceived?.invoke(sid, messageId, plaintext)
    }

    private fun handleAck(sid: String, envelope: PeerEnvelope) {
        val messageId = envelope.payload?.body
            ?.let { JSONObject(it).optString("messageId") }
            ?.takeIf { it.isNotEmpty() } ?: return
        queue.acknowledge(messageId)
        onMessageAcknowledged?.invoke(sid, messageId)
    }

    private fun handleSessionClosed(sid: String) {
        channels[sid]?.status = ChannelStatus.CLOSED
        cryptoService.clearSession(sid)
        pending.remove(sid)
        onChannelClosed?.invoke(sid)
    }

    private fun setChannelReady(sid: String) {
        channels[sid]?.status = ChannelStatus.READY
        onChannelReady?.invoke(sid, channels[sid]?.remoteNodeId)
    }

    private fun failChannel(sid: String, reason: String) {
        channels[sid]?.status = ChannelStatus.ERROR
        pending.remove(sid)?.reject?.invoke(IllegalStateException("Channel auth failed: $reason"))
        cryptoService.clearSession(sid)
        onChannelError?.invoke(reason)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun sendJson(sessionId: String, contentType: String, body: Map<String, Any?>) {
        val json = JSONObject(body).toString()
        client.sendData(
            sessionId   = sessionId,
            body        = json,
            contentType = contentType,
            encoding    = PeerPayloadEncoding.JSON
        )
    }
}
