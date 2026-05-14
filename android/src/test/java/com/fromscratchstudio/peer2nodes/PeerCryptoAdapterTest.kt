package com.fromscratchstudio.peer2nodes

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class PeerCryptoAdapterTest {

    // ── Fixtures ─────────────────────────────────────────────────────────────

    private val kp = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    /** DER/SPKI public key as produced natively by JCE */
    private val realDerSpki: ByteArray get() = kp.public.encoded  // 91 bytes

    /** x9.63 uncompressed point extracted from the DER/SPKI key */
    private val realX963: ByteArray get() = realDerSpki.copyOfRange(26, 91)

    /** DER ECDSA signature */
    private val realDerSig: ByteArray get() = Signature.getInstance("SHA256withECDSA").run {
        initSign(kp.private); update("hello".toByteArray()); sign()
    }

    /** P1363 signature derived from the DER sig */
    private val realP1363: ByteArray get() = PeerCryptoAdapter.derToP1363(realDerSig)

    // ── x9.63 ↔ DER/SPKI ─────────────────────────────────────────────────────

    @Test fun x963ToDerSpki_produces91ByteResult() {
        assertEquals(91, PeerCryptoAdapter.x963ToDerSpki(realX963).size)
    }

    @Test fun x963ToDerSpki_roundTripsToOriginalDerSpki() {
        assertArrayEquals(realDerSpki, PeerCryptoAdapter.x963ToDerSpki(realX963))
    }

    @Test fun derSpkiToX963_extracts65BytePoint() {
        assertEquals(65, PeerCryptoAdapter.derSpkiToX963(realDerSpki).size)
        assertEquals(0x04.toByte(), PeerCryptoAdapter.derSpkiToX963(realDerSpki)[0])
    }

    @Test fun derSpkiToX963_roundTripsToOriginalX963() {
        assertArrayEquals(realX963, PeerCryptoAdapter.derSpkiToX963(realDerSpki))
    }

    @Test fun x963ToDerSpki_importableByKeyFactory() {
        val der = PeerCryptoAdapter.x963ToDerSpki(realX963)
        // Should not throw:
        val pub = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(der))
        assertNotNull(pub)
    }

    @Test(expected = IllegalArgumentException::class)
    fun x963ToDerSpki_throwsOnWrongSize() {
        PeerCryptoAdapter.x963ToDerSpki(ByteArray(64))
    }

    @Test(expected = IllegalArgumentException::class)
    fun derSpkiToX963_throwsOnWrongSize() {
        PeerCryptoAdapter.derSpkiToX963(ByteArray(90))
    }

    @Test(expected = IllegalArgumentException::class)
    fun derSpkiToX963_throwsOnCorruptHeader() {
        val bad = realDerSpki.copyOf()
        bad[2] = 0xff.toByte()  // corrupt AlgorithmIdentifier
        PeerCryptoAdapter.derSpkiToX963(bad)
    }

    // ── P1363 ↔ DER ECDSA ────────────────────────────────────────────────────

    @Test fun p1363ToDer_producesSequenceTag() {
        val der = PeerCryptoAdapter.p1363ToDer(realP1363)
        assertEquals(0x30.toByte(), der[0])
        assertTrue("DER sig should be 70–72 bytes, got ${der.size}", der.size in 70..72)
    }

    @Test fun derToP1363_produces64Bytes() {
        assertEquals(64, PeerCryptoAdapter.derToP1363(realDerSig).size)
    }

    @Test fun der_p1363_der_roundTrip_sigStillVerifies() {
        val p1363     = PeerCryptoAdapter.derToP1363(realDerSig)
        val backToDer = PeerCryptoAdapter.p1363ToDer(p1363)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public); update("hello".toByteArray()); verify(backToDer)
        }
        assertTrue("Round-tripped signature should verify", ok)
    }

    @Test fun p1363ToDer_convertedSigVerifies() {
        val converted = PeerCryptoAdapter.p1363ToDer(realP1363)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public); update("hello".toByteArray()); verify(converted)
        }
        assertTrue("P1363→DER signature should verify", ok)
    }

    @Test(expected = IllegalArgumentException::class)
    fun p1363ToDer_throwsOnWrongSize() {
        PeerCryptoAdapter.p1363ToDer(ByteArray(63))
    }

    @Test(expected = IllegalArgumentException::class)
    fun derToP1363_throwsOnNonSequence() {
        PeerCryptoAdapter.derToP1363(byteArrayOf(0x02, 0x01, 0x00))
    }

    // ── Edge cases: R/S boundary conditions ──────────────────────────────────

    @Test fun p1363ToDer_handlesRWithHighBitSet() {
        val p1363 = ByteArray(64) { 0x01 }
        p1363[0] = 0x80.toByte()  // high bit set → needs 0x00 prefix in DER
        val der = PeerCryptoAdapter.p1363ToDer(p1363)
        // DER: [0x30][len][0x02][R_len=33][0x00][0x80]...
        assertEquals(0x02.toByte(), der[2])   // INTEGER tag
        assertEquals(33.toByte(),   der[3])   // R length = 33 (with 0x00 prefix)
        assertEquals(0x00.toByte(), der[4])   // 0x00 prefix
        assertEquals(0x80.toByte(), der[5])   // first R byte
    }

    @Test fun p1363ToDer_handlesRWithLeadingZeros() {
        val p1363 = ByteArray(64) { 0x01 }
        p1363[0] = 0x00; p1363[1] = 0x00; p1363[2] = 0x7f  // two leading zeros stripped
        val der = PeerCryptoAdapter.p1363ToDer(p1363)
        // DER: [0x30][len][0x02][R_len=30][0x7f][0x01]...
        assertEquals(0x02.toByte(), der[2])   // INTEGER tag
        assertEquals(30.toByte(),   der[3])   // R length = 30 (2 leading zeros stripped)
        assertEquals(0x7f.toByte(), der[4])   // first R value byte
    }

    @Test fun derToP1363_paddingHandledCorrectly() {
        // Build DER where R is only 30 bytes (had leading zeros in P1363)
        val shortR   = ByteArray(30) { 0x01 }
        val fullS    = ByteArray(32) { 0x02 }
        val rDer     = byteArrayOf(0x02.toByte(), 30.toByte()) + shortR
        val sDer     = byteArrayOf(0x02.toByte(), 32.toByte()) + fullS
        val seq      = rDer + sDer
        val der      = byteArrayOf(0x30.toByte(), seq.size.toByte()) + seq

        val p1363 = PeerCryptoAdapter.derToP1363(der)
        assertEquals(64, p1363.size)
        assertEquals(0x00.toByte(), p1363[0])   // zero-padded
        assertEquals(0x00.toByte(), p1363[1])   // zero-padded
        assertEquals(0x01.toByte(), p1363[2])   // actual value
    }

    // ── Auto-detecting normalisation ──────────────────────────────────────────

    @Test fun normalizePublicKey_noOpForDerSpki() {
        val b64 = Base64.getEncoder().encodeToString(realDerSpki)
        assertEquals(b64, PeerCryptoAdapter.normalizePublicKey(b64))
    }

    @Test fun normalizePublicKey_convertsX963ToDerSpki() {
        val x963b64   = Base64.getEncoder().encodeToString(realX963)
        val expected  = Base64.getEncoder().encodeToString(realDerSpki)
        assertEquals(expected, PeerCryptoAdapter.normalizePublicKey(x963b64))
    }

    @Test fun normalizeSignature_noOpForDer() {
        val b64 = Base64.getEncoder().encodeToString(realDerSig)
        assertEquals(b64, PeerCryptoAdapter.normalizeSignature(b64))
    }

    @Test fun normalizeSignature_convertsP1363ToDer() {
        val p1363b64 = Base64.getEncoder().encodeToString(realP1363)
        val result   = PeerCryptoAdapter.normalizeSignature(p1363b64)
        val resultBytes = Base64.getDecoder().decode(result)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public); update("hello".toByteArray()); verify(resultBytes)
        }
        assertTrue("normalizeSignature result should verify", ok)
    }

    @Test(expected = IllegalStateException::class)
    fun normalizePublicKey_throwsOnUnrecognizedFormat() {
        PeerCryptoAdapter.normalizePublicKey(Base64.getEncoder().encodeToString(ByteArray(33)))
    }

    // ── End-to-end cross-format scenario ─────────────────────────────────────

    @Test fun iosToAndroid_x963KeyAndP1363SigVerifiableAfterNormalization() {
        // "iOS" transmits x9.63 key and P1363 signature
        val iosKeyB64 = Base64.getEncoder().encodeToString(realX963)
        val iosSigB64 = Base64.getEncoder().encodeToString(realP1363)

        // "Android" normalises and verifies
        val normalizedKey = PeerCryptoAdapter.normalizePublicKey(iosKeyB64)
        val normalizedSig = PeerCryptoAdapter.normalizeSignature(iosSigB64)

        val importedPub = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(
                Base64.getDecoder().decode(normalizedKey)
            ))

        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(importedPub)
            update("hello".toByteArray())
            verify(Base64.getDecoder().decode(normalizedSig))
        }
        assertTrue("Cross-format iOS→Android signature should verify", ok)
    }

    @Test fun androidToIos_derKeyAndSigConvertibleToX963AndP1363() {
        // "Android" emits DER; convert to x9.63 / P1363 for CryptoKit
        val derKeyB64 = Base64.getEncoder().encodeToString(realDerSpki)
        val derSigB64 = Base64.getEncoder().encodeToString(realDerSig)

        val x963      = PeerCryptoAdapter.derSpkiToX963(Base64.getDecoder().decode(derKeyB64))
        val p1363     = PeerCryptoAdapter.derToP1363(Base64.getDecoder().decode(derSigB64))

        // Round-trip back and verify
        val backToDer = PeerCryptoAdapter.p1363ToDer(p1363)
        val importedPub = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(
                PeerCryptoAdapter.x963ToDerSpki(x963)
            ))
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(importedPub); update("hello".toByteArray()); verify(backToDer)
        }
        assertTrue("Android→iOS reverse cross-format should verify", ok)
    }
}
