package com.github.heisthecat.davevoice.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TransportCryptoTest {
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val key = ByteArray(32) { it.toByte() }
    private val header = unhex("80780001000003e8deadbeef")
    private val nonce = unhex("00000007")
    private val plain = unhex("f8fffe0102030405060708")

    @Test
    fun aesGcmMatchesReference() {
        // Python cryptography AESGCM(key).encrypt(nonce4 + 8 zero bytes, plain, header)
        val expected = unhex("a7182a80782b278ee9d59c6cbda06352fbb3dce22ae0fb3c322ec8")
        val cipher = AesGcmRtpSize(key)
        assertArrayEquals(expected, cipher.seal(header, plain, nonce))
        assertArrayEquals(plain, cipher.open(header, expected, nonce))
        val tamperedHeader = header.clone().also { it[11] = 0 }
        assertNull(cipher.open(tamperedHeader, expected, nonce))
    }

    @Test
    fun xsalsaMatchesReference() {
        // Independent Python XSalsa20 + Poly1305 (validated against the NaCl secretbox vector), nonce4 + 20 zeros.
        val expected = unhex("6e25b2232829221cc329cc57ea9b687b8e9667b2de69d28ddca6ab")
        val cipher = XSalsa20Poly1305Lite(key)
        assertArrayEquals(expected, cipher.seal(header, plain, nonce))
        assertArrayEquals(plain, cipher.open(header, expected, nonce))
        val tampered = expected.clone().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertNull(cipher.open(header, tampered, nonce))
    }

    @Test
    fun rtpHeaderParsing() {
        val withExt = unhex("90780001000003e8deadbeefbede0001")
        assertEquals(16, Rtp.clearHeaderSize(withExt))
        assertEquals(4, Rtp.extensionBodySize(withExt))
        assertEquals(0xdeadbeefL, Rtp.ssrc(withExt))
        assertEquals(120, Rtp.payloadType(withExt))
        val rtcp = unhex("80c90001deadbeef")
        assertEquals(true, Rtp.isRtcp(rtcp))
        assertEquals(false, Rtp.isRtp(rtcp))
    }
}
