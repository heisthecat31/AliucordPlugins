package com.github.heisthecat.davevoice.core

import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class FrameCryptoTest {
    private val suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
    private fun ratchet(fill: Int) = KeyRatchet(suite, ByteArray(16) { fill.toByte() })
    private val opus = ByteArray(60) { (it * 7).toByte() }

    @Test
    fun roundTrip() {
        val enc = DaveEncryptor().apply { setKeyRatchet(ratchet(0xA5)) }
        val dec = DaveDecryptor().apply { transitionToKeyRatchet(ratchet(0xA5)) }
        repeat(5) {
            val frame = enc.encrypt(opus)!!
            // footer: 8 tag + 1 nonce byte + size + FAFA
            assertEquals(opus.size + 12, frame.size)
            assertEquals(0xFA.toByte(), frame[frame.size - 1])
            assertEquals(12, frame.u8(frame.size - 3))
            assertArrayEquals(opus, dec.decrypt(frame))
        }
    }

    @Test
    fun replayAndWrongKeyRejected() {
        val enc = DaveEncryptor().apply { setKeyRatchet(ratchet(1)) }
        val dec = DaveDecryptor().apply { transitionToKeyRatchet(ratchet(1)) }
        val frame = enc.encrypt(opus)!!
        assertNotNull(dec.decrypt(frame))
        assertNull(dec.decrypt(frame))
        val other = DaveDecryptor().apply { transitionToKeyRatchet(ratchet(2)) }
        assertNull(other.decrypt(enc.encrypt(opus)!!))
    }

    @Test
    fun passthroughAndSilence() {
        val dec = DaveDecryptor()
        assertNull(dec.decrypt(opus))
        val silence = byteArrayOf(0xF8.toByte(), 0xFF.toByte(), 0xFE.toByte())
        assertArrayEquals(silence, dec.decrypt(silence))
        dec.transitionToPassthrough(true)
        assertArrayEquals(opus, dec.decrypt(opus))

        val enc = DaveEncryptor()
        assertNull(enc.encrypt(opus))
        enc.passthrough = true
        assertArrayEquals(opus, enc.encrypt(opus))
    }

    @Test
    fun oldEpochKeptDuringTransition() {
        var now = 0L
        val dec = DaveDecryptor { now }
        val oldEnc = DaveEncryptor().apply { setKeyRatchet(ratchet(1)) }
        val newEnc = DaveEncryptor().apply { setKeyRatchet(ratchet(2)) }
        dec.transitionToKeyRatchet(ratchet(1))
        dec.transitionToKeyRatchet(ratchet(2))
        assertNotNull(dec.decrypt(oldEnc.encrypt(opus)!!))
        assertNotNull(dec.decrypt(newEnc.encrypt(opus)!!))
        now += TRANSITION_EXPIRY_MS + 1
        assertNull(dec.decrypt(oldEnc.encrypt(opus)!!))
        assertNotNull(dec.decrypt(newEnc.encrypt(opus)!!))
    }

    @Test
    fun unencryptedRangesParsed() {
        // Hand-built frame: 2 clear bytes at offset 0, rest encrypted, as a video encryptor would produce.
        val key = ratchet(9).get(0)!!
        val media = byteArrayOf(0x10, 0x20, 1, 2, 3, 4, 5)
        val nonce = 1L
        val fullNonce = ByteArray(12).also { it[8] = 1 }
        val cipher = org.bouncycastle.crypto.modes.GCMBlockCipher.newInstance(org.bouncycastle.crypto.engines.AESEngine.newInstance())
        cipher.init(true, org.bouncycastle.crypto.params.AEADParameters(org.bouncycastle.crypto.params.KeyParameter(key), 64, fullNonce, byteArrayOf(0x10, 0x20)))
        val out = ByteArray(cipher.getOutputSize(5))
        cipher.doFinal(out, cipher.processBytes(media, 2, 5, out, 0))
        val ct = out.copyOfRange(0, 5)
        val tag = out.copyOfRange(5, 13)
        val frame = byteArrayOf(0x10, 0x20) + ct + tag + byteArrayOf(nonce.toByte(), 0, 2, (8 + 1 + 2 + 1 + 2).toByte(), 0xFA.toByte(), 0xFA.toByte())
        val dec = DaveDecryptor().apply { transitionToKeyRatchet(ratchet(9)) }
        assertArrayEquals(media, dec.decrypt(frame, audio = false))
    }
}
