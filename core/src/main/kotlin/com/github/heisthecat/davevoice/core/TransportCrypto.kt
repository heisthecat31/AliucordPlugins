package com.github.heisthecat.davevoice.core

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.util.Arrays

/**
 * Voice transport encryption for the "_rtpsize" modes: the RTP header (plus the 4 byte extension header, if any)
 * or the 8 byte RTCP header stays in the clear, the rest is encrypted, and a 4 byte nonce counter is appended.
 */
interface TransportCipher {
    val mode: String

    /** Returns the encrypted payload (including the tag), without the appended nonce. */
    fun seal(header: ByteArray, plaintext: ByteArray, nonce: ByteArray): ByteArray

    /** Returns the plaintext, or null if authentication fails. */
    fun open(header: ByteArray, ciphertext: ByteArray, nonce: ByteArray): ByteArray?

    companion object {
        const val AES_GCM = "aead_aes256_gcm_rtpsize"
        const val XSALSA_LITE = "xsalsa20_poly1305_lite_rtpsize"

        fun forMode(mode: String, key: ByteArray): TransportCipher? = when (mode) {
            AES_GCM -> AesGcmRtpSize(key)
            XSALSA_LITE -> XSalsa20Poly1305Lite(key)
            else -> null
        }
    }
}

/** aead_aes256_gcm_rtpsize: AAD is the clear header, 12 byte nonce is the counter followed by zeros. */
class AesGcmRtpSize(private val key: ByteArray) : TransportCipher {
    override val mode get() = TransportCipher.AES_GCM

    private fun cipher(encrypt: Boolean, header: ByteArray, nonce: ByteArray): GCMBlockCipher {
        val iv = ByteArray(12)
        System.arraycopy(nonce, 0, iv, 0, 4)
        val c = GCMBlockCipher.newInstance(AESEngine.newInstance()) as GCMBlockCipher
        c.init(encrypt, AEADParameters(KeyParameter(key), 128, iv, header))
        return c
    }

    override fun seal(header: ByteArray, plaintext: ByteArray, nonce: ByteArray): ByteArray {
        val c = cipher(true, header, nonce)
        val out = ByteArray(c.getOutputSize(plaintext.size))
        val len = c.processBytes(plaintext, 0, plaintext.size, out, 0)
        c.doFinal(out, len)
        return out
    }

    override fun open(header: ByteArray, ciphertext: ByteArray, nonce: ByteArray): ByteArray? {
        if (ciphertext.size < 16) return null
        val c = cipher(false, header, nonce)
        val out = ByteArray(c.getOutputSize(ciphertext.size))
        return try {
            val len = c.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            c.doFinal(out, len)
            out
        } catch (e: Exception) {
            null
        }
    }
}

/** xsalsa20_poly1305_lite_rtpsize: NaCl secretbox (tag || ciphertext), 24 byte nonce is the counter then zeros. */
class XSalsa20Poly1305Lite(private val key: ByteArray) : TransportCipher {
    override val mode get() = TransportCipher.XSALSA_LITE

    private fun stream(nonce: ByteArray): Pair<XSalsa20Engine, ByteArray> {
        val iv = ByteArray(24)
        System.arraycopy(nonce, 0, iv, 0, 4)
        val engine = XSalsa20Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), iv))
        // The first 32 keystream bytes are the one-time Poly1305 key; encryption continues from byte 32.
        val polyKey = ByteArray(32)
        engine.processBytes(ByteArray(32), 0, 32, polyKey, 0)
        return engine to polyKey
    }

    private fun tag(polyKey: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray {
        val mac = Poly1305()
        mac.init(KeyParameter(polyKey))
        mac.update(data, offset, length)
        val out = ByteArray(16)
        mac.doFinal(out, 0)
        return out
    }

    override fun seal(header: ByteArray, plaintext: ByteArray, nonce: ByteArray): ByteArray {
        val (engine, polyKey) = stream(nonce)
        val out = ByteArray(16 + plaintext.size)
        engine.processBytes(plaintext, 0, plaintext.size, out, 16)
        System.arraycopy(tag(polyKey, out, 16, plaintext.size), 0, out, 0, 16)
        return out
    }

    override fun open(header: ByteArray, ciphertext: ByteArray, nonce: ByteArray): ByteArray? {
        if (ciphertext.size < 16) return null
        val (engine, polyKey) = stream(nonce)
        val expected = tag(polyKey, ciphertext, 16, ciphertext.size - 16)
        if (!Arrays.constantTimeAreEqual(expected, ciphertext.copyOfRange(0, 16))) return null
        val out = ByteArray(ciphertext.size - 16)
        engine.processBytes(ciphertext, 16, out.size, out, 0)
        return out
    }
}

/** Minimal RTP/RTCP framing helpers. */
object Rtp {
    const val OPUS_PAYLOAD_TYPE = 120

    fun isRtcp(packet: ByteArray) = packet.size >= 8 && (packet[0].toInt() and 0xC0) == 0x80 && packet.u8(1) in 200..204

    fun isRtp(packet: ByteArray) = packet.size >= 12 && (packet[0].toInt() and 0xC0) == 0x80 && !isRtcp(packet)

    /** Size of the cleartext header for _rtpsize modes: fixed header + CSRCs + 4 byte extension header if present. */
    fun clearHeaderSize(packet: ByteArray): Int {
        var size = 12 + 4 * (packet[0].toInt() and 0x0F)
        if (packet[0].toInt() and 0x10 != 0) size += 4
        return size
    }

    /** Length of the extension body that sits at the start of the decrypted payload. */
    fun extensionBodySize(packet: ByteArray): Int {
        if (packet[0].toInt() and 0x10 == 0) return 0
        val headerSize = clearHeaderSize(packet)
        return packet.u16(headerSize - 2) * 4
    }

    fun payloadType(packet: ByteArray) = packet[1].toInt() and 0x7F

    fun ssrc(packet: ByteArray) = packet.u32(8)

    fun hasPadding(packet: ByteArray) = packet[0].toInt() and 0x20 != 0
}
