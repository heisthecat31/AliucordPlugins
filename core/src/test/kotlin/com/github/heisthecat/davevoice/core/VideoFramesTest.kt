package com.github.heisthecat.davevoice.core

import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VideoFramesTest {
    private val suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
    private fun ratchet() = KeyRatchet(suite, ByteArray(16) { 7 })

    /** Splits a VP8 frame into RTP packets like WebRTC: descriptor with X/I (15 bit picture ID), S on the first. */
    private fun packetize(frame: ByteArray, firstSeq: Int, timestamp: Long, chunk: Int): List<RtpPacket> {
        val out = ArrayList<RtpPacket>()
        var offset = 0
        var seq = firstSeq
        while (offset < frame.size) {
            val n = minOf(chunk, frame.size - offset)
            val start = offset == 0
            val descriptor = byteArrayOf((0x80 or if (start) 0x10 else 0).toByte(), 0x80.toByte(), 0x81.toByte(), 0x23)
            val header = ByteArray(12)
            header[0] = 0x80.toByte()
            header[1] = ((if (offset + n == frame.size) 0x80 else 0) or 105).toByte()
            header.putU16(2, seq and 0xFFFF)
            header.putU32(4, timestamp)
            header.putU32(8, 0x1234)
            out.add(RtpPacket(header, ByteArray(0), descriptor + frame.copyOfRange(offset, offset + n), ByteArray(0)))
            offset += n
            seq++
        }
        return out
    }

    private fun copy(p: RtpPacket) = RtpPacket(p.header.clone(), p.extension, p.payload.clone(), p.padding)

    @Test
    fun keyFrameRoundTripAcrossSeqWrap() {
        val frame = ByteArray(3000) { (it * 31).toByte() }.also { it[0] = 0x10 } // P bit clear: key frame
        val original = packetize(frame, 65534, 90000, 1100)
        assertEquals(3, original.size)

        val encryptor = DaveEncryptor().apply { setKeyRatchet(ratchet()) }
        val outgoing = OutgoingVideo()
        val sent = ArrayList<RtpPacket>()
        for (p in original.map(::copy)) sent += outgoing.onPacket(0x1234, p) { f, prefix -> encryptor.encrypt(f, prefix) }
        assertEquals(3, sent.size)
        // Same packets and sizes, except the last grows by the DAVE footer; the 10 byte VP8 header stays readable.
        for (i in 0 until 2) assertEquals(original[i].payload.size, sent[i].payload.size)
        assertTrue(sent[2].payload.size > original[2].payload.size)
        assertArrayEquals(frame.copyOfRange(0, 10), sent[0].payload.copyOfRange(4, 14))
        assertTrue(!frame.copyOfRange(10, 40).contentEquals(sent[0].payload.copyOfRange(14, 44)))
        assertArrayEquals(sent[1].payload, outgoing.sentPayload(0x1234, original[1].seq))

        val decryptor = DaveDecryptor().apply { transitionToKeyRatchet(ratchet()) }
        val incoming = IncomingVideo()
        val received = ArrayList<RtpPacket>()
        for (p in listOf(sent[2], sent[0], sent[0], sent[1]).map(::copy)) {
            received += incoming.onPacket(0x1234, p) { decryptor.decrypt(it, audio = false) }
        }
        assertEquals(3, received.size)
        for (i in 0 until 3) assertArrayEquals(original[i].payload, received[i].payload)
        assertTrue(received[2].marker)
    }

    @Test
    fun footerOnlyPacketIsDroppedOnReceive() {
        val frame = ByteArray(1105) { it.toByte() }.also { it[0] = 0x11 } // delta frame
        val encryptor = DaveEncryptor().apply { setKeyRatchet(ratchet()) }
        val outgoing = OutgoingVideo()
        // Sender packetizes the protocol frame so the last packet holds only footer bytes.
        val plainPackets = packetize(frame, 10, 1, 1105)
        val sent = outgoing.onPacket(0x1234, plainPackets.single()) { f, prefix -> encryptor.encrypt(f, prefix) }
        val protocolFrame = sent.single().payload.copyOfRange(4, sent.single().payload.size)
        val resplit = packetize(protocolFrame, 10, 1, 1105)
        assertEquals(2, resplit.size)

        val decryptor = DaveDecryptor().apply { transitionToKeyRatchet(ratchet()) }
        val incoming = IncomingVideo()
        val received = resplit.flatMap { p -> incoming.onPacket(0x1234, copy(p)) { decryptor.decrypt(it, audio = false) } }
        assertEquals(1, received.size)
        assertArrayEquals(frame, received[0].payload.copyOfRange(4, received[0].payload.size))
        assertTrue(received[0].marker)
    }

    @Test
    fun vp8DescriptorParsing() {
        assertEquals(1, Vp8.descriptorSize(byteArrayOf(0x10, 0)))
        assertEquals(3, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0x80.toByte(), 0x05, 0)))
        assertEquals(4, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0x80.toByte(), 0x85.toByte(), 0x01, 0)))
        assertEquals(6, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0xF0.toByte(), 0x85.toByte(), 1, 2, 3, 0)))
        assertEquals(10, Vp8.clearPrefix(ByteArray(20)))
        assertEquals(1, Vp8.clearPrefix(byteArrayOf(1, 2, 3)))
    }
}
