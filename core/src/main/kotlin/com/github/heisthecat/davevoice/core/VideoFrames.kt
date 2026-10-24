package com.github.heisthecat.davevoice.core

import java.util.concurrent.ConcurrentHashMap

/**
 * Who owns which SSRC, and the negotiated video payload types. Filled from the voice gateway (READY, op 12) and
 * select_protocol, shared with the relay.
 */
class SsrcMap {
    /** Remote audio SSRC to user ID. */
    val audioToUser = ConcurrentHashMap<Long, Long>()

    /** Remote video SSRC to user ID. */
    val videoToUser = ConcurrentHashMap<Long, Long>()

    /** Remote RTX SSRC to the video SSRC it retransmits. */
    val rtxToVideo = ConcurrentHashMap<Long, Long>()

    /** Our own video SSRCs, and our RTX SSRC to video SSRC. */
    val ownVideo: MutableSet<Long> = ConcurrentHashMap.newKeySet()
    val ownRtxToVideo = ConcurrentHashMap<Long, Long>()

    @Volatile
    var selfAudio = -1L

    /** VP8 and its RTX payload type from select_protocol, or -1 if unknown. */
    @Volatile
    var vp8PayloadType = -1

    @Volatile
    var rtxPayloadType = -1

    fun addRemoteVideo(userId: Long, ssrc: Long, rtxSsrc: Long) {
        if (ssrc <= 0) return
        videoToUser[ssrc] = userId
        if (rtxSsrc > 0) rtxToVideo[rtxSsrc] = ssrc
    }

    fun addOwnVideo(ssrc: Long, rtxSsrc: Long) {
        if (ssrc <= 0) return
        ownVideo.add(ssrc)
        if (rtxSsrc > 0) ownRtxToVideo[rtxSsrc] = ssrc
    }

    fun forgetUser(userId: Long) {
        audioToUser.entries.removeAll { it.value == userId }
        val videos = videoToUser.filterValues { it == userId }.keys
        videoToUser.keys.removeAll(videos)
        rtxToVideo.entries.removeAll { it.value in videos }
    }
}

/** A decrypted RTP packet split into its parts; [payload] is the codec payload (VP8 descriptor + frame bytes). */
internal class RtpPacket(val header: ByteArray, val extension: ByteArray, var payload: ByteArray, val padding: ByteArray) {
    val seq get() = header.u16(2)
    val timestamp get() = header.u32(4)
    val marker get() = header[1].toInt() and 0x80 != 0

    fun body() = extension + payload + padding

    companion object {
        /** Splits a decrypted _rtpsize body (extension body + payload + padding) for [packet]'s clear header. */
        fun split(packet: ByteArray, header: ByteArray, body: ByteArray): RtpPacket? {
            val ext = Rtp.extensionBodySize(packet)
            val pad = if (Rtp.hasPadding(packet) && body.isNotEmpty()) body.u8(body.size - 1) else 0
            if (ext + pad > body.size) return null
            return RtpPacket(
                header,
                body.copyOfRange(0, ext),
                body.copyOfRange(ext, body.size - pad),
                body.copyOfRange(body.size - pad, body.size),
            )
        }
    }
}

/** VP8 RTP payload format (RFC 7741) and DAVE's VP8 codec handling. */
internal object Vp8 {
    /** Length of the payload descriptor at the start of every VP8 RTP payload, or -1 if malformed. */
    fun descriptorSize(p: ByteArray): Int {
        if (p.isEmpty()) return -1
        var i = 1
        if (p[0].toInt() and 0x80 != 0) {
            if (p.size < 2) return -1
            val x = p[1].toInt()
            i = 2
            if (x and 0x80 != 0) {
                if (p.size <= i) return -1
                i += if (p[i].toInt() and 0x80 != 0) 2 else 1
            }
            if (x and 0x40 != 0) i++
            if (x and 0x30 != 0) i++
        }
        return if (i <= p.size) i else -1
    }

    /** S bit set and partition 0: first packet of a frame. */
    fun isFrameStart(p: ByteArray) = p.isNotEmpty() && p[0].toInt() and 0x10 != 0 && p[0].toInt() and 0x07 == 0

    /** Width and height from a key frame's uncompressed header (RFC 6386 9.1), or null for delta frames. */
    fun keyFrameSize(frame: ByteArray): Pair<Int, Int>? {
        if (frame.size < 10 || frame[0].toInt() and 0x01 != 0) return null
        return ((frame.u8(6) or (frame.u8(7) shl 8)) and 0x3FFF) to ((frame.u8(8) or (frame.u8(9) shl 8)) and 0x3FFF)
    }

    /** DAVE leaves the 10 byte uncompressed header of key frames (P bit clear) or 1 byte otherwise unencrypted. */
    fun clearPrefix(frame: ByteArray) = when {
        frame.isEmpty() -> 0
        frame[0].toInt() and 0x01 == 0 -> minOf(10, frame.size)
        else -> 1
    }
}

/**
 * Outgoing video: DAVE encrypts whole frames, so packets from the engine are held until the frame's marker packet,
 * the frame is encrypted, and the result is written back into the same packets (same sequence numbers). AES-GCM
 * keeps lengths, so only the last packet grows, by the DAVE footer.
 */
internal class OutgoingVideo(private val onKeyFrameSize: (Long, Int, Int) -> Unit = { _, _, _ -> }) {
    private val lastSize = HashMap<Long, Int>()
    private val pending = HashMap<Long, ArrayList<RtpPacket>>()
    private val sent = object : LinkedHashMap<Long, ByteArray>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>?) = size > 2048
    }

    /** Returns the packets to send now (empty while a frame is incomplete or if it could not be encrypted). */
    fun onPacket(ssrc: Long, packet: RtpPacket, encrypt: (ByteArray, Int) -> ByteArray?): List<RtpPacket> {
        val frame = pending.getOrPut(ssrc) { ArrayList() }
        if (frame.isNotEmpty() && frame[0].timestamp != packet.timestamp) frame.clear()
        frame.add(packet)
        if (!packet.marker) return emptyList()
        pending.remove(ssrc)

        val descriptors = IntArray(frame.size) { Vp8.descriptorSize(frame[it].payload) }
        if (descriptors.any { it < 0 }) return emptyList()
        val plain = concatFrame(frame, descriptors)
        Vp8.keyFrameSize(plain)?.let { (w, h) ->
            if (lastSize.put(ssrc, (w shl 16) or h) != (w shl 16) or h) onKeyFrameSize(ssrc, w, h)
        }
        val encrypted = encrypt(plain, Vp8.clearPrefix(plain)) ?: return emptyList()

        var offset = 0
        for ((i, p) in frame.withIndex()) {
            val take = if (i == frame.lastIndex) encrypted.size - offset else p.payload.size - descriptors[i]
            p.payload = p.payload.copyOfRange(0, descriptors[i]) + encrypted.copyOfRange(offset, offset + take)
            offset += take
            synchronized(sent) { sent[key(ssrc, p.seq)] = p.payload }
        }
        return frame
    }

    /** The payload we actually sent for [seq], for answering an RTX retransmission request. */
    fun sentPayload(ssrc: Long, seq: Int): ByteArray? = synchronized(sent) { sent[key(ssrc, seq)] }

    private fun key(ssrc: Long, seq: Int) = (ssrc shl 16) or seq.toLong()
}

/**
 * Incoming video: packets of a frame are collected (including RTX retransmissions converted back) until the frame
 * is complete, then the DAVE protocol frame is decrypted and written back into the same packets. Trailing packets
 * that only carried the footer are dropped and the marker moves to the new last packet.
 */
internal class IncomingVideo(private val now: () -> Long = System::currentTimeMillis) {
    private class Frame(val created: Long) {
        val packets = HashMap<Int, RtpPacket>()
    }

    private val frames = HashMap<Long, LinkedHashMap<Long, Frame>>()
    private val finished = HashMap<Long, java.util.ArrayDeque<Long>>()

    fun onPacket(ssrc: Long, packet: RtpPacket, decrypt: (ByteArray) -> ByteArray?): List<RtpPacket> {
        val done = finished.getOrPut(ssrc) { java.util.ArrayDeque() }
        if (done.contains(packet.timestamp)) return emptyList()
        val byTimestamp = frames.getOrPut(ssrc) { LinkedHashMap() }
        val t = now()
        byTimestamp.entries.removeAll { t - it.value.created > MAX_FRAME_AGE_MS }
        val frame = byTimestamp.getOrPut(packet.timestamp) { Frame(t) }
        frame.packets[packet.seq] = packet

        val ordered = completeFrame(frame) ?: return emptyList()
        byTimestamp.remove(packet.timestamp)
        done.addLast(packet.timestamp)
        while (done.size > 64) done.removeFirst()

        val descriptors = IntArray(ordered.size) { Vp8.descriptorSize(ordered[it].payload) }
        if (descriptors.any { it < 0 }) return emptyList()
        val plain = decrypt(concatFrame(ordered, descriptors)) ?: return emptyList()

        val out = ArrayList<RtpPacket>(ordered.size)
        var offset = 0
        for ((i, p) in ordered.withIndex()) {
            val take = minOf(p.payload.size - descriptors[i], plain.size - offset)
            if (take <= 0 && out.isNotEmpty()) break
            p.payload = p.payload.copyOfRange(0, descriptors[i]) + plain.copyOfRange(offset, offset + maxOf(take, 0))
            offset += maxOf(take, 0)
            out.add(p)
        }
        val last = out.last()
        last.header[1] = (last.header[1].toInt() or 0x80).toByte()
        return out
    }

    /** Packets from the frame-start packet to the marker packet if none are missing, else null. */
    private fun completeFrame(frame: Frame): List<RtpPacket>? {
        val start = frame.packets.values.firstOrNull { Vp8.isFrameStart(it.payload) } ?: return null
        val end = frame.packets.values.firstOrNull { it.marker } ?: return null
        val count = ((end.seq - start.seq) and 0xFFFF) + 1
        if (count > frame.packets.size) return null
        return List(count) { frame.packets[(start.seq + it) and 0xFFFF] ?: return null }
    }

    companion object {
        private const val MAX_FRAME_AGE_MS = 1000L
    }
}

private fun concatFrame(packets: List<RtpPacket>, descriptors: IntArray): ByteArray {
    var size = 0
    for ((i, p) in packets.withIndex()) size += p.payload.size - descriptors[i]
    val out = ByteArray(size)
    var offset = 0
    for ((i, p) in packets.withIndex()) {
        val n = p.payload.size - descriptors[i]
        System.arraycopy(p.payload, descriptors[i], out, offset, n)
        offset += n
    }
    return out
}
