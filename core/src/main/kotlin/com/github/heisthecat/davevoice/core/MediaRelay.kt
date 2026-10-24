package com.github.heisthecat.davevoice.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * Local UDP relay between the old native voice engine and Discord's media server.
 *
 * The engine is pointed at 127.0.0.1:[localPort] and given a throwaway key for xsalsa20_poly1305_lite_rtpsize,
 * a mode it still supports. Each packet is opened with that key, its frame is wrapped (or unwrapped) with DAVE,
 * and it is sealed again with the real aead_aes256_gcm_rtpsize key towards Discord, and vice versa. Audio is one
 * Opus frame per packet; VP8 video frames are reassembled first (see OutgoingVideo/IncomingVideo).
 * IP discovery and anything else that isn't RTP/RTCP is forwarded untouched, so the engine discovers the relay's
 * public address, which is the one Discord sees.
 */
class MediaRelay(
    serverHost: String,
    serverPort: Int,
    val ssrcs: SsrcMap,
    private val log: (String) -> Unit,
) {
    private val random = SecureRandom()
    private val serverAddress = InetSocketAddress(InetAddress.getByName(serverHost), serverPort)
    private val local = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
    private val remote = DatagramSocket()

    @Volatile
    private var engineAddress: SocketAddress? = null

    /** Key handed to the native engine in place of the real one. */
    val engineKey = ByteArray(32).also { random.nextBytes(it) }
    private val engineCipher: TransportCipher = XSalsa20Poly1305Lite(engineKey)

    @Volatile
    private var serverCipher: TransportCipher? = null

    @Volatile
    var session: DaveSession? = null

    private val outgoingVideo = OutgoingVideo { ssrc, w, h -> log("Sending VP8 key frames for ssrc $ssrc at ${w}x$h") }
    private val incomingVideo = IncomingVideo()

    private val toServerNonce = AtomicLong(random.nextInt().toLong() and 0xFFFFFFFFL)
    private val toEngineNonce = AtomicLong(0)

    @Volatile
    private var closed = false

    val localPort: Int get() = local.localPort

    // Counters, readable for diagnostics.
    val sentFrames = AtomicLong()
    val receivedFrames = AtomicLong()
    val sentVideoFrames = AtomicLong()
    val receivedVideoFrames = AtomicLong()
    val droppedOutgoing = AtomicLong()
    val droppedIncoming = AtomicLong()

    init {
        remote.connect(serverAddress)
        thread("DaveVoice-up") { pumpUp() }
        thread("DaveVoice-down") { pumpDown() }
        log("Relay 127.0.0.1:$localPort <-> $serverHost:$serverPort")
    }

    /** Called with the real session description (op 4). */
    fun setServerKey(mode: String, key: ByteArray) {
        serverCipher = TransportCipher.forMode(mode, key)
        if (serverCipher == null) log("Unsupported transport mode from server: $mode")
    }

    fun close() {
        closed = true
        local.close()
        remote.close()
    }

    private fun thread(name: String, body: () -> Unit) {
        val t = Thread({
            try {
                body()
            } catch (e: SocketException) {
                if (!closed) log("$name socket error: $e")
            } catch (e: Throwable) {
                log("$name crashed: $e")
            }
        }, name)
        t.isDaemon = true
        t.priority = Thread.MAX_PRIORITY
        t.start()
    }

    private fun pumpUp() {
        val buf = ByteArray(2048)
        val packet = DatagramPacket(buf, buf.size)
        while (!closed) {
            packet.setData(buf, 0, buf.size)
            local.receive(packet)
            engineAddress = packet.socketAddress
            val out = try {
                transformUp(buf.copyOfRange(0, packet.length))
            } catch (e: Exception) {
                log("Outgoing packet error: $e")
                null
            }
            if (out == null) droppedOutgoing.incrementAndGet() else for (p in out) remote.send(DatagramPacket(p, p.size))
        }
    }

    private fun pumpDown() {
        val buf = ByteArray(2048)
        val packet = DatagramPacket(buf, buf.size)
        while (!closed) {
            packet.setData(buf, 0, buf.size)
            remote.receive(packet)
            val target = engineAddress ?: continue
            val out = try {
                transformDown(buf.copyOfRange(0, packet.length))
            } catch (e: Exception) {
                log("Incoming packet error: $e")
                null
            }
            if (out == null) droppedIncoming.incrementAndGet() else for (p in out) local.send(DatagramPacket(p, p.size, target))
        }
    }

    /** Engine -> Discord. Null means dropped; an empty list means held back (rest of a video frame pending). */
    internal fun transformUp(packet: ByteArray): List<ByteArray>? {
        val server = serverCipher ?: return listOf(packet)
        val opened = open(engineCipher, packet) ?: return if (isMedia(packet)) null else listOf(packet)
        val (header, body) = opened
        if (Rtp.isRtcp(packet)) return listOf(seal(server, header, body, toServerNonce))

        val dave = session
        val ssrc = Rtp.ssrc(packet)
        if (dave == null || dave.protocolVersion == 0) return listOf(seal(server, header, body, toServerNonce))
        val rtp = RtpPacket.split(packet, header, body) ?: return null

        return when {
            ssrc == ssrcs.selfAudio -> {
                val frame = dave.encryptFrame(rtp.payload) ?: return null
                sentFrames.incrementAndGet()
                rtp.payload = frame
                listOf(seal(server, rtp.header, rtp.body(), toServerNonce))
            }
            ssrc in ssrcs.ownVideo -> {
                if (rtp.payload.isEmpty()) return listOf(seal(server, header, body, toServerNonce))
                if (!isVp8(packet)) return null
                val frame = outgoingVideo.onPacket(ssrc, rtp) { f, prefix -> dave.encryptFrame(f, prefix) }
                if (frame.isNotEmpty()) sentVideoFrames.incrementAndGet()
                frame.map { seal(server, it.header, it.body(), toServerNonce) }
            }
            ssrcs.ownRtxToVideo.containsKey(ssrc) -> {
                // RTX payload = original sequence number + original payload. Resend what we actually sent.
                if (rtp.payload.size < 2) return listOf(seal(server, header, body, toServerNonce))
                val sent = outgoingVideo.sentPayload(ssrcs.ownRtxToVideo.getValue(ssrc), rtp.payload.u16(0)) ?: return null
                rtp.payload = rtp.payload.copyOfRange(0, 2) + sent
                listOf(seal(server, rtp.header, rtp.body(), toServerNonce))
            }
            else -> null
        }
    }

    /** Discord -> engine. Null means dropped; an empty list means held back (rest of a video frame pending). */
    internal fun transformDown(packet: ByteArray): List<ByteArray>? {
        val server = serverCipher ?: return listOf(packet)
        val opened = open(server, packet) ?: return if (isMedia(packet)) null else listOf(packet)
        val (header, body) = opened
        if (Rtp.isRtcp(packet)) return listOf(seal(engineCipher, header, body, toEngineNonce))

        val dave = session
        val ssrc = Rtp.ssrc(packet)
        if (dave == null || dave.protocolVersion == 0) return listOf(seal(engineCipher, header, body, toEngineNonce))
        val rtp = RtpPacket.split(packet, header, body) ?: return null

        ssrcs.audioToUser[ssrc]?.let { user ->
            rtp.payload = dave.decryptFrame(user, rtp.payload) ?: return null
            receivedFrames.incrementAndGet()
            return listOf(seal(engineCipher, rtp.header, rtp.body(), toEngineNonce))
        }
        ssrcs.videoToUser[ssrc]?.let { user ->
            if (rtp.payload.isEmpty()) return listOf(seal(engineCipher, header, body, toEngineNonce))
            if (!isVp8(packet)) return null
            return decryptVideo(ssrc, user, dave, rtp)
        }
        ssrcs.rtxToVideo[ssrc]?.let { videoSsrc ->
            // Turn the retransmission back into the original packet so it can complete its frame.
            val user = ssrcs.videoToUser[videoSsrc] ?: return null
            if (rtp.payload.size < 2) return listOf(seal(engineCipher, header, body, toEngineNonce))
            val original = rtp.header.clone()
            original.putU16(2, rtp.payload.u16(0))
            original[1] = ((original[1].toInt() and 0x80) or (ssrcs.vp8PayloadType and 0x7F)).toByte()
            original.putU32(8, videoSsrc)
            val restored = RtpPacket(original, rtp.extension, rtp.payload.copyOfRange(2, rtp.payload.size), rtp.padding)
            return decryptVideo(videoSsrc, user, dave, restored)
        }
        return null
    }

    private fun decryptVideo(ssrc: Long, user: Long, dave: DaveSession, rtp: RtpPacket): List<ByteArray> {
        val frame = incomingVideo.onPacket(ssrc, rtp) { dave.decryptFrame(user, it, audio = false) }
        if (frame.isNotEmpty()) receivedVideoFrames.incrementAndGet()
        return frame.map { seal(engineCipher, it.header, it.body(), toEngineNonce) }
    }

    private fun isVp8(packet: ByteArray) = ssrcs.vp8PayloadType < 0 || Rtp.payloadType(packet) == ssrcs.vp8PayloadType

    private fun isMedia(packet: ByteArray) = Rtp.isRtp(packet) || Rtp.isRtcp(packet)

    /** Splits an _rtpsize packet into (clear header, decrypted body), or null if it isn't one / fails to open. */
    private fun open(cipher: TransportCipher, packet: ByteArray): Pair<ByteArray, ByteArray>? {
        if (!isMedia(packet)) return null
        val headerSize = if (Rtp.isRtcp(packet)) 8 else Rtp.clearHeaderSize(packet)
        if (packet.size < headerSize + 16 + 4) return null
        val header = packet.copyOfRange(0, headerSize)
        val body = cipher.open(header, packet.copyOfRange(headerSize, packet.size - 4), packet.copyOfRange(packet.size - 4, packet.size))
            ?: return null
        return header to body
    }

    private fun seal(cipher: TransportCipher, header: ByteArray, payload: ByteArray, counter: AtomicLong): ByteArray {
        val nonce = ByteArray(4)
        nonce.putU32(0, counter.incrementAndGet() and 0xFFFFFFFFL)
        val sealed = cipher.seal(header, payload, nonce)
        val out = ByteArray(header.size + sealed.size + 4)
        System.arraycopy(header, 0, out, 0, header.size)
        System.arraycopy(sealed, 0, out, header.size, sealed.size)
        System.arraycopy(nonce, 0, out, header.size + sealed.size, 4)
        return out
    }
}
