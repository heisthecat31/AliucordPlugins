package com.github.heisthecat.davevoice

import com.aliucord.Logger
import com.discord.rtcconnection.RtcConnection
import com.github.heisthecat.davevoice.core.DaveGateway
import com.github.heisthecat.davevoice.core.DaveOpcodes
import com.github.heisthecat.davevoice.core.DaveSession
import com.github.heisthecat.davevoice.core.MediaRelay
import com.github.heisthecat.davevoice.core.SsrcMap
import okio.ByteString
import org.json.JSONArray
import org.json.JSONObject
import java.util.WeakHashMap
import b.a.q.h0 as SocketListener
import b.a.q.n0.a as RtcControlSocket
import f0.e0.n.d as RealWebSocket

/**
 * DAVE state for one RtcConnection (a voice/call connection): the MLS session, the media relay and the
 * voice gateway v8 bookkeeping the old v5 client doesn't know about.
 */
internal class VoiceConnection(private val rtc: RtcConnection, private val logger: Logger) : DaveGateway {
    // Real (obfuscated) RtcConnection fields: T = userId, P = channelId, S = rtcServerId, d0 = streamKey.
    private val userId: Long = rtc.T
    private val channelId: Long = rtc.P

    /** Go Live stream connection (has a stream key) rather than the call itself. */
    private val isStream = rtc.d0 != null

    /** MLS group ID: the channel for calls; for Go Live streams Discord uses rtcServerId - 1. */
    private val groupId: Long = if (isStream) (rtc.S.toLongOrNull() ?: channelId + 1) - 1 else channelId

    /** SSRC ownership shared with this connection's relays. */
    val ssrcs = SsrcMap()

    @Volatile
    var socket: RtcControlSocket? = null

    /** Relay of the current media connection (each LegacyMediaConnection owns its own, see bindMedia). */
    @Volatile
    var relay: MediaRelay? = null
        set(value) {
            field = value
            value?.session = session
        }

    @Volatile
    var session: DaveSession = newSession()
        private set

    /** Highest sequence number seen from the gateway (JSON "seq" or binary header), for seq_ack. */
    @Volatile
    var lastSeq = -1

    private fun newSession() = DaveSession(userId, groupId, this, { logger.info("[$channelId] $it") })

    fun log(message: String) = logger.info("[$channelId] $message")

    // region Outgoing JSON (rewritten on its way into okhttp)

    fun patchOutgoing(text: String): String {
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            return text
        }
        when (json.optInt("op", -1)) {
            0 -> {
                // Fresh identify = fresh media session, so start a new MLS session too.
                session = newSession()
                relay?.session = session
                json.getJSONObject("d").put("max_dave_protocol_version", 1)
                log("Identifying with max_dave_protocol_version=1")
            }
            3 -> {
                val nonce = json.opt("d")?.toString()?.toLongOrNull() ?: System.currentTimeMillis()
                json.put("d", JSONObject().put("t", nonce).put("seq_ack", lastSeq))
            }
            7 -> json.getJSONObject("d").put("seq_ack", lastSeq)
            1 -> restrictToVp8(json.getJSONObject("d"))
            12 -> {
                val streams = json.getJSONObject("d").optJSONArray("streams")
                ownStreams(streams)
                if (!isStream) return text
                // The old client announces screen shares as fixed 1280x720, so viewers size a landscape player and
                // stretch portrait phone screens into it. Current clients announce screen shares at source size.
                for (i in 0 until (streams?.length() ?: 0)) {
                    streams!!.getJSONObject(i).put("max_resolution", JSONObject().put("type", "source").put("width", 0).put("height", 0))
                }
            }
            else -> return text
        }
        return json.toString()
    }

    // endregion

    // region Incoming

    /** Handles an incoming JSON message; returns replacement text if the old client must see something else. */
    fun onIncoming(text: String): String? {
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            return null
        }
        if (json.has("seq")) lastSeq = maxOf(lastSeq, json.optInt("seq"))
        val op = json.optInt("op", -1)
        val d = json.opt("d")
        try {
            when (op) {
                2 -> ownStreams((d as JSONObject).optJSONArray("streams"))
                4 -> session.onSelectProtocolAck((d as JSONObject).optInt("dave_protocol_version", 0))
                5 -> (d as JSONObject).let { mapAudio(it.optLong("ssrc"), it.optString("user_id").toLong()) }
                6 -> if (d is JSONObject) {
                    // v8 acks with {"t": nonce}; the old client parses d as a plain number.
                    json.put("d", d.optLong("t"))
                    return json.toString()
                }
                12 -> (d as JSONObject).let {
                    val user = it.optString("user_id").toLongOrNull() ?: return null
                    mapAudio(it.optLong("audio_ssrc"), user)
                    ssrcs.addRemoteVideo(user, it.optLong("video_ssrc"), it.optLong("rtx_ssrc"))
                    val streams = it.optJSONArray("streams")
                    for (i in 0 until (streams?.length() ?: 0)) {
                        val stream = streams!!.getJSONObject(i)
                        ssrcs.addRemoteVideo(user, stream.optLong("ssrc"), stream.optLong("rtx_ssrc"))
                    }
                }
                DaveOpcodes.CLIENTS_CONNECT -> session.onClientsConnect(longs((d as JSONObject).getJSONArray("user_ids")))
                DaveOpcodes.CLIENT_DISCONNECT -> {
                    val user = (d as JSONObject).optString("user_id").toLong()
                    session.onClientDisconnect(user)
                    ssrcs.forgetUser(user)
                }
                DaveOpcodes.PREPARE_TRANSITION -> (d as JSONObject).let {
                    session.onPrepareTransition(it.getInt("transition_id"), it.getInt("protocol_version"))
                }
                DaveOpcodes.EXECUTE_TRANSITION -> session.onExecuteTransition((d as JSONObject).getInt("transition_id"))
                DaveOpcodes.PREPARE_EPOCH -> (d as JSONObject).let {
                    session.onPrepareEpoch(it.getLong("epoch"), it.getInt("protocol_version"))
                }
            }
        } catch (e: Exception) {
            logger.error("[$channelId] Failed to handle opcode $op", e)
        }
        return null
    }

    private fun mapAudio(ssrc: Long, user: Long) {
        if (ssrc > 0) ssrcs.audioToUser[ssrc] = user
    }

    private fun ownStreams(streams: JSONArray?) {
        for (i in 0 until (streams?.length() ?: 0)) {
            val stream = streams!!.getJSONObject(i)
            ssrcs.addOwnVideo(stream.optLong("ssrc"), stream.optLong("rtx_ssrc"))
        }
    }

    /**
     * Offer only Opus and VP8. DAVE's VP8 handling keeps packet boundaries (the relay can encrypt frames in place),
     * while H264/AV1 would need the relay to re-packetize; the SFU doesn't transcode, so everyone then uses VP8.
     */
    private fun restrictToVp8(d: JSONObject) {
        val codecs = d.optJSONArray("codecs") ?: return
        val kept = JSONArray()
        for (i in 0 until codecs.length()) {
            val codec = codecs.getJSONObject(i)
            when {
                codec.optString("type") == "audio" -> kept.put(codec)
                codec.optString("name").equals("VP8", ignoreCase = true) -> {
                    ssrcs.vp8PayloadType = codec.optInt("payload_type", -1)
                    ssrcs.rtxPayloadType = codec.optInt("rtx_payload_type", -1)
                    kept.put(codec.put("priority", 1))
                }
            }
        }
        d.put("codecs", kept)
        log("select_protocol codecs: $kept")
    }

    fun onIncomingBinary(bytes: ByteArray) {
        if (bytes.size >= 2) lastSeq = maxOf(lastSeq, ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF))
        try {
            session.onBinaryMessage(bytes)
        } catch (e: Exception) {
            logger.error("[$channelId] Failed to handle binary message", e)
        }
    }

    // endregion

    // region DaveGateway

    override fun sendReadyForTransition(transitionId: Int) =
        sendJson(DaveOpcodes.READY_FOR_TRANSITION, JSONObject().put("transition_id", transitionId))

    override fun sendInvalidCommitWelcome(transitionId: Int) =
        sendJson(DaveOpcodes.MLS_INVALID_COMMIT_WELCOME, JSONObject().put("transition_id", transitionId))

    override fun sendBinary(opcode: Int, payload: ByteArray) {
        // okhttp's WebSocket.send(ByteString) was stripped from this build, so queue a binary frame the way
        // RealWebSocket.send(String) queues a text one (fields: k = message queue, l = queue size, m/p = closing).
        val ws = socket?.s as? RealWebSocket ?: return log("Cannot send binary opcode $opcode: no websocket")
        val bytes = ByteString(byteArrayOf(opcode.toByte()) + payload)
        synchronized(ws) {
            if (ws.p || ws.m) return
            ws.l += bytes.j().toLong()
            ws.k.add(RealWebSocket.b(2, bytes))
            ws.l()
        }
    }

    private fun sendJson(op: Int, d: JSONObject) {
        socket?.s?.a(JSONObject().put("op", op).put("d", d).toString())
    }

    // endregion

    fun status(): String {
        val s = session
        val r = relay
        return buildString {
            append("Channel ").append(channelId).append(": DAVE v").append(s.protocolVersion)
            append(", epoch ").append(s.epoch)
            s.epochCode()?.let { append("\nVerification code: ").append(it.chunked(5).joinToString(" ")) }
            if (r != null) {
                append("\nAudio frames sent ").append(r.sentFrames.get()).append(", received ").append(r.receivedFrames.get())
                append("\nVideo frames sent ").append(r.sentVideoFrames.get()).append(", received ").append(r.receivedVideoFrames.get())
                append("\nPackets dropped out/in ").append(r.droppedOutgoing.get()).append('/').append(r.droppedIncoming.get())
            }
        }
    }

    fun close() {
        relay?.close()
        relay = null
    }

    private fun longs(array: JSONArray) = (0 until array.length()).map { array.getString(it).toLong() }

    companion object {
        private val byRtc = WeakHashMap<RtcConnection, VoiceConnection>()
        private val bySocket = WeakHashMap<RtcControlSocket, VoiceConnection>()
        private val byMedia = WeakHashMap<Any, Pair<VoiceConnection, MediaRelay>>()

        @Synchronized
        fun forRtc(rtc: RtcConnection, logger: Logger): VoiceConnection = byRtc.getOrPut(rtc) { VoiceConnection(rtc, logger) }

        /** Finds the connection owning [socket] through its RtcConnection socket listener (h0.a). */
        @Synchronized
        fun forSocket(socket: RtcControlSocket, logger: Logger): VoiceConnection? {
            bySocket[socket]?.let { return it }
            for (listener in socket.q) {
                if (listener is SocketListener) {
                    val conn = forRtc(listener.a, logger)
                    conn.socket = socket
                    bySocket[socket] = conn
                    return conn
                }
            }
            return null
        }

        @Synchronized
        fun bindMedia(media: Any, conn: VoiceConnection, relay: MediaRelay) {
            byMedia[media] = conn to relay
        }

        @Synchronized
        fun forMedia(media: Any): Pair<VoiceConnection, MediaRelay>? = byMedia[media]

        @Synchronized
        fun unbindMedia(media: Any) {
            val (conn, relay) = byMedia.remove(media) ?: return
            relay.close()
            if (conn.relay === relay) conn.relay = null
        }

        @Synchronized
        fun status(): String = byRtc.values.joinToString("\n\n") { it.status() }.ifEmpty { "Not in a call." }

        @Synchronized
        fun closeAll() {
            for (c in byRtc.values) c.close()
            byRtc.clear()
            bySocket.clear()
            byMedia.clear()
        }
    }
}
