package com.github.heisthecat.davevoice.harness

import com.github.heisthecat.davevoice.core.AesGcmRtpSize
import com.github.heisthecat.davevoice.core.DaveGateway
import com.github.heisthecat.davevoice.core.DaveOpcodes
import com.github.heisthecat.davevoice.core.DaveSession
import com.github.heisthecat.davevoice.core.Rtp
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.nio.ByteBuffer
import java.util.concurrent.CompletionStage
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Usage: DAVE_BOT_TOKEN=... (or DISCORD_BOT_TOKEN) gradlew :harness:run --args="<guildId> <voiceChannelId> [--no-echo]"
 *
 * Joins the voice channel as the bot, takes part in the DAVE MLS group with the official clients in the call, and
 * logs how many of their audio frames it can decrypt. Unless --no-echo is given it re-encrypts and sends back what
 * it hears, so anyone talking hears themselves only if both directions interoperate.
 */
fun main(args: Array<String>) {
    val token = System.getenv("DAVE_BOT_TOKEN") ?: System.getenv("DISCORD_BOT_TOKEN")
        ?: error("Set the DAVE_BOT_TOKEN (or DISCORD_BOT_TOKEN) environment variable")
    require(args.size >= 2) { "Usage: <guildId> <voiceChannelId> [--no-echo]" }
    Harness(token, args[0].toLong(), args[1].toLong(), echo = "--no-echo" !in args).run()
}

private fun log(msg: String) = println("[${System.currentTimeMillis() % 100000}] $msg")

/** java.net.http WebSocket with whole-message text/binary callbacks. */
private class Ws(url: String, private val onText: (String) -> Unit, private val onBinary: (ByteArray) -> Unit) {
    private val text = StringBuilder()
    private val binary = ByteArrayOutputStream()
    private val sendLock = Any()
    val closed = CountDownLatch(1)

    val socket: WebSocket = HttpClient.newHttpClient().newWebSocketBuilder().buildAsync(
        URI.create(url),
        object : WebSocket.Listener {
            override fun onText(ws: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
                text.append(data)
                if (last) {
                    val s = text.toString()
                    text.setLength(0)
                    try {
                        onText(s)
                    } catch (e: Exception) {
                        log("text handler error: $e")
                        e.printStackTrace()
                    }
                }
                ws.request(1)
                return null
            }

            override fun onBinary(ws: WebSocket, data: ByteBuffer, last: Boolean): CompletionStage<*>? {
                val chunk = ByteArray(data.remaining())
                data.get(chunk)
                binary.write(chunk)
                if (last) {
                    val b = binary.toByteArray()
                    binary.reset()
                    try {
                        onBinary(b)
                    } catch (e: Exception) {
                        log("binary handler error: $e")
                        e.printStackTrace()
                    }
                }
                ws.request(1)
                return null
            }

            override fun onClose(ws: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
                log("websocket $url closed: $statusCode $reason")
                closed.countDown()
                return null
            }

            override fun onError(ws: WebSocket, error: Throwable) {
                log("websocket $url error: $error")
                closed.countDown()
            }
        },
    ).join()

    fun send(json: JSONObject) = synchronized(sendLock) { socket.sendText(json.toString(), true).join() }

    fun send(bytes: ByteArray) = synchronized(sendLock) { socket.sendBinary(ByteBuffer.wrap(bytes), true).join() }
}

private class Harness(
    private val token: String,
    private val guildId: Long,
    private val channelId: Long,
    private val echo: Boolean,
) : DaveGateway {
    private lateinit var gateway: Ws
    private var gatewaySeq: Any = JSONObject.NULL
    private var selfId = 0L
    private var voiceSessionId: String? = null
    private var voiceToken: String? = null
    private var voiceEndpoint: String? = null
    private var voiceStarted = false

    private lateinit var voice: Ws
    private lateinit var session: DaveSession
    private val lastSeq = AtomicInteger(-1)
    private var ssrc = 0L
    private var server: InetSocketAddress? = null
    private val udp = DatagramSocket()
    private var cipher: AesGcmRtpSize? = null
    private val ssrcToUser = ConcurrentHashMap<Long, Long>()
    private val decrypted = ConcurrentHashMap<Long, AtomicLong>()
    private val failed = ConcurrentHashMap<Long, AtomicLong>()
    private val sent = AtomicLong()
    private var rtpSeq = 0
    private var rtpTimestamp = 0L
    private val nonce = AtomicLong()

    fun run() {
        gateway = Ws("wss://gateway.discord.gg/?v=10&encoding=json", ::onGateway) {}
        gateway.closed.await()
    }

    // region Main gateway

    private fun onGateway(text: String) {
        val json = JSONObject(text)
        if (json.has("s") && !json.isNull("s")) gatewaySeq = json.get("s")
        when (json.getInt("op")) {
            10 -> {
                val interval = json.getJSONObject("d").getLong("heartbeat_interval")
                thread(isDaemon = true, name = "gateway-heartbeat") {
                    while (true) {
                        Thread.sleep(interval)
                        gateway.send(JSONObject().put("op", 1).put("d", gatewaySeq))
                    }
                }
                val properties = JSONObject().put("os", "linux").put("browser", "davevoice-harness").put("device", "davevoice-harness")
                gateway.send(
                    JSONObject().put("op", 2).put(
                        "d",
                        JSONObject().put("token", token).put("intents", 1 or (1 shl 7)).put("properties", properties),
                    ),
                )
            }
            0 -> onDispatch(json.getString("t"), json.optJSONObject("d") ?: JSONObject())
        }
    }

    private fun onDispatch(type: String, d: JSONObject) {
        when (type) {
            "READY" -> {
                selfId = d.getJSONObject("user").getString("id").toLong()
                log("Logged in as ${d.getJSONObject("user").optString("username")} ($selfId), joining $channelId")
                gateway.send(
                    JSONObject().put("op", 4).put(
                        "d",
                        JSONObject().put("guild_id", guildId.toString()).put("channel_id", channelId.toString())
                            .put("self_mute", false).put("self_deaf", false),
                    ),
                )
            }
            "VOICE_STATE_UPDATE" -> if (d.optString("user_id") == selfId.toString()) voiceSessionId = d.getString("session_id")
            "VOICE_SERVER_UPDATE" -> {
                voiceToken = d.getString("token")
                voiceEndpoint = d.optString("endpoint")
            }
        }
        if (!voiceStarted && voiceSessionId != null && voiceToken != null && voiceEndpoint != null) {
            voiceStarted = true
            thread(name = "voice") { startVoice() }
        }
    }

    // endregion

    // region Voice gateway

    private fun startVoice() {
        session = DaveSession(selfId, channelId, this, { log("DAVE: $it") })
        val endpoint = voiceEndpoint!!.removePrefix("wss://")
        log("Connecting to voice gateway $endpoint")
        voice = Ws("wss://$endpoint/?v=8", ::onVoiceText, ::onVoiceBinary)
        voice.send(
            JSONObject().put("op", 0).put(
                "d",
                JSONObject().put("server_id", guildId.toString()).put("user_id", selfId.toString())
                    .put("session_id", voiceSessionId).put("token", voiceToken).put("max_dave_protocol_version", 1),
            ),
        )
        thread(isDaemon = true, name = "stats") {
            while (true) {
                Thread.sleep(3000)
                val users = (decrypted.keys + failed.keys).joinToString { "$it ok=${decrypted[it]?.get() ?: 0} fail=${failed[it]?.get() ?: 0}" }
                log("v${session.protocolVersion} epoch=${session.epoch} code=${session.epochCode()?.chunked(5)?.joinToString(" ")} sent=${sent.get()} [$users]")
            }
        }
    }

    private fun onVoiceText(text: String) {
        val json = JSONObject(text)
        if (json.has("seq")) lastSeq.accumulateAndGet(json.getInt("seq"), ::maxOf)
        val op = json.getInt("op")
        val d = json.opt("d")
        if (op != 6) log("voice <- op $op ${text.take(300)}")
        when (op) {
            8 -> {
                val interval = (d as JSONObject).getDouble("heartbeat_interval").toLong()
                thread(isDaemon = true, name = "voice-heartbeat") {
                    while (true) {
                        Thread.sleep(interval)
                        voice.send(JSONObject().put("op", 3).put("d", JSONObject().put("t", System.currentTimeMillis()).put("seq_ack", lastSeq.get())))
                    }
                }
            }
            2 -> {
                d as JSONObject
                ssrc = d.getLong("ssrc")
                server = InetSocketAddress(d.getString("ip"), d.getInt("port"))
                val (address, port) = discoverIp()
                log("IP discovery: $address:$port")
                voice.send(
                    JSONObject().put("op", 1).put(
                        "d",
                        JSONObject().put("protocol", "udp").put(
                            "data",
                            JSONObject().put("address", address).put("port", port).put("mode", "aead_aes256_gcm_rtpsize"),
                        ),
                    ),
                )
            }
            4 -> {
                d as JSONObject
                val keyArray = d.getJSONArray("secret_key")
                cipher = AesGcmRtpSize(ByteArray(keyArray.length()) { keyArray.getInt(it).toByte() })
                session.onSelectProtocolAck(d.optInt("dave_protocol_version", 0))
                voice.send(JSONObject().put("op", 5).put("d", JSONObject().put("speaking", 1).put("delay", 0).put("ssrc", ssrc)))
                thread(isDaemon = true, name = "udp") { receiveLoop() }
            }
            5 -> (d as JSONObject).let { ssrcToUser[it.getLong("ssrc")] = it.getString("user_id").toLong() }
            DaveOpcodes.CLIENTS_CONNECT -> session.onClientsConnect(longs((d as JSONObject).getJSONArray("user_ids")))
            DaveOpcodes.CLIENT_DISCONNECT -> session.onClientDisconnect((d as JSONObject).getString("user_id").toLong())
            DaveOpcodes.PREPARE_TRANSITION -> (d as JSONObject).let { session.onPrepareTransition(it.getInt("transition_id"), it.getInt("protocol_version")) }
            DaveOpcodes.EXECUTE_TRANSITION -> session.onExecuteTransition((d as JSONObject).getInt("transition_id"))
            DaveOpcodes.PREPARE_EPOCH -> (d as JSONObject).let { session.onPrepareEpoch(it.getLong("epoch"), it.getInt("protocol_version")) }
        }
    }

    private fun onVoiceBinary(bytes: ByteArray) {
        if (bytes.size >= 3) {
            lastSeq.accumulateAndGet(((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF), ::maxOf)
            log("voice <- binary op ${bytes[2].toInt() and 0xFF} (${bytes.size} bytes)")
        }
        session.onBinaryMessage(bytes)
    }

    override fun sendReadyForTransition(transitionId: Int) {
        voice.send(JSONObject().put("op", DaveOpcodes.READY_FOR_TRANSITION).put("d", JSONObject().put("transition_id", transitionId)))
    }

    override fun sendInvalidCommitWelcome(transitionId: Int) {
        log("!! sending invalid_commit_welcome for transition $transitionId")
        voice.send(JSONObject().put("op", DaveOpcodes.MLS_INVALID_COMMIT_WELCOME).put("d", JSONObject().put("transition_id", transitionId)))
    }

    override fun sendBinary(opcode: Int, payload: ByteArray) {
        log("voice -> binary op $opcode (${payload.size} bytes)")
        voice.send(byteArrayOf(opcode.toByte()) + payload)
    }

    private fun longs(array: JSONArray) = (0 until array.length()).map { array.getString(it).toLong() }

    // endregion

    // region UDP

    private fun discoverIp(): Pair<String, Int> {
        val request = ByteArray(74)
        request[1] = 1
        request[3] = 70
        putU32(request, 4, ssrc)
        udp.send(DatagramPacket(request, request.size, server))
        val response = DatagramPacket(ByteArray(74), 74)
        udp.soTimeout = 5000
        udp.receive(response)
        udp.soTimeout = 0
        val data = response.data
        var end = 8
        while (end < 72 && data[end] != 0.toByte()) end++
        return String(data, 8, end - 8) to (((data[72].toInt() and 0xFF) shl 8) or (data[73].toInt() and 0xFF))
    }

    private fun receiveLoop() {
        val buf = ByteArray(2048)
        val packet = DatagramPacket(buf, buf.size)
        while (true) {
            udp.receive(packet)
            val data = buf.copyOf(packet.length)
            if (!Rtp.isRtp(data)) continue
            val c = cipher ?: continue
            val headerSize = Rtp.clearHeaderSize(data)
            if (data.size < headerSize + 20) continue
            val plain = c.open(data.copyOf(headerSize), data.copyOfRange(headerSize, data.size - 4), data.copyOfRange(data.size - 4, data.size)) ?: continue
            val ext = Rtp.extensionBodySize(data)
            if (ext > plain.size) continue
            val frame = plain.copyOfRange(ext, plain.size)
            val user = ssrcToUser[Rtp.ssrc(data)] ?: continue
            if (frame.size == 3 && frame[0] == 0xF8.toByte()) continue
            val clear = session.decryptFrame(user, frame)
            if (clear == null) {
                failed.getOrPut(user) { AtomicLong() }.incrementAndGet()
                continue
            }
            decrypted.getOrPut(user) { AtomicLong() }.incrementAndGet()
            if (echo) sendFrame(clear)
        }
    }

    private fun sendFrame(opus: ByteArray) {
        val c = cipher ?: return
        val encrypted = session.encryptFrame(opus) ?: return
        val header = ByteArray(12)
        header[0] = 0x80.toByte()
        header[1] = Rtp.OPUS_PAYLOAD_TYPE.toByte()
        rtpSeq = (rtpSeq + 1) and 0xFFFF
        header[2] = (rtpSeq ushr 8).toByte()
        header[3] = rtpSeq.toByte()
        rtpTimestamp = (rtpTimestamp + 960) and 0xFFFFFFFFL
        putU32(header, 4, rtpTimestamp)
        putU32(header, 8, ssrc)
        val n = ByteArray(4).also { putU32(it, 0, nonce.incrementAndGet()) }
        val packet = header + c.seal(header, encrypted, n) + n
        udp.send(DatagramPacket(packet, packet.size, server))
        sent.incrementAndGet()
    }

    private fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }

    // endregion
}
