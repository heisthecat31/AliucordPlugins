package com.github.heisthecat.davevoice

import android.content.Context
import co.discord.media_engine.Connection
import com.aliucord.annotations.AliucordPlugin
import com.aliucord.api.CommandsAPI
import com.aliucord.entities.Plugin
import com.aliucord.patcher.Hook
import com.aliucord.patcher.PreHook
import com.discord.rtcconnection.RtcConnection
import com.discord.rtcconnection.mediaengine.MediaEngine
import com.aliucord.Utils
import com.discord.utilities.display.DisplayUtils
import com.discord.rtcconnection.socket.io.Payloads
import com.github.heisthecat.davevoice.core.MediaRelay
import com.github.heisthecat.davevoice.core.TransportCipher
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import b.a.q.h0 as SocketListener
import b.a.q.m0.b as ScreenCapturer
import b.a.q.m0.c.e as LegacyMediaConnection
import b.a.q.n0.a as RtcControlSocket
import f0.e0.n.d as RealWebSocket
import f0.x as OkHttpClient

/**
 * Discord now requires DAVE (end-to-end encrypted voice) for every call. Discord 126.21's native voice engine predates
 * it and only speaks the retired xsalsa20 transport modes, so on its own it loops on "4016 Unknown encryption mode".
 *
 * This plugin leaves the native engine alone and puts a local UDP relay in front of it (see MediaRelay): the engine
 * talks xsalsa20_poly1305_lite_rtpsize to the relay with a throwaway key, and the relay adds/removes the DAVE frame
 * encryption and re-encrypts with aead_aes256_gcm_rtpsize for Discord. On the voice gateway (which is Java in this
 * build) it upgrades the connection to v8 and runs the DAVE MLS handshake (see core.DaveSession).
 */
@AliucordPlugin(requiresRestart = true)
@Suppress("unused")
class DaveVoice : Plugin() {
    /** Hands the relay from the constructor's before-hook to its after-hook (same thread). */
    private val pendingRelay = ThreadLocal<MediaRelay>()

    /** RtcConnection whose READY is being handled; it creates its media connection synchronously on this thread. */
    private val readyRtc = ThreadLocal<RtcConnection>()

    override fun start(context: Context) {
        hookGatewayVersion()
        hookOutgoingJson()
        hookIncomingJson()
        hookIncomingBinary()
        hookSelectProtocol()
        hookMediaConnection()
        hookScreenshareSize()

        commands.registerCommand("davestatus", "Show DAVE (voice E2EE) status for the current call") {
            CommandsAPI.CommandResult(VoiceConnection.status(), null, false)
        }
    }

    override fun stop(context: Context) {
        patcher.unpatchAll()
        commands.unregisterCommand("davestatus")
        VoiceConnection.closeAll()
    }

    /** RtcControlSocket hardcodes "?v=5"; DAVE needs voice gateway v8 (binary messages, seq/seq_ack). */
    private fun hookGatewayVersion() {
        val newWebSocket = OkHttpClient::class.java.getDeclaredMethod("g", Request::class.java, WebSocketListener::class.java)
        patcher.patch(
            newWebSocket,
            PreHook { param ->
                if (param.args[1] !is RtcControlSocket) return@PreHook
                val request = param.args[0] as Request
                val url = request.b.toString()
                if (url.contains("v=5")) {
                    param.args[0] = Request.a(request).f(url.replace("v=5", "v=8")).a()
                }
            },
        )
    }

    /** Rewrites identify/heartbeat/resume into their v8 + DAVE form as they go out (RealWebSocket.send(String)). */
    private fun hookOutgoingJson() {
        patcher.patch(
            RealWebSocket::class.java.getDeclaredMethod("a", String::class.java),
            PreHook { param ->
                val socket = (param.thisObject as RealWebSocket).v as? RtcControlSocket ?: return@PreHook
                val conn = VoiceConnection.forSocket(socket, logger) ?: return@PreHook
                param.args[0] = conn.patchOutgoing(param.args[0] as String)
            },
        )
    }

    private fun hookIncomingJson() {
        patcher.patch(
            RtcControlSocket::class.java.getDeclaredMethod("onMessage", WebSocket::class.java, String::class.java),
            PreHook { param ->
                val conn = VoiceConnection.forSocket(param.thisObject as RtcControlSocket, logger) ?: return@PreHook
                conn.onIncoming(param.args[1] as String)?.let { param.args[1] = it }
            },
        )
    }

    /** RtcControlSocket doesn't override the binary onMessage, so hook the base listener and filter. */
    private fun hookIncomingBinary() {
        patcher.patch(
            WebSocketListener::class.java.getDeclaredMethod("onMessage", WebSocket::class.java, ByteString::class.java),
            PreHook { param ->
                val socket = param.thisObject as? RtcControlSocket ?: return@PreHook
                val conn = VoiceConnection.forSocket(socket, logger) ?: return@PreHook
                conn.onIncomingBinary((param.args[1] as ByteString).l())
            },
        )
    }

    /** select_protocol always asks for xsalsa20_poly1305; ask for the AES-GCM mode the relay speaks to Discord. */
    private fun hookSelectProtocol() {
        patcher.patch(
            Payloads.Protocol.ProtocolInfo::class.java.getDeclaredConstructor(
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
            ),
            PreHook { param -> param.args[2] = TransportCipher.AES_GCM },
        )
    }

    /**
     * The native engine asks for a fixed 1280x720 capture. The capturer only fixes the aspect ratio after its first
     * frame, so viewers first see a landscape key frame and then portrait frames squeezed into that shape.
     * Start the capture at the screen's own proportions instead (same rounding as the capturer: multiples of 16).
     */
    private fun hookScreenshareSize() {
        val int = Int::class.javaPrimitiveType
        patcher.patch(
            ScreenCapturer::class.java.getDeclaredMethod("startCapture", int, int, int),
            PreHook { p ->
                val longest = maxOf(p.args[0] as Int, p.args[1] as Int)
                val screen = DisplayUtils.getScreenSize(Utils.appContext)
                val screenLongest = maxOf(screen.width(), screen.height())
                if (longest <= 0 || screenLongest <= 0) return@PreHook
                val scale = longest.toFloat() / screenLongest
                p.args[0] = roundTo16((screen.width() * scale).toInt())
                p.args[1] = roundTo16((screen.height() * scale).toInt())
                logger.info("Screenshare capture ${p.args[0]}x${p.args[1]} (asked ${longest}px longest side)")
            },
        )
    }

    private fun roundTo16(v: Int) = (v + 8) / 16 * 16

    private fun hookMediaConnection() {
        // h0.k(port, ssrc, ip, streams) is the READY handler; it calls MediaEngine.connect -> LegacyMediaConnection(...).
        // The constructor only gets the media engine's own listener, so remember the RtcConnection here.
        val onReady = SocketListener::class.java.getDeclaredMethod(
            "k",
            Int::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
            String::class.java,
            List::class.java,
        )
        patcher.patch(onReady, PreHook { param -> readyRtc.set((param.thisObject as SocketListener).a) })
        patcher.patch(onReady, Hook { readyRtc.remove() })

        val constructor = LegacyMediaConnection::class.java.declaredConstructors.first { it.parameterTypes.size == 9 }

        // Start the relay towards the real server and point the native engine at it instead.
        patcher.patch(
            constructor,
            PreHook { param ->
                val rtc = readyRtc.get() ?: return@PreHook logger.warn("Media connection created outside READY; no relay")
                val conn = VoiceConnection.forRtc(rtc, logger)
                val options = param.args[7] as MediaEngine.a
                try {
                    conn.ssrcs.selfAudio = options.a.toLong() and 0xFFFFFFFFL
                    val relay = MediaRelay(options.b, options.c, conn.ssrcs) { conn.log(it) }
                    conn.relay = relay
                    pendingRelay.set(relay)
                    param.args[7] = MediaEngine.a(options.a, "127.0.0.1", relay.localPort, options.d)
                } catch (e: Exception) {
                    logger.error("Failed to start voice relay", e)
                }
            },
        )
        patcher.patch(
            constructor,
            Hook { param ->
                val media = param.thisObject as LegacyMediaConnection
                val relay = pendingRelay.get() ?: return@Hook
                pendingRelay.remove()
                val rtc = readyRtc.get() ?: return@Hook
                val conn = VoiceConnection.forRtc(rtc, logger)
                VoiceConnection.bindMedia(media, conn, relay)
                media.j.getEncryptionModes(
                    Connection.EncryptionModesCallback { modes -> conn.log("Native engine modes: ${modes.joinToString()}") },
                )
            },
        )

        // The session description's key goes to the relay; the engine gets the relay's key and a mode it supports.
        patcher.patch(
            LegacyMediaConnection::class.java.getDeclaredMethod("t", String::class.java, IntArray::class.java),
            PreHook { param ->
                val (conn, relay) = VoiceConnection.forMedia(param.thisObject) ?: return@PreHook
                val mode = param.args[0] as String
                val key = param.args[1] as IntArray
                conn.log("Session description: mode=$mode")
                relay.setServerKey(mode, ByteArray(key.size) { key[it].toByte() })
                param.args[0] = TransportCipher.XSALSA_LITE
                param.args[1] = IntArray(relay.engineKey.size) { relay.engineKey[it].toInt() and 0xFF }
            },
        )

        patcher.patch(
            LegacyMediaConnection::class.java.getDeclaredMethod("destroy"),
            Hook { param -> VoiceConnection.unbindMedia(param.thisObject) },
        )
    }
}
