package com.github.heisthecat.davevoice.core

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.bouncycastle.mls.crypto.Secret
import java.io.ByteArrayOutputStream

// DAVE media frame transforms, ported from libdave (encryptor.cpp, decryptor.cpp, cryptor_manager.cpp,
// frame_processors.cpp). Frames are the codec payload (one Opus packet for audio), not RTP packets.

private const val TAG_BYTES = 8
private const val NONCE_BYTES = 12
private const val NONCE_OFFSET = 8
private const val GENERATION_SHIFT = 24
private const val GENERATION_WRAP = 256L
private const val MARKER = 0xFA.toByte()
private const val MIN_SUPPLEMENTAL = TAG_BYTES + 1 + 2
private const val CRYPTOR_EXPIRY_MS = 10_000L
private const val MAX_GENERATION_GAP = 250
private const val MAX_MISSING_NONCES = 1000
private const val MAX_FRAMES_PER_SECOND = 50 + 2 * 60

/** Default retention of previous-epoch keys while a transition is in flight. */
const val TRANSITION_EXPIRY_MS = 10_000L

private val OPUS_SILENCE = byteArrayOf(0xF8.toByte(), 0xFF.toByte(), 0xFE.toByte())

/** Per-sender media key ratchet (libdave MlsKeyRatchet over mlspp HashRatchet). */
class KeyRatchet(private val suite: MlsCipherSuite, baseSecret: ByteArray) {
    val domainIdentity: ByteArray = baseSecret.clone()
    private var nextSecret = Secret(baseSecret.clone())
    private var nextGeneration = 0L
    private val cache = HashMap<Long, ByteArray>()

    @Synchronized
    fun get(generation: Long): ByteArray? {
        cache[generation]?.let { return it }
        if (nextGeneration > generation) return null
        while (nextGeneration <= generation) {
            val gen = nextGeneration.toInt()
            val key = nextSecret.deriveTreeSecret(suite, "key", gen, 16).value().clone()
            val secret = nextSecret.deriveTreeSecret(suite, "secret", gen, suite.kdf.hashLength).value().clone()
            cache[nextGeneration] = key
            nextSecret = Secret(secret)
            nextGeneration++
        }
        return cache[generation]
    }

    @Synchronized
    fun erase(generation: Long) {
        cache.remove(generation)
    }
}

private fun wrappedGeneration(oldest: Long, generation: Long): Long {
    val remainder = oldest % GENERATION_WRAP
    val factor = oldest / GENERATION_WRAP + if (generation < remainder) 1 else 0
    return factor * GENERATION_WRAP + generation
}

private fun fullNonce(truncated: Long): ByteArray {
    // libdave memcpy's the uint32 into bytes 8..12, i.e. little endian on every platform Discord ships.
    val nonce = ByteArray(NONCE_BYTES)
    for (i in 0 until 4) nonce[NONCE_OFFSET + i] = (truncated ushr (8 * i)).toByte()
    return nonce
}

private fun gcm(key: ByteArray, nonce: ByteArray, aad: ByteArray, encrypt: Boolean): GCMBlockCipher {
    val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance()) as GCMBlockCipher
    cipher.init(encrypt, AEADParameters(KeyParameter(key), TAG_BYTES * 8, nonce, aad))
    return cipher
}

/** Encrypts outgoing frames for the local user. All Opus frames are fully encrypted (no unencrypted ranges). */
class DaveEncryptor {
    @Volatile
    var passthrough = false

    private var ratchet: KeyRatchet? = null
    private var domainIdentity: ByteArray? = null
    private var currentGeneration = 0L
    private var truncatedNonce = 0L
    private var key: ByteArray? = null

    @Synchronized
    fun setKeyRatchet(newRatchet: KeyRatchet?) {
        if (newRatchet != null && !newRatchet.domainIdentity.contentEquals(domainIdentity ?: ByteArray(0))) {
            domainIdentity = newRatchet.domainIdentity
            currentGeneration = 0
            truncatedNonce = 0
        }
        ratchet = newRatchet
        key = null
    }

    val hasKey: Boolean
        @Synchronized get() = ratchet != null

    /**
     * Returns the protocol frame, the input unchanged in passthrough, or null if there is no key yet.
     * The first [clearPrefix] bytes stay unencrypted (authenticated only), as codec handling requires for VP8.
     */
    fun encrypt(frame: ByteArray, clearPrefix: Int = 0): ByteArray? {
        if (passthrough) return frame
        val nonce: Long
        val frameKey: ByteArray
        synchronized(this) {
            val r = ratchet ?: return null
            truncatedNonce = (truncatedNonce + 1) and 0xFFFFFFFFL
            val generation = wrappedGeneration(currentGeneration, truncatedNonce ushr GENERATION_SHIFT)
            if (generation != currentGeneration || key == null) {
                currentGeneration = generation
                key = r.get(generation)
            }
            frameKey = key ?: return null
            nonce = truncatedNonce
        }

        val prefix = clearPrefix.coerceIn(0, frame.size)
        val clear = frame.copyOfRange(0, prefix)
        val cipher = gcm(frameKey, fullNonce(nonce), clear, true)
        val sealed = ByteArray(cipher.getOutputSize(frame.size - prefix))
        val len = cipher.processBytes(frame, prefix, frame.size - prefix, sealed, 0)
        cipher.doFinal(sealed, len)
        // sealed = ciphertext || 8 byte tag. Interleave: clear prefix in place, ciphertext after it, then the footer.
        val ranges = ByteArrayOutputStream()
        if (prefix > 0) {
            Leb128.write(0, ranges)
            Leb128.write(prefix.toLong(), ranges)
        }
        val out = ByteArrayOutputStream(frame.size + 32)
        out.write(clear, 0, prefix)
        out.write(sealed, 0, sealed.size)
        Leb128.write(nonce, out)
        out.write(ranges.toByteArray())
        out.write(MIN_SUPPLEMENTAL + Leb128.size(nonce) + ranges.size())
        out.write(MARKER.toInt())
        out.write(MARKER.toInt())
        return out.toByteArray()
    }
}

/** libdave CryptorManager: the receive keys for one sender ratchet (one epoch), with replay protection. */
private class CryptorManager(private val ratchet: KeyRatchet, private val now: () -> Long) {
    val domainIdentity get() = ratchet.domainIdentity
    private val creation = now()
    private var expiry = Long.MAX_VALUE
    private var oldestGeneration = 0L
    private var newestGeneration = 0L
    private var newestProcessedNonce: Long? = null
    private val missingNonces = java.util.ArrayDeque<Long>()
    private val cryptors = HashMap<Long, Pair<ByteArray, Long>>()

    fun updateExpiry(time: Long) {
        expiry = minOf(expiry, time)
    }

    val isExpired get() = now() > expiry

    fun computeWrappedGeneration(generation: Long) = wrappedGeneration(oldestGeneration, generation)

    private fun bigNonce(generation: Long, nonce: Long) =
        (generation shl GENERATION_SHIFT) or (nonce and ((1L shl GENERATION_SHIFT) - 1))

    fun canProcessNonce(generation: Long, nonce: Long): Boolean {
        val expected = newestProcessedNonce?.plus(1) ?: 0L
        val big = bigNonce(generation, nonce)
        return big >= expected || missingNonces.contains(big)
    }

    fun getKey(generation: Long): ByteArray? {
        cleanup()
        if (generation < oldestGeneration) return null
        if (generation > newestGeneration + MAX_GENERATION_GAP) return null
        val lifetimeSec = (now() - creation) / 1000
        val maxLifetimeGenerations = (MAX_FRAMES_PER_SECOND * lifetimeSec) shr GENERATION_SHIFT
        if (generation > maxLifetimeGenerations) return null
        cryptors[generation]?.let { return it.first }
        val key = ratchet.get(generation) ?: return null
        val exp = if (generation < newestGeneration) now() + CRYPTOR_EXPIRY_MS else Long.MAX_VALUE
        cryptors[generation] = key to exp
        return key
    }

    fun reportSuccess(generation: Long, nonce: Long) {
        val expected = newestProcessedNonce?.plus(1) ?: 0L
        val big = bigNonce(generation, nonce)
        if (big >= expected) {
            val missing = minOf(big - expected, MAX_MISSING_NONCES.toLong())
            while (missingNonces.isNotEmpty() && missingNonces.size + missing > MAX_MISSING_NONCES) {
                missingNonces.removeFirst()
            }
            var i = big - missing
            while (i < big) missingNonces.addLast(i++)
            newestProcessedNonce = big
        } else {
            missingNonces.remove(big)
        }
        if (generation <= newestGeneration || !cryptors.containsKey(generation)) return
        newestGeneration = generation
        val expiryTime = now() + CRYPTOR_EXPIRY_MS
        for ((gen, entry) in cryptors.entries.toList()) {
            if (gen < newestGeneration) cryptors[gen] = entry.first to minOf(entry.second, expiryTime)
        }
    }

    private fun cleanup() {
        val t = now()
        cryptors.entries.removeAll { it.value.second < t }
        while (oldestGeneration < newestGeneration && !cryptors.containsKey(oldestGeneration)) {
            ratchet.erase(oldestGeneration)
            oldestGeneration++
        }
    }
}

/** Decrypts incoming frames from one remote user. Codec agnostic, so it also handles unencrypted ranges. */
class DaveDecryptor(private val now: () -> Long = System::currentTimeMillis) {
    // Plain java.util collections: Aliucord ships a trimmed kotlin-stdlib (no kotlin.collections.ArrayDeque).
    private val managers = ArrayList<CryptorManager>()
    private var allowPassthroughUntil = Long.MIN_VALUE

    @Synchronized
    fun transitionToKeyRatchet(ratchet: KeyRatchet?, expiryMs: Long = TRANSITION_EXPIRY_MS) {
        cleanup()
        if (ratchet != null && managers.any { it.domainIdentity.contentEquals(ratchet.domainIdentity) }) return
        val maxExpiry = now() + expiryMs
        for (m in managers) m.updateExpiry(maxExpiry)
        if (ratchet != null) managers.add(CryptorManager(ratchet, now))
    }

    @Synchronized
    fun transitionToPassthrough(passthrough: Boolean, expiryMs: Long = TRANSITION_EXPIRY_MS) {
        allowPassthroughUntil = if (passthrough) Long.MAX_VALUE else minOf(allowPassthroughUntil, now() + expiryMs)
    }

    /** Returns the plain frame, or null if it must be dropped. */
    @Synchronized
    fun decrypt(frame: ByteArray, audio: Boolean = true): ByteArray? {
        if (audio && frame.contentEquals(OPUS_SILENCE)) return frame
        cleanup()
        val parsed = ProtocolFrame.parse(frame)
        if (parsed == null) return if (allowPassthroughUntil > now()) frame else null
        for (i in managers.indices.reversed()) {
            decryptWith(managers[i], parsed)?.let { return it }
        }
        return null
    }

    private fun decryptWith(manager: CryptorManager, frame: ProtocolFrame): ByteArray? {
        val generation = manager.computeWrappedGeneration(frame.nonce ushr GENERATION_SHIFT)
        if (!manager.canProcessNonce(generation, frame.nonce)) return null
        val key = manager.getKey(generation) ?: return null
        val cipher = gcm(key, fullNonce(frame.nonce), frame.authenticated, false)
        val input = frame.ciphertext + frame.tag
        val plain = ByteArray(cipher.getOutputSize(input.size))
        return try {
            val len = cipher.processBytes(input, 0, input.size, plain, 0)
            cipher.doFinal(plain, len)
            manager.reportSuccess(generation, frame.nonce)
            frame.reconstruct(plain)
        } catch (e: Exception) {
            null
        }
    }

    private fun cleanup() {
        while (managers.isNotEmpty() && managers[0].isExpired) managers.removeAt(0)
    }
}

/** A parsed DAVE protocol frame (libdave InboundFrameProcessor). */
internal class ProtocolFrame(
    val tag: ByteArray,
    val nonce: Long,
    private val ranges: List<LongArray>,
    val authenticated: ByteArray,
    val ciphertext: ByteArray,
) {
    /** Re-interleaves the decrypted bytes with the unencrypted ranges. */
    fun reconstruct(plain: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(authenticated.size + plain.size)
        var frameIndex = 0L
        var authIndex = 0
        var plainIndex = 0
        for (r in ranges) {
            if (r[0] > frameIndex) {
                val n = (r[0] - frameIndex).toInt()
                out.write(plain, plainIndex, n)
                plainIndex += n
                frameIndex += n
            }
            out.write(authenticated, authIndex, r[1].toInt())
            authIndex += r[1].toInt()
            frameIndex += r[1]
        }
        if (plainIndex < plain.size) out.write(plain, plainIndex, plain.size - plainIndex)
        return out.toByteArray()
    }

    companion object {
        fun parse(frame: ByteArray): ProtocolFrame? {
            if (frame.size < MIN_SUPPLEMENTAL) return null
            if (frame[frame.size - 1] != MARKER || frame[frame.size - 2] != MARKER) return null
            val supplementalSize = frame.u8(frame.size - 3)
            if (supplementalSize < MIN_SUPPLEMENTAL || frame.size < supplementalSize) return null
            val supplementalStart = frame.size - supplementalSize
            val tag = frame.copyOfRange(supplementalStart, supplementalStart + TAG_BYTES)
            val pos = intArrayOf(supplementalStart + TAG_BYTES)
            val end = frame.size - 3
            val nonce = (Leb128.read(frame, pos, end) ?: return null) and 0xFFFFFFFFL
            val ranges = ArrayList<LongArray>()
            while (pos[0] < end) {
                val offset = Leb128.read(frame, pos, end) ?: return null
                val size = Leb128.read(frame, pos, end) ?: return null
                ranges.add(longArrayOf(offset, size))
            }
            for (i in ranges.indices) {
                val maxEnd = if (i + 1 < ranges.size) ranges[i + 1][0] else frame.size.toLong()
                val rangeEnd = ranges[i][0] + ranges[i][1]
                if (ranges[i][0] < 0 || ranges[i][1] < 0 || rangeEnd < ranges[i][0] || rangeEnd > maxEnd) return null
            }
            val mediaSize = supplementalStart
            val auth = ByteArrayOutputStream()
            val cipher = ByteArrayOutputStream()
            var index = 0
            for (r in ranges) {
                val offset = r[0].toInt()
                val size = r[1].toInt()
                if (offset + size > mediaSize) return null
                if (offset > index) cipher.write(frame, index, offset - index)
                auth.write(frame, offset, size)
                index = offset + size
            }
            if (index < mediaSize) cipher.write(frame, index, mediaSize - index)
            return ProtocolFrame(tag, nonce, ranges, auth.toByteArray(), cipher.toByteArray())
        }
    }
}
