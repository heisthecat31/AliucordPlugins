package com.github.heisthecat.davevoice.core

import java.io.ByteArrayOutputStream

internal fun longToBigEndian(value: Long): ByteArray = ByteArray(8) { i -> (value ushr ((7 - i) * 8)).toByte() }

internal fun longToLittleEndian(value: Long): ByteArray = ByteArray(8) { i -> (value ushr (i * 8)).toByte() }

internal fun bigEndianToLong(bytes: ByteArray): Long {
    var value = 0L
    for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
    return value
}

internal fun ByteArray.u8(offset: Int): Int = this[offset].toInt() and 0xFF

internal fun ByteArray.u16(offset: Int): Int = (u8(offset) shl 8) or u8(offset + 1)

internal fun ByteArray.u32(offset: Int): Long =
    (u8(offset).toLong() shl 24) or (u8(offset + 1).toLong() shl 16) or (u8(offset + 2).toLong() shl 8) or
        u8(offset + 3).toLong()

internal fun ByteArray.putU16(offset: Int, value: Int) {
    this[offset] = (value ushr 8).toByte()
    this[offset + 1] = value.toByte()
}

internal fun ByteArray.putU32(offset: Int, value: Long) {
    this[offset] = (value ushr 24).toByte()
    this[offset + 1] = (value ushr 16).toByte()
    this[offset + 2] = (value ushr 8).toByte()
    this[offset + 3] = value.toByte()
}

internal fun hex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0xF])
    }
    return sb.toString()
}

/** Unsigned LEB128, used by DAVE for the truncated nonce and unencrypted ranges in the frame footer. */
internal object Leb128 {
    fun size(value: Long): Int {
        var v = value
        var size = 1
        while (v >= 0x80 || v < 0) {
            v = v ushr 7
            size++
        }
        return size
    }

    fun write(value: Long, out: ByteArrayOutputStream) {
        var v = value
        while (v >= 0x80 || v < 0) {
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
        out.write(v.toInt())
    }

    /** Reads one value from [buf] starting at [pos][0] and stopping before [end]; returns null if truncated. */
    fun read(buf: ByteArray, pos: IntArray, end: Int): Long? {
        var result = 0L
        var shift = 0
        while (pos[0] < end) {
            val b = buf[pos[0]++].toInt() and 0xFF
            if (shift >= 64) return null
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        return null
    }
}
