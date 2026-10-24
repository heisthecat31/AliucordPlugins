package com.github.heisthecat.davevoice.core

import java.util.concurrent.ConcurrentHashMap

/** Outgoing side of the voice gateway, implemented by the plugin (JSON) or a test harness. */
interface DaveGateway {
    /** dave_protocol_ready_for_transition (23). */
    fun sendReadyForTransition(transitionId: Int)

    /** dave_mls_invalid_commit_welcome (31). */
    fun sendInvalidCommitWelcome(transitionId: Int)

    /** Binary opcodes 26 (key package) and 28 (commit + welcome); the opcode byte is prepended by the caller. */
    fun sendBinary(opcode: Int, payload: ByteArray)
}

object DaveOpcodes {
    const val CLIENTS_CONNECT = 11
    const val CLIENT_DISCONNECT = 13
    const val PREPARE_TRANSITION = 21
    const val EXECUTE_TRANSITION = 22
    const val READY_FOR_TRANSITION = 23
    const val PREPARE_EPOCH = 24
    const val MLS_EXTERNAL_SENDER = 25
    const val MLS_KEY_PACKAGE = 26
    const val MLS_PROPOSALS = 27
    const val MLS_COMMIT_WELCOME = 28
    const val MLS_ANNOUNCE_COMMIT = 29
    const val MLS_WELCOME = 30
    const val MLS_INVALID_COMMIT_WELCOME = 31
}

/**
 * One DAVE media session (one voice connection), following libdave's sample DaveSessionManager.
 * [groupId] is the voice channel ID.
 */
class DaveSession(
    val selfUserId: Long,
    private val groupId: Long,
    private val gateway: DaveGateway,
    private val log: (String) -> Unit,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val mls = MlsSession { log("MLS: $it") }
    private val recognizedUserIds = ConcurrentHashMap.newKeySet<Long>()
    private val transitions = HashMap<Int, Int>()
    private var latestPreparedVersion = 0

    val encryptor = DaveEncryptor()
    private val decryptors = ConcurrentHashMap<Long, DaveDecryptor>()

    /** Protocol version currently used for sending (0 = transport encryption only). */
    @Volatile
    var protocolVersion = 0
        private set

    /** Last binary sequence number seen, needed for the v8 heartbeat's seq_ack. */
    @Volatile
    var lastBinarySeq = -1
        private set

    val epoch get() = mls.epoch

    val epochAuthenticator: ByteArray? get() = mls.lastEpochAuthenticator

    // region Incoming gateway messages

    @Synchronized
    fun onSelectProtocolAck(version: Int) {
        log("select_protocol_ack: dave_protocol_version=$version")
        handleInit(version)
    }

    @Synchronized
    fun onClientsConnect(userIds: Collection<Long>) {
        for (id in userIds) {
            recognizedUserIds.add(id)
            setupKeyRatchetForUser(id, latestPreparedVersion)
        }
    }

    @Synchronized
    fun onClientDisconnect(userId: Long) {
        recognizedUserIds.remove(userId)
        decryptors.remove(userId)
    }

    @Synchronized
    fun onPrepareTransition(transitionId: Int, version: Int) {
        log("prepare_transition id=$transitionId version=$version")
        prepareRatchets(transitionId, version)
        maybeSendReady(transitionId)
    }

    @Synchronized
    fun onExecuteTransition(transitionId: Int) {
        log("execute_transition id=$transitionId")
        executeTransition(transitionId)
    }

    @Synchronized
    fun onPrepareEpoch(epoch: Long, version: Int) {
        log("prepare_epoch epoch=$epoch version=$version")
        if (epoch == 1L) {
            mls.init(version, groupId, selfUserId)
            sendKeyPackage()
        }
    }

    /** A binary voice gateway message: uint16 seq, uint8 opcode, payload. */
    @Synchronized
    fun onBinaryMessage(message: ByteArray) {
        if (message.size < 3) return
        lastBinarySeq = message.u16(0)
        val opcode = message.u8(2)
        val payload = message.copyOfRange(3, message.size)
        when (opcode) {
            DaveOpcodes.MLS_EXTERNAL_SENDER -> {
                log("external_sender_package")
                mls.setExternalSender(payload)
            }
            DaveOpcodes.MLS_PROPOSALS -> {
                log("mls_proposals (${payload.size} bytes)")
                mls.processProposals(payload, allRecognized())?.let {
                    gateway.sendBinary(DaveOpcodes.MLS_COMMIT_WELCOME, it)
                }
            }
            DaveOpcodes.MLS_ANNOUNCE_COMMIT -> {
                val transitionId = payload.u16(0)
                log("announce_commit_transition id=$transitionId")
                when (val result = mls.processCommit(payload.copyOfRange(2, payload.size))) {
                    is CommitResult.Ignored -> {}
                    is CommitResult.Joined -> {
                        log("Joined group at epoch ${mls.epoch}, roster changes: ${result.roster.keys}")
                        prepareRatchets(transitionId, mls.protocolVersion)
                        maybeSendReady(transitionId)
                    }
                    is CommitResult.Failed -> {
                        gateway.sendInvalidCommitWelcome(transitionId)
                        handleInit(mls.protocolVersion)
                    }
                }
            }
            DaveOpcodes.MLS_WELCOME -> {
                val transitionId = payload.u16(0)
                log("welcome id=$transitionId")
                val roster = mls.processWelcome(payload.copyOfRange(2, payload.size), allRecognized())
                if (roster != null) {
                    log("Welcomed into group at epoch ${mls.epoch}, roster: ${mls.roster.keys}")
                    prepareRatchets(transitionId, mls.protocolVersion)
                    maybeSendReady(transitionId)
                } else {
                    gateway.sendInvalidCommitWelcome(transitionId)
                    sendKeyPackage()
                }
            }
            else -> log("Unknown binary opcode $opcode")
        }
    }

    // endregion

    // region Media

    /** Encrypts an outgoing frame; null means drop it (no key yet). [clearPrefix] bytes stay readable (VP8). */
    fun encryptFrame(frame: ByteArray, clearPrefix: Int = 0): ByteArray? = encryptor.encrypt(frame, clearPrefix)

    /** Decrypts an incoming frame from [userId]; null means drop it. */
    fun decryptFrame(userId: Long, frame: ByteArray, audio: Boolean = true): ByteArray? {
        val decryptor = decryptors[userId] ?: return if (protocolVersion == 0) frame else null
        return decryptor.decrypt(frame, audio)
    }

    // endregion

    private fun allRecognized(): Set<Long> = HashSet(recognizedUserIds).apply { add(selfUserId) }

    private fun handleInit(version: Int) {
        if (version > 0) {
            mls.init(version, groupId, selfUserId)
            sendKeyPackage()
        } else {
            prepareRatchets(INIT_TRANSITION_ID, version)
            executeTransition(INIT_TRANSITION_ID)
        }
    }

    private fun sendKeyPackage() {
        val keyPackage = mls.marshalledKeyPackage() ?: return
        log("Sending key package (${keyPackage.size} bytes)")
        gateway.sendBinary(DaveOpcodes.MLS_KEY_PACKAGE, keyPackage)
    }

    private fun maybeSendReady(transitionId: Int) {
        if (transitionId != INIT_TRANSITION_ID) gateway.sendReadyForTransition(transitionId)
    }

    private fun executeTransition(transitionId: Int) {
        val version = transitions.remove(transitionId) ?: return
        if (version == 0) mls.reset()
        setupKeyRatchetForUser(selfUserId, version)
    }

    private fun prepareRatchets(transitionId: Int, version: Int) {
        for (userId in recognizedUserIds) {
            if (userId != selfUserId) setupKeyRatchetForUser(userId, version)
        }
        if (transitionId == INIT_TRANSITION_ID) {
            setupKeyRatchetForUser(selfUserId, version)
        } else {
            transitions[transitionId] = version
        }
        latestPreparedVersion = version
    }

    private fun setupKeyRatchetForUser(userId: Long, version: Int) {
        val ratchet = if (version == 0) null else mls.keyRatchet(userId)
        if (userId == selfUserId) {
            encryptor.setKeyRatchet(ratchet)
            encryptor.passthrough = version == 0
            protocolVersion = version
            log("Sender now using protocol version $version (key: ${ratchet != null})")
        } else {
            val decryptor = decryptors.getOrPut(userId) { DaveDecryptor(now) }
            decryptor.transitionToKeyRatchet(ratchet)
            decryptor.transitionToPassthrough(version == 0)
        }
    }

    /** The 30 digit epoch verification code official clients show in the call's E2EE panel, or null. */
    fun epochCode(): String? = epochAuthenticator?.let { displayableCode(it, 30, 5) }

    companion object {
        const val INIT_TRANSITION_ID = 0

        /** DAVE displayable code: each group is group-size bytes read big endian, mod 10^group, zero padded. */
        fun displayableCode(data: ByteArray, length: Int, groupSize: Int): String {
            require(data.size >= length && length % groupSize == 0 && groupSize <= 7)
            var modulus = 1L
            repeat(groupSize) { modulus *= 10 }
            val sb = StringBuilder()
            var i = 0
            while (i < length) {
                var value = 0L
                for (j in 0 until groupSize) value = (value shl 8) or (data[i + j].toLong() and 0xFF)
                sb.append((value % modulus).toString().padStart(groupSize, '0'))
                i += groupSize
            }
            return sb.toString()
        }
    }
}
