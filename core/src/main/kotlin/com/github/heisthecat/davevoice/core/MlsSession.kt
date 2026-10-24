package com.github.heisthecat.davevoice.core

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.mls.TreeKEM.LeafIndex
import org.bouncycastle.mls.TreeKEM.LeafNode
import org.bouncycastle.mls.TreeKEM.LifeTime
import org.bouncycastle.mls.codec.AuthenticatedContent
import org.bouncycastle.mls.codec.Capabilities
import org.bouncycastle.mls.codec.ContentType
import org.bouncycastle.mls.codec.Credential
import org.bouncycastle.mls.codec.CredentialType
import org.bouncycastle.mls.codec.Extension
import org.bouncycastle.mls.codec.ExtensionType
import org.bouncycastle.mls.codec.ExternalSender
import org.bouncycastle.mls.codec.FramedContent
import org.bouncycastle.mls.codec.KeyPackage
import org.bouncycastle.mls.codec.MLSInputStream
import org.bouncycastle.mls.codec.MLSMessage
import org.bouncycastle.mls.codec.MLSOutputStream
import org.bouncycastle.mls.codec.ProposalOrRefType
import org.bouncycastle.mls.codec.ProposalType
import org.bouncycastle.mls.codec.SenderType
import org.bouncycastle.mls.codec.Welcome
import org.bouncycastle.mls.codec.WireFormat
import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.bouncycastle.mls.crypto.Secret
import org.bouncycastle.mls.protocol.Group
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/** Result of handling an announced commit. */
sealed class CommitResult {
    object Ignored : CommitResult()

    object Failed : CommitResult()

    class Joined(val roster: Map<Long, ByteArray>) : CommitResult()
}

/**
 * The MLS half of DAVE, a port of libdave's mls::Session onto BouncyCastle's MLS implementation.
 * BouncyCastle's Group is itself a port of mlspp's State (which libdave uses), so the logic maps 1:1.
 */
class MlsSession(private val log: (String) -> Unit) {
    private class QueuedProposal(val message: ByteArray, val ref: ByteArray)

    private val suite: MlsCipherSuite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
    private val random = SecureRandom()

    // Transient signature key, reused across Init calls like libdave's TransientKeys.
    private val signatureKey: AsymmetricCipherKeyPair = suite.generateSignatureKeyPair()
    private val signaturePriv: ByteArray = suite.serializeSignaturePrivateKey(signatureKey.private)
    val signaturePublicKey: ByteArray = suite.serializeSignaturePublicKey(signatureKey.public)

    var protocolVersion = 0
        private set
    private var groupId = ByteArray(0)
    private var selfUserId = 0L
    private var externalSender: ExternalSender? = null

    private var hpkeKey: AsymmetricCipherKeyPair? = null
    private var selfLeafNode: LeafNode? = null
    private var joinInitKey: AsymmetricCipherKeyPair? = null
    private var joinKeyPackage: KeyPackage? = null

    private var pendingGroup: Group? = null
    private var currentState: Group? = null
    private var stateWithProposals: Group? = null
    private val proposalQueue = ArrayList<QueuedProposal>()
    private var outboundCommit: ByteArray? = null
    private var outboundCachedGroup: Group? = null

    /** Current roster: user ID to signature public key. */
    var roster: Map<Long, ByteArray> = emptyMap()
        private set

    val hasEstablishedGroup get() = currentState != null

    val epoch: Long get() = currentState?.epoch ?: 0L

    val lastEpochAuthenticator: ByteArray? get() = currentState?.epochAuthenticator

    @Synchronized
    fun init(version: Int, groupId: Long, selfUserId: Long) {
        reset()
        this.selfUserId = selfUserId
        protocolVersion = version
        this.groupId = longToBigEndian(groupId)
        initLeafNode()
        if (externalSender != null) createPendingGroup()
    }

    @Synchronized
    fun reset() {
        clearPendingState()
        currentState = null
        protocolVersion = 0
        groupId = ByteArray(0)
    }

    @Synchronized
    fun setProtocolVersion(version: Int) {
        protocolVersion = version
    }

    @Synchronized
    fun setExternalSender(marshalled: ByteArray) {
        if (currentState != null) {
            log("Cannot set external sender after joining/creating an MLS group")
            return
        }
        try {
            externalSender = MLSInputStream.decode(marshalled, ExternalSender::class.java) as ExternalSender
            if (groupId.isNotEmpty()) createPendingGroup()
        } catch (e: Exception) {
            log("Failed to parse external sender: $e")
        }
    }

    /** Handles a dave_mls_proposals payload (starting at operation_type). Returns the commit(+welcome) to send. */
    @Synchronized
    fun processProposals(payload: ByteArray, recognizedUserIds: Set<Long>): ByteArray? {
        try {
            val base = pendingGroup ?: currentState
            if (base == null) {
                log("Got proposals without any MLS group state")
                return null
            }
            var state = stateWithProposals ?: copyGroup(base).also { stateWithProposals = it }

            val input = MLSInputStream(payload)
            val isRevoke = (input.read(java.lang.Byte.TYPE) as Byte).toInt() != 0
            val body = input.readOpaque()
            if (isRevoke) {
                val refs = ArrayList<ByteArray>()
                val refStream = MLSInputStream(body)
                var remaining = body.size
                while (remaining > 0) {
                    val ref = refStream.readOpaque()
                    refs.add(ref)
                    remaining -= ref.size + mlsVarintSize(ref.size)
                }
                for (ref in refs) {
                    val index = proposalQueue.indexOfFirst { it.ref.contentEquals(ref) }
                    if (index < 0) {
                        log("Unrecognized proposal revocation")
                        return null
                    }
                    proposalQueue.removeAt(index)
                }
                state = copyGroup(base)
                stateWithProposals = state
                for (queued in proposalQueue) state.handle(queued.message, null)
            } else {
                for (message in splitMessages(body)) {
                    val auth = authenticatedContentOf(message) ?: return null
                    if (!validateProposal(auth, state, recognizedUserIds)) return null
                    state.handle(message, null)
                    val ref = suite.refHash(MLSOutputStream.encode(auth), "MLS 1.0 Proposal Reference")
                    proposalQueue.add(QueuedProposal(message, ref))
                }
            }

            if (proposalQueue.isEmpty()) return null
            val hasAdds = proposalQueue.any {
                (authenticatedContentOf(it.message)?.content?.proposal?.proposalType) == ProposalType.ADD
            }
            val commitSecret = ByteArray(suite.kdf.hashLength).also { random.nextBytes(it) }
            val result = state.commit(
                Secret(commitSecret),
                Group.CommitOptions(ArrayList(), true, false, Group.LeafNodeOptions()),
                Group.MessageOptions(),
                Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS),
            )
            val commitBytes = MLSOutputStream.encode(result.message)
            outboundCommit = commitBytes
            outboundCachedGroup = result.group
            val out = ByteArrayOutputStream()
            out.write(commitBytes)
            if (hasAdds) out.write(MLSOutputStream.encode(result.message.welcome))
            return out.toByteArray()
        } catch (e: Exception) {
            log("processProposals failed: $e")
            return null
        }
    }

    private fun validateProposal(auth: AuthenticatedContent, state: Group, recognizedUserIds: Set<Long>): Boolean {
        val content = auth.content
        if (auth.wireFormat != WireFormat.mls_public_message) {
            log("Invalid proposal wire format")
            return false
        }
        if (content.epoch != state.epoch) {
            log("Proposal epoch mismatch (${content.epoch} != ${state.epoch})")
            return false
        }
        if (content.contentType != ContentType.PROPOSAL) {
            log("Unexpected message type")
            return false
        }
        if (content.sender.senderType != SenderType.EXTERNAL) {
            log("Unexpected proposal sender type")
            return false
        }
        val proposal = content.proposal
        return when (proposal.proposalType) {
            ProposalType.ADD -> {
                val ok = isRecognized(proposal.add.keyPackage.leafNode.credential, recognizedUserIds)
                if (!ok) log("Unexpected user ID in add proposal")
                ok
            }
            ProposalType.REMOVE -> true
            else -> {
                log("Unexpected proposal type")
                false
            }
        }
    }

    @Synchronized
    fun processCommit(commit: ByteArray): CommitResult {
        try {
            val state = stateWithProposals
            if (state == null) {
                if (currentState == null) {
                    log("Received commit without state")
                    return CommitResult.Ignored
                }
                throw IllegalStateException("ProcessCommit called without queued proposals")
            }
            val isOutbound = outboundCommit?.contentEquals(commit) == true
            if (currentState == null && !isOutbound) throw IllegalStateException("Unexpected commit before welcome")

            val content = framedContentOf(commit)
            if (!content.groupID.contentEquals(groupId)) throw IllegalStateException("Commit for unexpected group")
            if (wireFormatOf(commit) != WireFormat.mls_public_message) throw IllegalStateException("Invalid commit wire format")
            if (content.epoch != state.epoch) throw IllegalStateException("Commit epoch mismatch")
            if (content.contentType != ContentType.COMMIT) throw IllegalStateException("Unexpected message type")
            if (content.sender.senderType != SenderType.MEMBER) throw IllegalStateException("Unexpected commit sender type")
            for (p in content.commit.proposals) {
                if (p.type != ProposalOrRefType.REFERENCE) throw IllegalStateException("Unexpected non-ref proposal")
            }

            val newState = state.handle(commit, if (isOutbound) outboundCachedGroup else null)
                ?: throw IllegalStateException("Commit handling did not produce a new state")
            val changes = replaceState(newState)
            clearPendingState()
            return CommitResult.Joined(changes)
        } catch (e: Exception) {
            log("processCommit failed: $e")
            return CommitResult.Failed
        }
    }

    @Synchronized
    fun processWelcome(welcomeBytes: ByteArray, recognizedUserIds: Set<Long>): Map<Long, ByteArray>? {
        try {
            val keyPackage = joinKeyPackage ?: throw IllegalStateException("Missing join key package")
            val initKey = joinInitKey ?: throw IllegalStateException("Missing join init private key")
            val leafKey = hpkeKey ?: throw IllegalStateException("Missing self HPKE private key")
            if (externalSender == null) throw IllegalStateException("Missing external sender")
            if (currentState != null) throw IllegalStateException("Already joined/created group")

            val welcome = MLSInputStream.decode(welcomeBytes, Welcome::class.java) as Welcome
            val newState = Group(
                suite.hpke.serializePrivateKey(initKey.private),
                leafKey,
                signaturePriv,
                keyPackage,
                welcome,
                null,
                HashMap(),
                HashMap(),
            )
            if (!verifyWelcomeState(newState, recognizedUserIds)) return null
            val changes = replaceState(newState)
            clearPendingState()
            return changes
        } catch (e: Exception) {
            log("processWelcome failed: $e")
            return null
        }
    }

    private fun verifyWelcomeState(state: Group, recognizedUserIds: Set<Long>): Boolean {
        val sender = externalSender ?: return false
        if (!state.groupID.contentEquals(groupId)) {
            log("Unexpected group ID in Welcome")
            return false
        }
        val ext = state.extensions.firstOrNull { it.extensionType == ExtensionType.EXTERNAL_SENDERS }
        if (ext == null) {
            log("Welcome message missing external sender extension")
            return false
        }
        val senders = ext.senders
        if (senders.size != 1 || !MLSOutputStream.encode(senders[0]).contentEquals(MLSOutputStream.encode(sender))) {
            log("Welcome message lists unexpected external sender")
            return false
        }
        for (leaf in leaves(state)) {
            if (!isRecognized(leaf.credential, recognizedUserIds)) {
                log("Welcome message lists unrecognized user ID")
                return false
            }
        }
        return true
    }

    /** Swaps in [state] and returns the roster changes (removed users map to an empty key). */
    private fun replaceState(state: Group): Map<Long, ByteArray> {
        val newRoster = LinkedHashMap<Long, ByteArray>()
        for (leaf in leaves(state)) {
            if (leaf.credential.credentialType != CredentialType.basic) throw IllegalStateException("Unexpected credential type")
            val id = bigEndianToLong(leaf.credential.identity)
            if (newRoster.put(id, leaf.signatureKey) != null) throw IllegalStateException("Duplicate identity in roster")
        }
        val changes = LinkedHashMap<Long, ByteArray>()
        for ((id, key) in newRoster) if (!roster.containsKey(id)) changes[id] = key
        for (id in roster.keys) if (!newRoster.containsKey(id)) changes[id] = ByteArray(0)
        roster = newRoster
        currentState = state
        return changes
    }

    /** Creates a fresh key package (they are single use) and returns its TLS encoding. */
    @Synchronized
    fun marshalledKeyPackage(): ByteArray? {
        val leaf = selfLeafNode ?: return null
        return try {
            val initKey = suite.hpke.generatePrivateKey()
            val keyPackage = KeyPackage(suite, suite.hpke.serializePublicKey(initKey.public), leaf, ArrayList(), signaturePriv)
            joinInitKey = initKey
            joinKeyPackage = keyPackage
            MLSOutputStream.encode(keyPackage)
        } catch (e: Exception) {
            log("Failed to create key package: $e")
            null
        }
    }

    /** Media key ratchet for [userId] in the current epoch. */
    @Synchronized
    fun keyRatchet(userId: Long): KeyRatchet? {
        val state = currentState ?: return null
        val base = state.keySchedule.MLSExporter("Discord Secure Frames v0", longToLittleEndian(userId), 16)
        return KeyRatchet(suite, base)
    }

    private fun initLeafNode() {
        try {
            val hpke = suite.hpke.generatePrivateKey()
            hpkeKey = hpke
            selfLeafNode = LeafNode(
                suite,
                suite.hpke.serializePublicKey(hpke.public),
                signaturePublicKey,
                Credential.forBasic(longToBigEndian(selfUserId)),
                daveCapabilities(),
                LifeTime(),
                ArrayList(),
                signaturePriv,
            )
        } catch (e: Exception) {
            log("Failed to create leaf node: $e")
        }
    }

    private fun createPendingGroup() {
        val sender = externalSender ?: return
        val leaf = selfLeafNode ?: return
        val hpke = hpkeKey ?: return
        if (groupId.isEmpty()) return
        try {
            pendingGroup = Group(groupId, suite, hpke, signaturePriv, leaf, listOf(Extension.externalSender(listOf(sender))))
        } catch (e: Exception) {
            log("Failed to create pending group: $e")
        }
    }

    private fun clearPendingState() {
        pendingGroup = null
        outboundCommit = null
        outboundCachedGroup = null
        joinInitKey = null
        joinKeyPackage = null
        hpkeKey = null
        selfLeafNode = null
        stateWithProposals = null
        proposalQueue.clear()
    }

    private fun isRecognized(credential: Credential, recognizedUserIds: Set<Long>): Boolean {
        if (credential.credentialType != CredentialType.basic) return false
        return recognizedUserIds.contains(bigEndianToLong(credential.identity))
    }

    private fun authenticatedContentOf(message: ByteArray): AuthenticatedContent? = try {
        val msg = MLSInputStream.decode(message, MLSMessage::class.java) as MLSMessage
        // Membership tags only exist for member senders; external proposals are checked by Group.handle().
        msg.publicMessage?.unprotect(suite, null, null)
    } catch (e: Exception) {
        log("Failed to parse MLS message: $e")
        null
    }

    companion object {
        private val successor = Group::class.java.getDeclaredMethod("successor").apply { isAccessible = true }

        /** Copy of [group] with no cached proposals (mlspp copies State by value; BC's successor() does the same). */
        private fun copyGroup(group: Group): Group = successor.invoke(group) as Group

        private fun leaves(state: Group): List<LeafNode> {
            val tree = state.tree
            val result = ArrayList<LeafNode>()
            for (i in 0 until tree.size.leafCount().toInt()) {
                val index = LeafIndex(i)
                if (tree.hasLeaf(index)) result.add(tree.getLeafNode(index))
            }
            return result
        }

        private fun wireFormatOf(message: ByteArray): WireFormat =
            (MLSInputStream.decode(message, MLSMessage::class.java) as MLSMessage).wireFormat

        private fun framedContentOf(message: ByteArray): FramedContent {
            // MLSMessage = version(2) + wire_format(2) + PublicMessage, which starts with the FramedContent.
            val input = MLSInputStream(message.copyOfRange(4, message.size))
            return input.read(FramedContent::class.java) as FramedContent
        }

        private fun splitMessages(body: ByteArray): List<ByteArray> {
            val input = MLSInputStream(body)
            val messages = ArrayList<ByteArray>()
            var consumed = 0
            while (consumed < body.size) {
                val msg = input.read(MLSMessage::class.java) as MLSMessage
                val bytes = MLSOutputStream.encode(msg)
                messages.add(bytes)
                consumed += bytes.size
            }
            return messages
        }

        /** Capabilities exactly as libdave advertises them: MLS 1.0, ciphersuite 2, basic credentials. */
        private fun daveCapabilities(): Capabilities = MLSInputStream.decode(
            byteArrayOf(2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 1),
            Capabilities::class.java,
        ) as Capabilities

        internal fun mlsVarintSize(length: Int) = when {
            length < 0x40 -> 1
            length < 0x4000 -> 2
            else -> 4
        }
    }
}
