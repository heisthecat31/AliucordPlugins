package com.github.heisthecat.davevoice.core

import org.bouncycastle.mls.TreeKEM.LeafIndex
import org.bouncycastle.mls.codec.Credential
import org.bouncycastle.mls.codec.ExternalSender
import org.bouncycastle.mls.codec.KeyPackage
import org.bouncycastle.mls.codec.MLSInputStream
import org.bouncycastle.mls.codec.MLSMessage
import org.bouncycastle.mls.codec.MLSOutputStream
import org.bouncycastle.mls.codec.Proposal
import org.bouncycastle.mls.codec.Welcome
import org.bouncycastle.mls.crypto.MlsCipherSuite
import java.io.ByteArrayOutputStream

/** Plays the voice gateway's role as MLS external sender, like libdave's test ExternalSender. */
class FakeVoiceGateway(groupId: Long) {
    private val suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
    private val groupIdBytes = longToBigEndian(groupId)
    private val signatureKey = suite.generateSignatureKeyPair()
    private val signaturePriv = suite.serializeSignaturePrivateKey(signatureKey.private)
    private val externalSender = ExternalSender(
        suite.serializeSignaturePublicKey(signatureKey.public),
        Credential.forBasic(byteArrayOf(0, 1, 1, 0)),
    )

    val marshalledExternalSender: ByteArray get() = MLSOutputStream.encode(externalSender)

    fun proposeAdd(epoch: Long, keyPackage: ByteArray): ByteArray {
        val kp = MLSInputStream.decode(keyPackage, KeyPackage::class.java) as KeyPackage
        return appendProposals(listOf(MLSMessage.externalProposal(suite, groupIdBytes, epoch, Proposal.add(kp), 0, signaturePriv)))
    }

    fun proposeRemove(epoch: Long, leaf: Int): ByteArray =
        appendProposals(listOf(MLSMessage.externalProposal(suite, groupIdBytes, epoch, Proposal.remove(LeafIndex(leaf)), 0, signaturePriv)))

    /** Proposal ref, computed like the gateway (and BC/mlspp) do. */
    fun proposalRef(proposalsPayload: ByteArray): ByteArray {
        val input = MLSInputStream(proposalsPayload)
        input.read(java.lang.Byte.TYPE)
        val body = input.readOpaque()
        val msg = MLSInputStream(body).read(MLSMessage::class.java) as MLSMessage
        val auth = msg.publicMessage.unprotect(suite, null, null)
        return suite.refHash(MLSOutputStream.encode(auth), "MLS 1.0 Proposal Reference")
    }

    fun revoke(refs: List<ByteArray>): ByteArray {
        val body = ByteArrayOutputStream()
        val stream = MLSOutputStream()
        for (r in refs) stream.writeOpaque(r)
        body.write(stream.toByteArray())
        val out = MLSOutputStream()
        out.write(1.toByte())
        out.writeOpaque(body.toByteArray())
        return out.toByteArray()
    }

    private fun appendProposals(messages: List<MLSMessage>): ByteArray {
        val body = ByteArrayOutputStream()
        for (m in messages) body.write(MLSOutputStream.encode(m))
        val out = MLSOutputStream()
        out.write(0.toByte())
        out.writeOpaque(body.toByteArray())
        return out.toByteArray()
    }

    /** Splits a dave_mls_commit_welcome payload into the commit MLSMessage and optional Welcome. */
    fun splitCommitWelcome(commitWelcome: ByteArray): Pair<ByteArray, ByteArray?> {
        val input = MLSInputStream(commitWelcome)
        val commit = input.read(MLSMessage::class.java) as MLSMessage
        val commitBytes = MLSOutputStream.encode(commit)
        if (commitBytes.size == commitWelcome.size) return commitBytes to null
        val welcome = input.read(Welcome::class.java) as Welcome
        return commitBytes to MLSOutputStream.encode(welcome)
    }

    companion object {
        fun binary(seq: Int, opcode: Int, payload: ByteArray): ByteArray {
            val out = ByteArray(3 + payload.size)
            out.putU16(0, seq)
            out[2] = opcode.toByte()
            System.arraycopy(payload, 0, out, 3, payload.size)
            return out
        }

        fun withTransition(transitionId: Int, body: ByteArray): ByteArray {
            val out = ByteArray(2 + body.size)
            out.putU16(0, transitionId)
            System.arraycopy(body, 0, out, 2, body.size)
            return out
        }
    }
}
