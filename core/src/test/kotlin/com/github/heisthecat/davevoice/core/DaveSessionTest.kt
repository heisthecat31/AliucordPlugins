package com.github.heisthecat.davevoice.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Drives several DaveSessions through the voice gateway's opcode sequence, like real clients in one call. */
class DaveSessionTest {
    private val channelId = 1234567890123456789L
    private val gateway = FakeVoiceGateway(channelId)
    private var seq = 0

    private class Client(val id: Long, channelId: Long) : DaveGateway {
        val sentBinary = ArrayList<Pair<Int, ByteArray>>()
        val ready = ArrayList<Int>()
        val invalid = ArrayList<Int>()
        val session = DaveSession(id, channelId, this, { println("[$id] $it") })

        override fun sendReadyForTransition(transitionId: Int) {
            ready.add(transitionId)
        }

        override fun sendInvalidCommitWelcome(transitionId: Int) {
            invalid.add(transitionId)
        }

        override fun sendBinary(opcode: Int, payload: ByteArray) {
            sentBinary.add(opcode to payload)
        }

        fun takeBinary(opcode: Int): ByteArray {
            val i = sentBinary.indexOfLast { it.first == opcode }
            assertTrue("client $id did not send opcode $opcode", i >= 0)
            return sentBinary.removeAt(i).second
        }
    }

    private fun Client.receive(opcode: Int, payload: ByteArray) =
        session.onBinaryMessage(FakeVoiceGateway.binary(seq++, opcode, payload))

    private fun connect(client: Client, others: List<Client>) {
        client.session.onClientsConnect(others.map { it.id })
        for (o in others) o.session.onClientsConnect(listOf(client.id))
        client.receive(DaveOpcodes.MLS_EXTERNAL_SENDER, gateway.marshalledExternalSender)
        client.session.onSelectProtocolAck(1)
    }

    /** Gateway proposes [proposals] to [members]; the first member's commit wins. Returns the transition ID. */
    private fun runCommit(members: List<Client>, proposals: ByteArray, joiners: List<Client>, transitionId: Int) {
        for (m in members) m.receive(DaveOpcodes.MLS_PROPOSALS, proposals)
        val commitWelcomes = members.map { it.takeBinary(DaveOpcodes.MLS_COMMIT_WELCOME) }
        val (commit, welcome) = gateway.splitCommitWelcome(commitWelcomes[0])
        for (m in members) m.receive(DaveOpcodes.MLS_ANNOUNCE_COMMIT, FakeVoiceGateway.withTransition(transitionId, commit))
        for (j in joiners) j.receive(DaveOpcodes.MLS_WELCOME, FakeVoiceGateway.withTransition(transitionId, welcome!!))
        for (c in members + joiners) {
            assertEquals("client ${c.id} invalid=${c.invalid}", listOf(transitionId), c.ready.takeLast(1))
            assertTrue(c.invalid.isEmpty())
        }
        for (c in members + joiners) c.session.onExecuteTransition(transitionId)
    }

    private fun assertMedia(clients: List<Client>) {
        val epochs = clients.map { it.session.epoch }.toSet()
        assertEquals("all clients should share one epoch", 1, epochs.size)
        val auth = clients.map { hex(it.session.epochAuthenticator!!) }.toSet()
        assertEquals("epoch authenticators should match", 1, auth.size)
        for (sender in clients) {
            val frame = ByteArray(80) { (it + sender.id).toByte() }
            val encrypted = sender.session.encryptFrame(frame)
            assertNotNull("client ${sender.id} has no send key", encrypted)
            for (receiver in clients) {
                if (receiver === sender) continue
                assertArrayEquals(frame, receiver.session.decryptFrame(sender.id, encrypted!!))
            }
        }
    }

    @Test
    fun createJoinLeave() {
        val a = Client(1111111111111111111L, channelId)
        val b = Client(2222222222222222222L, channelId)
        connect(a, emptyList())
        connect(b, listOf(a))

        // Initial group creation: each pending member gets the other's add proposal at epoch 0.
        val kpA = a.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)
        val kpB = b.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)
        assertNull("no key before the group exists", a.session.encryptFrame(ByteArray(10)))
        a.receive(DaveOpcodes.MLS_PROPOSALS, gateway.proposeAdd(0, kpB))
        b.receive(DaveOpcodes.MLS_PROPOSALS, gateway.proposeAdd(0, kpA))
        val (commit, welcome) = gateway.splitCommitWelcome(a.takeBinary(DaveOpcodes.MLS_COMMIT_WELCOME))
        a.receive(DaveOpcodes.MLS_ANNOUNCE_COMMIT, FakeVoiceGateway.withTransition(1, commit))
        b.receive(DaveOpcodes.MLS_WELCOME, FakeVoiceGateway.withTransition(1, welcome!!))
        assertEquals(listOf(1), a.ready)
        assertEquals(listOf(1), b.ready)
        a.session.onExecuteTransition(1)
        b.session.onExecuteTransition(1)
        assertEquals(1, a.session.protocolVersion)
        assertMedia(listOf(a, b))

        // A third member joins the established group (epoch 1).
        val c = Client(3333333333333333333L, channelId)
        connect(c, listOf(a, b))
        val kpC = c.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)
        runCommit(listOf(a, b), gateway.proposeAdd(1, kpC), listOf(c), 2)
        assertMedia(listOf(a, b, c))

        // C leaves: it was added third, so it sits in leaf 2.
        for (m in listOf(a, b)) m.session.onClientDisconnect(c.id)
        runCommit(listOf(b, a), gateway.proposeRemove(2, 2), emptyList(), 3)
        assertMedia(listOf(a, b))
    }

    @Test
    fun revokedProposalIsNotCommitted() {
        val a = Client(1111111111111111111L, channelId)
        val b = Client(2222222222222222222L, channelId)
        val c = Client(3333333333333333333L, channelId)
        connect(a, emptyList())
        connect(b, listOf(a))
        connect(c, listOf(a, b))
        val kpB = b.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)
        val kpC = c.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)
        a.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)

        val addB = gateway.proposeAdd(0, kpB)
        val addC = gateway.proposeAdd(0, kpC)
        a.receive(DaveOpcodes.MLS_PROPOSALS, addB)
        a.receive(DaveOpcodes.MLS_PROPOSALS, addC)
        a.sentBinary.clear()
        a.receive(DaveOpcodes.MLS_PROPOSALS, gateway.revoke(listOf(gateway.proposalRef(addC))))
        val (commit, welcome) = gateway.splitCommitWelcome(a.takeBinary(DaveOpcodes.MLS_COMMIT_WELCOME))
        a.receive(DaveOpcodes.MLS_ANNOUNCE_COMMIT, FakeVoiceGateway.withTransition(5, commit))
        b.receive(DaveOpcodes.MLS_WELCOME, FakeVoiceGateway.withTransition(5, welcome!!))
        // C's key package was not used, so its welcome attempt must fail.
        c.receive(DaveOpcodes.MLS_WELCOME, FakeVoiceGateway.withTransition(5, welcome))
        assertEquals(listOf(5), c.invalid)
        a.session.onExecuteTransition(5)
        b.session.onExecuteTransition(5)
        assertMedia(listOf(a, b))
    }

    @Test
    fun unexpectedUserInAddIsRejected() {
        val a = Client(1111111111111111111L, channelId)
        val b = Client(2222222222222222222L, channelId)
        connect(a, emptyList())
        b.receive(DaveOpcodes.MLS_EXTERNAL_SENDER, gateway.marshalledExternalSender)
        b.session.onSelectProtocolAck(1)
        // A never saw B in clients_connect.
        a.receive(DaveOpcodes.MLS_PROPOSALS, gateway.proposeAdd(0, b.takeBinary(DaveOpcodes.MLS_KEY_PACKAGE)))
        assertTrue(a.sentBinary.none { it.first == DaveOpcodes.MLS_COMMIT_WELCOME })
    }

    @Test
    fun protocolZeroIsPassthrough() {
        val a = Client(1L, channelId)
        a.session.onSelectProtocolAck(0)
        val frame = ByteArray(20) { it.toByte() }
        assertArrayEquals(frame, a.session.encryptFrame(frame))
        assertArrayEquals(frame, a.session.decryptFrame(42L, frame))
    }
}
