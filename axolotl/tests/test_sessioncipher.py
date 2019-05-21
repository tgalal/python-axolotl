# -*- coding: utf-8 -*-

import unittest

from ..state.sessionrecord import SessionRecord
from ..ecc.curve import Curve
from ..identitykeypair import IdentityKeyPair, IdentityKey
from ..ratchet.aliceaxolotlparameters import AliceAxolotlParameters
from ..ratchet.bobaxolotlparamaters import BobAxolotlParameters
from ..ratchet.ratchetingsession import RatchetingSession
from ..tests.inmemoryaxolotlstore import InMemoryAxolotlStore
from ..sessioncipher import SessionCipher
from ..protocol.whispermessage import WhisperMessage


class SessionCipherTest(unittest.TestCase):

    def test_basicSessionV3(self):
        aliceSessionRecord = SessionRecord()
        bobSessionRecord = SessionRecord()
        self.initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState())
        self.runInteraction(aliceSessionRecord, bobSessionRecord)

    def runInteraction(self, aliceSessionRecord, bobSessionRecord):
        aliceStore = InMemoryAxolotlStore()
        bobStore = InMemoryAxolotlStore()

        aliceStore.storeSession(2, 1, aliceSessionRecord)
        bobStore.storeSession(3, 1, bobSessionRecord)

        aliceCipher = SessionCipher(aliceStore, aliceStore, aliceStore, aliceStore, 2, 1)
        bobCipher = SessionCipher(bobStore, bobStore, bobStore, bobStore, 3, 1)

        alicePlaintext = b"This is a plaintext message."
        message = aliceCipher.encrypt(alicePlaintext)
        bobPlaintext = bobCipher.decryptMsg(WhisperMessage(serialized=message.serialize()))

        self.assertEqual(alicePlaintext, bobPlaintext)

        bobReply = b"This is a message from Bob."
        reply = bobCipher.encrypt(bobReply)
        receivedReply = aliceCipher.decryptMsg(WhisperMessage(serialized=reply.serialize()))

        self.assertEqual(bobReply, receivedReply)

        alicePlaintext = b"ABCDEFGHIJKLMNOP"  # ensure padding/unpadding properly applies on message of blocksize length
        message = aliceCipher.encrypt(alicePlaintext)
        bobPlaintext = bobCipher.decryptMsg(WhisperMessage(serialized=message.serialize()))
        self.assertEqual(alicePlaintext, bobPlaintext)

        aliceCiphertextMessages = []
        alicePlaintextMessages = []

        for i in range(0, 50):
            alicePlaintextMessages.append(b"aaaaaa %d" % i)
            aliceCiphertextMessages.append(aliceCipher.encrypt(b"aaaaaa %d" % i))

        # shuffle(aliceCiphertextMessages)
        # shuffle(alicePlaintextMessages)

        for i in range(0, int(len(aliceCiphertextMessages)/2)):
            receivedPlaintext = bobCipher.decryptMsg(WhisperMessage(serialized=aliceCiphertextMessages[i].serialize()))
            self.assertEqual(receivedPlaintext, alicePlaintextMessages[i])

    def initializeSessionsV3(self, aliceSessionState, bobSessionState):
        aliceIdentityKeyPair = Curve.generateKeyPair()
        aliceIdentityKey = IdentityKeyPair(IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                           aliceIdentityKeyPair.getPrivateKey())
        aliceBaseKey = Curve.generateKeyPair()
        # aliceEphemeralKey = Curve.generateKeyPair()

        # alicePreKey = aliceBaseKey

        bobIdentityKeyPair = Curve.generateKeyPair()
        bobIdentityKey = IdentityKeyPair(IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                         bobIdentityKeyPair.getPrivateKey())
        bobBaseKey = Curve.generateKeyPair()
        bobEphemeralKey = bobBaseKey

        # bobPreKey = Curve.generateKeyPair()

        aliceParameters = AliceAxolotlParameters.newBuilder()\
            .setOurBaseKey(aliceBaseKey)\
            .setOurIdentityKey(aliceIdentityKey)\
            .setTheirOneTimePreKey(None)\
            .setTheirRatchetKey(bobEphemeralKey.getPublicKey())\
            .setTheirSignedPreKey(bobBaseKey.getPublicKey())\
            .setTheirIdentityKey(bobIdentityKey.getPublicKey())\
            .create()

        bobParameters = BobAxolotlParameters.newBuilder()\
            .setOurRatchetKey(bobEphemeralKey)\
            .setOurSignedPreKey(bobBaseKey)\
            .setOurOneTimePreKey(None)\
            .setOurIdentityKey(bobIdentityKey)\
            .setTheirIdentityKey(aliceIdentityKey.getPublicKey())\
            .setTheirBaseKey(aliceBaseKey.getPublicKey())\
            .create()

        RatchetingSession.initializeSessionAsAlice(aliceSessionState, aliceParameters)
        RatchetingSession.initializeSessionAsBob(bobSessionState, bobParameters)
