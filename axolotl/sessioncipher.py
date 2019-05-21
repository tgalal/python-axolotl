# -*- coding: utf-8 -*-

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from .ecc.curve import Curve
from .sessionbuilder import SessionBuilder
from .state.sessionstate import SessionState
from .protocol.whispermessage import WhisperMessage
from .protocol.prekeywhispermessage import PreKeyWhisperMessage
from .nosessionexception import NoSessionException
from .invalidmessageexception import InvalidMessageException
from .duplicatemessagexception import DuplicateMessageException

import  logging

logger = logging.getLogger(__name__)

class SessionCipher:
    def __init__(self, sessionStore, preKeyStore, signedPreKeyStore, identityKeyStore, recepientId, deviceId):
        self.sessionStore = sessionStore
        self.preKeyStore = preKeyStore
        self.recipientId = recepientId
        self.deviceId = deviceId
        self.sessionBuilder = SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                             identityKeyStore, recepientId, deviceId)

    def encrypt(self, paddedMessage):
        """
        :type paddedMessage: bytes
        """
        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)
        sessionState = sessionRecord.getSessionState()
        chainKey = sessionState.getSenderChainKey()
        messageKeys = chainKey.getMessageKeys()
        senderEphemeral = sessionState.getSenderRatchetKey()
        previousCounter = sessionState.getPreviousCounter()
        sessionVersion = sessionState.getSessionVersion()

        ciphertextBody = self.getCiphertext(sessionVersion, messageKeys, paddedMessage)
        ciphertextMessage = WhisperMessage(sessionVersion, messageKeys.getMacKey(),
                                           senderEphemeral, chainKey.getIndex(),
                                           previousCounter, ciphertextBody,
                                           sessionState.getLocalIdentityKey(),
                                           sessionState.getRemoteIdentityKey())

        if sessionState.hasUnacknowledgedPreKeyMessage():
            items = sessionState.getUnacknowledgedPreKeyMessageItems()
            localRegistrationid = sessionState.getLocalRegistrationId()

            ciphertextMessage = PreKeyWhisperMessage(sessionVersion, localRegistrationid, items.getPreKeyId(),
                                                     items.getSignedPreKeyId(), items.getBaseKey(),
                                                     sessionState.getLocalIdentityKey(),
                                                     ciphertextMessage)
        sessionState.setSenderChainKey(chainKey.getNextChainKey())
        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)

        return ciphertextMessage

    def decryptMsg(self, ciphertext, textMsg=True):
        """
        :type ciphertext: WhisperMessage
        :type textMsg: Bool set this to False if you are decrypting bytes
                       instead of string
        """

        if not self.sessionStore.containsSession(self.recipientId, self.deviceId):
            raise NoSessionException("No session for: %s, %s" % (self.recipientId, self.deviceId))

        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)
        plaintext = self.decryptWithSessionRecord(sessionRecord, ciphertext)

        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)

        return plaintext

    def decryptPkmsg(self, ciphertext, textMsg=True):
        """
        :type ciphertext: PreKeyWhisperMessage
        """
        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)
        unsignedPreKeyId = self.sessionBuilder.process(sessionRecord, ciphertext)
        plaintext = self.decryptWithSessionRecord(sessionRecord, ciphertext.getWhisperMessage())

        # callback.handlePlaintext(plaintext)
        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)

        if unsignedPreKeyId is not None:
            self.preKeyStore.removePreKey(unsignedPreKeyId)

        return plaintext

    def decryptWithSessionRecord(self, sessionRecord, cipherText):
        """
        :type sessionRecord: SessionRecord
        :type cipherText: WhisperMessage
        """

        previousStates = sessionRecord.getPreviousSessionStates()
        exceptions = []
        try:
            sessionState = SessionState(sessionRecord.getSessionState())
            plaintext = self.decryptWithSessionState(sessionState, cipherText)
            sessionRecord.setState(sessionState)
            return plaintext
        except InvalidMessageException as e:
            exceptions.append(e)

        for i in range(0, len(previousStates)):
            previousState = previousStates[i]
            try:
                promotedState = SessionState(previousState)
                plaintext = self.decryptWithSessionState(promotedState, cipherText)
                previousStates.pop(i)
                sessionRecord.promoteState(promotedState)
                return plaintext
            except InvalidMessageException as e:
                exceptions.append(e)

        raise InvalidMessageException("No valid sessions", exceptions)

    def decryptWithSessionState(self, sessionState, ciphertextMessage):

        if not sessionState.hasSenderChain():
            raise InvalidMessageException("Uninitialized session!")

        if ciphertextMessage.getMessageVersion() != sessionState.getSessionVersion():
            raise InvalidMessageException("Message version %s, but session version %s" % (ciphertextMessage.getMessageVersion, sessionState.getSessionVersion()))

        messageVersion = ciphertextMessage.getMessageVersion()
        theirEphemeral = ciphertextMessage.getSenderRatchetKey()
        counter = ciphertextMessage.getCounter()
        chainKey = self.getOrCreateChainKey(sessionState, theirEphemeral)
        messageKeys = self.getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter)

        ciphertextMessage.verifyMac(messageVersion,
                                    sessionState.getRemoteIdentityKey(),
                                    sessionState.getLocalIdentityKey(),
                                    messageKeys.getMacKey())

        plaintext = self.getPlaintext(messageVersion, messageKeys, ciphertextMessage.getBody())
        sessionState.clearUnacknowledgedPreKeyMessage()

        return plaintext

    def getOrCreateChainKey(self, sessionState, ECPublickKey_theirEphemeral):
        theirEphemeral = ECPublickKey_theirEphemeral
        if sessionState.hasReceiverChain(theirEphemeral):
            return sessionState.getReceiverChainKey(theirEphemeral)
        else:
            rootKey = sessionState.getRootKey()
            ourEphemeral = sessionState.getSenderRatchetKeyPair()
            receiverChain = rootKey.createChain(theirEphemeral, ourEphemeral)
            ourNewEphemeral = Curve.generateKeyPair()
            senderChain = receiverChain[0].createChain(theirEphemeral, ourNewEphemeral)

            sessionState.setRootKey(senderChain[0])
            sessionState.addReceiverChain(theirEphemeral, receiverChain[1])
            sessionState.setPreviousCounter(max(sessionState.getSenderChainKey().getIndex() - 1, 0))
            sessionState.setSenderChain(ourNewEphemeral, senderChain[1])
            return receiverChain[1]

    def getOrCreateMessageKeys(self, sessionState, ECPublicKey_theirEphemeral, chainKey, counter):
        theirEphemeral = ECPublicKey_theirEphemeral
        if chainKey.getIndex() > counter:
            if sessionState.hasMessageKeys(theirEphemeral, counter):
                return sessionState.removeMessageKeys(theirEphemeral, counter)
            else:
                raise DuplicateMessageException("Received message with old counter: %s, %s" % (chainKey.getIndex(),
                                                                                               counter))

        if counter - chainKey.getIndex() > 2000:
            raise InvalidMessageException("Over 2000 messages into the future!")

        while chainKey.getIndex() < counter:
            messageKeys = chainKey.getMessageKeys()
            sessionState.setMessageKeys(theirEphemeral, messageKeys)
            chainKey = chainKey.getNextChainKey()

        sessionState.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey())
        return chainKey.getMessageKeys()

    def getCiphertext(self, version, messageKeys, plainText):
        """
        :type version: int
        :type messageKeys: MessageKeys
        :type  plainText: bytearray
        """
        cipher = self.getCipher(messageKeys.getCipherKey(), messageKeys.getIv())
        return cipher.encrypt(plainText)

    def getPlaintext(self, version, messageKeys, cipherText):
        cipher = self.getCipher(messageKeys.getCipherKey(), messageKeys.getIv())

        return cipher.decrypt(cipherText)

    def getCipher(self, key, iv):
        return AESCipher(key, iv)

class AESCipher:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def encrypt(self, raw):
        padder = padding.PKCS7(128).padder()
        rawPadded = padder.update(raw) + padder.finalize()

        encryptor = self.cipher.encryptor()
        try:
            return encryptor.update(rawPadded) + encryptor.finalize()
        except ValueError:
            raise

    def decrypt(self, enc):
        decryptor = self.cipher.decryptor()
        decrypted = decryptor.update(enc) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
