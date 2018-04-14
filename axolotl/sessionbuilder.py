# -*- coding: utf-8 -*-

import logging

from .ecc.curve import Curve
from .ratchet.aliceaxolotlparameters import AliceAxolotlParameters
from .ratchet.bobaxolotlparamaters import BobAxolotlParameters
from .ratchet.symmetricaxolotlparameters import SymmetricAxolotlParameters
from .ratchet.ratchetingsession import RatchetingSession
from .invalidkeyexception import InvalidKeyException
from .invalidkeyidexception import InvalidKeyIdException
from .untrustedidentityexception import UntrustedIdentityException
from .protocol.keyexchangemessage import KeyExchangeMessage
from .protocol.ciphertextmessage import CiphertextMessage
from .statekeyexchangeexception import StaleKeyExchangeException
from .util.medium import Medium
from .util.keyhelper import KeyHelper


logger = logging.getLogger(__name__)


class SessionBuilder:
    def __init__(self, sessionStore, preKeyStore, signedPreKeyStore, identityKeyStore, recepientId, deviceId):
        self.sessionStore = sessionStore
        self.preKeyStore = preKeyStore
        self.signedPreKeyStore = signedPreKeyStore
        self.identityKeyStore = identityKeyStore
        self.recipientId = recepientId
        self.deviceId = deviceId

    def process(self, sessionRecord, message):
        """
        :param sessionRecord:
        :param message:
        :type message: PreKeyWhisperMessage
        """

        theirIdentityKey = message.getIdentityKey()

        if not self.identityKeyStore.isTrustedIdentity(self.recipientId, theirIdentityKey):
            raise UntrustedIdentityException(self.recipientId, theirIdentityKey)

        unsignedPreKeyId = self.processV3(sessionRecord, message)

        self.identityKeyStore.saveIdentity(self.recipientId, theirIdentityKey)

        return unsignedPreKeyId

    def processV3(self, sessionRecord, message):
        """
        :param sessionRecord:
        :param message:
        :type message: PreKeyWhisperMessage
        :return:
        """

        if sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().serialize()):
            logger.warn("We've already setup a session for this V3 message, letting bundled message fall through...")
            return None

        ourSignedPreKey = self.signedPreKeyStore.loadSignedPreKey(message.getSignedPreKeyId()).getKeyPair()
        parameters = BobAxolotlParameters.newBuilder()
        parameters.setTheirBaseKey(message.getBaseKey())\
            .setTheirIdentityKey(message.getIdentityKey())\
            .setOurIdentityKey(self.identityKeyStore.getIdentityKeyPair())\
            .setOurSignedPreKey(ourSignedPreKey)\
            .setOurRatchetKey(ourSignedPreKey)

        if message.getPreKeyId() is not None:
            parameters.setOurOneTimePreKey(self.preKeyStore.loadPreKey(message.getPreKeyId()).getKeyPair())
        else:
            parameters.setOurOneTimePreKey(None)

        if not sessionRecord.isFresh():
            sessionRecord.archiveCurrentState()

        RatchetingSession.initializeSessionAsBob(sessionRecord.getSessionState(), parameters.create())
        sessionRecord.getSessionState().setLocalRegistrationId(self.identityKeyStore.getLocalRegistrationId())
        sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId())
        sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize())

        if message.getPreKeyId() is not None and message.getPreKeyId() != Medium.MAX_VALUE:
            return message.getPreKeyId()
        else:
            return None

    def processPreKeyBundle(self, preKey):
        """
        :type preKey: PreKeyBundle
        """
        if not self.identityKeyStore.isTrustedIdentity(self.recipientId, preKey.getIdentityKey()):
            raise UntrustedIdentityException(self.recipientId, preKey.getIdentityKey())

        if preKey.getSignedPreKey() is not None and\
            not Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
                                      preKey.getSignedPreKey().serialize(),
                                      preKey.getSignedPreKeySignature()):
            raise InvalidKeyException("Invalid signature on device key!")

        if preKey.getSignedPreKey() is None:
            raise InvalidKeyException("No signed prekey!!")

        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)
        ourBaseKey = Curve.generateKeyPair()
        theirSignedPreKey = preKey.getSignedPreKey()
        theirOneTimePreKey = preKey.getPreKey()
        theirOneTimePreKeyId = preKey.getPreKeyId() if theirOneTimePreKey is not None else None

        parameters = AliceAxolotlParameters.newBuilder()

        parameters.setOurBaseKey(ourBaseKey)\
            .setOurIdentityKey(self.identityKeyStore.getIdentityKeyPair())\
            .setTheirIdentityKey(preKey.getIdentityKey())\
            .setTheirSignedPreKey(theirSignedPreKey)\
            .setTheirRatchetKey(theirSignedPreKey)\
            .setTheirOneTimePreKey(theirOneTimePreKey)

        if not sessionRecord.isFresh():
            sessionRecord.archiveCurrentState()

        RatchetingSession.initializeSessionAsAlice(sessionRecord.getSessionState(), parameters.create())

        sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId,
                                                                       preKey.getSignedPreKeyId(),
                                                                       ourBaseKey.getPublicKey())
        sessionRecord.getSessionState().setLocalRegistrationId(self.identityKeyStore.getLocalRegistrationId())
        sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId())
        sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize())
        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)
        self.identityKeyStore.saveIdentity(self.recipientId, preKey.getIdentityKey())

    def processKeyExchangeMessage(self, keyExchangeMessage):

        if not self.identityKeyStore.isTrustedIdentity(self.recipientId, keyExchangeMessage.getIdentityKey()):
            raise UntrustedIdentityException(self.recipientId, keyExchangeMessage.getIdentityKey())

        responseMessage = None

        if keyExchangeMessage.isInitiate():
            responseMessage = self.processInitiate(keyExchangeMessage)
        else:
            self.processResponse(keyExchangeMessage)

        return responseMessage

    def processInitiate(self, keyExchangeMessage):
        flags = KeyExchangeMessage.RESPONSE_FLAG
        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)

        if not Curve.verifySignature(
                keyExchangeMessage.getIdentityKey().getPublicKey(),
                keyExchangeMessage.getBaseKey().serialize(),
                keyExchangeMessage.getBaseKeySignature()):
            raise InvalidKeyException("Bad signature!")

        builder = SymmetricAxolotlParameters.newBuilder()
        if not sessionRecord.getSessionState().hasPendingKeyExchange():
            builder.setOurIdentityKey(self.identityKeyStore.getIdentityKeyPair())\
                .setOurBaseKey(Curve.generateKeyPair())\
                .setOurRatchetKey(Curve.generateKeyPair())
        else:
            builder.setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())\
                .setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())\
                .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey())
            flags |= KeyExchangeMessage.SIMULTAENOUS_INITIATE_FLAG

        builder.setTheirBaseKey(keyExchangeMessage.getBaseKey())\
            .setTheirRatchetKey(keyExchangeMessage.getRatchetKey())\
            .setTheirIdentityKey(keyExchangeMessage.getIdentityKey())

        parameters = builder.create()

        if not sessionRecord.isFresh():
            sessionRecord.archiveCurrentState()

        RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters)

        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)
        self.identityKeyStore.saveIdentity(self.recipientId, keyExchangeMessage.getIdentityKey())

        baseKeySignature = Curve.calculateSignature(parameters.getOurIdentityKey().getPrivateKey(),
                                                    parameters.getOurBaseKey().getPublicKey().serialize())

        return KeyExchangeMessage(sessionRecord.getSessionState().getSessionVersion(),
                                  keyExchangeMessage.getSequence(), flags,
                                  parameters.getOurBaseKey().getPublicKey(),
                                  baseKeySignature, parameters.getOurRatchetKey().getPublicKey(),
                                  parameters.getOurIdentityKey().getPublicKey())

    def processResponse(self, keyExchangeMessage):
        sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)
        sessionState = sessionRecord.getSessionState()
        hasPendingKeyExchange = sessionState.hasPendingKeyExchange()
        isSimultaneousInitiateResponse = keyExchangeMessage.isResponseForSimultaneousInitiate()

        if not hasPendingKeyExchange \
                or sessionState.getPendingKeyExchangeSequence() != keyExchangeMessage.getSequence():
            logger.warn("No matching sequence for response. "
                        "Is simultaneous initiate response: %s" % isSimultaneousInitiateResponse)
            if not isSimultaneousInitiateResponse:
                raise StaleKeyExchangeException()
            else:
                return

        parameters = SymmetricAxolotlParameters.newBuilder()

        parameters.setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())\
            .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey())\
            .setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())\
            .setTheirBaseKey(keyExchangeMessage.getBaseKey())\
            .setTheirRatchetKey(keyExchangeMessage.getRatchetKey())\
            .setTheirIdentityKey(keyExchangeMessage.getIdentityKey())

        if not sessionRecord.isFresh():
            sessionRecord.archiveCurrentState()

        RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create())

        if not Curve.verifySignature(
                keyExchangeMessage.getIdentityKey().getPublicKey(),
                keyExchangeMessage.getBaseKey().serialize(),
                keyExchangeMessage.getBaseKeySignature()):
            raise InvalidKeyException("Base key signature doesn't match!")

        self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)
        self.identityKeyStore.saveIdentity(self.recipientId, keyExchangeMessage.getIdentityKey())

    def processInitKeyExchangeMessage(self):
        try:
            sequence = KeyHelper.getRandomSequence(65534) + 1
            flags = KeyExchangeMessage.INITIATE_FLAG
            baseKey = Curve.generateKeyPair()
            ratchetKey = Curve.generateKeyPair()
            identityKey = self.identityKeyStore.getIdentityKeyPair()
            baseKeySignature = Curve.calculateSignature(identityKey.getPrivateKey(), baseKey.getPublicKey().serialize())
            sessionRecord = self.sessionStore.loadSession(self.recipientId, self.deviceId)

            sessionRecord.getSessionState().setPendingKeyExchange(sequence, baseKey, ratchetKey, identityKey)
            self.sessionStore.storeSession(self.recipientId, self.deviceId, sessionRecord)

            return KeyExchangeMessage(CiphertextMessage.CURRENT_VERSION, sequence, flags, baseKey.getPublicKey(), baseKeySignature,
                                      ratchetKey.getPublicKey(), identityKey.getPublicKey())
        except InvalidKeyException as e:
            raise AssertionError(e)
