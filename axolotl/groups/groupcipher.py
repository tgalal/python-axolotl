import sys
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.invalidkeyexception import InvalidKeyException
from axolotl.invalidmessageexception import InvalidMessageException
from axolotl.duplicatemessagexception import DuplicateMessageException
from axolotl.nosessionexception import NoSessionException
from axolotl.groups.state.senderkeystore import SenderKeyStore
from axolotl.protocol.senderkeymessage import SenderKeyMessage
from axolotl.sessioncipher import AESCipher
class GroupCipher:
    def __init__(self, senderKeyStore, senderKeyId):
        """
        :type senderKeyStore: SenderKeyStore
        :type senderKeyId: str
        """
        self.senderKeyStore = senderKeyStore
        self.senderKeyId = senderKeyId

    def encrypt(self, paddedPlaintext):
        """
        :type paddedPlaintext: str
        """
        paddedPlaintext = bytearray(paddedPlaintext.encode() if sys.version_info > (3,0) else paddedPlaintext)

        try:
            record         = self.senderKeyStore.loadSenderKey(self.senderKeyId)
            senderKeyState = record.getSenderKeyState()
            senderKey      = senderKeyState.getSenderChainKey().getSenderMessageKey()
            ciphertext     = self.getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext)

            senderKeyMessage = SenderKeyMessage(senderKeyState.getKeyId(),
                                                                 senderKey.getIteration(),
                                                                 ciphertext,
                                                                 senderKeyState.getSigningKeyPrivate())

            senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext())
            self.senderKeyStore.storeSenderKey(self.senderKeyId, record)

            return senderKeyMessage.serialize()
        except InvalidKeyIdException as e:
            raise NoSessionException(e)

    def decrypt(self, senderKeyMessageBytes):
        """
        :type senderKeyMessageBytes: bytearray
        """
        try:
            record           = self.senderKeyStore.loadSenderKey(self.senderKeyId)
            senderKeyMessage = SenderKeyMessage(serialized = bytes(senderKeyMessageBytes))
            senderKeyState   = record.getSenderKeyState(senderKeyMessage.getKeyId())

            senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic())

            senderKey = self.getSenderKey(senderKeyState, senderKeyMessage.getIteration())

            plaintext = self.getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText())

            self.senderKeyStore.storeSenderKey(self.senderKeyId, record)

            return plaintext
        except (InvalidKeyException, InvalidKeyIdException) as e:
            raise InvalidMessageException(e)


    def getSenderKey(self, senderKeyState, iteration):
        senderChainKey = senderKeyState.getSenderChainKey()

        if senderChainKey.getIteration() > iteration:
            if senderKeyState.hasSenderMessageKey(iteration):
                return senderKeyState.removeSenderMessageKey(iteration)
            else:
                raise DuplicateMessageException("Received message with old counter: %s, %s" %
                                                (senderChainKey.getIteration(), iteration))

        if senderChainKey.getIteration() - iteration > 2000:
            raise InvalidMessageException("Over 2000 messages into the future!")

        while senderChainKey.getIteration() < iteration:
            senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey())
            senderChainKey = senderChainKey.getNext()

        senderKeyState.setSenderChainKey(senderChainKey.getNext())
        return senderChainKey.getSenderMessageKey()


    def getPlainText(self, iv, key, ciphertext):
        """
        :type iv: bytearray
        :type key: bytearray
        :type ciphertext: bytearray
        """
        try:
            cipher = AESCipher(key, iv)
            plaintext = cipher.decrypt(ciphertext)
            if sys.version_info >= (3,0):
                return plaintext.decode()
            return plaintext
        except Exception as e:
            raise InvalidMessageException(e)

    def getCipherText(self, iv, key, plaintext):
        """
        :type iv: bytearray
        :type key: bytearray
        :type plaintext: bytearray
        """
        cipher = AESCipher(key, iv)
        return cipher.encrypt(bytes(plaintext))
