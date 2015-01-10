from .ciphertextmessage import CiphertextMessage
from . import whisperprotos
class SenderKeyDistributionMessage(CiphertextMessage):
    def __init__(self, id, iteration, chainKey, signatureKey):
        """
        :type id: int
        :type iteration: int
        :type chainKey: bytearray
        :type signatureKey: ECPublicKey
        """

        self.id = id
        self.iteration = iteration
        self.chainKey = chainKey
        self.signatureKey = signatureKey
        self.serialized = whisperprotos.SenderKeyDistributionMessage()
        self.serialized.id = id
        self.serialized.iteration = iteration
        self.serialized.chainKey= chainKey
        self.serialized.signingKey = signatureKey.serialize()

    def serialize(self):
        return self.serialized

    def getType(self):
        return self.__class__.SENDERKEY_DISTRIBUTION_TYPE

    def getIteration(self):
        return self.iteration

    def getChainKey(self):
        return self.chainKey

    def getSignatureKey(self):
        return self.signatureKey

    def getId(self):
        return self.id
