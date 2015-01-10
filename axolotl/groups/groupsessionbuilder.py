from axolotl.protocol.senderkeydistributionmessage import SenderKeyDistributionMessage
class GroupSessionBuilder:
    def __init__(self, senderKeyStore):
        self.senderKeyStore = senderKeyStore

    def processSender(self, sender, senderKeyDistributionMessage):
        """
        :type sender: str
        :type senderKeyDistributionMessage: SenderKeyDistributionMessage
        """
        senderKeyRecord = self.senderKeyStore.loadSenderKey(sender)
        senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getId(),
                                        senderKeyDistributionMessage.getIteration(),
                                        senderKeyDistributionMessage.getChainKey(),
                                        senderKeyDistributionMessage.getSignatureKey())
        self.senderKeyStore.storeSenderKey(sender, senderKeyRecord)


    def process(self, groupId, keyId, iteration, chainKey, signatureKey):
        """
        :type groupId: str
        :type keyId: int
        :type iteration: int
        :type chainKey: bytearray
        :type signatureKey: ECKeyPair
        """
        senderKeyRecord = self.senderKeyStore.loadSenderKey(groupId)
        senderKeyRecord.setSenderKeyState(keyId, iteration, chainKey, signatureKey)
        self.senderKeyStore.storeSenderKey(groupId, senderKeyRecord)

        return SenderKeyDistributionMessage(keyId, iteration, chainKey, signatureKey.getPublicKey())
