from axolotl.groups.state.senderkeystore import SenderKeyStore
from axolotl.groups.state.senderkeyrecord import SenderKeyRecord
class InMemorySenderKeyStore(SenderKeyStore):
    def __init__(self):
        self.store = {}

    def storeSenderKey(self, senderKeyId, senderKeyRecord):
        self.store[senderKeyId] = senderKeyRecord

    def loadSenderKey(self, senderKeyId):
        if senderKeyId in self.store:
            return SenderKeyRecord(serialized=self.store[senderKeyId].serialize())

        return SenderKeyRecord()
