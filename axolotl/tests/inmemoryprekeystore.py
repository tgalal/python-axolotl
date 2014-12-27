from axolotl.state.prekeystore import PreKeyStore
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException
class InMemoryPreKeyStore(PreKeyStore):
    def __init__(self):
        self.store = {}

    def loadPreKey(self, preKeyId):
        if preKeyId not in self.store:
            raise InvalidKeyIdException("No such prekeyRecord!")

        return PreKeyRecord(serialized = self.store[preKeyId])

    def storePreKey(self, preKeyId, preKeyRecord):
        self.store[preKeyId] = preKeyRecord.serialize()

    def containsPreKey(self, preKeyId):
        return preKeyId in self.store

    def removePreKey(self, preKeyId):
        if preKeyId in self.store:
            del self.store[preKeyId]