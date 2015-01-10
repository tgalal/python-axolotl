import unittest
from axolotl.tests.groups.inmemorysenderkeystore import InMemorySenderKeyStore
from axolotl.groups.groupsessionbuilder import GroupSessionBuilder
from axolotl.util.keyhelper import KeyHelper
from axolotl.groups.groupcipher import GroupCipher
from axolotl.duplicatemessagexception import DuplicateMessageException
from axolotl.nosessionexception import NoSessionException

class GroupCipherTest(unittest.TestCase):
    def test_basicEncryptDecrypt(self):
        aliceStore = InMemorySenderKeyStore()
        bobStore   =  InMemorySenderKeyStore()

        aliceSessionBuilder = GroupSessionBuilder(aliceStore)
        bobSessionBuilder   = GroupSessionBuilder(bobStore)


        aliceGroupCipher =  GroupCipher(aliceStore, "groupWithBobInIt")
        bobGroupCipher   = GroupCipher(bobStore, "groupWithBobInIt::aliceUserName")

        aliceSenderKey        = KeyHelper.generateSenderKey()
        aliceSenderSigningKey = KeyHelper.generateSenderSigningKey()
        aliceSenderKeyId      = KeyHelper.generateSenderKeyId()

        aliceDistributionMessage = aliceSessionBuilder.process("groupWithBobInIt", aliceSenderKeyId, 0,
                                aliceSenderKey, aliceSenderSigningKey)

        bobSessionBuilder.processSender("groupWithBobInIt::aliceUserName", aliceDistributionMessage)

        ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert")
        plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice)

        self.assertEqual(plaintextFromAlice, "smert ze smert")

    def test_basicRatchet(self):
        aliceStore = InMemorySenderKeyStore()
        bobStore   = InMemorySenderKeyStore()

        aliceSessionBuilder = GroupSessionBuilder(aliceStore)
        bobSessionBuilder   = GroupSessionBuilder(bobStore)

        aliceGroupCipher = GroupCipher(aliceStore, "groupWithBobInIt")
        bobGroupCipher   = GroupCipher(bobStore, "groupWithBobInIt::aliceUserName")

        aliceSenderKey        = KeyHelper.generateSenderKey()
        aliceSenderSigningKey = KeyHelper.generateSenderSigningKey()
        aliceSenderKeyId      = KeyHelper.generateSenderKeyId()

        aliceDistributionMessage = aliceSessionBuilder.process("groupWithBobInIt", aliceSenderKeyId, 0,
                                    aliceSenderKey, aliceSenderSigningKey)

        bobSessionBuilder.processSender("groupWithBobInIt::aliceUserName", aliceDistributionMessage)

        ciphertextFromAlice  = aliceGroupCipher.encrypt("smert ze smert")
        ciphertextFromAlice2 = aliceGroupCipher.encrypt("smert ze smert2")
        ciphertextFromAlice3 = aliceGroupCipher.encrypt("smert ze smert3")

        plaintextFromAlice   = bobGroupCipher.decrypt(ciphertextFromAlice)

        try:
            bobGroupCipher.decrypt(ciphertextFromAlice)
            raise AssertionError("Should have ratcheted forward!")
        except DuplicateMessageException as dme:
            # good
            pass

        plaintextFromAlice2  = bobGroupCipher.decrypt(ciphertextFromAlice2)
        plaintextFromAlice3  = bobGroupCipher.decrypt(ciphertextFromAlice3)

        self.assertEqual(plaintextFromAlice,"smert ze smert")
        self.assertEqual(plaintextFromAlice2, "smert ze smert2")
        self.assertEqual(plaintextFromAlice3, "smert ze smert3")


    def test_outOfOrder(self):

        aliceStore = InMemorySenderKeyStore()
        bobStore   = InMemorySenderKeyStore()

        aliceSessionBuilder = GroupSessionBuilder(aliceStore)
        bobSessionBuilder   = GroupSessionBuilder(bobStore)

        aliceGroupCipher = GroupCipher(aliceStore, "groupWithBobInIt")
        bobGroupCipher   = GroupCipher(bobStore, "groupWithBobInIt::aliceUserName")

        aliceSenderKey        = KeyHelper.generateSenderKey()
        aliceSenderSigningKey = KeyHelper.generateSenderSigningKey()
        aliceSenderKeyId      = KeyHelper.generateSenderKeyId()

        aliceDistributionMessage = aliceSessionBuilder.process("groupWithBobInIt", aliceSenderKeyId, 0,
                                    aliceSenderKey, aliceSenderSigningKey)

        bobSessionBuilder.processSender("groupWithBobInIt::aliceUserName", aliceDistributionMessage)

        ciphertexts = []
        for i in range(0, 100):
            ciphertexts.append(aliceGroupCipher.encrypt("up the punks"))
        while len(ciphertexts) > 0:
            index = KeyHelper.getRandomSequence(2147483647) % len(ciphertexts)
            ciphertext = ciphertexts.pop(index)
            plaintext = bobGroupCipher.decrypt(ciphertext)
            self.assertEqual(plaintext, "up the punks")

    def test_encryptNoSession(self):

        aliceStore = InMemorySenderKeyStore()
        aliceGroupCipher = GroupCipher(aliceStore, "groupWithBobInIt")
        try:
            aliceGroupCipher.encrypt("up the punks")
            raise AssertionError("Should have failed!")
        except NoSessionException as nse:
            # good
            pass
