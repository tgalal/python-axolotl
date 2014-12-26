from axolotl.state.identitykeystore import IdentityKeyStore
from axolotl.ecc.curve import Curve
from axolotl.identitykey import IdentityKey
from axolotl.util.keyhelper import KeyHelper
from axolotl.identitykeypair import IdentityKeyPair

class LiteIdentityKeyStore(IdentityKeyStore):
    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        dbConn.execute("CREATE TABLE IF NOT EXISTS identities (_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "recipient_id INTEGER UNIQUE,"
                       "registration_id INTEGER, public_key BLOB, private_key BLOB,"
                       "next_prekey_id INTEGER, timestamp INTEGER);")

        identityKeyPairKeys = Curve.generateKeyPair()
        self.identityKeyPair = IdentityKeyPair(IdentityKey(identityKeyPairKeys.getPublicKey()),
                                               identityKeyPairKeys.getPrivateKey())
        self.localRegistrationId = KeyHelper.generateRegistrationId()

    def getIdentityKeyPair(self):
        return self.identityKeyPair

    def getLocalRegistrationId(self):
        return self.localRegistrationId

    def saveIdentity(self, recipientId, identityKey):
        q = "DELETE FROM identities WHERE recipient_id=?"
        self.dbConn.cursor().execute(q, (recipientId,))
        self.dbConn.commit()


        q = "INSERT INTO identities (recipient_id, public_key) VALUES(?, ?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, identityKey.getPublicKey().serialize()))
        self.dbConn.commit()

    def isTrustedIdentity(self, recipientId, identityKey):
        q = "SELECT public_key from identities WHERE recipient_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (identityKey.getPublicKey().serialize(),))
        result = c.fetchone()
        if not result:
            return True
        return result[0] == identityKey.getPublicKey().serialize()