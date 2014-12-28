import struct
from .ec import ECPublicKey, ECPrivateKey
from ..util.byteutil import ByteUtil
from axolotl.ecc import curve
import sys
import binascii
class DjbECPublicKey(ECPublicKey):

    def __init__(self, publicKey):
        self.publicKey = publicKey

    def serialize(self):
        combined = ByteUtil.combine([curve.Curve.DJB_TYPE], self.publicKey)
        return bytes(combined)

    def getType(self):
        return curve.Curve.DJB_TYPE

    def getPublicKey(self):
        return self.publicKey

    def __eq__(self, other):
        return self.publicKey == other.getPublicKey()

    def __lt__(self, other):
        myVal = int(binascii.hexlify(self.publicKey), 16)
        otherVal = int(binascii.hexlify(other.getPublicKey()), 16)

        return myVal < otherVal

    def __cmp__(self, other):
        myVal = int(binascii.hexlify(self.publicKey), 16)
        otherVal = int(binascii.hexlify(other.getPublicKey()), 16)

        if myVal < otherVal:
            return -1
        elif myVal == otherVal:
            return 0
        else:
            return 1

class DjbECPrivateKey(ECPrivateKey):

    def __init__(self, privateKey):
        self.privateKey = privateKey

    def getType(self):
        return curve.Curve.DJB_TYPE

    def getPrivateKey(self):
        return self.privateKey

    def serialize(self):
        return self.privateKey

    def __eq__(self, other):
        return self.privateKey == other.getPrivateKey()
