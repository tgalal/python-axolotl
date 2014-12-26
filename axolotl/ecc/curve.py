import axolotl_curve25519 as _curve
import os

from .djbec import DjbECPrivateKey, DjbECPublicKey
from .eckeypair import ECKeyPair


class Curve:

    DJB_TYPE = 5
    # always DJB curve25519 keys

    @staticmethod
    def generatePrivateKey():
        rand = os.urandom(32)
        return _curve.generatePrivateKey(rand)

    @staticmethod
    def generatePublicKey(privateKey):
        return _curve.generatePublicKey(privateKey)

    @staticmethod
    def generateKeyPair():
        privateKey = Curve.generatePrivateKey()
        publicKey = Curve.generatePublicKey(privateKey)
        return ECKeyPair(DjbECPublicKey(publicKey), DjbECPrivateKey(privateKey))

    @staticmethod
    def decodePoint(bytes, offset=0):
        type = bytes[0] # byte appears to be automatically converted to an integer??

        if type == Curve.DJB_TYPE:
            type = bytes[offset] & 0xFF
            if type != Curve.DJB_TYPE:
                raise Exception("InvalidKeyException Unknown key type: " + str(type) )
            keyBytes = bytes[offset+1:][:32]
            return DjbECPublicKey(str(keyBytes))
        else:
            raise Exception("InvalidKeyException Unknown key type: " + str(type) )

    @staticmethod
    def decodePrivatePoint(bytes):
        return DjbECPrivateKey(str(bytes))


    @staticmethod
    def calculateAgreement(publicKey, privateKey):
        return _curve.calculateAgreement(privateKey.getPrivateKey(), publicKey.getPublicKey())

    @staticmethod
    def verifySignature(ecPublicSigningKey, message, signature):
        result = _curve.verifySignature(ecPublicSigningKey.getPublicKey(), message, signature)
        return result == 0

    @staticmethod
    def calculateSignature(privateSigningKey ,message):
        rand = os.urandom(64)
        res = _curve.calculateSignature(rand, privateSigningKey.getPrivateKey(), message)
        return res
