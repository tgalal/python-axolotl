# -*- coding: utf-8 -*-

import codecs

decode_hex = codecs.getdecoder("hex_codec")


class HexUtil:
    @staticmethod
    def decodeHex(hexString):
        result = decode_hex(hexString)[0]
        return result
