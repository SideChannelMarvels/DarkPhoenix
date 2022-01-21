#!/usr/bin/env python3

# -----------------------------------------------------------------------------
# Copyright (C) Quarkslab. See README.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the Apache License as published by
# the Apache Software Foundation, either version 2.0 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.txt for the text of the Apache license.
# -----------------------------------------------------------------------------

from ..WhiteBoxedAES import WhiteBoxedAES
from .AESEncoded import AESEncoded
import random

class WhiteBoxedAESTest(WhiteBoxedAES):

    def __init__(self, aesEncoded, enc=True, useReverse=True, fast=True):
        self.aesEncoded = aesEncoded
        self.enc = enc
        self.useReverse = useReverse
        self.fast = fast

    def getRoundNumber(self):
        return self.aesEncoded.getRoundNumber()

    def isEncrypt(self):
        return self.enc

    def hasReverse(self):
        return self.useReverse

    def apply(self, data):
        if self.fast:
            if self.enc:
                return self.aesEncoded.encrypt_encode_fast(data)
            else:
                return self.aesEncoded.decrypt_encode_fast(data)
        else:
            if self.enc:
                return self.aesEncoded.encrypt_encode(data)
            else:
                return self.aesEncoded.decrypt_encode(data)

    def applyReverse(self, data):
        if self.useReverse:
            if self.fast:
                if self.enc:
                    return self.aesEncoded.decrypt_encode_fast(data)
                else:
                    return self.aesEncoded.encrypt_encode_fast(data)
            else:
                if self.enc:
                    return self.aesEncoded.decrypt_encode(data)
                else:
                    return self.aesEncoded.encrypt_encode(data)
        else:
            raise NotImplementedError("applyReverse must not be used if hasReverse returns False")

    def applyRound(self, data, roundN):
        if self.fast:
            raise NotImplementedError("applyRound must not be used if fast mode is used")
        if self.enc:
            return self.aesEncoded.encrypt_round_encode(data, roundN)
        else:
            return self.aesEncoded.decrypt_round_encode(data,
                    self.aesEncoded.getRoundNumber() - 1 - roundN)

    def applyFault(self, data, faults):

        if self.fast:
            if self.enc:
                return self._applyFault_fast_enc(data, faults)
            else:
                return self._applyFault_fast_dec(data, faults)
        else:
            return super().applyFault(data, faults)

    def _applyFault_fast_enc(self, data, faults):

        state = self.aesEncoded.encoding[0].decode(data)

        faultsRound = set([fround for fround, _, _ in faults])

        for roundN in range(self.getRoundNumber()):
            if roundN in faultsRound:
                state = self.aesEncoded.encoding[roundN].encode(state)
                state = list(state)

                for fround, fbytes, fxorval in faults:
                    if fround != roundN:
                        continue
                    assert 0 <= fbytes and fbytes <= 15, "Invalid fbytes value"
                    assert 1 <= fxorval and fxorval <= 255, "Invalid fxorval value"
                    position = fbytes
                    if roundN != 0:
                        position = self.aesEncoded.roundPerm[roundN-1][fbytes]
                    state[position] ^= fxorval

                state = self.aesEncoded.encoding[roundN].decode(bytes(state))

            state = self.aesEncoded.encrypt_round(bytes(state), roundN)

        state = self.aesEncoded.encoding[self.getRoundNumber()].encode(state)

        return bytes(state)

    def _applyFault_fast_dec(self, data, faults):

        state = self.aesEncoded.encoding[self.getRoundNumber()].decode(data)

        faultsRound = set([fround for fround, _, _ in faults])

        for roundN in range(self.getRoundNumber()):
            AESroundN = self.getRoundNumber() -1 - roundN

            if roundN in faultsRound:
                state = self.aesEncoded.encoding[AESroundN+1].encode(state)
                state = list(state)

                for fround, fbytes, fxorval in faults:
                    if fround != roundN:
                        continue
                    assert 0 <= fbytes and fbytes <= 15, "Invalid fbytes value"
                    assert 1 <= fxorval and fxorval <= 255, "Invalid fxorval value"
                    position = fbytes
                    if AESroundN + 1 != self.getRoundNumber():
                        position = self.aesEncoded.reverseRoundPerm[AESroundN][fbytes]
                    state[position] ^= fxorval

                state = self.aesEncoded.encoding[AESroundN+1].decode(bytes(state))

            state = self.aesEncoded.decrypt_round(bytes(state), AESroundN)

        state = self.aesEncoded.encoding[0].encode(state)

        return bytes(state)

# run with `python3 -m darkphoenixAES.test.WhiteBoxedAESTest`

def test():
    # test fast AES
    for i in range(16):
        for keylen in [16, 24, 32]:
            key = random.randbytes(keylen)
            aesEncoding = AESEncoded(key)

            wbEncFast = WhiteBoxedAESTest(aesEncoding, enc=True, fast=True)
            wbEncSlow = WhiteBoxedAESTest(aesEncoding, enc=True, fast=False)
            wbDecFast = WhiteBoxedAESTest(aesEncoding, enc=False, fast=True)
            wbDecSlow = WhiteBoxedAESTest(aesEncoding, enc=False, fast=False)

            for roundN in range(aesEncoding.roundNumber):
                f = [(roundN, random.randrange(16), random.randrange(1, 256))]
                data = random.randbytes(16)

                assert wbEncFast.applyFault(data, f) == wbEncSlow.applyFault(data, f)
                assert wbDecFast.applyFault(data, f) == wbDecSlow.applyFault(data, f)

    print("test OK")

if __name__ == "__main__":
    test()
