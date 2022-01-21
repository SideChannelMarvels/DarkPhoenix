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

# run with 'python3 -m darkphoenixAES.test.test_AES'

import random
from ..AES import AES, RoundType, expandKey, revertKey

def test_AES():
    # test case : https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
    test_cases = [
        ( "2b7e151628aed2a6abf7158809cf4f3c", 10,
          "6bc1bee22e409f96e93d7e117393172a",
          "3ad77bb40d7a3660a89ecaf32466ef97"),
        ( "2b7e151628aed2a6abf7158809cf4f3c", 10,
          "ae2d8a571e03ac9c9eb76fac45af8e51",
          "f5d3d58503b9699de785895a96fdbaaf"),
        ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 12,
          "6bc1bee22e409f96e93d7e117393172a",
          "bd334f1d6e45f25ff712a214571fa5cc"),
        ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 12,
          "ae2d8a571e03ac9c9eb76fac45af8e51",
          "974104846d0ad3ad7734ecb3ecee4eef"),
        ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 14,
          "6bc1bee22e409f96e93d7e117393172a",
          "f3eed1bdb5d2a03c064b5a7e3db181f8"),
        ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 14,
          "ae2d8a571e03ac9c9eb76fac45af8e51",
          "591ccb10d410ed26dc5ba74a31362870"),
    ]

    for roundType in RoundType:
        for key, r, plain, cipher in test_cases:
            c = AES(bytes.fromhex(key), r, roundType=roundType)
            assert c.encrypt(bytes.fromhex(plain)) == bytes.fromhex(cipher)
            assert c.decrypt(bytes.fromhex(cipher)) == bytes.fromhex(plain)

            for i in range(r):
                assert c.decrypt_round(c.encrypt_round(bytes.fromhex(plain), i), i) == bytes.fromhex(plain)

    for l in [16, 24, 32]:
        for _ in range(16):
            key = random.randbytes(l)
            keySched = expandKey(key, 10)
            rKey = (keySched[9] + keySched[10])[:l]
            assert revertKey(rKey, 9) == key
    print("[OK] AES")


if __name__ == "__main__":
    test_AES()
