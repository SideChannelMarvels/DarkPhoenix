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

# run with 'python3 -m darkphoenixAES.test.test_Encoding'

from ..Encoding import Encoding8Random, EncodingGenerator, EncodeType
import random

def test_Encoding():
    for _ in range(32):
        obj = Encoding8Random()
        enc = obj.getEncodeTable()
        dec = obj.getDecodeTable()
        for i in range(256):
            assert dec[enc[i]] == i, "Encoding8Random encodage error"
    print("[OK] Encoding8Random")

    for _ in range(32):
        obj1 = Encoding8Random()
        obj2 = Encoding8Random()
        obj12 = obj1.combine(obj2)
        assert obj1.encode(obj2.encode(list(range(256)))) == obj12.encode(list(range(256)))
    print("[OK] Encoding8 combine")

    for _ in range(32):
        obj1 = EncodingGenerator(16, EncodeType.RANDOM)
        obj2 = EncodingGenerator(16, EncodeType.RANDOM)
        obj12 = obj1.combine(obj2)
        for _ in range(32):
            data = random.randbytes(16)
            assert obj1.encode(obj2.encode(data)) == obj12.encode(data)
    print("[OK] Encoding combine")

if __name__ == '__main__':
    test_Encoding()
