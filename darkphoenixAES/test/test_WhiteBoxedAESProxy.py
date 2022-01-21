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

# run with 'python3 -m darkphoenixAES.test.test_WhiteBoxedAESProxy'

from .WhiteBoxedAESTest import WhiteBoxedAESTest
from .AESEncoded import AESEncoded
from ..WhiteBoxedAESProxy import WhiteBoxedAESProxy
import random

def test_WhiteBoxedAESProxy():
    for _ in range(16):
        key = random.randbytes(16)
        aesEncoded = AESEncoded(key)

        WhiteBoxedAESProxy(WhiteBoxedAESTest(aesEncoded, enc=True), None).selfTest()
        WhiteBoxedAESProxy(WhiteBoxedAESTest(aesEncoded, enc=False), None).selfTest()
    print("[OK] WhiteBoxedAESProxy")

if __name__ == "__main__":
    test_WhiteBoxedAESProxy()

