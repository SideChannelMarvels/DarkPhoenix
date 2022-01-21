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

# run with 'python3 -m darkphoenixAES.test.test_Attack'

from ..Attack import Attack
from ..Exception import InvalidArgument, UnexpectedFailure, FaultPositionError, DarkPhoenixException
from .AESEncoded import AESEncoded
from .WhiteBoxedAESTest import WhiteBoxedAESTest
from .WhiteBoxedAESAutoTest import WhiteBoxedAESAutoTest
import argparse
import os

def test_Attack_core(key=None, encode=True, reverse=True, nprocess=None, doubleValue=False,
         beginFile=None, backupFile=None, seed=None, dynamic=False,
         print_encoding=False):

    if key is None:
        key_len = 32
        key = bytes(list(range(key_len)))
    else:
        key = bytes.fromhex(key)
        key_len = len(key)
        InvalidArgument.check( key_len in [16, 24, 32],
            f"the len of the key ({keyLen}) must be equal to 16, 24 or 32")

    aesEncoded = AESEncoded(key, encodingSeed=seed)

    if dynamic:
        wb = WhiteBoxedAESAutoTest(aesEncoded, enc=encode, useReverse=reverse,
                                   multiFault=(dynamic>1))
    else:
        wb = WhiteBoxedAESTest(aesEncoded, enc=encode, useReverse=reverse)

    a = Attack(wb, nprocess=nprocess, step1DoubleValue=doubleValue)

    if beginFile is not None:
        a.restore(beginFile)
        if backupFile is not None:
            a.save(backupFile)
    if backupFile is not None and not os.path.isfile(backupFile):
        a.save(backupFile)

    finish = False
    if dynamic:
        a.runAuto(backupFile=backupFile)
    else:
        a.run(backupFile=backupFile)

    a.printKey()
    foundKey = a.getKey()
    print("key:", foundKey.hex())

    UnexpectedFailure.check(key == foundKey,
        "Didn't find the good Key")

    if print_encoding:
        inputEncoding, outputEncoding = a.externalEncoding()
        print(f"inputEncoding: {inputEncoding.toTable()}")
        print(f"outputEncoding: {outputEncoding.toTable()}")

def test_Attack():

    parser = argparse.ArgumentParser()

    parser.add_argument("-k", "--key", type=str, default=None)
    parser.add_argument("-e", "--encode", action='store_true')
    parser.add_argument("-d", "--decode", dest="encode", action='store_false')
    parser.set_defaults(encode=True)
    parser.add_argument("-r", "--reverse", action='store_true')
    parser.add_argument("--no-reverse", dest="reverse", action='store_false')
    parser.set_defaults(reverse=True)
    parser.add_argument("--doubleValue", action='store_true')
    parser.add_argument("--singleValue", dest="doubleValue", action='store_false')
    parser.set_defaults(doubleValue=False)
    parser.add_argument("--dynamic", action='store_const', const=1)
    parser.add_argument("--dynamic2", dest="dynamic", action='store_const', const=2)
    parser.add_argument("--static", dest="dynamic", action='store_false')
    parser.set_defaults(dynamic=False)
    parser.add_argument("-p", "--process", type=int, default=None)
    parser.add_argument("-s", "--seed", type=int, default=None)
    parser.add_argument("--beginFile", type=str, default=None)
    parser.add_argument("--backupFile", type=str, default=None)

    parser.add_argument("--print-encoding", action='store_true')
    parser.add_argument("--no-print-encoding", dest="print-encoding", action='store_false')
    parser.set_defaults(print_encoding=False)

    args = parser.parse_args()

    test_Attack_core(key=args.key, encode=args.encode, reverse=args.reverse, nprocess=args.process,
         doubleValue=args.doubleValue, beginFile=args.beginFile, backupFile=args.backupFile,
         seed=args.seed, dynamic=args.dynamic, print_encoding=args.print_encoding)

if __name__ == "__main__":
    test_Attack()
