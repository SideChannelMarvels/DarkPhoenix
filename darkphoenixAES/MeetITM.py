#!/usr/bin/env sage

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

import sys
import json
from .AES import _AesInvSBox, _AesSBox
from .MultTable import MultTable, InvTable
from .Exception import UnexpectedFailure, InvalidArgument

class MeetITM:

    def __init__(self):
        self.coefEnc = [
            [
                None,
                MultTable[2],
                MultTable[2],
                MultTable[MultTable[2][InvTable[3]]],
            ], [
                None,
                MultTable[MultTable[3][InvTable[2]]],
                MultTable[3],
                MultTable[3],
            ], [
                None,
                MultTable[InvTable[3]],
                MultTable[InvTable[2]],
                MultTable[1],
            ], [
                None,
                MultTable[1],
                MultTable[InvTable[3]],
                MultTable[InvTable[2]],
            ]
        ]
        self.coefDec = [
            [
                None,
                MultTable[MultTable[14][InvTable[9]]],  # p14 * (p9 ** -1))
                MultTable[MultTable[14][InvTable[13]]], # p14 * (p13 ** -1))
                MultTable[MultTable[14][InvTable[11]]], # p14 * (p11 ** -1))
            ], [
                None,
                MultTable[MultTable[11][InvTable[14]]],
                MultTable[MultTable[11][InvTable[9]]],
                MultTable[MultTable[11][InvTable[13]]],
            ], [
                None,
                MultTable[MultTable[13][InvTable[11]]],
                MultTable[MultTable[13][InvTable[14]]],
                MultTable[MultTable[13][InvTable[9]]],
            ], [
                None,
                MultTable[MultTable[9][InvTable[13]]],
                MultTable[MultTable[9][InvTable[11]]],
                MultTable[MultTable[9][InvTable[14]]],
            ]
        ]

    def reset_local_var(self, col, fault, midalpha, encrypt, fpos, limitedLambda):
        self.Rtable = {}
        self.Rtable2_inv = {}
        self.Lcoef = self.coefEnc[fpos] if encrypt else self.coefDec[fpos]
        self.Sb = _AesInvSBox if encrypt else _AesSBox
        if limitedLambda is None:
            self.limitedLambda0 = list(range(1, 256))
            self.limitedLambda1 = list(range(1, 256))
            self.limitedLambda2 = list(range(1, 256))
            self.limitedLambda3 = list(range(1, 256))
        else:
            UnexpectedFailure.check( len(limitedLambda) == 4,
                f"Expect an array of 4 elements, get {len(limitedLambda)} elements")
            UnexpectedFailure.check( 0 not in limitedLambda,
                f"0 isn't a valid lambda value")
            if encrypt:
                self.limitedLambda0 = [limitedLambda[((4 - col) % 4)]]
                self.limitedLambda1 = [limitedLambda[((4 + 1 - col) % 4)]]
                self.limitedLambda2 = [limitedLambda[((4 + 2 - col) % 4)]]
                self.limitedLambda3 = [limitedLambda[((4 + 3 - col) % 4)]]
            else:
                self.limitedLambda0 = [limitedLambda[((col) % 4)]]
                self.limitedLambda1 = [limitedLambda[((col + 1) % 4)]]
                self.limitedLambda2 = [limitedLambda[((col + 2) % 4)]]
                self.limitedLambda3 = [limitedLambda[((col + 3) % 4)]]

        InvalidArgument.check( 1 < midalpha and midalpha + 1 < len(fault),
            f"Invalid value of midalpha ({midalpha}), expect a value between 2 and {len(fault)}")

        self.fault0 = fault[:midalpha+1]

        self.fault1 = fault[0:1] + fault[midalpha+1:]

    def computeR(self):

        for Rlambda in self.limitedLambda0:
            for beta in range(256):

                RHash = []
                v0 = self.Sb[MultTable[Rlambda][self.fault0[0][0]] ^ beta]

                for x in self.fault0[1:]:
                    RHash.append( v0 ^ self.Sb[MultTable[Rlambda][x[0]] ^ beta] )
                RintHash = int.from_bytes(RHash, 'little')

                # Not sure if a collision is possible
                if RintHash in self.Rtable.keys():
                    self.Rtable[RintHash].append((Rlambda, beta))
                else:
                    self.Rtable[RintHash] = [(Rlambda, beta)]

    def computeR2(self, Rlambda, Rbeta):
        if (Rlambda, Rbeta) in self.Rtable2_inv:
            return self.Rtable2_inv[(Rlambda, Rbeta)]

        RHash = []
        v0 = self.Sb[MultTable[Rlambda][self.fault1[0][0]] ^ Rbeta]

        for x in self.fault1[1:]:
            RHash.append( v0 ^ self.Sb[MultTable[Rlambda][x[0]] ^ Rbeta] )
        RintHash = int.from_bytes(RHash, 'little')

        self.Rtable2_inv[(Rlambda, Rbeta)] = RintHash
        return RintHash

    def computeL(self, row):
        solutions = []

        limitedLambdaN = {1: self.limitedLambda1, 2: self.limitedLambda2, 3: self.limitedLambda3}[row]
        Lncoef = self.Lcoef[row]

        for Llambda in limitedLambdaN:
            for Lbeta in range(256):
                v0 = self.Sb[MultTable[Llambda][self.fault0[0][row]] ^ Lbeta]

                LHash = []
                for x in self.fault0[1:]:
                    LHash.append( Lncoef[v0 ^ self.Sb[MultTable[Llambda][x[row]] ^ Lbeta]] )
                LintHash = int.from_bytes(LHash, 'little')

                if LintHash not in self.Rtable.keys():
                    continue

                LHash2 = []
                for x in self.fault1[1:]:
                    LHash2.append( Lncoef[v0 ^ self.Sb[MultTable[Llambda][x[row]] ^ Lbeta]] )
                LintHash2 = int.from_bytes(LHash2, 'little')

                for Rlambda, Rbeta in self.Rtable[LintHash]:
                    RintHash2 = self.computeR2(Rlambda, Rbeta)
                    if RintHash2 == LintHash2:
                        solutions.append((Rlambda, Rbeta, Llambda, Lbeta))

        return solutions

    def resolv(self, col, fault, midalpha, encrypt, fpos, limitedLambda=None):

        self.reset_local_var(col, fault, midalpha, encrypt, fpos, limitedLambda)
        self.computeR()

        sol1 = self.computeL(1)
        if len(sol1) != 1:
            return False, [], []

        sol2 = self.computeL(2)
        if len(sol2) != 1:
            return False, [], []

        sol3 = self.computeL(3)
        if len(sol3) != 1:
            return False, [], []

        Rlambda1, Rbeta1, Llambda1, Lbeta1 = sol1[0]
        Rlambda2, Rbeta2, Llambda2, Lbeta2 = sol2[0]
        Rlambda3, Rbeta3, Llambda3, Lbeta3 = sol3[0]

        if Rlambda1 != Rlambda2 or Rlambda1 != Rlambda3 or Rbeta1 != Rbeta2 or Rbeta1 != Rbeta3:
            return False, [], []

        return True, [Rlambda1, Llambda1, Llambda2, Llambda3], [Rbeta1, Lbeta1, Lbeta2, Lbeta3]

    def __call__(self, col, fault, midalpha, encrypt, limitedLambda=None):
        for fpos in range(4):
            res = self.resolv(col, fault, midalpha, encrypt, fpos, limitedLambda)
            if res[0]:
                break
        return res



