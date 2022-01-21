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

from sage.all_cmdline import *   # import sage library

def bytesToBinaryRep(value):
    return [((value >> x) & 1) for x in range(8)]

def binaryToBytesRep(value):
    return sum([int(x) << index for index, x in enumerate(value)])

class ResolverStep3:

    def __init__(self):

        K = GF(2)['u']
        u = K._first_ngens(1)[0]

        T = K.quotient(u**8 + u**4 + u**3 + u + 1, names=('w',))

        P = PolynomialRing(GF(2), names=('x',));
        x = P._first_ngens(1)[0]
        p = x**8 + x**4 + x**3 + x + 1
        self.F = GF(2).extension(p, names=('w',))

        self.M = MatrixSpace(GF(2), 8)
        M_2 = self.M.matrix([
            ( T(bytesToBinaryRep(2)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])
        M_3 = self.M.matrix([
            ( T(bytesToBinaryRep(3)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])
        M_9 = self.M.matrix([
            ( T(bytesToBinaryRep(9)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])
        M_11 = self.M.matrix([
            ( T(bytesToBinaryRep(11)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])
        M_13 = self.M.matrix([
            ( T(bytesToBinaryRep(13)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])
        M_14 = self.M.matrix([
            ( T(bytesToBinaryRep(14)) * T(bytesToBinaryRep(1<<i)) ).list()
                for i in range(8)])

        # all possible lambda for (i, j) in [(0, 1), (1, 0), (2, 3), (3, 2)]
        self.MEnc = {
            '2' : M_2,
            '2*3' : M_2*M_3,
            '2*3^(-1)' : M_2*(M_3**(-1)),
            '2*3^(-2)' : M_2*(M_3**(-2)),
            '2^(-1)' : (M_2**(-1)),
            '2^(-1)*3' : (M_2**(-1))*M_3,
            '2^(-1)*3^(-1)' : (M_2**(-1))*(M_3**(-1)),
            '2^(-1)*3^(2)' : (M_2**(-1))*(M_3**(2)),
            '2^(-2)*3' : (M_2**(-2))*M_3,
            '2^(2)*3^(-1)' : (M_2**(2))*(M_3**(-1)),
            '3' : M_3,
            '3^(-1)' : (M_3**(-1)),
        }
        self.MDec = {
            '9*11*13^(-2)' : M_9*M_11*(M_13**(-2)),
            '9*11*14^(-2)' : M_9*M_11*(M_14**(-2)),
            '9*11^(-1)*13*14^(-1)' : M_9*(M_11**(-1))*M_13*(M_14**(-1)),
            '9*11^(-1)*13^(-1)*14' : M_9*(M_11**(-1))*(M_13**(-1))*M_14,
            '9^(-1)*11*13*14^(-1)' : (M_9**(-1))*M_11*M_13*(M_14**(-1)),
            '9^(-1)*11*13^(-1)*14' : (M_9**(-1))*M_11*(M_13**(-1))*M_14,
            '9^(-1)*11^(-1)*13^(2)' : (M_9**(-1))*(M_11**(-1))*(M_13**(2)),
            '9^(-1)*11^(-1)*14^(2)' : (M_9**(-1))*(M_11**(-1))*(M_14**(2)),
            '9^(-2)*13*14' : (M_9**(-2))*M_13*M_14,
            '9^(2)*13^(-1)*14^(-1)' : (M_9**(2))*(M_13**(-1))*(M_14**(-1)),
            '11^(-2)*13*14' : (M_11**(-2))*M_13*M_14,
            '11^(2)*13^(-1)*14^(-1)' : (M_11**(2))*(M_13**(-1))*(M_14**(-1)),
        }

        self.EigenValuesEnc = { name: x.eigenvalues() for name, x in self.MEnc.items() }
        self.EigenValuesDec = { name: x.eigenvalues() for name, x in self.MDec.items() }

        self.AssociateFaultCol = {
            '2' : {(1, 0): (0, 3), (2, 3): (1, 2), (3, 2): (2, 1), (0, 1): (3, 0)},
            '2*3' : {(1, 0): (0, 2), (2, 3): (0, 2), (0, 1): (2, 0), (3, 2): (2, 0)},
            '2*3^(-1)' : {(0, 1): (1, 3), (3, 2): (1, 3), (1, 0): (3, 1), (2, 3): (3, 1)},
            '2*3^(-2)' : {(3, 2): (0, 3), (0, 1): (1, 2), (1, 0): (2, 1), (2, 3): (3, 0)},
            '2^(-1)' : {(0, 1): (0, 3), (3, 2): (1, 2), (2, 3): (2, 1), (1, 0): (3, 0)},
            '2^(-1)*3' : {(1, 0): (1, 3), (2, 3): (1, 3), (0, 1): (3, 1), (3, 2): (3, 1)},
            '2^(-1)*3^(-1)' : {(0, 1): (0, 2), (3, 2): (0, 2), (1, 0): (2, 0), (2, 3): (2, 0)},
            '2^(-1)*3^(2)' : {(2, 3): (0, 3), (1, 0): (1, 2), (0, 1): (2, 1), (3, 2): (3, 0)},
            '2^(-2)*3' : {(0, 1): (0, 1), (1, 0): (1, 0), (2, 3): (2, 3), (3, 2): (3, 2)},
            '2^(2)*3^(-1)' : {(1, 0): (0, 1), (0, 1): (1, 0), (3, 2): (2, 3), (2, 3): (3, 2)},
            '3' : {(2, 3): (0, 1), (3, 2): (1, 0), (0, 1): (2, 3), (1, 0): (3, 2)},
            '3^(-1)' : {(3, 2): (0, 1), (2, 3): (1, 0), (1, 0): (2, 3), (0, 1): (3, 2)},

            '9*11*14^(-2)' : {(0, 1): (0, 1), (1, 0): (1, 0), (2, 3): (2, 3), (3, 2): (3, 2)},
            '9^(-1)*11^(-1)*14^(2)' : {(1, 0): (0, 1), (0, 1): (1, 0), (3, 2): (2, 3), (2, 3): (3, 2)},
            '9*11*13^(-2)' : {(2, 3): (0, 1), (3, 2): (1, 0), (0, 1): (2, 3), (1, 0): (3, 2)},
            '9^(-1)*11^(-1)*13^(2)' : {(3, 2): (0, 1), (2, 3): (1, 0), (1, 0): (2, 3), (0, 1): (3, 2)},
            '9*11^(-1)*13*14^(-1)' : {(0, 1): (0, 2), (3, 2): (0, 2), (1, 0): (2, 0), (2, 3): (2, 0)},
            '9^(-1)*11*13^(-1)*14' : {(1, 0): (0, 2), (2, 3): (0, 2), (0, 1): (2, 0), (3, 2): (2, 0)},
            '9^(2)*13^(-1)*14^(-1)' : {(0, 1): (0, 3), (3, 2): (1, 2), (2, 3): (2, 1), (1, 0): (3, 0)},
            '9^(-2)*13*14' : {(1, 0): (0, 3), (2, 3): (1, 2), (3, 2): (2, 1), (0, 1): (3, 0)},
            '11^(2)*13^(-1)*14^(-1)' : {(2, 3): (0, 3), (1, 0): (1, 2), (0, 1): (2, 1), (3, 2): (3, 0)},
            '11^(-2)*13*14' : {(3, 2): (0, 3), (0, 1): (1, 2), (1, 0): (2, 1), (2, 3): (3, 0)},
            '9*11^(-1)*13^(-1)*14' : {(0, 1): (1, 3), (3, 2): (1, 3), (1, 0): (3, 1), (2, 3): (3, 1)},
            '9^(-1)*11*13*14^(-1)' : {(1, 0): (1, 3), (2, 3): (1, 3), (0, 1): (3, 1), (3, 2): (3, 1)},
        }
        self.cacheTref = {}

        # debug check, verify the eigen values are unique
        l = []
        for _, x in self.EigenValuesEnc.items():
            assert x not in l, "Internal Error: duplicate eigen value found"
            l.append(x)
        l = []
        for _, x in self.EigenValuesDec.items():
            assert x not in l, "Internal Error: duplicate eigen value found"
            l.append(x)

    def getTref(self, name, encrypt):
        if name in self.cacheTref:
            return self.cacheTref[name]

        M = self.MEnc[name] if encrypt else self.MDec[name]
        Mref = Matrix(self.F, 8, 8, [x for row in M for x in row])
        _, Tref = Mref.jordan_form(transformation=True)
        self.cacheTref[name] = Tref
        return Tref

    def __call__(self, state, pos, encrypt):

        EigenValues = self.EigenValuesEnc if encrypt else self.EigenValuesDec

        target = self.M.matrix([bytesToBinaryRep(x) for x in state])
        eigenVal = target.eigenvalues()

        Mt = Matrix(self.F, 8, 8, [x for row in target for x in row])
        _, Tt = Mt.jordan_form(transformation=True)

        for name, eigenComp in EigenValues.items():
            if eigenComp == eigenVal:

                G_matrix = self.getTref(name, encrypt) * (Tt**(-1))

                G = [binaryToBytesRep(vector(bytesToBinaryRep(i)) * G_matrix) for i in range(256)]
                return True, self.AssociateFaultCol[name][tuple(pos)], G

        return False, (None, None), []

if __name__ == "__main__":
    import json
    import sys
    resolver = ResolverStep3()

    if len(sys.argv) > 1:
        print(json.dumps(resolver(*json.loads(sys.argv[1]))), flush=True)
    else:
        while True:
            data = sys.stdin.readline()
            if data == "stop\n":
                break
            res = resolver(*json.loads(data))
            print(json.dumps(res), flush=True)

