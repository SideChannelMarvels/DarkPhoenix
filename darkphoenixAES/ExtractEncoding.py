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

from .AES import expandKey, ShiftRow, InvShiftRow, SBox, InvSBox, MC, InvMC
from .AES import _AesSBox, _AesInvSBox, xor, AES
from .Encoding import Encoding8, Encoding
from .Exception import UnexpectedFailure


__all__ = ['getExternalEncoding']

def applyPermut(firstPerm, lambdaBetaPerm, data, encrypt):
    if encrypt:
        return lambdaBetaPerm.encode(InvShiftRow(InvMC(firstPerm.encode(InvShiftRow(data)))))
    else:
        return lambdaBetaPerm.encode(ShiftRow(MC(firstPerm.encode(ShiftRow(data)))))

def applyLastRound(keyShed, data, encrypt):
    if encrypt:
        return xor(ShiftRow(SBox(xor(MC(ShiftRow(SBox(data))), keyShed[-2]))), keyShed[-1])
    else:
        return xor(InvSBox(InvShiftRow(InvMC(xor(InvSBox(InvShiftRow(data)), keyShed[1])))), keyShed[0])

def getExternalEncoding(wb, gtilde_inv, Gbar_inv, C, LambdaS4, BetaS4, aesKey):
    firstPerm = Encoding.fromAffinParam(C, None).combine(Gbar_inv).combine(gtilde_inv)

    if wb.isEncrypt():
        sbox = Encoding.fromTable([_AesInvSBox for _ in range(16)])
    else:
        sbox = Encoding.fromTable([_AesSBox for _ in range(16)])
    lambdaBetaPerm = sbox.combine(Encoding.fromAffinParam(LambdaS4, BetaS4))

    keyShed = expandKey(aesKey, wb.getRoundNumber())

    outEncoding = [[None for _ in range(256)] for _ in range(16)]

    for i in range(256):
        d = applyLastRound(keyShed, applyPermut(firstPerm, lambdaBetaPerm, bytes([i] * 16), wb.isEncrypt()), wb.isEncrypt())

        for index, x in enumerate(d):
            UnexpectedFailure.check( outEncoding[index][x] is None,
                "fail to compute output external encoding: same encoding value found twice")
            outEncoding[index][x] = i

    outEncoding = Encoding.fromTable(outEncoding)

    inEncoding = [[None for _ in range(256)] for _ in range(16)]
    aes = AES(aesKey, wb.getRoundNumber())

    for i in range(256):
        if wb.isEncrypt():
            d = aes.decrypt(outEncoding.decode(wb.apply(bytes([i] * 16), revertLastShift=False)))
        else:
            d = aes.encrypt(outEncoding.decode(wb.apply(bytes([i] * 16), revertLastShift=False)))

        for index, x in enumerate(d):
            UnexpectedFailure.check( inEncoding[index][x] is None,
                "fail to compute input external encoding: same encoding value found twice")
            inEncoding[index][x] = i

    inEncoding = Encoding.fromTable(inEncoding)

    return inEncoding, outEncoding
