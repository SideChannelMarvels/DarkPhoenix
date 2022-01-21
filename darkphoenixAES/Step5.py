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

from .AES import _AesShiftRow, _AesInvShiftRow, ShiftRow, InvShiftRow
from .AES import _AesInvSBox, _AesSBox, MC, InvMC, InvSBox, SBox
from .Encoding import Encoding8, Encoding
from .MeetITM import MeetITM
from .Exception import FaultPositionError, UnexpectedFailure, WhiteBoxError
import json
import os.path
import subprocess
import tqdm

__all__ = ["compute"]

def getInjectionParam(wb, col, value, roundN, pos=0):
    # this should provide a good fault offset for the pos in [0, 1, 2, 3]
    # however, if this isn't good, we iterate on all values
    fpos = (col * 4 + pos) % 16
    fround = wb.getRoundNumber() - (3 if wb.lastRoundHasMC else 4) - roundN

    if wb.isEncrypt():
        return [fround, _AesShiftRow[fpos], value]
    else:
        return [fround, _AesInvShiftRow[fpos], value]

def computeFault(wb, mref, vref, perm, roundN, col, pbar, alpha):
    UnexpectedFailure.check( 0 <= col and col < 4, "Invalid column number")

    for pos in range(16):
        Wc = [vref[4*col:4*col+4]]

        changePos = False

        for fvalue in range(1, alpha+1):
            fault = getInjectionParam(wb, col, fvalue, roundN, pos)

            w1 = wb.applyFault(mref, fault=[fault],
                    outputF=perm, reverseMC=True)

            faultdiff = [0 if x == y else 1 for x, y in zip(vref, w1)]
            FaultPositionError.check( sum(faultdiff) == 4, fault[0], fault[1])
            fcol = faultdiff.index(1) // 4

            if fcol != col:
                WhiteBoxError.check( fvalue == 1,
                    "A fault injection position has changed when applying a different fault value")
                changePos = True
                break

            FaultPositionError.check( faultdiff[col*4] == 1, fault[0], fault[1])
            FaultPositionError.check( faultdiff[col*4+1] == 1, fault[0], fault[1])
            FaultPositionError.check( faultdiff[col*4+2] == 1, fault[0], fault[1])
            FaultPositionError.check( faultdiff[col*4+3] == 1, fault[0], fault[1])

            Wc.append(w1[4*col:4*col+4])
            pbar.update(1)

        if not changePos:
            return Wc

    raise FaultPositionError(getInjectionParam(wb, col, 1, roundN)[0])

def createPermRound(LambdaRound, BetaRound, encrypt):
    if encrypt:
        sbox = Encoding.fromTable([_AesInvSBox for _ in range(16)])
        return sbox.combine(Encoding.fromAffinParam(LambdaRound, BetaRound))
    else:
        sbox = Encoding.fromTable([_AesSBox for _ in range(16)])
        return sbox.combine(Encoding.fromAffinParam(LambdaRound, BetaRound))

def createKeyPartRound(keyPart, encrypt):
    if encrypt:
        return createPermRound(None, InvShiftRow(InvMC(keyPart)), encrypt)
    else:
        return createPermRound(None, ShiftRow(keyPart), encrypt)

def createPerm(gtilde_inv, Gbar_inv, C, LambdaRound, BetaRound, KeyPart, encrypt):
    UnexpectedFailure.check(len(LambdaRound) == 16, "Wrong number of lambda")
    UnexpectedFailure.check(len(BetaRound) == 16, "Wrong number of beta")

    perms = [Encoding.fromAffinParam(C, None).combine(Gbar_inv).combine(gtilde_inv)]
    perms.append(createPermRound(LambdaRound, BetaRound, encrypt))

    for b in KeyPart:
        perms.append(createKeyPartRound(b, encrypt))

    return perms

def compute(wb, gtilde_inv, Gbar_inv, C, LambdaS4, BetaS4, mref, noprogress, allRound=True):
    retry = 10
    alpha = 16
    midalpha = 4
    Keypart = []

    if allRound:
        nround = getInjectionParam(wb, 0, 0, 0)[0]
        if not wb.lastRoundHasMC:
            nround += 1
    elif wb.getRoundNumber() == 10:
        nround = 1
    else:
        nround = 2

    permsAes = createPerm(gtilde_inv, Gbar_inv, C, LambdaS4, BetaS4, [], wb.isEncrypt())
    resolver = MeetITM()
    for roundN in range(nround):

        r = getInjectionParam(wb, 0, 0, roundN)[0]

        wb.prepareFaultPosition(r, outputF=permsAes, reverseMC=True)

        with tqdm.tqdm(total=4*alpha+1, desc=f"Step5 r{r+1}",
                       unit='input', disable=noprogress) as pbar:

            vref = wb.apply(mref, outputF=permsAes, reverseMC=True)
            pbar.update(1)

            success = False
            for r in range(retry):
                if r == 0:
                    Fault0 = computeFault(wb, mref, vref, permsAes, roundN, 0, pbar, alpha)
                else:
                    pbar.total += 1 + alpha
                    mref2 = wb.getRandomInput(r)
                    vref2 = wb.apply(mref2, outputF=permsAes, reverseMC=True)
                    pbar.update(1)
                    Fault0 = computeFault(wb, mref2, vref2, permsAes, roundN, 0, pbar, alpha)
                success, _, betaCol0 = resolver(0, Fault0, midalpha, wb.isEncrypt(), [1, 1, 1, 1])
                if success:
                    break
            UnexpectedFailure.check(success,
                f"Fail to extract beta for column 0 after {retry} retries")

            success = False
            for r in range(retry):
                if r == 0:
                    Fault1 = computeFault(wb, mref, vref, permsAes, roundN, 1, pbar, alpha)
                else:
                    pbar.total += 1 + alpha
                    mref2 = wb.getRandomInput(r)
                    vref2 = wb.apply(mref2, outputF=permsAes, reverseMC=True)
                    pbar.update(1)
                    Fault1 = computeFault(wb, mref2, vref2, permsAes, roundN, 1, pbar, alpha)
                success, _, betaCol1 = resolver(1, Fault1, midalpha, wb.isEncrypt(), [1, 1, 1, 1])
                if success:
                    break
            UnexpectedFailure.check(success,
                f"Fail to extract beta for column 1 after {retry} retries")

            success = False
            for r in range(retry):
                if r == 0:
                    Fault2 = computeFault(wb, mref, vref, permsAes, roundN, 2, pbar, alpha)
                else:
                    pbar.total += 1 + alpha
                    mref2 = wb.getRandomInput(r)
                    vref2 = wb.apply(mref2, outputF=permsAes, reverseMC=True)
                    pbar.update(1)
                    Fault2 = computeFault(wb, mref2, vref2, permsAes, roundN, 2, pbar, alpha)
                success, _, betaCol2 = resolver(2, Fault2, midalpha, wb.isEncrypt(), [1, 1, 1, 1])
                if success:
                    break
            UnexpectedFailure.check(success,
                f"Fail to extract beta for column 2 after {retry} retries")

            success = False
            for r in range(retry):
                if r == 0:
                    Fault3 = computeFault(wb, mref, vref, permsAes, roundN, 3, pbar, alpha)
                else:
                    pbar.total += 1 + alpha
                    mref2 = wb.getRandomInput(r)
                    vref2 = wb.apply(mref2, outputF=permsAes, reverseMC=True)
                    pbar.update(1)
                    Fault3 = computeFault(wb, mref2, vref2, permsAes, roundN, 3, pbar, alpha)
                success, _, betaCol3 = resolver(3, Fault3, midalpha, wb.isEncrypt(), [1, 1, 1, 1])
                if success:
                    break
            UnexpectedFailure.check(success,
                f"Fail to extract beta for column 3 after {retry} retries")

        betaRound = betaCol0 + betaCol1 + betaCol2 + betaCol3
        if wb.isEncrypt():
            rkey = list(MC(ShiftRow(betaRound)))
        else:
            rkey = list(InvShiftRow(betaRound))

        permsAes.append(createKeyPartRound(rkey, wb.isEncrypt()))
        Keypart.append(rkey)

    return Keypart

