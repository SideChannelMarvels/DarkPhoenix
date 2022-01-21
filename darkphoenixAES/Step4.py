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
from .Encoding import Encoding8, Encoding
from .MeetITM import MeetITM
from .Exception import FaultPositionError, UnexpectedFailure, WhiteBoxError
import json
import os.path
import subprocess
import tqdm

__all__ = ["compute"]

def getInjectionParam(wb, col, value, pos=0):
    # this should provide a good fault offset for the pos in [0, 1, 2, 3]
    # however, if this isn't good, we iterate on all values
    fpos = (col * 4 + pos) % 16
    fround = wb.getRoundNumber() - (2 if wb.lastRoundHasMC else 3)

    if wb.isEncrypt():
        return [fround, _AesShiftRow[fpos], value]
    else:
        return [fround, _AesInvShiftRow[fpos], value]

def computeFault(wb, mref, vref, perm, col, pbar, alpha):
    UnexpectedFailure.check( 0 <= col and col < 4, "Invalid column number")

    for pos in range(16):
        Wc = [vref[4*col:4*col+4]]

        changePos = False

        for fvalue in range(1, alpha+1):
            fault = getInjectionParam(wb, col, fvalue, pos)

            w1 = wb.applyFault(mref, fault=[fault],
                    outputF=[perm], reverseMC=True)

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

    raise FaultPositionError(fault[0])

def compute(wb, gtilde_inv, Gbar_inv, C, mref, noprogress):
    retry = 10
    alpha = 16
    midalpha = 4
    Cperm = Encoding.fromAffinParam(C, None)
    resolver = MeetITM()
    permAes = Cperm.combine(Gbar_inv).combine(gtilde_inv)

    wb.prepareFaultPosition(getInjectionParam(wb, 0, 0)[0], outputF=[permAes], reverseMC=True)

    with tqdm.tqdm(total=4*alpha+1, desc="Step4", unit='input', disable=noprogress) as pbar:

        vref = wb.apply(mref, outputF=[permAes], reverseMC=True)
        pbar.update(1)

        # do column 0 first.
        # when we get the lambda,beta for the column 0, only the beta of column 1, 2
        # and 3 should be computed

        success = False
        for r in range(retry):
            if r == 0:
                Fault0 = computeFault(wb, mref, vref, permAes, 0, pbar, alpha)
            else:
                pbar.total += 1 + alpha
                mref2 = wb.getRandomInput(r)
                vref2 = wb.apply(mref2, outputF=[permAes], reverseMC=True)
                pbar.update(1)
                Fault0 = computeFault(wb, mref2, vref2, permAes, 0, pbar, alpha)
            success, lambdaCol0, betaCol0 = resolver(0, Fault0, midalpha, wb.isEncrypt())
            if success:
                break
        UnexpectedFailure.check(success,
            f"Fail to extract lambda and beta for column 0 after {retry} retries")

        success = False
        for r in range(retry):
            if r == 0:
                Fault1 = computeFault(wb, mref, vref, permAes, 1, pbar, alpha)
            else:
                pbar.total += 1 + alpha
                mref2 = wb.getRandomInput(r)
                vref2 = wb.apply(mref2, outputF=[permAes], reverseMC=True)
                pbar.update(1)
                Fault1 = computeFault(wb, mref2, vref2, permAes, 1, pbar, alpha)
            success, lambdaCol1, betaCol1 = resolver(1, Fault1, midalpha, wb.isEncrypt(), lambdaCol0)
            if success:
                break
        UnexpectedFailure.check(success,
            f"Fail to extract beta for column 1 after {retry} retries")

        success = False
        for r in range(retry):
            if r == 0:
                Fault2 = computeFault(wb, mref, vref, permAes, 2, pbar, alpha)
            else:
                pbar.total += 1 + alpha
                mref2 = wb.getRandomInput(r)
                vref2 = wb.apply(mref2, outputF=[permAes], reverseMC=True)
                pbar.update(1)
                Fault2 = computeFault(wb, mref2, vref2, permAes, 2, pbar, alpha)
            success, lambdaCol2, betaCol2 = resolver(2, Fault2, midalpha, wb.isEncrypt(), lambdaCol0)
            if success:
                break
        UnexpectedFailure.check(success,
            f"Fail to extract beta for column 2 after {retry} retries")

        success = False
        for r in range(retry):
            if r == 0:
                Fault3 = computeFault(wb, mref, vref, permAes, 3, pbar, alpha)
            else:
                pbar.total += 1 + alpha
                mref2 = wb.getRandomInput(r)
                vref2 = wb.apply(mref2, outputF=[permAes], reverseMC=True)
                pbar.update(1)
                Fault3 = computeFault(wb, mref2, vref2, permAes, 3, pbar, alpha)
            success, lambdaCol3, betaCol3 = resolver(3, Fault3, midalpha, wb.isEncrypt(), lambdaCol0)
            if success:
                break
        UnexpectedFailure.check(success,
            f"Fail to extract beta for column 3 after {retry} retries")

    if wb.isEncrypt():
        lambdaCol = list(ShiftRow(lambdaCol0 + lambdaCol1 + lambdaCol2 + lambdaCol3))
    else:
        lambdaCol = list(InvShiftRow(lambdaCol0 + lambdaCol1 + lambdaCol2 + lambdaCol3))

    UnexpectedFailure.check( all([lambdaCol[x] == lambdaCol[x - (x % 4)] for x in range(16)]),
        "Different Lambda have been found for the same column")

    return lambdaCol0 + lambdaCol1 + lambdaCol2 + lambdaCol3, betaCol0 + betaCol1 + betaCol2 + betaCol3

