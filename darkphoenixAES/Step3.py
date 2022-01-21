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

from .Encoding import Encoding8, Encoding
from .Utils import SageProcess
from .MultTable import MultTable, InvTable
from .Exception import FaultPositionError, UnexpectedFailure
import json
import os.path
import subprocess
import tqdm

__all__ = ["compute"]

def getFaultRound(wb):
    return wb.getRoundNumber() - (1 if wb.lastRoundHasMC else 2)

################################################################
# Step 3.1: First part of the algorithm 3 with fault injection #
################################################################

def computeFaultCol(wb, gtilde_inv, mref, vref, fpos, pbar):
    Wc = []
    fround = getFaultRound(wb)

    w1 = wb.applyFault(mref, fault=[(fround, fpos, 1)], outputF=[gtilde_inv])
    pbar.update(1)

    faultdiff = [0 if x == y else 1 for x, y in zip(vref, w1)]
    FaultPositionError.check( sum(faultdiff) == 4, fround, fpos)
    col = faultdiff.index(1) // 4
    FaultPositionError.check( faultdiff[col*4] == 1, fround, fpos)
    FaultPositionError.check( faultdiff[col*4+1] == 1, fround, fpos)
    FaultPositionError.check( faultdiff[col*4+2] == 1, fround, fpos)
    FaultPositionError.check( faultdiff[col*4+3] == 1, fround, fpos)

    Wc.append(vref[4*col:4*col+4])
    Wc.append(w1[4*col:4*col+4])

    for fval in range(2, 256):
        w = wb.applyFault(mref, fault=[(fround, fpos, fval)], outputF=[gtilde_inv])
        pbar.update(1)

        faultdiff = [0 if x == y else 1 for x, y in zip(vref, w)]
        FaultPositionError.check( sum(faultdiff) == 4, fround, fpos)
        FaultPositionError.check( faultdiff[col*4] == 1, fround, fpos)
        FaultPositionError.check( faultdiff[col*4+1] == 1, fround, fpos)
        FaultPositionError.check( faultdiff[col*4+2] == 1, fround, fpos)
        FaultPositionError.check( faultdiff[col*4+3] == 1, fround, fpos)

        Wc.append(w[4*col:4*col+4])

    return col, Wc

def computeFault(wb, gtilde_inv, mref, noprogress):

    wb.prepareFaultPosition(getFaultRound(wb), outputF=[gtilde_inv])

    vref = wb.apply(mref, outputF=[gtilde_inv])

    W = [[] for i in range(4)]
    Fpos = [[] for i in range(4)]

    with tqdm.tqdm(initial=1, total=1 + 255 * 16, desc="Step3.1", unit='input', disable=noprogress) as pbar:
        for fpos in range(16):
            col, Wc = computeFaultCol(wb, gtilde_inv, mref, vref, fpos, pbar)

            UnexpectedFailure.check( 0 <= col and col < 4,
                f"Invalid column number {col}")

            FaultPositionError.check( len(W[col]) < 4, getFaultRound(wb), fpos)

            W[col].append(Wc)
            Fpos[col].append(fpos)

    return W, Fpos

#################################################################
# Step 3.2: Second part of the algorithm 3 with fault injection #
#################################################################

def computeGbar(wb, W, Fpos, noprogress, sageSubProc):
    Gbar = []
    associateCol = [[None for i in range(4)] for i in range(4)]

    with tqdm.tqdm(total=16, desc="Step3.2", unit='input', disable=noprogress) as pbar:
        with SageProcess("Step3_sage.py", ".Step3_sage", "ResolverStep3", sageSubProc) as sageP:
            for b in range(16):
                col = b // 4
                p0 = b % 4
                p1 = 2 * (p0 // 2) + ((p0+1) % 2)

                Gbari = None

                # The position can be the same for all rows
                # however, in order to complete associateCol, we must hit each row at
                # least one time. We use each row two times to validate the result
                # for each row
                FPos0, FPos1 = [(0, 1), (2, 3), (1, 3), (2, 0)][p0]

                Fault0 = W[col][FPos0]
                Fault1 = W[col][FPos1]
                fposition = (Fpos[col][FPos0], Fpos[col][FPos1])

                FaultPositionError.check( Fault0[0] == Fault1[0], getFaultRound(wb), fposition)
                base = Fault0[0]

                w01 = [None for _ in range(256)]
                w10 = [None for _ in range(256)]

                for f0, f1 in zip(Fault0, Fault1):
                    FaultPositionError.check( w01[base[p0] ^ f0[p0]] is None, getFaultRound(wb), fposition)
                    FaultPositionError.check( w10[base[p1] ^ f1[p1]] is None, getFaultRound(wb), fposition)
                    w01[base[p0] ^ f0[p0]] = base[p1] ^ f0[p1]
                    w10[base[p1] ^ f1[p1]] = base[p0] ^ f1[p0]

                L01 = Encoding8(w10).combine(Encoding8(w01))

                success, posFault, Gbari = sageP([L01[1<<x] for x in range(8)],
                                                (p0, p1),
                                                wb.isEncrypt())
                FaultPositionError.check( success, getFaultRound(wb), fposition)

                if associateCol[col][FPos0] is None:
                    FaultPositionError.check( posFault[0] not in associateCol[col], getFaultRound(wb), fposition)
                    associateCol[col][FPos0] = posFault[0]
                else:
                    FaultPositionError.check( associateCol[col][FPos0] == posFault[0], getFaultRound(wb), fposition)

                if associateCol[col][FPos1] is None:
                    FaultPositionError.check( posFault[1] not in associateCol[col], getFaultRound(wb), fposition)
                    associateCol[col][FPos1] = posFault[1]
                else:
                    FaultPositionError.check( associateCol[col][FPos1] == posFault[1], getFaultRound(wb), fposition)

                pbar.update(1)
                Gbar.append(Encoding8(Gbari))

    UnexpectedFailure.check( all([x is not None for c in associateCol for x in c]),
                            "missing Column after Step 3.2")

    return Encoding(Gbar), associateCol

###################################
# Step 3.3 (Annex B in the paper) #
###################################

def computeC(wb, W, Gbar_inv, associateCol, noprogress):
    C = []

    with tqdm.tqdm(total=16, desc="Step3.3", unit='input', disable=noprogress) as pbar:
        for b in range(16):

            # computeC is only implement for fault on the first row
            if b % 4 == 0:
                C.append(1)
                pbar.update(1)
                continue

            col = b // 4
            # Wi is the fault of the first row for this column
            Wi0 = W[col][associateCol[col].index(0)]

            if wb.isEncrypt():
                if b % 4 == 3:
                    coef = MultTable[3][InvTable[2]]
                else:
                    coef = InvTable[2]
            else:
                if b % 4 == 1:
                    coef = MultTable[9][InvTable[14]]  # p9 * (p14 ** -1))
                elif b % 4 == 2:
                    coef = MultTable[13][InvTable[14]] # p13 * (p14 ** -1))
                else:
                    coef = MultTable[11][InvTable[14]] # p11 * (p14 ** -1))

            ci = None

            for p in range(256):
                ti = Gbar_inv[b][Wi0[0][b % 4] ^ Wi0[p][b % 4]]
                t0 = Gbar_inv[col*4][Wi0[0][0] ^ Wi0[p][0]]

                if ti == 0:
                    pass
                elif ci is None:
                    ci = MultTable[InvTable[ti]][MultTable[t0][coef]]
                else:
                    UnexpectedFailure.check(ci == MultTable[InvTable[ti]][MultTable[t0][coef]],
                        f"Step 3.3: Found a different value for C associated with byte {b}")

            UnexpectedFailure.check( ci != None,
                f"Step 3.3: Fail to compute a value for C associated with byte {b}")
            C.append(ci)
            pbar.update(1)

    return C

########################
# Compute entry method #
########################

def compute(wb, gtilde_inv, mref, noprogress, sageSubProc):
    W, Fpos = computeFault(wb, gtilde_inv, mref, noprogress)
    Gbar, associateCol = computeGbar(wb, W, Fpos, noprogress, sageSubProc)
    Gbar_inv = Gbar.getInverseEncoding()

    roundShift = [None for _ in range(16)]
    for ncol in range(4):
        for p, x in zip(Fpos[ncol], associateCol[ncol]):
            roundShift[4*ncol+x] = p

    C = computeC(wb, W, Gbar_inv, associateCol, noprogress)
    return Gbar_inv, roundShift, C

