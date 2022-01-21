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

from .AES import _AesShiftRow, _AesInvShiftRow
from .Encoding import Encoding8, Encoding
from .Exception import InvalidState, FaultPositionError, UnexpectedFailure
import multiprocessing as mp
import tqdm

__all__ = ["compute"]

#########################
# Shared implementation #
#########################

def getInjectionParam(wb, b, value, pos=0):
    # this should provide a good fault offset for the pos in [0, 1, 2, 3]
    # however, if this isn't good, we iterate on all values
    fpos = (b - (b % 4) + pos) % 16

    if wb.lastRoundHasMC:
        return (wb.getRoundNumber() - 1, fpos, value)
    elif wb.isEncrypt():
        return (wb.getRoundNumber() - 2, _AesShiftRow[fpos], value)
    else:
        return (wb.getRoundNumber() - 2, _AesInvShiftRow[fpos], value)

def verifyDoubleValue(R, val, r, s, index):
    if s is None:
        return True

    if index == 0:
        if R[val[r]] is None:
            R[val[r]] = val[s]
            return True
        else:
            return False
    else:
        return R[val[r]] == val[s]

def computeSRunner(wb, R, b, r_val, index, mval, pos):
    progress = 0
    if len(r_val) == 2:
        r, s = r_val
    else:
        r, s = r_val[0], None

    S = [None for _ in range(256)]

    val = wb.apply(mval)
    progress += 1

    InvalidState.check(val[b] == index,
            "Invalid State1 State, target byte doesn't have the expected value")

    S[val[r]] = index
    if not verifyDoubleValue(R, val, r, s, index):
        return (False, R, S, progress)

    for fval in range(1, 256):
        val = wb.applyFault(mval, [getInjectionParam(wb, b, fval, pos)])
        progress += 1

        if S[val[r]] != None:
            # We already know this byte value, we didn't fault the good byte, retry
            # with another position
            return (False, R, S, progress)

        S[val[r]] = val[b]
        if not verifyDoubleValue(R, val, r, s, index):
            return (False, R, S, progress)

    return (True, R, S, progress)

#############################
# Monothread implementation #
#############################

def computeSAlone(wb, M, r_s, noprogress):

    SRes = [[[None for index in range(256)] for x in range(256)] for b in range(16)]
    R = [None for _ in range(16)]
    position = [None for _ in range(16)]

    # The step 2 can use r_s to verify the fault injection position.
    # In order to detect a wrong position early, each position is used in a
    # balanced way over the iterations. Otherwise, if the last fault position is
    # wrong, we can only raise an exception after more than 93% (15/16) of the
    # step.

    with tqdm.tqdm(total=16 * 256 * 256, desc="Step2", unit='input', disable=noprogress) as pbar:

        for b, (mi, r_val) in enumerate(zip(M, r_s)):
            goodPos = False
            for pos in range(16):
                goodPos, Ri, Sb, progress = computeSRunner(wb, [None for _ in range(256)], b, r_val, 0, mi[0], pos)

                pbar.update(progress)
                if not goodPos:
                    pbar.total += progress
                else:
                    position[b] = pos
                    R[b] = Ri
                    for rval, xval in enumerate(Sb):
                        if SRes[b][rval][0] is not None:
                            raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

                        SRes[b][rval][0] = xval
                    break

            if not goodPos:
                raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

        for index in range(1, 256):
            for b, (mi, r_val, pos) in enumerate(zip(M, r_s, position)):
                goodPos, Ri, Sb, progress = computeSRunner(wb, R[b], b, r_val, index, mi[index], pos)
                pbar.update(progress)
                if not goodPos:
                    raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

                for rval, xval in enumerate(Sb):
                    if SRes[b][rval][index] is not None:
                        raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

                    SRes[b][rval][index] = xval

    UnexpectedFailure.check(
        all([x is not None for Sb in SRes for Sbr in Sb for x in Sbr]),
        "Fail Step2: all values weren't found")

    return SRes

#################################
# Multithreading implementation #
#################################

localWB = None
def init_localWB(wb):
    global localWB
    wb.newThread()
    localWB = wb

def computeSRunnerProxy(R, b, r_val, index, mval, pos):
    result, Ri, Sb, progress = computeSRunner(localWB, R, b, r_val, index, mval, pos)
    if (not result) and index == 0 and pos == 0:
        addTotal = progress

        for new_pos in range(1, 16):
            R = [None for _ in range(256)]
            result, Ri, Sb, progress = computeSRunner(localWB, R, b, r_val, index, mval, new_pos)

            if result:
                return result, b, index, new_pos, Ri, Sb, progress, addTotal
            else:
                addTotal += progress

        return False, b, index, 16, Ri, Sb, progress, addTotal

    return result, b, index, pos, Ri, Sb, progress, 0

def computeSMulti(wb, M, r_s, nprocess, noprogress):
    R = [None for _ in range(256)]
    SRes = [[[None for index in range(256)] for x in range(256)] for b in range(16)]

    with tqdm.tqdm(total=16 * 256 * 256, desc="Step2", unit='input', disable=noprogress) as pbar:

        with mp.Pool(processes=nprocess, initializer=init_localWB, initargs=[wb]) as pool:
            res = []
            for b in range(16):
                res.append(pool.apply_async(computeSRunnerProxy, (R, b, r_s[b], 0, M[b][0], 0)))

            while len(res) > 0:
                found = False
                for pindex, p in enumerate(res):
                    if p.ready():
                        found = True
                        break
                if not found:
                    res[0].wait(0.001)
                    continue

                result, b, index, pos, Ri, Sb, cnt, totalCnt = res.pop(pindex).get()
                pbar.total += totalCnt
                pbar.update(cnt)

                if not result:
                    raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

                # try to mix the job
                # we want to advance each column at the same time in order to detect
                # early if a fault position isn't good
                job_block = 16
                if index % job_block == 0:
                    for new_index in range(index + 1, min(256, index + job_block + 1)):
                        res.append(pool.apply_async(computeSRunnerProxy,
                            (Ri, b, r_s[b], new_index, M[b][new_index], pos)))

                for rval, xval in enumerate(Sb):
                    if SRes[b][rval][index] is not None:
                        raise FaultPositionError(getInjectionParam(wb, 0, 0)[0])

                    SRes[b][rval][index] = xval


    UnexpectedFailure.check(
        all([x is not None for Sb in SRes for Sbr in Sb for x in Sbr]),
        "Fail Step2: all values weren't found")

    return SRes

######################################
# Final stage: Tolhuizen's Algorithm #
######################################

def tolhuizen_algo(S_):

    S = [None for _ in range(256)]
    for s in S_:
        UnexpectedFailure.check(S[s[0]] == None, "Fail Tolhuizen's Algorithm")
        S[s[0]] = s

    perm = [None for _ in range(256)]
    perm[0] = 0
    i = 1
    for j in range(8):
        while(perm[i] is not None):
            i += 1
        perm[i] = 2**j
        for k in range(1, 256):
            if perm[k] is not None:
                m = S[i][k]
                if perm[m] is None:
                    perm[m] = perm[k] ^ perm[i]
                else:
                    UnexpectedFailure.check(perm[m] == perm[k] ^ perm[i], "Fail Tolhuizen's Algorithm")
    return Encoding8(perm)

def compute(wb, M, r_s, nprocess, noprogress):

    wb.prepareFaultPosition(getInjectionParam(wb, 0, 0)[0])

    if nprocess == 0:
        S = computeSAlone(wb, M, r_s, noprogress)
    else:
        S = computeSMulti(wb, M, r_s, nprocess, noprogress)

    return Encoding([tolhuizen_algo(Si) for Si in S])
