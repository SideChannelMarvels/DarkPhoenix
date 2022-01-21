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

import multiprocessing as mp
import queue
import tqdm
import time
from .AES import xor
from .Exception import InvalidState, UnexpectedFailure

__all__ = ["compute", "verify"]

# During the step 1, we compute 16 lists of 256 inputs such as
# - one input is present in each of the lists
# - each list is associated with an output byte
# - for each list, every input lead to a different byte value
# - for each list, another (or two other) byte on the same column keeps the same
#    value for every input on the list

# If the reverse of the whitebox is available, we use it to compute inputs
# that give fixed outputs with two common bytes in the same column.
# Otherwise, we perform a bruteforce to find the needed values. In order to
# end the bruteforce early, we verify if the output column has one (or two)
# common byte with the reference output. We therefore keep three lists of
# inputs for each byte:
# - column 0, row 0 with common row 1 and 2
# - column 0, row 0 with common row 1 and 3
# - column 0, row 0 with common row 2 and 3
# - column 0, row 1 with common row 0 and 2
# ...
# When one of the three lists is complete for every byte, we stop the bruteforce

# When performing the bruteforce, two situations are possible:
# - bruteforce with only one byte in common in the column. This is the minimum
#   needed to perform the step2. However, the step2 will not detect immediately
#   if the fault injection is misplaced.
# - bruteforce with two bytes in common in the column (as explained in the
#   paper). The difficulty of the bruteforce is increased by a factor of 256.
#   However, a wrong fault position will be detected early during the step 2

# For the two last possibilities, computeAlone performs the computation in
# a process alone, and computeMulti performs the same operation with multiple processes

########################
# Validation of Step 1 #
########################

def verifyOne(v, value_ref, r_s, index, xi):
    # check if byte value has the expected value
    if v[index] != xi:
        return False
    # check if first common byte has the expected value
    if v[r_s[0]] != value_ref[r_s[0]]:
        return False
    # if uses two common bytes, check the second one
    if len(r_s) == 2 and v[r_s[1]] != value_ref[r_s[1]]:
        return False
    return True

def verify(wb, Mref, M, r_s, noprogress):

    value_ref = wb.apply(Mref)
    with tqdm.tqdm(total=256 * 16, desc="VerifyStep1", unit='input', disable=noprogress) as pbar:

        for index, mi in enumerate(M):
            for xi, indata in enumerate(mi):
                InvalidState.check(
                    verifyOne(wb.apply(indata), value_ref, r_s[index], index, xi),
                    "Invalid Step1 state")
                pbar.update(1)

####################################
# Bruteforce implementation common #
####################################

RS = [(0, 1, 2, 3),
      (0, 2, 3, 1),
      (0, 3, 1, 2)]

def isCandidate(v, value_ref, r_s):
    if v[r_s[0]] != value_ref[r_s[0]] or v[r_s[1]] != value_ref[r_s[1]]:
        return False
    return True

def isCandidate2(v, value_ref, r_s):
    if v[r_s] != value_ref[r_s]:
        return False
    return True

########################################
# Bruteforce implementation monothread #
########################################

def computeAlone(wb, Mref, noprogress, doubleRS):
    M = [[[[None for _ in range(256)] for _ in range(len(RS)) ] for _ in range(4) ] for _ in range(4)]

    value_ref = wb.apply(Mref)
    for c in range(4):
        for rs_index, (a1, a2, b1, b2) in enumerate(RS):
            M[c][a1][rs_index][value_ref[c*4+a1]] = Mref
            M[c][a2][rs_index][value_ref[c*4+a2]] = Mref
            M[c][b1][rs_index][value_ref[c*4+b1]] = Mref
            M[c][b2][rs_index][value_ref[c*4+b2]] = Mref

    startValue = 0

    present = sum([max([sum([0 if v is None else 1 for v in mrsrow]) for mrsrow in mrow]) for mcol in M for mrow in mcol])

    with tqdm.tqdm(initial = present, total=16 * 256, desc="Step1", unit='input', disable=noprogress, position=1) as pbarFound:
        with tqdm.tqdm(desc="WB Iteration", disable=noprogress, position=0) as pbarIt:

            while present != 256 * 16:
                data = startValue.to_bytes(16, 'big')
                startValue += 1
                value = wb.apply(data)
                has_update = False
                for c in range(4):
                    for rs_index, (a1, a2, b1, b2) in enumerate(RS):
                        if doubleRS:
                            if isCandidate(value, value_ref, (c*4+a1, c*4+a2)):
                                if M[c][b1][rs_index][value[c*4+b1]] is None:
                                    M[c][b1][rs_index][value[c*4+b1]] = data
                                    has_update = True
                                if M[c][b2][rs_index][value[c*4+b2]] is None:
                                    M[c][b2][rs_index][value[c*4+b2]] = data
                                    has_update = True
                            if isCandidate(value, value_ref, (c*4+b1, c*4+b2)):
                                if M[c][b1][rs_index][value[c*4+a1]] is None:
                                    M[c][b1][rs_index][value[c*4+a1]] = data
                                    has_update = True
                                if M[c][a2][rs_index][value[c*4+a2]] is None:
                                    M[c][a2][rs_index][value[c*4+a2]] = data
                                    has_update = True
                        else:
                            if isCandidate2(value, value_ref, c*4+a1):
                                if M[c][b1][rs_index][value[c*4+b1]] is None:
                                    M[c][b1][rs_index][value[c*4+b1]] = data
                                    has_update = True
                            if isCandidate2(value, value_ref, c*4+a2):
                                if M[c][b2][rs_index][value[c*4+b2]] is None:
                                    M[c][b2][rs_index][value[c*4+b2]] = data
                                    has_update = True
                            if isCandidate2(value, value_ref, c*4+b1):
                                if M[c][a1][rs_index][value[c*4+a1]] is None:
                                    M[c][a1][rs_index][value[c*4+a1]] = data
                                    has_update = True
                            if isCandidate2(value, value_ref, c*4+b2):
                                if M[c][a2][rs_index][value[c*4+a2]] is None:
                                    M[c][a2][rs_index][value[c*4+a2]] = data
                                    has_update = True
                if has_update:
                    old_present = present
                    present = sum([max([sum([0 if v is None else 1 for v in mrsrow]) for mrsrow in mrow]) for mcol in M for mrow in mcol])
                    if old_present != present:
                        pbarFound.update(present - old_present)
                    elif old_present > present:
                        # should never happen
                        raise UnexpectedFailure("Lost a solution")

                pbarIt.update(1)

    resM = []
    r_s = []
    for colindex, mcol in enumerate(M):
        for rowindex, mrow in enumerate(mcol):
            found = False
            for mrsrow, (a1, a2, b1, b2) in zip(mrow, RS):
                if all([v is not None for v in mrsrow]) and not found:
                    found = True
                    resM.append(mrsrow)
                    if doubleRS:
                        if rowindex == a1 or rowindex == a2:
                            a1, a2 = b1, b2
                        if rowindex == a1 or rowindex == a2:
                            raise UnexpectedFailure("Invalid rowindex")
                        r_s.append((colindex * 4 + a1, colindex * 4 + a2))
                    else:
                        if rowindex == a1:
                            r_s.append((colindex * 4 + b1, ))
                        elif rowindex == a2:
                            r_s.append((colindex * 4 + b2, ))
                        elif rowindex == b1:
                            r_s.append((colindex * 4 + a1, ))
                        elif rowindex == b2:
                            r_s.append((colindex * 4 + a2, ))
                        else:
                            raise UnexpectedFailure("Invalid rowindex")
                    break

            UnexpectedFailure.check(found,
                f"Incomplete computation for column {colindex} row {rowindex}")

    return resM, r_s

#########################################
# Bruteforce implementation multithread #
#########################################

def computeRunnerReport(progress, buff, rs_index, c, rindex, data, value):
    position = (c*4+rindex)*256*len(RS) + rs_index*256 + value[c*4+rindex]
    if progress[position] == 1:
        return
    with buff.get_lock():
        if progress[position] == 0:
            progress[position] = 1
            buff[position*16:(position+1)*16] = data[:]


def readbuff(progress, buff, c, rindex, rs_index):
    position = (c*4+rindex)*256*len(RS) + rs_index*256

    res = [None for i in range(256)]

    for i in range(256):
        if progress[position + i] == 1:
            res[i] = bytes(buff[(position+i)*16:(position+i+1)*16])

    return res

def computeRunner(wb, value_ref, startValue, progress, buff, reportP, stopVal, doubleRS):
    nb = 0
    reportNum = 256
    wb.newThread()
    while stopVal.value == 0:
        data = startValue.to_bytes(16, 'big')
        startValue += 1
        value = wb.apply(data)
        for c in range(4):
            for rs_index, (a1, a2, b1, b2) in enumerate(RS):
                if doubleRS:
                    if isCandidate(value, value_ref, (c*4+a1, c*4+a2)):
                        computeRunnerReport(progress, buff, rs_index, c, b1, data, value)
                        computeRunnerReport(progress, buff, rs_index, c, b2, data, value)
                    if isCandidate(value, value_ref, (c*4+b1, c*4+b2)):
                        computeRunnerReport(progress, buff, rs_index, c, a1, data, value)
                        computeRunnerReport(progress, buff, rs_index, c, a2, data, value)
                else:
                    if isCandidate2(value, value_ref, c*4+a1):
                        computeRunnerReport(progress, buff, rs_index, c, b1, data, value)
                    if isCandidate2(value, value_ref, c*4+a2):
                        computeRunnerReport(progress, buff, rs_index, c, b2, data, value)
                    if isCandidate2(value, value_ref, c*4+b1):
                        computeRunnerReport(progress, buff, rs_index, c, a1, data, value)
                    if isCandidate2(value, value_ref, c*4+b2):
                        computeRunnerReport(progress, buff, rs_index, c, a2, data, value)
        nb += 1
        if nb >= reportNum:
            l = reportP.get_lock()
            if l.acquire():
                reportP.value += nb
                l.release()
                nb = 0
            else:
                reportNum += 16

    # a last time before exit
    with reportP.get_lock():
        reportP.value += nb


def computeMulti(wb, Mref, nprocess, noprogress, doubleRS):

    reportP = mp.Value('Q', 0)
    stopVal = mp.Value('B', 0)
    progress = mp.Array('B', 256 * 16 * len(RS))
    buff = mp.Array('B', 256 * 16 * len(RS) * 16)

    value_ref = wb.apply(Mref)
    for c in range(4):
        for rs_index, (a1, a2, b1, b2) in enumerate(RS):
            computeRunnerReport(progress, buff, rs_index, c, a1, Mref, value_ref)
            computeRunnerReport(progress, buff, rs_index, c, a2, Mref, value_ref)
            computeRunnerReport(progress, buff, rs_index, c, b1, Mref, value_ref)
            computeRunnerReport(progress, buff, rs_index, c, b2, Mref, value_ref)

    present = 0
    for i in range(16):
        max_cel = 0
        for j in range(len(RS)):
            max_cel = max(max_cel, sum(progress[i*256*len(RS)+j*256:i*256*len(RS)+(j+1)*256]))
        present += max_cel

    with tqdm.tqdm(initial = present, total=16 * 256, desc="Step1", unit='input', disable=noprogress, position=1) as pbarFound:
        with tqdm.tqdm(desc="WB Iteration", disable=noprogress, position=0) as pbarIt:

            ps = []
            for i in range(nprocess):
                ps.append( mp.Process(target=computeRunner, args=(wb, value_ref, i * ((2**128) // nprocess), progress, buff, reportP, stopVal, doubleRS)) )
                ps[i].start()

            try:
                while present != 256 * 16:
                    time.sleep(0.1)
                    with reportP.get_lock():
                        inputData = reportP.value
                        reportP.value = 0
                    pbarIt.update(inputData)

                    old_present = present
                    present = 0
                    for i in range(16):
                        max_cel = 0
                        for j in range(len(RS)):
                            max_cel = max(max_cel, sum(progress[i*256*len(RS)+j*256:i*256*len(RS)+(j+1)*256]))
                        present += max_cel
                    UnexpectedFailure.check(old_present <= present, "Lost a solution")
                    pbarFound.update(present - old_present)

            finally:
                stopVal.value = 1
                # close all process
                for p in ps:
                    p.join(1)
                    if p.exitcode == None:
                        p.terminate()
                    p.close()

                pbarIt.update(reportP.value)


    resM = []
    r_s = []
    for colindex in range(4):
        for rowindex in range(4):
            found = False
            for rs_index, (a1, a2, b1, b2) in enumerate(RS):
                mrsrow = readbuff(progress, buff, colindex, rowindex, rs_index)
                if all([v is not None for v in mrsrow]) and not found:
                    found = True
                    resM.append(mrsrow)
                    if doubleRS:
                        if rowindex == a1 or rowindex == a2:
                            a1, a2 = b1, b2
                        if rowindex == a1 or rowindex == a2:
                            raise UnexpectedFailure("Invalid rowindex")
                        r_s.append((colindex * 4 + a1, colindex * 4 + a2))
                    else:
                        if rowindex == a1:
                            r_s.append((colindex * 4 + b1, ))
                        elif rowindex == a2:
                            r_s.append((colindex * 4 + b2, ))
                        elif rowindex == b1:
                            r_s.append((colindex * 4 + a1, ))
                        elif rowindex == b2:
                            r_s.append((colindex * 4 + a2, ))
                        else:
                            raise UnexpectedFailure("Invalid rowindex")
                    break

            UnexpectedFailure.check(found,
                f"Incomplete computation for column {colindex} row {rowindex}")

    return resM, r_s

#######################################
# Compute with reverse implementation #
#######################################

def computeWithReverseMultiProc(wb, value_ref, i):
    data1 = wb.applyReverse(xor(value_ref[:], bytes([i, i, 0, 0, i, i, 0, 0, i, i, 0, 0, i, i, 0, 0])))
    data2 = wb.applyReverse(xor(value_ref[:], bytes([0, 0, i, i, 0, 0, i, i, 0, 0, i, i, 0, 0, i, i])))
    return data1, data2, i

def computeWithReverse(wb, Mref, noprogress):
    M = [[None for _ in range(256)] for _ in range(16)]

    with tqdm.tqdm(total=256 * 16, desc="Step1", unit='input', disable=noprogress) as pbar:
        value_ref = wb.apply(Mref)
        for b in range(16):
            M[b][value_ref[b]] = Mref
            pbar.update(1)

        for i in range(1, 256):
            data1, data2, _ = computeWithReverseMultiProc(wb, value_ref, i)
            for b in range(16):
                if b % 4 < 2:
                    M[b][value_ref[b] ^ i] = data1
                else:
                    M[b][value_ref[b] ^ i] = data2
                pbar.update(1)

    r_s = [( 2,  3), ( 2,  3), ( 0,  1), ( 0,  1),
           ( 6,  7), ( 6,  7), ( 4,  5), ( 4,  5),
           (10, 11), (10, 11), ( 8,  9), ( 8,  9),
           (14, 15), (14, 15), (12, 13), (12, 13)]

    return M, r_s

########################
# Compute entry method #
########################

def compute(wb, Mref, nprocess, noprogress, doubleRS):
    if wb.hasReverse():
        return computeWithReverse(wb, Mref, noprogress)
    else:
        if nprocess == 0:
            return computeAlone(wb, Mref, noprogress, doubleRS)
        else:
            return computeMulti(wb, Mref, nprocess, noprogress, doubleRS)
