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

from .Exception import InvalidArgument
import random

class FaultPositionValidator:

    def __init__(self, wb, fround, reverseRoundMethod, reverseRoundMethod2, pbarWbIt):
        self.wb = wb
        self.fround = fround
        self.reverseRoundMethod = reverseRoundMethod
        self.reverseRoundMethod2 = reverseRoundMethod2
        self.pbarWbIt = pbarWbIt

        self.foundColumn = 0

        # input: injected fault position
        # result: the position has been accepted
        self.commitedPosition = [False for i in range(16) ]

        # input: output byte fault position
        # result: output column associated with this byte
        self.columnByByte = [None for i in range(16) ]

        # input: output column
        # result: injected fault position
        self.columnPos = [ [] for i in range(4) ]

        # input: output column
        # result: the fault associated with this column
        self.commitedFault = [set() for i in range(4) ]

        self.commonInput = random.randbytes(16)
        baseOutput = self.wb.apply(self.commonInput)
        self.pbarWbIt.update(1)

        self.commonOutput = self.reverseRoundMethod(baseOutput)
        if self.reverseRoundMethod2 is not None:
            self.commonOutput2 = self.reverseRoundMethod2(baseOutput)
        else:
            self.commonOutput2 = None

    def get_result(self, fault):
        output_raw = self.wb.applyFault(self.commonInput, fault)
        self.pbarWbIt.update(1)
        output = self.reverseRoundMethod(output_raw)

        faultPosition = [i for i in range(16) if self.commonOutput[i] != output[i] ]
        shortOutput = bytes([output[i] for i in faultPosition])
        result = (len(faultPosition) == 4)

        if result and self.reverseRoundMethod2 is not None:
            output2 = self.reverseRoundMethod2(output_raw)
            result &= all([self.commonOutput2[i] != output2[i] for i in range(16)])

        return result, faultPosition, shortOutput

    def test_and_commit(self, fpos):
        InvalidArgument.check(not self.commitedPosition[fpos],
            f"Position {fpos} already committed")

        validOutput, faultPosition, shortOutput = self.get_result([(self.fround, fpos, 1)])

        # not 4 faults in fround-1 or not 16 faults in fround-2
        if not validOutput:
            return False

        col = self.columnByByte[faultPosition[0]]
        # verify that every byte has the same column (or None)
        if not all([self.columnByByte[x] == col for x in faultPosition]):
            return False

        if col is not None:
            # check if 4 fault positions have already be found for this column
            if len(self.columnPos[col]) == 4:
                return False

            # check if the fault isn't a duplicate
            if shortOutput in self.commitedFault[col]:
                return False
        else:
            if self.foundColumn == 4:
                return False

        faults = set([shortOutput])

        for fvalue in range(2, 256):
            validOutput, faultPosition2, shortOutput2 = self.get_result([(self.fround, fpos, fvalue)])

            if not validOutput:
                return False
            elif faultPosition2 != faultPosition:
                return False
            elif shortOutput2 in faults:
                return False
            elif col is not None and shortOutput2 in self.commitedFault[col]:
                return False
            else:
                faults.add(shortOutput2)

        # now, we know that the fault position is valid, commit it
        self.commitedPosition[fpos] = True

        # allocate a new column if needed
        if col is None:
            col = self.foundColumn
            self.foundColumn += 1
            for p in faultPosition:
                self.columnByByte[p] = col

        # add the position to the column
        self.columnPos[col].append(fpos)

        # add the fault in the known faults
        self.commitedFault[col].update(faults)

        return True

    def allPositionFound(self):
        return all(self.commitedPosition)

