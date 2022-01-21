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

from .AES import InvShiftRow, ShiftRow, xor, _AesShiftRow, _AesInvShiftRow
from .AES import MC, InvMC
from .Exception import InvalidArgument, WhiteBoxError, FaultPositionError, UnexpectedFailure
from .WhiteBoxedAES import WhiteBoxedAESDynamic, WhiteBoxedAESAuto
from .FaultPositionValidator import FaultPositionValidator
from collections.abc import Iterable
import random
import tqdm

class WhiteBoxedReverseRound:

    def __init__(self, encrypt, revertLastShift=True, outputF=None, reverseMC=False):
        self.encrypt = encrypt
        self.revertLastShift = revertLastShift
        self.outputF = outputF
        self.reverseMC = reverseMC

    def __call__(self, data):
        if self.revertLastShift:
            if self.encrypt:
                data = InvShiftRow(data)
            else:
                data = ShiftRow(data)
        if self.outputF is not None:
            for num, perm in enumerate(self.outputF):
                data = perm.encode(data)
                if self.reverseMC or num < len(self.outputF) - 1:
                    if self.encrypt:
                        data = InvShiftRow(InvMC(data))
                    else:
                        data = ShiftRow(MC(data))
        return data

class WhiteBoxedAESProxy:

    def __init__(self, realWB, noprogress):
        self.realWB = realWB
        self.enc = self.realWB.isEncrypt()
        self.roundNumber = self.realWB.getRoundNumber()
        self.useReverse = self.realWB.hasReverse()
        self.lastRoundHasMC = getattr(self.realWB, "lastRoundHasMC", None)
        self.random_input = []
        self.noprogress = noprogress

        # auto mode variable
        self.autoAvailablePosition = {}
        self.lastFaultPosition = None
        self.validatePositionNumber = 1

        self.detectLastRound()

    def getRoundNumber(self):
        return self.roundNumber

    def isEncrypt(self):
        return self.enc

    def hasReverse(self):
        return self.useReverse

    def newThread(self):
        if hasattr(self.realWB, "newThread") and callable(self.realWB.newThread):
            self.realWB.newThread()

    def applyReverse(self, data, revertLastShift=True):
        if revertLastShift:
            if self.enc:
                data = ShiftRow(data)
            else:
                data = InvShiftRow(data)
        out = self.realWB.applyReverse(data)
        return out

    def apply(self, data, revertLastShift=True, outputF=None, reverseMC=False):
        out = self.realWB.apply(data)
        return WhiteBoxedReverseRound(self.enc,
                                      revertLastShift=revertLastShift,
                                      outputF=outputF,
                                      reverseMC=reverseMC)(out)

    def applyFault(self, data, fault, revertLastShift=True, outputF=None, reverseMC=False):
        for fround, _, _ in fault:
            self.lastFaultPosition = fround
        out = self.realWB.applyFault(data, fault)
        return WhiteBoxedReverseRound(self.enc,
                                      revertLastShift=revertLastShift,
                                      outputF=outputF,
                                      reverseMC=reverseMC)(out)

    def getRandomInput(self, n=0):
        # allows the whitebox to choose mref and the retry input for step4 and
        # step5
        if hasattr(self.realWB, 'getRandomInput') and callable(self.realWB.getRandomInput):
            return self.realWB.getRandomInput(n)

        while len(self.random_input) <= n:
            self.random_input.append(random.randbytes(16))
        return self.random_input[n]

    def selfTest(self):
        InvalidArgument.check( self.roundNumber in [10, 12, 14],
            f"roundNumber ({self.roundNumber}) must be equal to 10, 12 or 14")

        # test generic property
        if self.useReverse:
            for i in range(16):
                data = random.randbytes(16)
                expect = self.apply(data)
                WhiteBoxError.check( self.applyReverse(expect) == data,
                    f"applyReverse must be the inverse of apply if available")

    def detectLastRound(self):

        if self.lastRoundHasMC is not None:
            return

        data = bytes([0]*16)
        unfaultRes = self.apply(data)
        self.prepareFaultPosition(self.getRoundNumber() - 1)
        faultRes = self.applyFault(data, [(self.getRoundNumber() - 1, 15, 1)])
        pfault = bytes([0 if a == b else 1 for a, b in zip(unfaultRes, faultRes)])
        nfault = sum(pfault)

        FaultPositionError.check(nfault in [1, 4], 15, 1)

        if nfault == 1:
            self.lastRoundHasMC = False
        elif nfault == 4:
            self.lastRoundHasMC = True

    def prepareFaultPosition(self, fround, revertLastShift=True, outputF=None, reverseMC=False):
        baseReverse = WhiteBoxedReverseRound(self.enc, revertLastShift=revertLastShift,
                                             outputF=outputF, reverseMC=reverseMC)
        if outputF is None:
            baseReverse2 = None
        elif len(outputF) >= 1 and reverseMC:
            baseReverse2 = WhiteBoxedReverseRound(self.enc, revertLastShift=revertLastShift,
                                                  outputF=outputF, reverseMC=False)
        elif len(outputF) > 1:
            baseReverse2 = WhiteBoxedReverseRound(self.enc, revertLastShift=revertLastShift,
                                                  outputF=outputF[:-1], reverseMC=reverseMC)
        else:
            baseReverse2 = None

        if isinstance(self.realWB, WhiteBoxedAESDynamic):
            self.realWB.prepareFaultPosition(fround, baseReverse, baseReverse2)
        if self.isAuto():
            self.performFaultSelection(fround, baseReverse, baseReverse2)

    def isAuto(self):
        return isinstance(self.realWB, WhiteBoxedAESAuto)

    def performFaultSelection(self, fround, baseReverse, baseReverse2):
        UnexpectedFailure.check( self.isAuto(),
            "Cannot use performFaultSelection without WhiteBoxedAESAuto")
        InvalidArgument.check(0 <= fround and fround < self.getRoundNumber(),
            "Unsupported fround ({fround})")
        self.lastFaultPosition = fround

        if fround not in self.autoAvailablePosition:
            self.autoAvailablePosition[fround] = [False for x in range(16)]

        # round position already valid
        if all(self.autoAvailablePosition[fround]):
            return

        currentValidation = 0
        alreadyKnow = sum([1 for x in self.autoAvailablePosition[fround] if x])

        with tqdm.tqdm(desc=f"Position tested for round {fround}", disable=self.noprogress,
                       position=1, unit='pos') as pbarIt:
            with tqdm.tqdm(desc="WhiteBox iteration", unit='it', disable=self.noprogress, position=0) as pbarWbIt:

                # try many time in order to detect wrong position with another value
                firstLoop = True
                while firstLoop or currentValidation < self.validatePositionNumber:
                    firstLoop = False
                    committedPos = 0
                    helper = FaultPositionValidator(self.realWB, fround, baseReverse, baseReverse2, pbarWbIt)

                    # 1. commit the existing valid position
                    for fbytes in range(16):
                        if self.autoAvailablePosition[fround][fbytes]:
                            accepted = helper.test_and_commit(fbytes)

                            if accepted:
                                committedPos += 1
                            else:
                                self.realWB.removeFaultPosition(fround, fbytes)
                                self.autoAvailablePosition[fround][fbytes] = False

                    if committedPos == 16:
                        UnexpectedFailure.check(helper.allPositionFound(),
                                "Missing position")
                        currentValidation += 1
                        continue
                    currentValidation = 0

                    # 2. fill missing position
                    for fbytes in range(16):
                        if self.autoAvailablePosition[fround][fbytes]:
                            continue

                        while True:
                            self.realWB.changeFaultPosition(fround, fbytes)
                            accepted = helper.test_and_commit(fbytes)
                            pbarIt.update(1)
                            if accepted:
                                break
                            else:
                                self.realWB.removeFaultPosition(fround, fbytes)

                        self.autoAvailablePosition[fround][fbytes] = True

                    UnexpectedFailure.check(helper.allPositionFound(),
                                "Missing position")

    def handleException(self, e):
        UnexpectedFailure.check( self.isAuto(),
            "Cannot use handleException without WhiteBoxedAESAuto")
        if isinstance(e, FaultPositionError):
            if isinstance(e.byteNumber, Iterable):
                for fbytes in e.byteNumber:
                    self.clearFaultPosition(fround=e.roundNumber, fbytes=fbytes)
            else:
                self.clearFaultPosition(fround=e.roundNumber, fbytes=e.byteNumber)
        else:
            self.clearFaultPosition(fround=self.lastFaultPosition)
            self.lastFaultPosition = None

    def clearFaultPosition(self, fround=None, fbytes=None):
        UnexpectedFailure.check( self.isAuto(),
            "Cannot use clearFaultPosition without WhiteBoxedAESAuto")
        InvalidArgument.check(fround is None or (0 <= fround and fround < self.getRoundNumber()),
            "Unsupported fround ({fround})")
        InvalidArgument.check(fbytes is None or (0 <= fbytes and fbytes < 16),
            "Unsupported fbytes ({fbytes})")

        if fround is None:
            # remove all fault position
            for fround, byteAvailable in self.autoAvailablePosition.items():
                for fbytes, available in enumerate(byteAvailable):
                    if available:
                        self.realWB.removeFaultPosition(fround, fbytes)
            self.autoAvailablePosition = {}
        elif fround not in self.autoAvailablePosition.keys():
            pass
        elif fbytes is None:
            # remove all fault position of a round
            for fbytes, available in enumerate(self.autoAvailablePosition[fround]):
                if available:
                    self.realWB.removeFaultPosition(fround, fbytes)
            self.autoAvailablePosition.pop(fround)
        else:
            # remove a fault position
            if self.autoAvailablePosition[fround][fbytes]:
                self.realWB.removeFaultPosition(fround, fbytes)
                self.autoAvailablePosition[fround][fbytes] = False
