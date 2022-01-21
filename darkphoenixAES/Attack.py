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

from .WhiteBoxedAESProxy import WhiteBoxedAESProxy
from .Encoding import Encoding
from .AES import revertKey
from .Exception import InvalidArgument, UnexpectedFailure, InvalidState, DarkPhoenixException
import os
import json
from . import Step1
from . import Step2
from . import Step3
from . import Step4
from . import Step5
from . import ExtractEncoding

class Attack:

    # wbAES is an implementation of WhiteBoxedAES for the whitebox to attack
    def __init__(self, wbAES, nprocess=None, noprogress=None, sageSubProc=True, step1DoubleValue=False):

        self.wb = WhiteBoxedAESProxy(wbAES, noprogress)
        self.wb.selfTest()

        self.state = 0
        if nprocess is None:
            self.nprocess = self.detectCPU()
        else:
            self.nprocess = nprocess
        self.noprogress = noprogress
        self.sageSubProc = sageSubProc
        self.step1DoubleValue = step1DoubleValue

        # step1 value
        self.mref = self.wb.getRandomInput()
        self.r_s = []
        self.M = []
        self.gtilde_inv = Encoding([])
        self.Gbar_inv = Encoding([])
        self.roundShift = []
        self.C = []
        self.lambdaCol = []
        self.betaCol = []
        self.keyPart = []

    @staticmethod
    def detectCPU():
        try:
            return len(os.sched_getaffinity(0))
        except:
            pass
        nCPU = os.cpu_count()
        if nCPU is not None:
            return nCPU
        else:
            return 0

    def save(self, filename):
        if filename is None:
            return

        data = {
            "State": self.state,
            "Mref": self.mref.hex(),
            "r_s": self.r_s,
            "M": [[x.hex() for x in mi] for mi in self.M],
            "gtilde_inv": self.gtilde_inv.toTable(),
            "Gbar_inv": self.Gbar_inv.toTable(),
            "roundShift": self.roundShift,
            "C": self.C,
            "lambdaCol": self.lambdaCol,
            "betaCol": self.betaCol,
            "keyPart": self.keyPart,
        }

        with open(filename, 'w') as f:
            f.write(json.dumps(data, indent=2))

    def restore(self, filename):

        if not os.path.isfile(filename):
            raise FileNotFoundError(f"File not found : {filename}")

        with open(filename, 'r') as f:
            data = json.loads(f.read())
        self.state = data["State"]
        self.mref = bytes.fromhex(data["Mref"])
        if "r_s" in data:
            self.r_s = data["r_s"]
        if "M" in data:
            self.M = [[bytes.fromhex(x) for x in mi] for mi in data["M"]]
        if "gtilde_inv" in data:
            self.gtilde_inv = Encoding.fromTable(data["gtilde_inv"])
        if "Gbar_inv" in data:
            self.Gbar_inv = Encoding.fromTable(data["Gbar_inv"])
        if "roundShift" in data:
            self.roundShift = data["roundShift"]
        if "C" in data:
            self.C = data["C"]
        if "lambdaCol" in data:
            self.lambdaCol = data["lambdaCol"]
        if "betaCol" in data:
            self.betaCol = data["betaCol"]
        if "keyPart" in data:
            self.keyPart = data["keyPart"]

    def runAuto(self, backupFile=None, retry=-1):
        if self.wb.isAuto():
            currentRun = 0
            success = False
            while not success:
                try:
                    self.run(backupFile)
                    success = True
                except DarkPhoenixException as e:
                    if currentRun == retry:
                        raise e
                    currentRun += 1
                    print(f"{e.__class__.__name__}: {e}: retry... ")
                    self.wb.handleException(e)
        else:
            self.run(backupFile)

    def run(self, backupFile=None):
        if backupFile is not None and os.path.isfile(backupFile):
            self.restore(backupFile)

        self.step1(backupFile)
        self.step2(backupFile)
        self.step3(backupFile)
        self.step4(backupFile)
        self.step5(backupFile)

    def step1(self, backupFile=None):
        if self.state == 0:
            self._step1()
            self.state = 1
            self.save(backupFile)

    def step2(self, backupFile=None):
        if self.state == 1:
            self.verifyStep1()
            self._step2()
            self.state = 2
            self.save(backupFile)
        elif self.state < 1:
            raise InvalidState("Cannot perform step2 before step1")

    def step3(self, backupFile=None):
        if self.state == 2:
            self._step3()
            self.state = 3
            self.save(backupFile)
        elif self.state < 2:
            raise InvalidState("Cannot perform step3 before step2")

    def step4(self, backupFile=None):
        if self.state == 3:
            self._step4()
            self.state = 4
            self.save(backupFile)
        elif self.state < 3:
            raise InvalidState("Cannot perform step4 before step3")

    def step5(self, backupFile=None):
        if self.state == 4:
            self._step5()
            self.state = 5
            self.save(backupFile)
        elif self.state < 4:
            raise InvalidState("Cannot perform step5 before step4")

    def printKey(self):
        if self.state < 5:
            self.run()
        if self.wb.isEncrypt():
            offset = self.wb.getRoundNumber() - 2
            for index, key in reversed(list(enumerate(self.keyPart))):
                print("k{:02d}: {}".format(offset - index, bytes(key).hex()))
        else:
            for index, key in enumerate(self.keyPart):
                print("k{:02d}: {}".format(index + 2, bytes(key).hex()))

    def getKey(self, keyLen=None, forceOffset=None):
        if keyLen is None:
            keyLen = {10: 16, 12: 24, 14: 32}[self.wb.getRoundNumber()]
        InvalidArgument.check( keyLen in [16, 24, 32],
            f"keyLen ({keyLen}) must be equal to 16, 24 or 32")
        if self.state < 5:
            self.run()
        if self.wb.isEncrypt():
            firstKey = self.wb.getRoundNumber() - 1 - len(self.keyPart)
            rKeyBuff = b"".join([bytes(x) for x in reversed(self.keyPart)])
        else:
            firstKey = 2
            rKeyBuff = b"".join([bytes(x) for x in self.keyPart])
        if forceOffset is not None:
            firstKey = forceOffset
        key = None
        for index in range(len(rKeyBuff) // keyLen):
            rkey = revertKey(rKeyBuff[index*16:index*16+keyLen], index + firstKey)
            if key is None:
                key = rkey
            else:
                UnexpectedFailure.check(key == rkey,
                    "Round key doesn't provide the same AES Key")
        return key

    def externalEncoding(self, keyLen=None, forceOffset=None):
        key = self.getKey(keyLen, forceOffset)
        return ExtractEncoding.getExternalEncoding(
                self.wb, self.gtilde_inv, self.Gbar_inv, self.C,
                self.lambdaCol, self.betaCol, key)


    def verifyStep1(self):
        InvalidState.check( len(self.mref) == 16, "Invalid Step1 state")
        InvalidState.check( len(self.M) == 16, "Invalid Step1 state")
        for mi in self.M:
            InvalidState.check( len(set(mi)) == 256, "Invalid Step1 state")
            InvalidState.check( self.mref in mi, "Invalid Step1 state")
            InvalidState.check( all([len(x) == 16 for x in mi]), "Invalid Step1 state")

        InvalidState.check( len(self.r_s) == 16, "Invalid Step1 state")
        for i, v in enumerate(self.r_s):
            if len(v) == 1:
                InvalidState.check( i != v[0], "Invalid Step1 state")
                InvalidState.check( v[0] // 4 == i // 4, "Invalid Step1 state")
            else:
                InvalidState.check( len(v) == 2, "Invalid Step1 state")
                r, s = v
                InvalidState.check( i != r and i != s and r != s, "Invalid Step1 state")
                InvalidState.check( r // 4 == i // 4, "Invalid Step1 state")
                InvalidState.check( s // 4 == i // 4, "Invalid Step1 state")
        Step1.verify(self.wb, self.mref, self.M, self.r_s, self.noprogress)

    def _step1(self):
        self.M, self.r_s = Step1.compute(self.wb, self.mref, self.nprocess,
                self.noprogress, self.step1DoubleValue)

    def _step2(self):
        self.gtilde_inv = Step2.compute(self.wb, self.M, self.r_s, self.nprocess,
                self.noprogress)

    def _step3(self):
        self.Gbar_inv, self.roundShift, self.C = Step3.compute(
                self.wb, self.gtilde_inv, self.mref,
                self.noprogress, self.sageSubProc)

    def _step4(self):
        self.lambdaCol, self.betaCol = Step4.compute(
                self.wb, self.gtilde_inv, self.Gbar_inv, self.C, self.mref,
                self.noprogress)

    def _step5(self):
        self.keyPart = Step5.compute(
                self.wb, self.gtilde_inv, self.Gbar_inv, self.C,
                self.lambdaCol, self.betaCol, self.mref, self.noprogress)

