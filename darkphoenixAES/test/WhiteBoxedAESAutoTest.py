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

from ..WhiteBoxedAES import WhiteBoxedAESAuto
from .WhiteBoxedAESTest import WhiteBoxedAESTest
import random

class WhiteBoxedAESAutoTest(WhiteBoxedAESTest, WhiteBoxedAESAuto):

    def __init__(self, aesEncoded, enc=True, useReverse=True, fast=True,
                 multiFault=True):
        super().__init__(aesEncoded, enc=enc, useReverse=useReverse, fast=fast)
        self.multiFault = multiFault

        self.faultPosition = {}

    def applyFault(self, data, faults):
        to_apply = []

        for fround, fbytes, fxorval in faults:
            assert (fround, fbytes) in self.faultPosition, f"fault position for round {fround} byte {fbytes} is missing"

            for (fround2, fbytes2) in self.faultPosition[(fround, fbytes)]:
                to_apply.append((fround2, fbytes2, fxorval))

        return super().applyFault(data, to_apply)

    def changeFaultPosition(self, fround, fbytes):
        self.faultPosition[(fround, fbytes)] = self._get_random_position()

    def removeFaultPosition(self, fround, fbytes):
        self.faultPosition.pop((fround, fbytes), None)

    def _get_random_position(self):
        fround = random.randrange(self.getRoundNumber())
        fbytes = random.randrange(16)
        fault = [ (fround, fbytes) ]

        if not self.multiFault:
            return fault

        numFault = random.choices((1, 2, 3), weights=(40, 40, 20))[0]
        while len(fault) != numFault:
            fround2 = fround + random.choices((-2, -1, 0, 1, 2), weights=(5, 25, 40, 25, 5))[0]
            if fround2 < 0 or fround2 >= self.getRoundNumber():
                continue
            fbytes2 = random.randrange(16)
            if (fround2, fbytes2) not in fault:
                fault.append((fround2, fbytes2))

        return fault
