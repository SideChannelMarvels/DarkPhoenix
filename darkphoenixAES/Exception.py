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

class DarkPhoenixException(Exception):
    "DarkPhoenix Internal Exception Base class"
    pass

    @classmethod
    def check(cls, cond, message):
        if not cond:
            raise cls(message)

class InvalidArgument(DarkPhoenixException):
    "When an invalid value is given as argument"
    pass

class InvalidState(DarkPhoenixException):
    "The current state isn't valid"
    pass

class UnexpectedFailure(DarkPhoenixException):
    "Invalid state, but no specific correction can be recommended"
    pass

class WhiteBoxError(DarkPhoenixException):
    "When the whitebox returns an incoherent result"
    pass

class FaultPositionError(DarkPhoenixException):
    "When the algorithm detects that the fault position isn't at the expected position"

    def __init__(self, roundNumber, byteNumber=None):
        if byteNumber is None:
            super().__init__(f"Wrong position for fault at round {roundNumber}")
        else:
            super().__init__(f"Wrong position for fault at round {roundNumber} byte {byteNumber}")

        self.roundNumber = roundNumber
        # byteNumber can be :
        # - None: if the wrong position is not known,
        # - an integer: if the exact position is known
        # - a list of integers: if the exact position is not known
        self.byteNumber = byteNumber

    @classmethod
    def check(cls, cond, roundNumber, byteNumber=None):
        if not cond:
            raise cls(roundNumber, byteNumber)
