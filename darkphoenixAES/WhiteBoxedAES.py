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


class WhiteBoxedAES:
    # This class is the interface with the whitebox (encrypt or decrypt).
    # A child class must be implemented for a whitebox with the same interface

    def getRoundNumber(self):
        # return the number of rounds of the whitebox (10 for AES128,
        #   12 for AES192 and 14 for AES256)
        raise NotImplementedError("WhiteBoxedAES.getRoundNumber must be implemented for a given whitebox")

    def isEncrypt(self):
        # Does the whitebox encrypt of decrypt data
        # (needed and validate with the MixColumns result)
        raise NotImplementedError("WhiteBoxedAES.isEncrypt must be implemented for a given whitebox")

    def hasReverse(self):
        # Is there an applyReverse method that can be called?
        raise NotImplementedError("WhiteBoxedAES.hasReverse must be implemented for a given whitebox")

    def newThread(self):
        # [optionnal]
        # When a new process starts, the whitebox is copied in the new thread.
        # This method is called on the WhiteBoxed copy before any call to apply,
        # applyReverse, applyRound or applyFault
        # If some elements cannot be shared when forking a process, they must be
        # reallocated when this method is called.
        pass

    def apply(self, data):
        # Apply the whitebox on a buffer
        # [param] data  a buffer of 16 bytes (type bytes)
        # return  16 bytes of the encrypted/decrypted data
        raise NotImplementedError("WhiteBoxedAES.apply must be implemented for a given whitebox")

    def applyReverse(self, data):
        # The inverse of the method apply
        # If the encrypt and decrypt are available, the second method can be
        # used to avoid the bruteforce in Step1
        # [param] data  a buffer of 16 bytes (type bytes)
        # return  16 bytes of the decrypted/encrypted data
        raise NotImplementedError("WhiteBoxedAES.applyReverse must be implemented for a given whitebox")

    def applyRound(self, data, roundN):
        # Apply a round of the whitebox on a buffer
        # [param] data    a buffer of 16 bytes (type bytes)
        # [param] roundN  the round number to apply (int in the range [0, self.getRoundNumber()) )
        # return  16 bytes of the encrypted data by the round
        #
        # [note] This function will only be used by applyFault.
        #   You may keep it unimplemented if you provide your one applyFault
        raise NotImplementedError("WhiteBoxedAES.applyRound or WhiteBoxedAES.applyFault must be implemented for a given whitebox")

    def applyFault(self, data, faults):
        # Apply the whitebox on a buffer and inject fault at the given position
        # [param] data      a buffer of 16 bytes (type bytes)
        # [param] faults    a list of faults to apply:
        #       fround, fbytes, fxorval = faults[0]
        #       fround      the round to apply the fault. 0 is the first round
        #       fbytes      the position of the internal state byte to fault (between 0 and 15)
        #       fxorval     the fault to apply by xor (between 1 and 255)
        # return  16 bytes of the faulted encrypted data
        # [note] This function is already implemented by using applyRound.
        #   You can override it if you have a more efficient process to inject
        #   faults. You must override it if you don't provide applyRound.
        # [note] The attack calls this method with only one fault at a time.
        #   This behaviour may change in the future to limit the number of runs.
        # [note] The value of fbytes only specifies a different byte of the
        #   round. There is not consequence if the state is mixed as long as
        #   each value of fbytes targets a different byte.

        state = data[:]
        for roundN in range(self.getRoundNumber()):
            for fround, fbytes, fxorval in faults:
                if fround != roundN:
                    continue
                assert 0 <= fbytes and fbytes <= 15, "Invalid fbytes value"
                assert 1 <= fxorval and fxorval <= 255, "Invalid fxorval value"
                state = list(state)
                state[fbytes] ^= fxorval
            state = self.applyRound(bytes(state), roundN)
        return bytes(state)

class WhiteBoxedAESDynamic(WhiteBoxedAES):
    # This class is the interface with the whitebox (encrypt or decrypt).
    # This class should be used as a base class for the whitebox interface if
    # the fault position isn't known before the attack. During the attack, before
    # any faults are requested on a new round, the method prepareFaultPosition
    # will be called.
    #
    # The algorithm to find valid fault positions is to be implemented inside
    # prepareFaultPosition. If you don't want to implement it, you can use the
    # base class WhiteBoxedAESAuto instead of WhiteBoxedAESDynamic.

    def prepareFaultPosition(self, fround, reverseRoundMethod,
                             reverseRoundMethod2=None):
        # Before applyFault is called for the first time on a round, this
        # method is called. If the fault position isn't defined, the Whitebox
        # must determine the fault position for the specified round.
        #
        # [param] fround  The round where the fault will be injected
        # [param] reverseRoundMethod  A method that reverse the result at
        #   fround-1
        # [param] reverseRoundMethod2  A method that reverse the result at
        #   fround-2 (if available)
        #
        # [note] prepareFaultPosition is always called on the first instance of
        #   WhiteBoxedAES. The fault position doesn't need to be shared with
        #   other existing copies of WhiteBoxedAES, but must be shared with the
        #   future copies.
        # [note] prepareFaultPosition can be called many times for the same fround.
        #   The existing position must remain unchanged, except if a FaultPositionError
        #   has been raised for this round.
        # [note] During this method, the whitebox must find 16 fault positions,
        #   each one faults 4 bytes of reverseRoundMethod(self.applyFault(...)).
        #   Only 4 positions can fault the same 4 bytes (4 positions for each
        #   column), but each position must have a different result (like in
        #   classical DFA).
        # [note] reverseRoundMethod2 is provided to detect if the fault position
        #   is performed after the target round, instead of before it. When this
        #   function is provided, a valid fault position must fault all bytes
        #   reversed by this method.
        pass

class WhiteBoxedAESAuto(WhiteBoxedAES):
    # This class is the interface with the whitebox (encrypt or decrypt).
    # This class should be used as a base class for the whitebox interface if
    # the fault position isn't known before the attack and you want to use
    # darkPhoenix algorithm to validate the fault position.
    #
    # WhiteBoxedAESAuto only needs to keep the correspondence between
    # (fround, fbytes) and the last position returned by changeFaultPosition.

    def changeFaultPosition(self, fround, fbytes):
        # select a new position for the fault (fround, fbytes).
        # This position must be valid (doesn't crash the programm)
        # for any fault value (between 1 and 255 included).
        #
        # [param] (fround, fbytes)  The parameter that will be used by
        #   applyFault to inject a fault in the selected position.
        #
        # [note] changeFaultPosition doesn't need to exclude already associated
        #   position. The algorithm should work with a random position, as long
        #   as the fault injection at this position does not crash the program.
        pass

    def removeFaultPosition(self, fround, fbytes):
        # [optionnal]
        # Inform that the fault position associated with (fround, fbytes) isn't
        # the expected position, or the algorithm reaches an exception while using
        # this position. WhiteBoxedAESAuto can forget the association between
        # the position and (fround, fbytes).
        #
        # [param] (fround, fbytes)  The parameter of the fault
        #
        # [note] This method only aims at signaling that the fault position must
        #   be dissociated with the parameter (fround, fbytes), but must remain
        #   in the positions assignable by changeFaultPosition, including for
        #   the parameter (fround, fbytes).
        pass

