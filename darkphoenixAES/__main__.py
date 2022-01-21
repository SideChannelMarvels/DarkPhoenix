#!/usr/bin/env python

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

import sys
from .test.test_AES import test_AES
from .test.test_Encoding import test_Encoding
from .test.test_WhiteBoxedAESProxy import test_WhiteBoxedAESProxy
from .test.test_Attack import test_Attack


def test():
    test_AES()
    test_Encoding()
    test_WhiteBoxedAESProxy()
    test_Attack()

if len(sys.argv) > 1 and '--selftest' in sys.argv:
    sys.argv.pop(sys.argv.index('--selftest'))
    test()
