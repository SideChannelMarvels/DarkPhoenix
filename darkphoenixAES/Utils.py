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

import subprocess
import json
import os
import importlib
from .Exception import UnexpectedFailure

class SageProcess:

    def __init__(self, script, module, classname, useSubproc=False):
        self.useSubproc = useSubproc
        if self.useSubproc:
            pInput, sndPipe = os.pipe()
            rcvPipe, pOutput = os.pipe()
            scriptPath = os.path.join(os.path.dirname(__file__), script)
            self.p = subprocess.Popen(['sage', scriptPath], stdin=pInput, stdout=pOutput)
            os.close(pInput)
            os.close(pOutput)
            self.sndPipe = os.fdopen(sndPipe, mode='w')
            self.rcvPipe = os.fdopen(rcvPipe, mode='r')
            self.isClose = False
        else:
            if module[0] == '.':
                package = os.path.basename(os.path.dirname(__file__))
                mod = importlib.import_module(module, package=package)
            else:
                mod = importlib.import_module(module)
            self.target = getattr(mod, classname)()


    def __call__(self, *args):
        if self.useSubproc:
            UnexpectedFailure.check(not self.isClose, "Cannot call SageProcess after __exit__")
            UnexpectedFailure.check(self.p.poll() is None, "SageProcess has been terminated")
            self.sndPipe.write(json.dumps(args) + '\n')
            self.sndPipe.flush()
            resline = self.rcvPipe.readline()
            while resline == "":
                UnexpectedFailure.check(self.p.poll() is None, "SageProcess has been terminated")
                resline = self.rcvPipe.readline()
            return json.loads(resline)
        else:
            return self.target(*args)

    def close(self):
        if not self.useSubproc or self.isClose:
            return
        self.isClose = True

        try:
            if self.p.poll() is None:
                self.sndPipe.write("stop\n")
            self.sndPipe.close()
        except BrokenPipeError:
            pass

        try:
            self.rcvPipe.close()
        except BrokenPipeError:
            pass

        self.p.wait(1)
        if self.p.poll() is None:
            self.p.kill()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()
