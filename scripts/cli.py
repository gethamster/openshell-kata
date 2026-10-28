#!/usr/bin/env python3
"""Use the official CLI with only this repository's local test state."""
import os
import sys
from local import LOCAL, environment

os.execve(str(LOCAL / "bin/openshell"), ["openshell", *sys.argv[1:]], environment())
