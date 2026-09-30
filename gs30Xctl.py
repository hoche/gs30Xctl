#!/usr/bin/env python3
"""
Compatibility shim: the code now lives in the `gs30xctl` package (src/gs30xctl).
Prefer `pip install .` and then `gs30xctl ...` or `python -m gs30xctl ...`.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from gs30xctl import *  # noqa: E402,F401,F403  (re-export for old `import gs30Xctl` users)
from gs30xctl.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
