"""Executable Chimera verification runner.

Runs contract-level tests and build gate sanity checks.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).parent
    cmd = [sys.executable, "-m", "unittest", "tests.test_chimera_core"]
    proc = subprocess.run(cmd, cwd=root)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
