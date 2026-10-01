#!/usr/bin/env python3
"""Repository and installed entry point; no shell evaluation of configuration."""
import pathlib
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "lib"))
from tunnel.manager import main
if __name__ == "__main__":
    sys.exit(main())
