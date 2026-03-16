#!/usr/bin/env python
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "idapro",
#     "ida-domain",
#     "rich",
# ]
# ///
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mapa.cli import main

if __name__ == "__main__":
    sys.exit(main())
