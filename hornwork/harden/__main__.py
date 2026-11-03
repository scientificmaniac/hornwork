"""python -m hornwork.harden 入口（等价 hardenctl）。"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
