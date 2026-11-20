#!/usr/bin/env python
"""Convenience launcher for the sigmatch PyQt6 desktop UI."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from sigmatch.gui import main as gui_main
    except ImportError as exc:
        if "PyQt6" in str(exc):
            if sys.stderr is not None:
                print(
                    "sigmatch requires PyQt6 for its desktop UI.",
                    "Install it with: python -m pip install PyQt6",
                    sep=chr(10),
                    file=sys.stderr,
                )
            return 2
        raise
    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
