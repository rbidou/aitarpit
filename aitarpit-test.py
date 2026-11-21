#!/usr/bin/env python3
"""Entry point for the AI Tarpit test tool — run it without installing the package.

From the repository root, after installing the runtime dependencies
(``pip install -r requirements.txt``), run::

    python aitarpit-test.py <command> [options]

This launcher puts the repository root on ``sys.path`` so the ``tester`` package imports
directly from the checkout — no ``pip install`` of the project itself is needed. Commands:
``check`` (deterministic per-technique conformance) and ``agent`` (origin-locked LLM
attacker). Run ``python aitarpit-test.py <command> --help`` for a command's options.

The honeypot itself has its own launcher: ``python aitarpit.py <command>``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the checked-out package without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tester.cli import main  # noqa: E402  (path set up above)

if __name__ == "__main__":
    raise SystemExit(main())
