#!/usr/bin/env python3
"""Entry point for the AI Tarpit honeypot — run it without installing the package.

From the repository root, after installing the runtime dependencies
(``pip install -r requirements.txt``), run::

    python aitarpit.py [command] [options]

``run`` is the default command, so ``python aitarpit.py`` with no command runs the
honeypot. This launcher puts the repository root on ``sys.path`` so the ``aitarpit``
package imports directly from the checkout — no ``pip install`` of the project itself is
needed. Commands: ``init-config``, ``validate``, ``run``, ``techniques``, ``test-alert``,
``report``, ``export``. Run ``python aitarpit.py <command> --help`` for a command's options.

The companion test tool has its own launcher: ``python test.py <command>``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the checked-out package without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aitarpit.cli import main  # noqa: E402  (path set up above)

if __name__ == "__main__":
    raise SystemExit(main())
