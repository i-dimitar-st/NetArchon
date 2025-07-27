#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH=$SCRIPT_DIR
VENV_BINARY=$SCRIPT_DIR/venv/bin/python
SCRIPT=main.py

# -u: Unbuffered stdout/stderr for real-time logs.
# -O: Optimized mode (removes asserts, sets __debug__ to False).
# -B: Don't write .pyc files or __pycache__ folders.
# sudo -E: Preserve environment variables when using sudo.

sudo -E \
     PYTHONDONTWRITEBYTECODE=1 \
     PYTHONPATH=${PYTHONPATH} \
     ${VENV_BINARY} -B -u -O ${SCRIPT}
