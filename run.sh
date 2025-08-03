#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH=$SCRIPT_DIR
VENV_BINARY=$SCRIPT_DIR/venv/bin/python
MODULE=app.main

# -B no pyc files
# -u unbuffered
# -o optimisation
# -m runs as script

sudo PYTHONDONTWRITEBYTECODE=1 \
     PYTHONPATH=${PYTHONPATH} \
     ${VENV_BINARY} -B -u -O -m ${MODULE}
