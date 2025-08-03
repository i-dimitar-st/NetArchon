#!/bin/bash

MAIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH=$MAIN_DIR
VENV_BINARY=$MAIN_DIR/venv/bin/python
MODULE=app.main

# -B no pyc files
# -u unbuffered
# -o optimisation
# -m runs as script

sudo PYTHONDONTWRITEBYTECODE=1 \
     PYTHONPATH=${PYTHONPATH} \
     ${VENV_BINARY} -B -u -O -m ${MODULE}
