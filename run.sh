#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH=$SCRIPT_DIR
VENV_BINARY=$SCRIPT_DIR/venv/bin/python
MODULE=app.main

sudo -E \
     PYTHONDONTWRITEBYTECODE=1 \
     PYTHONPATH=${PYTHONPATH} \
     ROOT_PATH=${SCRIPT_DIR} \
     ${VENV_BINARY} -B -u -O -m ${MODULE}
