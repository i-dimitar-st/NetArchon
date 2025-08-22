#!/bin/bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH=$ROOT_PATH
VENV_BINARY=$ROOT_PATH/venv/bin/python
APP_MAIN=app.main

# -B => no pyc files
# -u => unbuffered
# -o => optimisation
# -m => runs as script

sudo ROOT_PATH=${ROOT_PATH} \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH=${PYTHONPATH} \
	${VENV_BINARY} -B -u -O -m ${APP_MAIN}
