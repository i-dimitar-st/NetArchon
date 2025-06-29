PYTHONPATH=.
VENV_BINARY=./venv/bin/python
SCRIPT=main.py

# -u: Unbuffered stdout/stderr (real-time logs).
# -O: Enable optimized mode:
#     - Removes all assert statements (they are not executed).
#     - Sets the built-in constant __debug__ to False (disables debug-only code blocks).

sudo PYTHONDONTWRITEBYTECODE=1 \
     PYTHONPATH=${PYTHONPATH} \
     ${VENV_BINARY} -u -O ${SCRIPT}