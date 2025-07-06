PYTHON := python
VENV := venv
ACTIVATE := source $(VENV)/bin/activate
SCRIPTS := scripts
SRC := src

.PHONY: venv requirements ssl config systemd test

venv:
	$(PYTHON) -m venv $(VENV)

requirements:
	$(VENV)/bin/pip install -r requirements.txt

requirements-dev:
	$(VENV)/bin/pip install -r requirements-dev.txt

ssl:
	$(SCRIPTS)/generate_ssl.sh

config:
	$(PYTHON) $(SCRIPTS)/make_config.py

systemd:
	$(SCRIPTS)/make_systemd_service.sh

test:
	@APP_ROOT_PATH=$(shell pwd) $(VENV)/bin/python -m pytest -s --tb=line