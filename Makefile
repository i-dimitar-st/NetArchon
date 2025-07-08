PYTHON := python
VENV := venv
ACTIVATE := source $(VENV)/bin/activate
SCRIPTS := scripts
SRC := src

.PHONY: set_net_buffers \
		install_venv install_requirements \
		install_requirements \
		generate_ssl \
		generate_config \
		create_systemd \
		run_tests

set_net_buffers:
	$(SCRIPTS)/set_buffers.sh

install_venv:
	$(PYTHON) -m venv $(VENV)

install_requirements:
	$(VENV)/bin/pip install -r requirements.txt

install_requirements-dev:
	$(VENV)/bin/pip install -r requirements-dev.txt

generate_ssl:
	$(SCRIPTS)/generate_ssl.sh

generate_config:
	$(PYTHON) $(SCRIPTS)/make_config.py

create_systemd:
	$(SCRIPTS)/make_systemd_service.sh

run_tests:
	@APP_ROOT_PATH=$(shell pwd) $(VENV)/bin/python -m pytest -s --tb=line