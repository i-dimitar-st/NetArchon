ROOT_PATH := $(abspath $(CURDIR))

VENV_DIR := venv
VENV := $(ROOT_PATH)/$(VENV_DIR)
VENV_PIP := $(VENV)/bin/pip
VENV_BLACK := $(VENV)/bin/black
VENV_ISORT := $(VENV)/bin/isort
VENV_FLAKE8 := $(VENV)/bin/flake8
VENV_PYTHON := $(VENV)/bin/python

SCRIPTS := $(ROOT_PATH)/scripts
APP := $(ROOT_PATH)/app
APP_MAIN := app.main
APP_NEURAL_NET := app.services.neural_net.neural_net

.PHONY: set_net \
        install \
        generate_ssl \
        create_systemd \
        make_config \
        test \
        format \
        lint \
        del_cache \
        run \
		train \
		setup

setup: set_net \
	   install \
	   generate_files \
	   make_config

set_net:
	$(SCRIPTS)/set_net_buffers.sh

install:
	python3 -m venv $(VENV)
	$(VENV_PIP) install -r requirements.txt
	$(VENV_PIP) install -r requirements-dev.txt

generate_ssl:
	ROOT_PATH=$(ROOT_PATH) $(SCRIPTS)/generate_ssl.sh

create_systemd:
	ROOT_PATH=$(ROOT_PATH) $(SCRIPTS)/make_systemd_service.sh

make_config:
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_blacklists.py
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_config.py
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_dhcp_static_map.py

test:
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) -m pytest

format:
	$(VENV_BLACK) $(APP)
	$(VENV_ISORT) $(APP)

lint:
	$(VENV_FLAKE8) $(APP)

del_cache:
	find $(APP) -type d -name "__pycache__" -exec rm -rf {} +

train:
	@PYTHONPATH=$(ROOT_PATH) ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) -m $(APP_NEURAL_NET)

run:
	@echo "Not configured yet"
