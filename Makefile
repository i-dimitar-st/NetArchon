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
STATIC_DIR := $(APP)/services/gui/static
STATIC_JS := $(STATIC_DIR)/js
STATIC_CSS := $(STATIC_DIR)/css
STATIC_WEBFONTS := $(STATIC_DIR)/webfonts

BOOTSTRAP_VER := 5.3.0
REACT_VER := 18.2.0
BABEL_VER := 7.23.9
FONTAWESOME_VER := 6.4.0


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

download_static:
	mkdir -p $(STATIC_JS) $(STATIC_CSS) $(STATIC_WEBFONTS)
	# Bootstrap
	curl -L -o $(STATIC_JS)/bootstrap.bundle.min.v$(BOOTSTRAP_VER).js https://cdnjs.cloudflare.com/ajax/libs/bootstrap/$(BOOTSTRAP_VER)/js/bootstrap.bundle.min.js
	curl -L -o $(STATIC_CSS)/bootstrap.min.v$(BOOTSTRAP_VER).css https://cdnjs.cloudflare.com/ajax/libs/bootstrap/$(BOOTSTRAP_VER)/css/bootstrap.min.css

	# React + Babel
	curl -L -o $(STATIC_JS)/react.production.min.v$(REACT_VER).js https://unpkg.com/react@$(REACT_VER)/umd/react.production.min.js
	curl -L -o $(STATIC_JS)/react-dom.production.min.v$(REACT_VER).js https://unpkg.com/react-dom@$(REACT_VER)/umd/react-dom.production.min.js
	curl -L -o $(STATIC_JS)/babel.min.v$(BABEL_VER).js https://unpkg.com/@babel/standalone@$(BABEL_VER)/babel.min.js

	# Font Awesome
	curl -L -o $(STATIC_CSS)/fontawesome.all.min.v$(FONTAWESOME_VER).css https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/css/all.min.css
	curl -L -o $(STATIC_WEBFONTS)/fa-solid-900.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-solid-900.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-regular-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-regular-400.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-brands-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-brands-400.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-solid-900.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-solid-900.woff
	curl -L -o $(STATIC_WEBFONTS)/fa-regular-400.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-regular-400.woff
	curl -L -o $(STATIC_WEBFONTS)/fa-brands-400.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-brands-400.woff


run:
	@echo "Not configured yet"
