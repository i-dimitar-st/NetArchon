ROOT_PATH := $(abspath $(CURDIR))

VENV := $(ROOT_PATH)/venv
VENV_PIP := $(VENV)/bin/pip
VENV_PYTHON := $(VENV)/bin/python
VENV_BLACK := $(VENV)/bin/black
VENV_AUTOPEP8 := $(VENV)/bin/autopep8
VENV_ISORT := $(VENV)/bin/isort
VENV_FLAKE8 := $(VENV)/bin/flake8

JINJA_CACHE_PATH := $(ROOT_PATH)/.jinja_cache
RUFF_CACHE_PATH := $(ROOT_PATH)/.ruff_cache

SCRIPTS := $(ROOT_PATH)/scripts
APP := $(ROOT_PATH)/src
APP_MAIN := src.main
APP_NEURAL_NET := src.services.neural_net.neural_net
APP_PROXY_DAP :=  $(ROOT_PATH)/src/services/http_proxy/dap_server.py
STATIC_DIR := $(APP)/services/gui/static
STATIC_JS := $(STATIC_DIR)/js
STATIC_CSS := $(STATIC_DIR)/css
STATIC_WEBFONTS := $(STATIC_DIR)/webfonts

BOOTSTRAP_VER := 5.3.0
REACT_VER := 18.2.0
BABEL_VER := 7.23.9
FONTAWESOME_VER := 6.4.0

.PHONY: configure_net \
		install install_venv install_packages \
		clear clear_venv clear_cache \
		create create_ssl create_systemd create_config \
		test fix lint del_cache \
		start stop restart \
		train download_static setup \
		debug_proxy

setup: configure_net install create download_static
	@echo "✅ Full setup completed"

configure_net:
	@echo "🌐 Setting network buffers ..."
	$(SCRIPTS)/set_net_buffers.sh
	@echo "✅ Network buffers set"

install_venv:
	@echo "🛠 Creating virtual environment ..."
	@python3 -m venv $(VENV)
	@echo "✅ Virtual environment created at $(VENV)"

install_packages:
	@echo "📦 Installing packages..."
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	$(VENV_PIP) install -r requirements-dev.txt
	@echo "✅ Packages installed"

install: install_venv install_packages
	@echo "✅ Environment ready with all packages installed"

clear_venv:
	@echo "🗑 Removing virtual environment ..."
	-@rm -rf $(VENV)
	@echo "✅ Virtual environment removed"

clear_cache:
	@echo "🧹 Clearing pip cache ..."
	-@$(VENV_PYTHON) -m pip cache purge
	@echo "🗑 Deleting __pycache__ folders ..."
	find $(APP) -type d -name "__pycache__" -exec rm -rf {} +
	@echo "🗑 Deleting Jinja bytecode cache ..."
	rm -rf $(JINJA_CACHE_PATH)/*
	@echo "🗑 Deleting Ruff cache ..."
	rm -rf $(RUFF_CACHE_PATH)/*
	@echo "✅ Done"

clear: clear_cache clear_venv
	@echo "✅ Environment fully cleaned"

create_ssl:
	@echo "🔒 Generating SSL certificates..."
	ROOT_PATH=$(ROOT_PATH) $(SCRIPTS)/generate_ssl.sh
	@echo "✅ SSL certificates created"

create_systemd:
	@echo "⚙️ Creating SystemD service..."
	ROOT_PATH=$(ROOT_PATH) $(SCRIPTS)/make_systemd_service.sh
	@echo "✅ SystemD service created"

create_config:
	@echo "📝 Creating configuration files..."
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_blacklists.py
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_config.py
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) $(SCRIPTS)/make_dhcp_static_map.py
	@echo "✅ Config files created"

create: create_ssl create_systemd create_config
	@echo "✅ All create tasks completed"

test:
	@echo "🧪 Running tests..."
	ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) -m pytest -s
	@echo "✅ Tests completed"

fix:
	@echo "🎨 Formatting app with Ruff..."
	$(VENV_PYTHON) -m ruff check --fix $(APP)/services/dns

fix-test:
	@echo "🎨 Formatting test with Ruff..."
	$(VENV_PYTHON) -m ruff check --fix $(ROOT_PATH)/tests
	@echo "✅ Sweet"

lint:
	@echo "🔍 Running linter with Ruff..."
	# $(VENV_FLAKE8) $(APP)
	$(VENV_PYTHON) -m ruff check $(APP)/services/dns/external_resolver.py
	@echo "✅ Linting completed with Ruff"

train:
	@echo "🤖 Training neural net..."
	@PYTHONPATH=$(ROOT_PATH) ROOT_PATH=$(ROOT_PATH) $(VENV_PYTHON) -m $(APP_NEURAL_NET)
	@echo "✅ Neural net training finished"

download_static:
	@echo "💾 Downloading static files..."
	mkdir -p $(STATIC_JS) $(STATIC_CSS) $(STATIC_WEBFONTS)
	curl -L -o $(STATIC_JS)/bootstrap.bundle.min.v$(BOOTSTRAP_VER).js https://cdnjs.cloudflare.com/ajax/libs/bootstrap/$(BOOTSTRAP_VER)/js/bootstrap.bundle.min.js
	curl -L -o $(STATIC_CSS)/bootstrap.min.v$(BOOTSTRAP_VER).css https://cdnjs.cloudflare.com/ajax/libs/bootstrap/$(BOOTSTRAP_VER)/css/bootstrap.min.css
	curl -L -o $(STATIC_JS)/react.production.min.v$(REACT_VER).js https://unpkg.com/react@$(REACT_VER)/umd/react.production.min.js
	curl -L -o $(STATIC_JS)/react-dom.production.min.v$(REACT_VER).js https://unpkg.com/react-dom@$(REACT_VER)/umd/react-dom.production.min.js
	curl -L -o $(STATIC_JS)/babel.min.v$(BABEL_VER).js https://unpkg.com/@babel/standalone@$(BABEL_VER)/babel.min.js
	curl -L -o $(STATIC_CSS)/fontawesome.all.min.v$(FONTAWESOME_VER).css https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/css/all.min.css
	curl -L -o $(STATIC_WEBFONTS)/fa-solid-900.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-solid-900.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-regular-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-regular-400.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-brands-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-brands-400.woff2
	curl -L -o $(STATIC_WEBFONTS)/fa-solid-900.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-solid-900.woff
	curl -L -o $(STATIC_WEBFONTS)/fa-regular-400.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-regular-400.woff
	curl -L -o $(STATIC_WEBFONTS)/fa-brands-400.woff https://cdnjs.cloudflare.com/ajax/libs/font-awesome/$(FONTAWESOME_VER)/webfonts/fa-brands-400.woff
	@echo "✅ Static files downloaded"

start:
	@echo "🚀 Starting Archon..."
	@if ! screen -list | grep -q "archon"; then \
		screen -dmS archon bash -c "sudo ./run.sh > ./logs/dump.log 2>&1"; \
		echo "✅ Archon started"; \
	else \
		echo "⚠️ Archon is already running."; \
	fi

stop:
	@echo "🛑 Stopping Archon..."
	-@PID=$$(screen -ls | grep archon | awk '{print $$1}' | cut -d. -f1); \
	if [ -n "$$PID" ]; then \
		echo "⚡ Sending SIGTERM to PID $$PID"; \
		kill -TERM $$PID; \
		echo "✅ Archon stopped"; \
	else \
		echo "⚠️ Archon not running"; \
	fi

restart: stop start

debug_proxy:
	sudo tcpdump -i any port 8899 -n -q
