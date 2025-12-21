"""Flask GUI Application.

Provides a Flask application wrapper for the GUI service, including:
- API and HTML routes
- Static file serving with caching
- Session and CSRF token handling
- Metrics tracking for API and page responses
- Integration with the ApiGateway for API requests
- SSL support for secure connections.
"""

import logging
from multiprocessing import Process
from logging import INFO, WARNING, Logger
from pathlib import Path

from flask import (
    Flask,
    Response,
    make_response,
    render_template,
    request,
    send_from_directory,
    session,
)
from jinja2 import FileSystemBytecodeCache

from src.config.config import config
from src.libs.libs import measure_latency_decorator
from src.services.gui.api.api import ApiGateway
from src.services.gui.metrics import (
    api_metrics,
    http_response_metrics,
)
from src.services.gui.utils.auth import (
    BEARER_TOKEN_HASH,
    generate_bearer_token,
    generate_csrf_token,
)
from src.services.gui.utils.utils import set_cache_control
from src.services.logger.logger import MainLogger

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")
JINJA_CACHE_PATH = ROOT_PATH / ".jinja_cache"

APP_CONFIG = config.get("app")
PORT = APP_CONFIG.get("port")
HOST = APP_CONFIG.get("host")
KEEP_ALIVE_TIMEOUT = int(APP_CONFIG.get("keep_alive_timeout_sec"))
APP_LOG_LEVEL = str(APP_CONFIG.get("log_level"))
PERMANENT_SESSION_LIFETIME_SEC = int(APP_CONFIG.get("permanent_session_livetime_sec"))

CACHED_HEADER_DURATION_SEC = 7 * 24 * 3600


logger: Logger = MainLogger.get_logger(service_name="GUI", log_level="debug")


class App:
    """Flask application wrapper for the GUI service."""

    _app: Flask
    _config = {
        "host" : '',
        "port" : 0,
        "threaded" : True,
        "debug" : False,
        "pem_path" : '',
        "key_path" : '',
    }

    @classmethod
    def _bootstrap_loggers(cls) -> None:
        # Flask logger
        if isinstance(cls._app, Flask):
            cls._app.logger.handlers.clear()
            cls._app.logger.propagate = False
            for _handler in logger.handlers:
                cls._app.logger.addHandler(_handler)
            cls._app.logger.setLevel(INFO)

            werkzeug_logger: Logger = logging.getLogger("werkzeug")
            werkzeug_logger.handlers.clear()
            werkzeug_logger.propagate = False  # fully controlled by our logger
            for h in logger.handlers:
                werkzeug_logger.addHandler(h)
            werkzeug_logger.setLevel(WARNING)

    @classmethod
    def _define_routes(cls) -> None:
        if not isinstance(cls._app, Flask):
            raise RuntimeError("App not initialized")

        @cls._app.before_request
        def require_session_and_validate() -> None:
            if request.path.startswith(("/static", "/healtz")):
                return

            if "_csrf_token" not in session:
                session["_csrf_token"] = generate_csrf_token()
            session.permanent = True
            session.modified = True
            session["bearer_token_hash"] = generate_bearer_token(session["_csrf_token"])

        # Static files

        @cls._app.route('/static/<path:filename>')
        def static_files(filename) -> Response:
            return set_cache_control(
                response=make_response(send_from_directory('static', filename)),
                max_age=CACHED_HEADER_DURATION_SEC,
                public=True,
            )

        # API Routes

        @cls._app.route("/healtz", methods=["GET"])
        def healtz() -> Response:
            return ApiGateway.handle_healtz(request)

        @cls._app.route("/api", methods=["POST"])
        @measure_latency_decorator(metrics=api_metrics)
        def api() -> Response:
            """Centralized API endpoint for all JSON calls."""
            return ApiGateway.handle_request(request)

        # HTML Routes

        @cls._app.route("/")
        @measure_latency_decorator(metrics=http_response_metrics)
        def index() -> str:
            return render_template("index.html", active_page="dashboard")

        @cls._app.route("/info")
        @measure_latency_decorator(metrics=http_response_metrics)
        def info() -> str:
            return render_template("info.html", active_page="info")

        @cls._app.route("/dhcp")
        @measure_latency_decorator(metrics=http_response_metrics)
        def dhcp() -> str:
            return render_template("dhcp.html", active_page="dhcp")

        @cls._app.route("/dns")
        @measure_latency_decorator(metrics=http_response_metrics)
        def dns() -> str:
            return render_template("dns.html", active_page="dns")

        @cls._app.route("/config")
        @measure_latency_decorator(metrics=http_response_metrics)
        def get_config() -> str:
            return render_template("config.html", active_page="config")

        @cls._app.route("/neural_net")
        @measure_latency_decorator(metrics=http_response_metrics)
        def get_neural_net() -> str:
            return render_template("neural_net.html", active_page="net")

        @cls._app.route("/logs")
        @measure_latency_decorator(metrics=http_response_metrics)
        def logs() -> str:
            return render_template("logs.html", active_page="logs")

        @cls._app.route("/metrics")
        @measure_latency_decorator(metrics=http_response_metrics)
        def metrics() -> str:
            return render_template("metrics.html", active_page="metrics")

        @cls._app.errorhandler(404)
        def not_found(error) -> str:
            return render_template("404.html", active_page="404")

        @cls._app.errorhandler(500)
        def internal_error(error) -> str:
            return render_template("500.html", active_page="500")

    @classmethod
    def init(
        cls,
        host: str = HOST,
        port: int = PORT,
        pem_path:Path=PEM_PATH,
        key_path:Path=KEY_PATH,
        threaded: bool = True,
        debug:bool = False
        ) -> None:
        """Initialize and configure the Flask application for the GUI service.

        This method sets up the Flask app instance, applies security and session
        settings, configures Jinja templating and caching, bootstraps loggers,
        defines routes (API, static files, HTML pages), and initializes the API
        gateway handlers.

        Args:
            host (str, optional): Host address to bind the application
            port (int, optional): Port number to bind the application.
            pem_path (Path, optional): Path to the SSL certificate PEM file
            key_path (Path, optional): Path to the SSL key file.
            threaded (bool, optional): Enable Flask threaded mode.
            debug (bool, optional): Enable Flask debug mode.

        Raises:
            RuntimeError: If the app cannot be initialized properly.

        """
        cls._config["host"] = host
        cls._config["port"] = port
        cls._config["pem_path"] = str(pem_path)
        cls._config["key_path"] = str(key_path)
        cls._config["threaded"] = threaded
        cls._config["debug"] = debug

        cls._app = Flask(__name__, static_folder=None)

        # Security configurations
        cls._app.secret_key = BEARER_TOKEN_HASH
        cls._app.config['SESSION_COOKIE_HTTPONLY'] = True
        cls._app.config['SESSION_COOKIE_SECURE'] = True
        cls._app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
        cls._app.config['PERMANENT_SESSION_LIFETIME'] = PERMANENT_SESSION_LIFETIME_SEC
        cls._app.config['SEND_FILE_MAX_AGE_DEFAULT'] = CACHED_HEADER_DURATION_SEC
        cls._app.config['MAX_CONTENT_LENGTH'] = 32 * 1024**2  # upload size <= 32MB

        # Template / Jinja
        cls._app.jinja_env.globals['csrf_token'] = generate_csrf_token
        cls._app.jinja_env.auto_reload = False
        cls._app.jinja_env.trim_blocks = True
        cls._app.jinja_env.lstrip_blocks = True
        cls._app.jinja_env.keep_trailing_newline = False
        cls._app.jinja_env.bytecode_cache = FileSystemBytecodeCache(
            directory=str(JINJA_CACHE_PATH),
            pattern="__jinja2_%s.cache"
        )

        # JSON handling
        cls._app.config['JSON_SORT_KEYS'] = False
        cls._app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

        cls._bootstrap_loggers()
        cls._define_routes()
        ApiGateway.init()

    @classmethod
    def start(cls):
        def _run():
            cls._app.run(
                host=cls._config["host"],
                port=cls._config["port"],
                threaded=cls._config["threaded"],
                debug=cls._config["debug"],
                ssl_context=(cls._config["pem_path"], cls._config["key_path"]),
            )

        cls._flask_proc = Process(target=_run, daemon=True)
        cls._flask_proc.start()
        logger.info(f"Flask app started on {cls._config['host']}:{cls._config['port']}")

    @classmethod
    def stop(cls):
        if cls._flask_proc:
            cls._flask_proc.terminate()
            cls._flask_proc.join(timeout=1)
            if cls._flask_proc.is_alive():
                cls._flask_proc.kill()
                cls._flask_proc.join()
            logger.info("Flask app stopped")
            cls._flask_proc = None

    @classmethod
    def restart(cls) -> None:
        """Restart the Flask application."""
        logger.info("App restarted")
