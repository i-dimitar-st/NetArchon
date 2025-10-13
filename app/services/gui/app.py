from logging import WARNING, Logger, getLogger
from pathlib import Path

from asgiref.wsgi import WsgiToAsgi
from flask import Flask, Response, render_template, request, session

from app.config.config import config
from app.libs.libs import measure_latency_decorator
from app.services.gui.api import ApiGateway
from app.services.gui.auth import (
    BEARER_TOKEN_HASH,
    generate_bearer_token,
    generate_csrf_token,
)
from app.services.gui.metrics import api_metrics, http_response_metrics
from app.services.gui.server import UvicornServer
from app.services.logger.logger import MainLogger

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")

APP_CONFIG = config.get("app")
PORT = APP_CONFIG.get("port")
HOST = APP_CONFIG.get("host")
KEEP_ALIVE_TIMEOUT = int(APP_CONFIG.get("keep_alive_timeout_sec"))
APP_LOG_LEVEL = str(APP_CONFIG.get("log_level"))
PERMANENT_SESSION_LIFETIME_SEC = int(APP_CONFIG.get("permanent_session_livetime_sec"))


logger: Logger = MainLogger.get_logger(service_name="GUI", log_level="debug")


class App:
    _app: Flask
    _app_wsgi: WsgiToAsgi
    _uvicorn_server: UvicornServer

    @classmethod
    def _init_app(cls):
        cls._app = Flask(__name__, static_folder='static')
        cls._app.secret_key = BEARER_TOKEN_HASH
        cls._app.config['SESSION_COOKIE_HTTPONLY'] = True
        cls._app.config['SESSION_COOKIE_SECURE'] = True
        cls._app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
        cls._app.config['PERMANENT_SESSION_LIFETIME'] = PERMANENT_SESSION_LIFETIME_SEC
        cls._app.jinja_env.globals['csrf_token'] = generate_csrf_token
        cls._app_wsgi = WsgiToAsgi(cls._app)

        cls._bootstrap_loggers()
        cls._define_routes()

    @classmethod
    def _bootstrap_loggers(cls):
        # Flask logger
        if isinstance(cls._app, Flask):
            cls._app.logger.handlers.clear()
            cls._app.logger.propagate = True
            for _handler in logger.handlers:
                cls._app.logger.addHandler(_handler)
            cls._app.logger.setLevel(WARNING)

        # Uvicorn loggers
        if isinstance(cls._app_wsgi, WsgiToAsgi):
            for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
                _uv_logger = getLogger(_name)
                _uv_logger.handlers.clear()
                _uv_logger.propagate = True
                for _handler in logger.handlers:
                    _uv_logger.addHandler(_handler)
                _uv_logger.setLevel(WARNING)

    @classmethod
    def _define_routes(cls):

        if isinstance(cls._app, Flask):

            @cls._app.before_request
            def require_session_and_validate():
                if request.endpoint == "static":
                    return

                # When request ends, Flask serializes session["_csrf_token"]
                # as cookie and signs it with app.secret_key
                if "_csrf_token" not in session:
                    session["_csrf_token"] = generate_csrf_token()
                session.permanent = True
                session.modified = True
                session["bearer_token_hash"] = generate_bearer_token(session["_csrf_token"])

            @cls._app.route("/api", methods=["GET", "POST"])
            @measure_latency_decorator(metrics=api_metrics)
            def api_endpoint() -> Response:
                """
                Centralized API endpoint for all JSON calls.
                """
                return ApiGateway.handle_request(request)

            @cls._app.route("/")
            @measure_latency_decorator(metrics=http_response_metrics)
            def index():
                return render_template("index.html", active_page="dashboard")

            @cls._app.route("/info")
            @measure_latency_decorator(metrics=http_response_metrics)
            def info():
                return render_template("info.html", active_page="info")

            @cls._app.route("/dhcp")
            @measure_latency_decorator(metrics=http_response_metrics)
            def dhcp():
                return render_template("dhcp.html", active_page="dhcp")

            @cls._app.route("/dns")
            @measure_latency_decorator(metrics=http_response_metrics)
            def dns():
                return render_template("dns.html", active_page="dns")

            @cls._app.route("/config")
            @measure_latency_decorator(metrics=http_response_metrics)
            def get_config():
                return render_template("config.html", active_page="config")

            @cls._app.route("/neural_net")
            @measure_latency_decorator(metrics=http_response_metrics)
            def get_neural_net():
                return render_template("neural_net.html", active_page="net")

            @cls._app.route("/logs")
            @measure_latency_decorator(metrics=http_response_metrics)
            def logs():
                return render_template("logs.html", active_page="logs")

            @cls._app.route("/metrics")
            @measure_latency_decorator(metrics=http_response_metrics)
            def metrics():
                return render_template("metrics.html", active_page="metrics")

            @cls._app.errorhandler(404)
            def not_found(error):
                return render_template("404.html", active_page="404"), 404

    @classmethod
    def init(cls, host: str = HOST, port: int = PORT):
        cls._init_app()
        cls._uvicorn_server = UvicornServer()
        cls._uvicorn_server.init(
            logger=logger,
            app_wsgi=cls._app_wsgi,
            host=host,
            port=port,
            cert_path=PEM_PATH,
            key_path=KEY_PATH,
            log_level=APP_LOG_LEVEL,
            keep_alive_timeout=KEEP_ALIVE_TIMEOUT,
        )

    @classmethod
    def start(cls):
        cls._uvicorn_server.start()
        logger.info("App started")

    @classmethod
    def stop(cls):
        cls._uvicorn_server.stop()
        logger.info("App stopped")

    @classmethod
    def restart(cls):
        cls._uvicorn_server.restart()
        logger.info("App restarted")
