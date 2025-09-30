from datetime import datetime
from logging import WARNING, getLogger
from pathlib import Path
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor

from asgiref.wsgi import WsgiToAsgi
from flask import Flask, abort, render_template, request, session
from uvicorn import run as runUvicorn

from app.config.config import config
from app.libs.libs import measure_latency_decorator
from app.services.gui.api import api_gateway
from app.services.gui.auth import (
    BEARER_TOKEN_HASH,
    decode_and_verify_bearer_token,
    generate_bearer_token,
    generate_csrf_token,
)
from app.services.gui.metrics import gui_metrics
from app.services.gui.utils import (
    generate_network_stats,
    generate_system_stats,
    get_blacklist,
    get_control_list,
    get_dhcp_leases,
    get_dhcp_statistics,
    get_dns_history,
    get_dns_statistics,
    get_metrics,
    get_network_interfaces,
    get_service_stats,
    get_system_logs,
    get_whitelist,
)
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


logger = MainLogger.get_logger(service_name="GUI", log_level="debug")


class App:
    _worker: Thread | None = None
    _app: Flask | None = None
    _stop_app = Event()

    @classmethod
    def init(cls, host: str = HOST, port: int = PORT):
        cls._host: str = host
        cls._port: int = port

    @classmethod
    def start(cls):
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("Flask App already running")
        cls._worker = Thread(target=cls._work, daemon=True)
        cls._worker.start()
        logger.info(f"Starting Flask App at {cls._host}:{cls._port}.")

    @classmethod
    def stop(cls):
        logger.info("Shutting Flask App")
        cls._stop_app.set()

    @classmethod
    def _work(cls):
        cls._app = Flask(__name__)
        cls._app.secret_key = BEARER_TOKEN_HASH
        cls._app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE="Lax",
            PERMANENT_SESSION_LIFETIME=PERMANENT_SESSION_LIFETIME_SEC,
        )

        @cls._app.template_filter('datetimeformat')
        def datetimeformat(value: int, fmt='%Y-%m-%d %H:%M:%S'):
            try:
                return datetime.fromtimestamp(int(value)).strftime(fmt)
            except (ValueError, TypeError):
                return value

        cls._app.jinja_env.globals['csrf_token'] = generate_csrf_token
        cls._app_wsgi: WsgiToAsgi = WsgiToAsgi(cls._app)

        cls._bootstrap_loggers()
        cls._define_routes()

        runUvicorn(
            cls._app_wsgi,
            host=cls._host,
            port=cls._port,
            ssl_certfile=PEM_PATH,
            ssl_keyfile=KEY_PATH,
            log_level=APP_LOG_LEVEL,
            timeout_keep_alive=KEEP_ALIVE_TIMEOUT,
        )

    @classmethod
    def _bootstrap_loggers(cls):
        # Flask logger
        if cls._app:
            cls._app.logger.handlers.clear()
            cls._app.logger.propagate = True
            for _handler in logger.handlers:
                cls._app.logger.addHandler(_handler)
            cls._app.logger.setLevel(WARNING)

        # Uvicorn loggers
        if cls._app_wsgi and isinstance(cls._app_wsgi, WsgiToAsgi):
            for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
                _uv_logger = getLogger(_name)
                _uv_logger.handlers.clear()
                _uv_logger.propagate = True
                for _handler in logger.handlers:
                    _uv_logger.addHandler(_handler)
                _uv_logger.setLevel(WARNING)

    @classmethod
    def _define_routes(cls):

        if cls._app and isinstance(cls._app, Flask):

            @cls._app.before_request
            def require_session_and_validate():
                if request.endpoint == "static":
                    return

                # When request ends, Flask serializes session["_csrf_token"]
                # as cookie and signs it with app.secret_key
                if "_csrf_token" not in session:
                    session["_csrf_token"] = generate_csrf_token()

                session.permanent = True

                if request.method == "POST" and request.endpoint == "get_config":
                    _auth_header = request.headers.get("Authorization", "")
                    if not _auth_header.startswith("Bearer "):
                        abort(401, description="Unauthorized")
                    _bearer_token = _auth_header[7:].strip()
                    if not decode_and_verify_bearer_token(_bearer_token, session["_csrf_token"]):
                        abort(401, description="Unauthorized")

                session.modified = True

            @cls._app.route("/api", methods=["GET", "POST"])
            @measure_latency_decorator(metrics=gui_metrics)
            def api_endpoint():
                """
                Centralized API endpoint for all JSON calls.
                """
                return api_gateway(request)

            @cls._app.route("/")
            @measure_latency_decorator(metrics=gui_metrics)
            def index():

                sys_stats = generate_system_stats()
                cpu_temps = [
                    sensor.get("value")
                    for label, sensors in sys_stats.get("temperature", {}).items()
                    if "core" in label.lower()
                    for sensor in sensors.values()
                ]

                system_stats = {
                    "system_time": sys_stats.get("system", {}).get("datetime"),
                    "uptime": sys_stats.get("system", {}).get("uptime", {}),
                    "cpu_temp": {"value": max(cpu_temps), "unit": "°C"},
                    "cpu_usage": sys_stats.get("cpu", {}).get("overall", {}),
                    "mem_usage": sys_stats.get("memory", {}).get("used", {}),
                }
                cards = {
                    "system": system_stats,
                    "services": get_service_stats(),
                    "network": generate_network_stats(),
                }

                return render_template(
                    "index.html",
                    active_page="dashboard",
                    cards=cards,
                    csrf_token=session["_csrf_token"],
                )

            @cls._app.route("/info")
            @measure_latency_decorator(metrics=gui_metrics)
            def info():
                return render_template(
                    "info.html",
                    active_page="info",
                    system_statistics=generate_system_stats(),
                    network_interfaces=get_network_interfaces(),
                )

            @cls._app.route("/dhcp")
            @measure_latency_decorator(metrics=gui_metrics)
            def dhcp():
                return render_template(
                    "dhcp.html",
                    active_page="dhcp",
                    dhcp_statistics=get_dhcp_statistics(),
                    dhcp_leases=get_dhcp_leases(),
                )

            @cls._app.route("/dns")
            @measure_latency_decorator(metrics=gui_metrics)
            def dns():
                return render_template(
                    "dns.html",
                    active_page="dns",
                    dns_history=get_dns_history(),
                    dns_statistics=get_dns_statistics(),
                )

            @cls._app.route("/config", methods=["GET", "POST"])
            @measure_latency_decorator(metrics=gui_metrics)
            def get_config():
                return render_template(
                    "config.html",
                    active_page="config",
                    config={
                        "network": config.get("network").get("interface"),
                        "dns": config.get("dns"),
                        "dhcp": config.get("dhcp"),
                    },
                    dns_control_list=get_control_list(),
                    bearer_token_hash=generate_bearer_token(session["_csrf_token"]),
                )

            @cls._app.route("/neural_net", methods=["GET", "POST"])
            def get_neural_net():
                return render_template(
                    "neural_net.html",
                    active_page="net",
                    config=dict(config.get("neural_net")),
                    dns_history=get_dns_history(),
                    blacklist=list(get_blacklist()),
                    whitelist=list(get_whitelist()),
                    bearer_token_hash=generate_bearer_token(session["_csrf_token"]),
                )

            @cls._app.route("/logs")
            @measure_latency_decorator(metrics=gui_metrics)
            def logs():
                return render_template(
                    "logs.html", active_page="logs", system_logs=get_system_logs()
                )

            @cls._app.route("/metrics")
            @measure_latency_decorator(metrics=gui_metrics)
            def metrics():
                return render_template("metrics.html", active_page="metrics", metrics=get_metrics())

            @cls._app.errorhandler(404)
            def not_found(error):
                return render_template("404.html", active_page="404"), 404
