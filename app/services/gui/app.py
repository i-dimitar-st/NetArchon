import hmac
from datetime import datetime
from hashlib import sha256
from logging import WARNING, getLogger
from pathlib import Path
from threading import Event, Thread
from typing import Any

from asgiref.wsgi import WsgiToAsgi
from flask import Flask, abort, jsonify, render_template, request, session
from uvicorn import run as runUvicorn

from app.config.config import config
from app.services.gui.helpers import (
    add_to_blacklist,
    delete_from_blacklist,
    generate_network_stats,
    generate_system_stats,
    get_control_list,
    get_csrf_token,
    get_dhcp_leases,
    get_dhcp_statistics,
    get_dns_history,
    get_dns_statistics,
    get_metrics,
    get_network_interfaces,
    get_service_stats,
    get_system_logs,
)
from app.services.logger.logger import MainLogger

APP_CONFIG = config.get("app")
PORT = APP_CONFIG.get("port")
HOST = APP_CONFIG.get("host")
BEARER_TOKEN = APP_CONFIG.get("bearer_token")
BEARER_TOKEN_HASH = sha256(BEARER_TOKEN.encode()).hexdigest()

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))

CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")
KEEP_ALIVE_TIMEOUT = 30
APP_LOG_LEVEL = "warning"
PERMANENT_SESSION_LIFETIME_SEC = 1800


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

        # --- REGISTER CUSTOM FILTER ---
        @cls._app.template_filter('datetimeformat')
        def datetimeformat(value, fmt='%Y-%m-%d %H:%M:%S'):
            try:
                return datetime.fromtimestamp(int(value)).strftime(fmt)
            except (ValueError, TypeError):
                return value  # fallback if value is invalid

        # --- END FILTER ---
        cls._app.jinja_env.globals['csrf_token'] = get_csrf_token
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
                    session["_csrf_token"] = get_csrf_token()

                session.permanent = True

                if request.method == "POST" and request.endpoint == "get_config":
                    _auth: str = request.headers.get("Authorization", "")
                    if not hmac.compare_digest(
                        _auth[7:].strip(),
                        hmac.new(
                            key=BEARER_TOKEN_HASH.encode(),
                            msg=session["_csrf_token"].encode(),
                            digestmod=sha256,
                        ).hexdigest(),
                    ):
                        abort(401, description="Unauthorized")

                session.modified = True

            @cls._app.route("/")
            def index():

                _sys_stats = generate_system_stats()
                _cpu_temps = [
                    sensor.get("value")
                    for label, sensors in _sys_stats.get("temperature", {}).items()
                    if "core" in label.lower()
                    for sensor in sensors.values()
                ]
                _max_cpu_temp = {"value": max(_cpu_temps), "unit": "°C"}
                _system_time = _sys_stats.get("system", {}).get("datetime")
                _uptime = _sys_stats.get("system", {}).get("uptime", {})
                _cpu_usage = _sys_stats.get("cpu", {}).get("overall", {})
                _mem_usage = _sys_stats.get("memory", {}).get("used", {})
                system_stats = {
                    "system_time": _system_time,
                    "uptime": _uptime,
                    "cpu_temp": _max_cpu_temp,
                    "cpu_usage": _cpu_usage,
                    "mem_usage": _mem_usage,
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
            def info():
                return render_template(
                    "info.html",
                    active_page="info",
                    system_statistics=generate_system_stats(),
                    network_interfaces=get_network_interfaces(),
                )

            @cls._app.route("/dhcp")
            def dhcp():
                return render_template(
                    "dhcp.html",
                    active_page="dhcp",
                    dhcp_statistics=get_dhcp_statistics(),
                    dhcp_leases=get_dhcp_leases(),
                )

            @cls._app.route("/dns")
            def dns():
                return render_template(
                    "dns.html",
                    active_page="dns",
                    dns_history=get_dns_history(),
                    dns_statistics=get_dns_statistics(),
                )

            @cls._app.route("/config", methods=["GET", "POST"])
            def get_config():
                if request.method == "POST":
                    # This passed header validation already
                    data: Any | None = request.get_json(silent=True)
                    if not data:
                        abort(400, description="Invalid or empty JSON")

                    category = data.get("category")
                    action = data.get("type")
                    payload = data.get("payload")

                    if category == "blacklist":
                        if action == "add" and add_to_blacklist(payload):
                            logger.info("%s added to blacklists.", payload)
                            return jsonify(status="received"), 200
                        if action == "delete" and delete_from_blacklist(payload):
                            logger.info("%s deleted from blacklists.", payload)
                            return jsonify(status="received"), 200
                        abort(400, description=f"Failed to {action} from {category}")

                    abort(400, description="Invalid action or category")

                return render_template(
                    "config.html",
                    active_page="config",
                    config={
                        "network": config.get("network").get("interface"),
                        "dns": config.get("dns"),
                        "dhcp": config.get("dhcp"),
                    },
                    dns_control_list=get_control_list(),
                    bearer_token_hash=hmac.new(
                        key=BEARER_TOKEN_HASH.encode(),
                        msg=session["_csrf_token"].encode(),
                        digestmod=sha256,
                    ).hexdigest(),
                )

            @cls._app.route("/logs")
            def logs():
                return render_template(
                    "logs.html", active_page="logs", system_logs=get_system_logs()
                )

            @cls._app.route("/metrics")
            def metrics():
                return render_template(
                    "metrics.html", active_page="metrics", metrics=get_metrics()
                )

            @cls._app.errorhandler(404)
            def not_found(error):
                return render_template("404.html", active_page="404"), 404
