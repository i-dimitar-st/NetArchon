from logging import Logger
from pathlib import Path
from threading import Thread

import uvicorn
from asgiref.wsgi import WsgiToAsgi


class UvicornServer:
    _server: uvicorn.Server
    _server_worker: Thread
    _config: uvicorn.Config
    _kill_timeout: int
    _logger: Logger

    @classmethod
    def init(
        cls,
        logger: Logger,
        app_wsgi: WsgiToAsgi,
        host: str,
        port: int,
        cert_path: Path,
        key_path: Path,
        log_level: str,
        keep_alive_timeout: int,
        kill_timeout: int = 3,
    ):
        cls._logger = logger
        cls._config = uvicorn.Config(
            app=app_wsgi,
            host=host,
            port=port,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            log_level=log_level,
            timeout_keep_alive=keep_alive_timeout,
        )
        cls._server = uvicorn.Server(config=cls._config)
        cls._kill_timeout = kill_timeout
        cls._logger.debug("GUI server initialized")

    @classmethod
    def start(cls):
        """Starts the server."""
        if not cls._server:
            raise RuntimeError("UvicornServer not initialized")
        if not cls._config:
            raise RuntimeError("Config missing")

        cls._server_worker = Thread(target=cls._server.run, daemon=True)
        cls._server_worker.start()
        cls._logger.info("GUI server started")

    @classmethod
    def stop(cls):
        """Stop the server."""
        if cls._server:
            cls._server.should_exit = True
        if cls._server_worker and cls._server_worker.is_alive():
            cls._server_worker.join(timeout=cls._kill_timeout)
        cls._logger.info("GUI server stopped")

    @classmethod
    def restart(cls) -> None:
        """Stop the server if running, then start it again."""
        cls.stop()
        cls.start()
        cls._logger.info("GUI server restarted")
