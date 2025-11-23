import threading
from functools import cache
from datetime import datetime,timedelta,timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

@cache
def _generate_content(proxy_host: str, proxy_port: int) -> bytes:
    content = f"""function FindProxyForURL(url, host) {{
        if (isPlainHostName(host) ||
            shExpMatch(host, "localhost") ||
            shExpMatch(host, "127.*") ||
            shExpMatch(host, "192.168.20.*")) {{
            return "DIRECT";
        }}
        return "PROXY {proxy_host}:{proxy_port}";
    }}"""
    return content.encode("utf-8")


class WPADHandler(BaseHTTPRequestHandler):
    proxy_host = "192.168.20.100"
    proxy_port = 8899
    wpad_path = "/wpad.dat"

    def do_GET(self) -> None:
        if self.path == self.wpad_path:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Expires", format_datetime(datetime.now(timezone.utc) + timedelta(days=1), usegmt=True))
            self.send_header("Cache-Control", "public, max-age=86400")

            self.end_headers()
            self.wfile.write(_generate_content(self.proxy_host, self.proxy_port))

        else:
            self.send_response(404)
            self.end_headers()

    # def log_message(self, format, *args) -> None:
    #     pass


class WPADDatServer:
    _server: Optional[HTTPServer] = None
    _thread: Optional[threading.Thread] = None

    @classmethod
    def init(
        cls,
        logger,
        host:str,
        proxy_host:str,
        port: int = 80,
        proxy_port: int = 8080,
    ) -> None:

        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid server port: {port}")
        if not (1 <= proxy_port <= 65535):
            raise ValueError(f"Invalid proxy port: {proxy_port}")

        cls._host:str = host
        cls._proxy_host:str= proxy_host
        cls._port = int(port)
        cls._proxy_port = int(proxy_port)
        cls._logger = logger
        WPADHandler.proxy_host = str(proxy_host)
        WPADHandler.proxy_port = proxy_port


    @classmethod
    def start(cls) -> None:
        if cls._server and cls._thread and cls._thread.is_alive():
            raise RuntimeError("WPAD server already running")

        cls._server = HTTPServer((str(cls._host), cls._port), WPADHandler)
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._logger.info(f"WPAD server running at http://{cls._host}:{cls._port}/wpad.dat")

    @classmethod
    def stop(cls) -> None:
        if cls._server:
            cls._server.shutdown()
            cls._server.server_close()
            cls._server = None
        if cls._thread:
            cls._thread.join()
            cls._thread = None
        cls._logger.info("WPAD server stopped")

    @classmethod
    def restart(cls) -> None:
        cls.stop()
        cls.start()
        cls._logger.info("")
