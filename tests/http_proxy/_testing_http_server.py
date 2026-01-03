import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

short_body = b"A" * 1
long_body = b"A" * 300_000

class TestHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.1)
        if self.path == "/long":
            body = long_body
        else:  # /short or any other
            body = short_body

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress default logging
        pass

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    daemon_threads = True  # Automatically kill threads when server shuts down

def run_local_server(host="0.0.0.0", port=9000):
    """Starts a threaded local HTTP server in a background thread.
    """
    server = ThreadedHTTPServer((host, port), TestHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Threaded local test server running at http://{host}:{port}")
    return server

if __name__ == "__main__":
    server = run_local_server()
    input("Press Enter to stop server...\n")
    server.shutdown()
