from __future__ import annotations

import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SSRFFixtureServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "SSRFFixtureServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Fixture server is not running")
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)

                if parsed.path in {"/fetch", "/fetch-redirect"}:
                    target_url = qs.get("url", [""])[0]
                    if not target_url:
                        self.send_response(400)
                        self.end_headers()
                        return
                    try:
                        urllib.request.urlopen(target_url, timeout=5).read()
                    except Exception:
                        self.send_response(502)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"fetched")
                    return

                if parsed.path == "/safe":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"safe")
                    return

                if parsed.path == "/reject":
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"rejected")
                    return

                self.send_response(404)
                self.end_headers()

            def log_message(self, _format: str, *args) -> None:
                return

        self._server = ThreadingHTTPServer((owner.host, owner.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
