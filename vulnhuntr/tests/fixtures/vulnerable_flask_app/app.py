"""Intentionally vulnerable stdlib HTTP app for verifier end-to-end tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import subprocess


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send(200, "ok")
            return

        if parsed.path == "/compile":
            cmd = parse_qs(parsed.query).get("cmd", ["echo noop"])[0]
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._send(200, result.stdout or result.stderr)
            return

        self._send(404, "not found")

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 5000), Handler)
    server.serve_forever()
