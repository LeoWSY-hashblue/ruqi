"""
Minimal deterministic SSRF verifier.

The verifier starts a local callback server, gives the PoC tokenized callback
and redirect URLs, and bases verdicts only on callback evidence. LLM output is
not used.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse

from vulnhuntr.candidate import Candidate
from vulnhuntr.verifier import VerifyResult


@dataclass(frozen=True)
class CallbackHit:
    method: str
    path: str
    headers: dict[str, str]
    timestamp: float
    body_sha256: str


@dataclass
class CallbackServer:
    host: str = "127.0.0.1"
    port: int = 0
    public_host: str | None = None
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _hits: list[CallbackHit] = field(default_factory=list, init=False, repr=False)

    def __enter__(self) -> "CallbackServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Callback server is not running")
        host, port = self._server.server_address
        if self.public_host:
            host = self.public_host
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._server is not None:
            return

        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, _format: str, *args) -> None:
                return

            def _handle(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
                hit = CallbackHit(
                    method=self.command,
                    path=self.path,
                    headers={key: value for key, value in self.headers.items()},
                    timestamp=time.time(),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                )
                owner._record(hit)

                parsed = urlparse(self.path)
                if parsed.path.startswith("/redirect/"):
                    target = parse_qs(parsed.query).get("to", [""])[0]
                    if target:
                        self.send_response(302)
                        self.send_header("Location", target)
                        self.end_headers()
                        return

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
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

    def callback_url(self, token: str) -> str:
        return f"{self.base_url}/callback/{token}"

    def canary_url(self, token: str) -> str:
        return f"{self.base_url}/canary/{token}"

    def redirect_url(self, token: str, target_url: str) -> str:
        return f"{self.base_url}/redirect/{token}?{urlencode({'to': target_url})}"

    def hits_for(self, token: str) -> list[CallbackHit]:
        with self._lock:
            return [hit for hit in self._hits if token in hit.path]

    def wait_for_hit(self, token: str, timeout: float = 1.0) -> list[CallbackHit]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = self.hits_for(token)
            if hits:
                return hits
            time.sleep(0.02)
        return self.hits_for(token)

    def _record(self, hit: CallbackHit) -> None:
        with self._lock:
            self._hits.append(hit)


SSRFPoC = Callable[[str, str, str], int]


def verify_ssrf(
    candidate: Candidate,
    target_base_url: str,
    poc: SSRFPoC,
    callback_server: CallbackServer | None = None,
    wait_timeout: float = 1.0,
) -> VerifyResult:
    if candidate.sink_type != "ssrf":
        return VerifyResult(
            status="false_positive",
            evidence=f"Unsupported sink_type for SSRF verifier: {candidate.sink_type!r}.",
            canary_path="",
        )

    token = uuid.uuid4().hex
    server = callback_server or CallbackServer()
    started_server = server._server is None

    if started_server:
        server.start()

    try:
        callback_url = server.callback_url(token)
        canary_url = server.canary_url(token)
        redirect_url = server.redirect_url(token, canary_url)

        try:
            poc_rc = poc(target_base_url, callback_url, redirect_url)
        except Exception as exc:
            return VerifyResult(
                status="false_positive",
                evidence=f"PoC raised {type(exc).__name__}: {str(exc)[:200]}",
                canary_path=canary_url,
            )

        hits = server.wait_for_hit(token, timeout=wait_timeout)
        if hits:
            paths = [hit.path for hit in hits]
            if any(path.startswith(f"/canary/{token}") for path in paths):
                evidence = f"SSRF callback canary hit for token {token}: {paths!r}"
            else:
                evidence = f"SSRF callback hit for token {token}: {paths!r}"
            return VerifyResult(status="confirmed", evidence=evidence, canary_path=canary_url)

        if poc_rc != 0:
            return VerifyResult(
                status="false_positive",
                evidence=f"PoC exited with code {poc_rc} and no callback was observed.",
                canary_path=canary_url,
            )

        return VerifyResult(
            status="suspected",
            evidence="PoC ran without error but no SSRF callback was observed.",
            canary_path=canary_url,
        )
    finally:
        if started_server:
            server.stop()
