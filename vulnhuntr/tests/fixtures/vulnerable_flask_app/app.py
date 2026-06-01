"""Intentionally vulnerable Flask app — used only in verifier end-to-end tests."""
from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/compile")
def compile_latex():
    """Vulnerability: user-controlled 'cmd' passed directly to subprocess(shell=True)."""
    cmd = request.args.get("cmd", "echo noop")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return result.stdout or result.stderr


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
