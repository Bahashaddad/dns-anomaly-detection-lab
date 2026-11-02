"""Read-only loopback dashboard; no privileged operations or remote assets."""

import argparse
from pathlib import Path
from flask import Flask, render_template, request, abort
from config import BASE_DIR, DEFAULT_DATABASE
from storage import EventStore


def create_app(database=DEFAULT_DATABASE):
    app = Flask(__name__, root_path=str(BASE_DIR))
    app.config.update(TRUSTED_HOSTS=["localhost", "127.0.0.1"], MAX_CONTENT_LENGTH=8192)
    store = EventStore(database)

    @app.before_request
    def loopback_only():
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            abort(403)

    @app.route("/")
    def home():
        events, summary = store.snapshot()
        return render_template("dashboard.html", events=events, summary=summary)

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        return response

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--port", type=int, default=5002)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be 1024-65535")
    create_app(args.database).run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
