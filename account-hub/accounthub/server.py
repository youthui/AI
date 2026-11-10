"""ローカル専用のダッシュボード（127.0.0.1 のみで待ち受け）。"""

from __future__ import annotations

import secrets

from flask import Flask, abort, jsonify, render_template, request

from .service import Monitor, build_view

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def create_app(monitor: Monitor) -> Flask:
    app = Flask(__name__)
    # 他サイトからの書き込み要求（CSRF）を防ぐため、操作には起動ごとの乱数トークンを要求する
    token = secrets.token_urlsafe(24)
    app.config["ACTION_TOKEN"] = token

    @app.before_request
    def _guard():
        # DNS リバインディング対策: Host ヘッダがローカル以外なら拒否
        host = (request.host or "").rsplit(":", 1)[0].strip("[]")
        if host not in ALLOWED_HOSTS:
            abort(403)
        if request.method == "POST" and request.headers.get("X-Action-Token") != token:
            abort(403)

    @app.after_request
    def _headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return resp

    @app.get("/")
    def index():
        return render_template("dashboard.html", v=build_view(monitor.cfg, monitor.store),
                               token=token)

    @app.get("/api/summary")
    def summary():
        v = build_view(monitor.cfg, monitor.store)
        return jsonify(counts=v["counts"], alerts=len(v["alerts"]))

    @app.post("/api/events/<int:event_id>/ack")
    def ack(event_id: int):
        if not monitor.store.acknowledge(event_id):
            abort(404)
        return jsonify(ok=True)

    @app.post("/api/accounts/<account_id>/reviewed")
    def reviewed(account_id: str):
        if monitor.cfg.account(account_id) is None:
            abort(404)
        return jsonify(ok=True, reviewed_at=monitor.store.mark_reviewed(account_id))

    @app.post("/api/poll")
    def poll():
        monitor.request_poll()
        return jsonify(ok=True)

    return app
