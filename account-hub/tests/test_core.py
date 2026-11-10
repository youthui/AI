import base64
from datetime import datetime, timezone
from pathlib import Path

import pytest

from accounthub.config import ConfigError, load_config, parse_config
from accounthub.db import Store
from accounthub.demo import demo_fetcher, sample_messages
from accounthub.gmail_source import build_query, to_message
from accounthub.ingest import ingest
from accounthub.parsers import Message, classify, parse, sender_provider
from accounthub.server import create_app
from accounthub.service import Monitor, build_view

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cfg():
    return load_config(ROOT / "config.example.yaml")


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


def msg(sender, subject, body, to="security.example@gmail.com", mid="m1"):
    return Message(msg_id=mid, sender=sender, subject=subject, body=body,
                   date=datetime(2026, 11, 1, tzinfo=timezone.utc), recipients=[to])


# --- parsers ---
@pytest.mark.parametrize("sender,expected", [
    ("Google <no-reply@accounts.google.com>", "google"),
    ("x <account-security-noreply@accountprotection.microsoft.com>", "microsoft"),
    ("Apple <noreply@id.apple.com>", "apple"),
    ("phish <no-reply@accounts.google.com.evil.example>", None),
    ("someone@example.com", None),
])
def test_sender_provider(sender, expected):
    assert sender_provider(sender) == expected


@pytest.mark.parametrize("text,kind", [
    ("Microsoft アカウントの通常と異なるサインイン アクティビティ", "signin_unusual"),
    ("A new sign-in on a Windows device", "signin_new"),
    ("Your password was changed", "password_change"),
    ("2段階認証プロセスが有効になりました", "auth_change"),
    ("Recovery phone changed", "recovery_change"),
    ("お知らせ", "other_security"),
])
def test_classify(text, kind):
    assert classify(text) == kind


def test_parse_non_security_mail_ignored():
    assert parse(msg("shop@example.com", "Sale", "")) is None


def test_device_extraction_en_and_ja():
    assert parse(msg("no-reply@accounts.google.com", "Security alert",
                     "A new sign-in on a Windows device")).device == "Windows"
    assert parse(msg("no-reply@accounts.google.com", "セキュリティ通知",
                     "Galaxy S24 デバイスでの新しいログイン")).device == "Galaxy S24"


# --- rules / ingest ---
def test_security_account_alerts_on_unknown_device(cfg, store):
    alerts = []
    ingest(cfg, store, "hub", sample_messages(), lambda t, m: alerts.append((t, m)))
    by_id = {e["msg_id"]: e for e in store.events()}
    assert by_id["demo-1"]["severity"] == "critical"          # 許可外端末
    assert by_id["demo-1"]["account_id"] == "g-security"
    assert by_id["demo-2"]["device_id"] == "pc-main"           # 許可端末と一致
    assert by_id["demo-4"]["severity"] == "info"               # 制限なしのアカウント
    assert by_id["demo-5"]["account_id"] == "ms-device"
    assert any("Galaxy S24" in m for _, m in alerts)
    # notify_min=critical なので warn は通知しない
    assert all(t.startswith("[CRITICAL]") for t, _ in alerts)


def test_unknown_device_text_is_treated_as_unknown(cfg, store):
    ingest(cfg, store, "hub", [msg("no-reply@accounts.google.com", "新しいログイン", "詳細なし")])
    e = store.events()[0]
    assert e["severity"] == "critical" and "判別できません" in e["note"]


def test_ingest_is_idempotent(cfg, store):
    assert len(ingest(cfg, store, "hub", sample_messages())) == 6
    assert ingest(cfg, store, "hub", sample_messages()) == []


def test_unmatched_account_still_recorded(cfg, store):
    ingest(cfg, store, "hub", [msg("no-reply@accounts.google.com", "Your password was changed",
                                   "", to="stranger@example.com")])
    e = store.events()[0]
    assert e["account_id"] is None and e["severity"] == "warn"


# --- config ---
def test_config_rejects_unknown_device():
    with pytest.raises(ConfigError):
        parse_config({"accounts": [{"id": "a", "provider": "google", "email": "a@x.jp",
                                    "allowed_devices": ["nope"]}]})


def test_config_rejects_duplicate_ids():
    with pytest.raises(ConfigError):
        parse_config({"accounts": [{"id": "a", "provider": "google", "email": "a@x.jp"},
                                   {"id": "a", "provider": "apple", "email": "b@x.jp"}]})


# --- gmail conversion ---
def test_gmail_to_message_uses_forwarded_headers():
    b = base64.urlsafe_b64encode("<p>A new sign-in on a <b>Pixel</b> device</p>".encode()).decode()
    raw = {"id": "x1", "internalDate": "0", "payload": {
        "mimeType": "multipart/alternative",
        "headers": [{"name": "From", "value": "Google <no-reply@accounts.google.com>"},
                    {"name": "To", "value": "game.example@gmail.com"},
                    {"name": "Subject", "value": "Security alert"},
                    {"name": "Date", "value": "Sun, 01 Nov 2026 10:00:00 +0900"}],
        "parts": [{"mimeType": "text/html", "body": {"data": b}}]}}
    m = to_message(raw)
    assert m.recipients == ["game.example@gmail.com"]
    assert parse(m).device == "Pixel"
    assert m.date.utcoffset() is not None


def test_query_contains_all_senders():
    q = build_query(3)
    assert "accounts.google.com" in q and "id.apple.com" in q and "newer_than:3d" in q


# --- view / server ---
def test_view_and_server(cfg, store, tmp_path):
    mon = Monitor(cfg, store, tmp_path, fetcher=demo_fetcher, notify_fn=lambda *a: None)
    assert mon.poll_once() == 6
    v = build_view(cfg, store)
    assert v["counts"]["critical"] == 1 and v["total"] == 10
    assert sum(v["counts"][k] for k in ("critical", "warn", "ok")) == 10

    app = create_app(mon)
    c = app.test_client()
    page = c.get("/", headers={"Host": "127.0.0.1:8765"})
    assert page.status_code == 200 and "Galaxy S24" in page.get_data(as_text=True)
    # Host 偽装・トークンなしの操作は拒否
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 403
    alert_id = v["alerts"][0]["id"]
    assert c.post(f"/api/events/{alert_id}/ack").status_code == 403
    tok = app.config["ACTION_TOKEN"]
    assert c.post(f"/api/events/{alert_id}/ack", headers={"X-Action-Token": tok}).status_code == 200
    assert c.post("/api/accounts/g-dev/reviewed", headers={"X-Action-Token": tok}).status_code == 200
    assert c.post("/api/accounts/nope/reviewed", headers={"X-Action-Token": tok}).status_code == 404
    v2 = build_view(cfg, store)
    assert len(v2["alerts"]) == len(v["alerts"]) - 1


def test_poll_records_source_error(cfg, store, tmp_path):
    def boom(_):
        raise PermissionError("未認証")
    mon = Monitor(cfg, store, tmp_path, fetcher=boom, notify_fn=lambda *a: None)
    mon.poll_once()
    assert "未認証" in store.source_statuses()["hub"]["last_error"]
