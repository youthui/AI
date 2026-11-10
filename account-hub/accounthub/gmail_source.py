"""Gmail API（読み取り専用）からセキュリティ通知メールを取得する。

- 権限は gmail.readonly のみ。送信・削除はできない。
- トークンは Windows 資格情報マネージャー（keyring）に保存。使えない環境ではファイルに保存。
"""

from __future__ import annotations

import base64
import html
import json
import re
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from .parsers import SENDER_DOMAINS, Message

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
KEYRING_SERVICE = "AccountHub"
RECIPIENT_HEADERS = ("to", "cc", "delivered-to", "x-forwarded-to", "x-original-to", "x-forwarded-for")


def build_query(days: int) -> str:
    senders = " OR ".join(sorted(set(SENDER_DOMAINS)))
    return f"from:({senders}) newer_than:{int(days)}d"


# ---------- token storage ----------
def _keyring():
    try:
        import keyring
        from keyring.backends import fail
        if isinstance(keyring.get_keyring(), fail.Keyring):
            return None
        return keyring
    except Exception:
        return None


def save_token(data_dir: Path, source_id: str, token_json: str) -> str:
    kr = _keyring()
    if kr:
        kr.set_password(KEYRING_SERVICE, f"gmail:{source_id}", token_json)
        return "keyring"
    p = data_dir / "tokens" / f"{source_id}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(token_json, encoding="utf-8")
    return str(p)


def load_token(data_dir: Path, source_id: str) -> str | None:
    kr = _keyring()
    if kr:
        v = kr.get_password(KEYRING_SERVICE, f"gmail:{source_id}")
        if v:
            return v
    p = data_dir / "tokens" / f"{source_id}.json"
    return p.read_text(encoding="utf-8") if p.exists() else None


# ---------- auth ----------
def authorize(data_dir: Path, source_id: str) -> str:
    """ブラウザで Google にログインして許可する（初回・トークン失効時）。"""
    from google_auth_oauthlib.flow import InstalledAppFlow

    secret = data_dir / "client_secret.json"
    if not secret.exists():
        raise FileNotFoundError(
            f"{secret} がありません。README の「Gmail API の準備」を参照してください。")
    flow = InstalledAppFlow.from_client_secrets_file(str(secret), SCOPES)
    creds = flow.run_local_server(port=0, open_browser=True)
    return save_token(data_dir, source_id, creds.to_json())


def _credentials(data_dir: Path, source_id: str):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    raw = load_token(data_dir, source_id)
    if not raw:
        raise PermissionError(f"未認証です: python -m accounthub auth {source_id}")
    creds = Credentials.from_authorized_user_info(json.loads(raw), SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            save_token(data_dir, source_id, creds.to_json())
        else:
            raise PermissionError(f"再認証が必要です: python -m accounthub auth {source_id}")
    return creds


# ---------- message conversion ----------
def _b64(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def _strip_html(s: str) -> str:
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", s)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"[ \t ]+", " ", s)


def extract_body(payload: dict) -> str:
    plain, htm = [], []

    def walk(p: dict) -> None:
        mime = p.get("mimeType", "")
        data = (p.get("body") or {}).get("data")
        if data and mime == "text/plain":
            plain.append(_b64(data))
        elif data and mime == "text/html":
            htm.append(_b64(data))
        for c in p.get("parts") or []:
            walk(c)

    walk(payload)
    return "\n".join(plain) if plain else _strip_html("\n".join(htm))


def to_message(raw: dict) -> Message:
    headers = {}
    for h in raw.get("payload", {}).get("headers", []):
        headers.setdefault(h["name"].lower(), []).append(h["value"])
    recipients = [addr for name in RECIPIENT_HEADERS
                  for _, addr in getaddresses(headers.get(name, [])) if addr]
    try:
        date = parsedate_to_datetime(headers["date"][0])
    except Exception:
        date = datetime.fromtimestamp(int(raw.get("internalDate", "0")) / 1000, timezone.utc)
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return Message(
        msg_id=raw["id"],
        sender=(headers.get("from") or [""])[0],
        subject=(headers.get("subject") or [""])[0],
        body=extract_body(raw.get("payload", {})),
        date=date,
        recipients=recipients,
    )


# ---------- fetch ----------
def fetch(data_dir: Path, source_id: str, days: int, known=lambda mid: False) -> list[Message]:
    from googleapiclient.discovery import build

    svc = build("gmail", "v1", credentials=_credentials(data_dir, source_id), cache_discovery=False)
    out: list[Message] = []
    token = None
    while True:
        res = svc.users().messages().list(
            userId="me", q=build_query(days), pageToken=token, maxResults=100).execute()
        for m in res.get("messages", []):
            if known(m["id"]):
                continue
            raw = svc.users().messages().get(userId="me", id=m["id"], format="full").execute()
            out.append(to_message(raw))
        token = res.get("nextPageToken")
        if not token:
            return out
