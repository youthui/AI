"""各社のセキュリティ通知メールを「イベント」に変換する。

注意:
- 通知メールの文面は各社が予告なく変える。ここのキーワードは
  実物のメールで調整する前提の「初期値」。
- 判別できなかった通知も kind="other_security" として残し、取りこぼさない。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

# 送信元ドメイン → プロバイダ
SENDER_DOMAINS = {
    "accounts.google.com": "google",
    "accountprotection.microsoft.com": "microsoft",
    "account.microsoft.com": "microsoft",
    "id.apple.com": "apple",
    "email.apple.com": "apple",
    "apple.com": "apple",
}

# 種別判定キーワード（上から順に評価。英語・日本語の両方）
KIND_RULES: list[tuple[str, list[str]]] = [
    ("signin_unusual", [
        "unusual sign-in", "suspicious sign-in", "blocked a sign-in", "sign-in attempt was blocked",
        "通常と異なるサインイン", "不審なログイン", "ログインをブロック", "疑わしいログイン",
    ]),
    ("signin_new", [
        "new sign-in", "was used to sign in", "signed in to", "new device", "new login",
        "新しいログイン", "新しいデバイス", "サインインに使用されました", "サインインしました",
        "ログインがありました",
    ]),
    ("password_change", [
        "password was changed", "password changed", "password has been changed", "password was reset",
        "パスワードが変更", "パスワードを変更", "パスワードがリセット",
    ]),
    ("recovery_change", [
        "recovery email", "recovery phone", "recovery information", "trusted phone number",
        "再設定用", "復旧用", "信頼できる電話番号",
    ]),
    ("auth_change", [
        "2-step verification", "two-step verification", "two-factor", "passkey", "security key",
        "security info", "authenticator", "sign-in method",
        "2 段階認証", "2段階認証", "2 ファクタ", "2ファクタ", "パスキー", "セキュリティ キー",
        "セキュリティキー", "セキュリティ情報", "認証システム", "サインイン方法",
    ]),
    ("app_access", [
        "access to your google account", "third-party", "connected to your", "app password",
        "アクセスを許可", "サードパーティ", "アプリ パスワード", "アプリパスワード",
    ]),
]

# 端末名の抽出パターン（最初にマッチしたもの）
DEVICE_PATTERNS = [
    re.compile(r"\bon (?:a|an) (.{2,60}?) device\b", re.I),
    re.compile(r"(?:device|デバイス)\s*[:：]\s*([^\n]{2,60})", re.I),
    re.compile(r"(?:platform|プラットフォーム|os)\s*[:：]\s*([^\n]{2,60})", re.I),
    re.compile(r"(?m)^\s*([^\n、。]{2,40}?)\s*デバイスで(?:の)?(?:新しい)?(?:ログイン|サインイン)"),
    re.compile(r"\bvia (?:a )?(web browser|[A-Za-z][\w ]{1,30}?)(?:[.,\n]|$)", re.I),
]

LOCATION_PATTERNS = [
    re.compile(r"(?:location|country/region|国/地域|場所|地域)\s*[:：]\s*([^\n]{2,60})", re.I),
    re.compile(r"\bnear ([A-Z][\w ,\-]{2,60})"),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


@dataclass
class Message:
    msg_id: str
    sender: str
    subject: str
    body: str
    date: datetime
    # To / Delivered-To / X-Forwarded-To などから集めた宛先
    recipients: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    provider: str
    kind: str
    device: str = ""
    location: str = ""


def sender_provider(sender: str) -> str | None:
    m = EMAIL_RE.search(sender or "")
    if not m:
        return None
    domain = m.group(0).split("@", 1)[1].lower()
    for d, provider in SENDER_DOMAINS.items():
        if domain == d or domain.endswith("." + d):
            return provider
    return None


def classify(text: str) -> str:
    t = text.lower()
    for kind, words in KIND_RULES:
        if any(w.lower() in t for w in words):
            return kind
    return "other_security"


def _first(patterns: list[re.Pattern], text: str) -> str:
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(1).strip(" .、。")
    return ""


def parse(msg: Message) -> ParsedEvent | None:
    """セキュリティ通知でなければ None。"""
    provider = sender_provider(msg.sender)
    if provider is None:
        return None
    # 件名を優先して判定し、決まらなければ本文も見る
    kind = classify(msg.subject)
    if kind == "other_security":
        kind = classify(msg.body[:3000])
    text = f"{msg.subject}\n{msg.body}"
    return ParsedEvent(
        provider=provider,
        kind=kind,
        device=_first(DEVICE_PATTERNS, text),
        location=_first(LOCATION_PATTERNS, msg.body),
    )


def find_account_addresses(msg: Message) -> list[str]:
    """宛先ヘッダ → 本文の順でメールアドレスを集める（重複除去・小文字）。"""
    found: list[str] = []
    for src in [*msg.recipients, msg.body]:
        for m in EMAIL_RE.findall(src or ""):
            m = m.lower()
            if m not in found:
                found.append(m)
    return found
