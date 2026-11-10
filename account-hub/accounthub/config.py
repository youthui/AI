"""設定ファイル（YAML）の読み込みと検証。

アカウント・デバイス・取得元（メールボックス）をすべてここで定義する。
将来サービスやデバイスを増やすときも、基本はこのファイルに追記するだけで済む形にしている。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITIES = ("info", "warn", "critical")
PROVIDERS = ("google", "microsoft", "apple", "other")

# 各社のセキュリティ確認ページ（ダッシュボードのリンク用）
SECURITY_URLS = {
    "google": {
        "端末": "https://myaccount.google.com/device-activity",
        "セキュリティ": "https://myaccount.google.com/security",
        "診断": "https://myaccount.google.com/security-checkup",
    },
    "microsoft": {
        "端末": "https://account.microsoft.com/devices",
        "セキュリティ": "https://account.microsoft.com/security",
        "サインイン履歴": "https://account.live.com/Activity",
    },
    "apple": {
        "アカウント": "https://account.apple.com/account/manage",
    },
    "other": {},
}


class ConfigError(ValueError):
    pass


@dataclass
class Device:
    id: str
    name: str
    type: str = ""
    # 通知メール中の端末表記にマッチさせる文字列（大文字小文字は区別しない）
    match: list[str] = field(default_factory=list)
    notes: str = ""

    def matches(self, text: str) -> bool:
        t = text.lower()
        return any(m.lower() in t for m in self.match)


@dataclass
class Account:
    id: str
    provider: str
    email: str
    category: str = ""
    label: str = ""
    auth_methods: list[str] = field(default_factory=list)
    # ログインを許可するデバイスID（devices の id）。空なら端末制限なし
    allowed_devices: list[str] = field(default_factory=list)
    # 許可外/判別不能な端末でのログインの重大度
    on_unknown_device: str = "warn"
    # 種別ごとの重大度上書き（例: {auth_change: critical}）
    severity_overrides: dict[str, str] = field(default_factory=dict)
    # このアカウント宛のメールを判別する追加のアドレス（エイリアス等）
    aliases: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def display_name(self) -> str:
        return self.label or self.email

    @property
    def addresses(self) -> list[str]:
        return [a.lower() for a in [self.email, *self.aliases] if a]

    @property
    def links(self) -> dict[str, str]:
        return SECURITY_URLS.get(self.provider, {})


@dataclass
class Source:
    id: str
    type: str = "gmail"
    label: str = ""
    query_days: int = 3


@dataclass
class Settings:
    poll_minutes: int = 5
    review_stale_days: int = 30
    port: int = 8765
    # この重大度以上で Windows 通知を出す
    notify_min: str = "critical"


@dataclass
class Config:
    settings: Settings
    devices: list[Device]
    accounts: list[Account]
    sources: list[Source]

    def device(self, device_id: str) -> Device | None:
        return next((d for d in self.devices if d.id == device_id), None)

    def account(self, account_id: str) -> Account | None:
        return next((a for a in self.accounts if a.id == account_id), None)

    def categories(self) -> list[str]:
        seen: list[str] = []
        for a in self.accounts:
            c = a.category or "未分類"
            if c not in seen:
                seen.append(c)
        return seen


def default_data_dir() -> Path:
    env = os.environ.get("ACCOUNTHUB_HOME")
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "AccountHub"


_ID_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _check_id(kind: str, value: str) -> None:
    if not value or not _ID_RE.match(value):
        raise ConfigError(f"{kind} の id が不正です（英数字・_・- のみ）: {value!r}")


def _check_sev(where: str, value: str) -> None:
    if value not in SEVERITIES:
        raise ConfigError(f"{where}: 重大度は {SEVERITIES} のいずれか: {value!r}")


def parse_config(raw: dict) -> Config:
    raw = raw or {}
    settings = Settings(**(raw.get("settings") or {}))
    _check_sev("settings.notify_min", settings.notify_min)

    devices = [Device(**d) for d in raw.get("devices") or []]
    for d in devices:
        _check_id("device", d.id)

    accounts = [Account(**a) for a in raw.get("accounts") or []]
    device_ids = {d.id for d in devices}
    for a in accounts:
        _check_id("account", a.id)
        if a.provider not in PROVIDERS:
            raise ConfigError(f"account {a.id}: provider は {PROVIDERS} のいずれか")
        _check_sev(f"account {a.id}.on_unknown_device", a.on_unknown_device)
        for k, v in a.severity_overrides.items():
            _check_sev(f"account {a.id}.severity_overrides.{k}", v)
        for dev in a.allowed_devices:
            if dev not in device_ids:
                raise ConfigError(f"account {a.id}: 未定義のデバイス {dev!r}")

    sources = [Source(**s) for s in raw.get("sources") or []]
    for s in sources:
        _check_id("source", s.id)
        if s.type != "gmail":
            raise ConfigError(f"source {s.id}: 現在対応しているのは type: gmail のみ")

    for kind, items in (("device", devices), ("account", accounts), ("source", sources)):
        ids = [i.id for i in items]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ConfigError(f"{kind} の id が重複しています: {sorted(dup)}")

    return Config(settings=settings, devices=devices, accounts=accounts, sources=sources)


def load_config(path: Path) -> Config:
    if not path.exists():
        raise ConfigError(f"設定ファイルがありません: {path}")
    with path.open(encoding="utf-8") as f:
        return parse_config(yaml.safe_load(f))
