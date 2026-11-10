"""取得したメールを解析・判定して保存し、必要なら通知する（取得元に依存しない部分）。"""

from __future__ import annotations

from typing import Callable, Iterable

from .config import SEVERITIES, Account, Config
from .db import Store
from .parsers import Message, find_account_addresses, parse
from .rules import evaluate

Notify = Callable[[str, str], None]


def resolve_account(cfg: Config, provider: str, msg: Message) -> Account | None:
    addrs = find_account_addresses(msg)
    # 同じアドレスを Microsoft アカウントのIDにも使っている場合があるので provider 一致を優先
    for want_provider in (True, False):
        for addr in addrs:
            for a in cfg.accounts:
                if addr in a.addresses and (not want_provider or a.provider == provider):
                    return a
    return None


def ingest(cfg: Config, store: Store, source_id: str, messages: Iterable[Message],
           notify: Notify | None = None) -> list[dict]:
    added: list[dict] = []
    threshold = SEVERITIES.index(cfg.settings.notify_min)
    for msg in messages:
        if store.has_message(source_id, msg.msg_id):
            continue
        ev = parse(msg)
        if ev is None:
            continue
        account = resolve_account(cfg, ev.provider, msg)
        verdict = evaluate(cfg, account, ev)
        row = dict(
            source_id=source_id, msg_id=msg.msg_id,
            account_id=account.id if account else None,
            provider=ev.provider, kind=ev.kind, device=ev.device, device_id=verdict.device_id,
            location=ev.location, occurred_at=msg.date.isoformat(timespec="seconds"),
            subject=msg.subject[:300], severity=verdict.severity, note=verdict.note,
        )
        if store.add_event(**row) is None:
            continue
        added.append(row)
        if notify and SEVERITIES.index(verdict.severity) >= threshold:
            who = account.display_name if account else "不明なアカウント"
            notify(f"[{verdict.severity.upper()}] {who}", verdict.note or msg.subject)
    return added
