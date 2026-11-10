"""監視ループとダッシュボード用データの組み立て。"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import SEVERITIES, Config
from .db import Store
from .ingest import ingest
from .notifier import notify
from .rules import KIND_LABELS

log = logging.getLogger("accounthub")


class Monitor:
    def __init__(self, cfg: Config, store: Store, data_dir: Path, fetcher=None, notify_fn=notify):
        self.cfg = cfg
        self.store = store
        self.data_dir = data_dir
        self.notify_fn = notify_fn
        self._fetcher = fetcher  # テスト・デモ用に差し替え可能
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._poll_lock = threading.Lock()

    def _fetch(self, source):
        if self._fetcher:
            return self._fetcher(source)
        from . import gmail_source
        return gmail_source.fetch(self.data_dir, source.id, source.query_days,
                                  known=lambda mid: self.store.has_message(source.id, mid))

    def poll_once(self) -> int:
        """全取得元を1回ずつ確認。追加したイベント数を返す。"""
        total = 0
        with self._poll_lock:
            for src in self.cfg.sources:
                try:
                    msgs = self._fetch(src)
                    total += len(ingest(self.cfg, self.store, src.id, msgs, self.notify_fn))
                    self.store.set_source_status(src.id, None)
                except Exception as e:
                    log.exception("取得失敗: %s", src.id)
                    self.store.set_source_status(src.id, f"{type(e).__name__}: {e}")
        return total

    def request_poll(self) -> None:
        self._wake.set()

    def run_forever(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._wake.wait(self.cfg.settings.poll_minutes * 60)
            self._wake.clear()

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, daemon=True, name="poller")
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _fmt(s: str | None) -> str:
    d = _parse_ts(s)
    return d.astimezone().strftime("%Y-%m-%d %H:%M") if d else "—"


def build_view(cfg: Config, store: Store, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    stale_after = timedelta(days=cfg.settings.review_stale_days)
    reviews = store.last_reviews()
    names = {a.id: a.display_name for a in cfg.accounts}

    def decorate(e: dict) -> dict:
        return {**e, "kind_label": KIND_LABELS.get(e["kind"], e["kind"]),
                "account_name": names.get(e["account_id"], "（判別不能）"),
                "when": _fmt(e["occurred_at"])}

    alerts = [decorate(e) for e in store.open_alerts()]
    alerts_by_acc: dict[str | None, list[dict]] = {}
    for e in alerts:
        alerts_by_acc.setdefault(e["account_id"], []).append(e)

    groups: dict[str, list[dict]] = {c: [] for c in cfg.categories()}
    counts = {"critical": 0, "warn": 0, "ok": 0, "stale": 0}
    for a in cfg.accounts:
        open_ = alerts_by_acc.get(a.id, [])
        status = "ok"
        if open_:
            status = max((e["severity"] for e in open_), key=SEVERITIES.index)
        recent = store.events(a.id, limit=1)
        reviewed = _parse_ts(reviews.get(a.id))
        stale = reviewed is None or now - reviewed > stale_after
        counts[status] += 1
        counts["stale"] += int(stale)
        groups[a.category or "未分類"].append({
            "a": a,
            "status": status,
            "open_alerts": open_,
            "last_event": decorate(recent[0]) if recent else None,
            "reviewed": _fmt(reviews.get(a.id)),
            "stale": stale,
            "allowed": [cfg.device(d).name for d in a.allowed_devices if cfg.device(d)],
        })

    devices = [{
        "d": d,
        "accounts": [a.display_name for a in cfg.accounts if d.id in a.allowed_devices],
    } for d in cfg.devices]

    statuses = store.source_statuses()
    sources = [{
        "s": s,
        "last_ok": _fmt((statuses.get(s.id) or {}).get("last_ok")),
        "error": (statuses.get(s.id) or {}).get("last_error"),
    } for s in cfg.sources]

    return {
        "now": now.astimezone().strftime("%Y-%m-%d %H:%M"),
        "alerts": alerts,
        "groups": groups,
        "counts": counts,
        "total": len(cfg.accounts),
        "devices": devices,
        "sources": sources,
        "events": [decorate(e) for e in store.events(limit=100)],
        "stale_days": cfg.settings.review_stale_days,
    }
