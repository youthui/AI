"""イベントの重大度判定。

基本方針:
- 許可端末が決まっているアカウントは「許可外 or 判別不能な端末でのログイン」を
  on_unknown_device の重大度にする（セキュリティ用なら critical を推奨）。
- 認証方法・パスワード・復旧情報の変更は乗っ取りの典型手順なので既定で warn 以上。
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import SEVERITIES, Account, Config
from .parsers import ParsedEvent

DEFAULT_SEVERITY = {
    "signin_new": "info",
    "signin_unusual": "warn",
    "password_change": "warn",
    "recovery_change": "warn",
    "auth_change": "warn",
    "app_access": "info",
    "other_security": "info",
}

KIND_LABELS = {
    "signin_new": "新しいログイン",
    "signin_unusual": "不審なログイン",
    "password_change": "パスワード変更",
    "recovery_change": "復旧情報の変更",
    "auth_change": "認証方法の変更",
    "app_access": "アプリ連携",
    "other_security": "その他の通知",
}

SIGNIN_KINDS = {"signin_new", "signin_unusual"}


@dataclass
class Verdict:
    severity: str
    note: str
    device_id: str = ""


def max_sev(*sevs: str) -> str:
    return max(sevs, key=SEVERITIES.index)


def evaluate(cfg: Config, account: Account | None, ev: ParsedEvent) -> Verdict:
    base = DEFAULT_SEVERITY.get(ev.kind, "info")
    if account is None:
        return Verdict(base, "どの登録アカウント宛か判別できません")

    sev = account.severity_overrides.get(ev.kind, base)
    note = ""
    device_id = ""

    if ev.kind in SIGNIN_KINDS and account.allowed_devices:
        allowed = [cfg.device(d) for d in account.allowed_devices]
        hit = next((d for d in allowed if d and ev.device and d.matches(ev.device)), None)
        if hit:
            device_id = hit.id
            note = f"許可端末「{hit.name}」と一致"
            if sev != "info":
                # 通知メールの端末表記は種別程度なので、一致しても本人の端末とは限らない
                note += "（表記のみの一致。各社画面で実機を確認）"
        elif not ev.device:
            sev = max_sev(sev, account.on_unknown_device)
            note = "端末を判別できません（許可端末の制限あり）"
        else:
            sev = max_sev(sev, account.on_unknown_device)
            note = f"許可外の端末: {ev.device}"
    elif ev.kind in SIGNIN_KINDS and ev.device:
        hit = next((d for d in cfg.devices if d.matches(ev.device)), None)
        if hit:
            device_id = hit.id
            note = f"登録端末「{hit.name}」と一致"

    return Verdict(sev, note, device_id)
