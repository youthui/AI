"""緊急通知（Windows のトースト通知。使えない環境ではコンソール出力）。"""

from __future__ import annotations

import logging
import sys
import threading

log = logging.getLogger("accounthub")


def notify(title: str, message: str) -> None:
    log.warning("ALERT %s: %s", title, message)
    if sys.platform != "win32":
        return
    def _run() -> None:
        try:
            from win11toast import toast
            toast(title, message, app_id="AccountHub")
        except Exception as e:  # 通知に失敗しても監視は止めない
            log.error("Windows 通知に失敗: %s", e)

    # toast() は閉じられるまで戻らないことがあるため別スレッドで出す
    threading.Thread(target=_run, daemon=True).start()
