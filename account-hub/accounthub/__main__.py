"""起動コマンド。

  python -m accounthub init            設定ファイルの雛形を作成
  python -m accounthub auth <source>   Gmail の読み取り許可（初回）
  python -m accounthub run             監視＋ダッシュボードを起動（既定）
  python -m accounthub poll            1回だけ取得して結果を表示
  python -m accounthub demo            サンプルデータで画面を確認
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path

from .config import ConfigError, default_data_dir, load_config
from .db import Store
from .service import Monitor

PKG_DIR = Path(__file__).resolve().parent
EXAMPLE = PKG_DIR.parent / "config.example.yaml"
log = logging.getLogger("accounthub")


def _paths(args) -> tuple[Path, Path]:
    data_dir = Path(args.data_dir) if args.data_dir else default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = Path(args.config) if args.config else data_dir / "config.yaml"
    return data_dir, cfg_path


def _serve(monitor: Monitor, port: int, window: bool) -> None:
    from .server import create_app

    app = create_app(monitor)
    url = f"http://127.0.0.1:{port}/"
    if window:
        try:
            import webview  # pywebview: 独立したウィンドウ（WebView2）で表示
        except ImportError:
            webview = None
        if webview:
            threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, threaded=True),
                             daemon=True).start()
            webview.create_window("Account Hub", url, width=1280, height=860)
            webview.start()
            return
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"ダッシュボード: {url}  （終了: Ctrl+C）")
    app.run(host="127.0.0.1", port=port, threaded=True)


def cmd_init(args) -> int:
    data_dir, cfg_path = _paths(args)
    if cfg_path.exists():
        print(f"既にあります: {cfg_path}")
        return 1
    shutil.copy(EXAMPLE, cfg_path)
    print(f"作成しました: {cfg_path}\nアカウントとデバイスを書き換えてください。")
    return 0


def cmd_auth(args) -> int:
    from .gmail_source import authorize

    data_dir, cfg_path = _paths(args)
    cfg = load_config(cfg_path)
    if not any(s.id == args.source for s in cfg.sources):
        print(f"source が設定にありません: {args.source}")
        return 1
    where = authorize(data_dir, args.source)
    print(f"保存しました（{where}）")
    return 0


def cmd_run(args) -> int:
    data_dir, cfg_path = _paths(args)
    cfg = load_config(cfg_path)
    monitor = Monitor(cfg, Store(data_dir / "accounthub.db"), data_dir)
    monitor.start()
    _serve(monitor, args.port or cfg.settings.port, window=not args.no_window)
    return 0


def cmd_poll(args) -> int:
    data_dir, cfg_path = _paths(args)
    cfg = load_config(cfg_path)
    monitor = Monitor(cfg, Store(data_dir / "accounthub.db"), data_dir)
    n = monitor.poll_once()
    for sid, st in monitor.store.source_statuses().items():
        print(f"{sid}: {'エラー ' + st['last_error'] if st['last_error'] else '正常'}")
    print(f"新規イベント: {n}件")
    return 0


def cmd_demo(args) -> int:
    from .demo import demo_fetcher

    data_dir = Path(tempfile.mkdtemp(prefix="accounthub-demo-"))
    cfg = load_config(EXAMPLE)
    monitor = Monitor(cfg, Store(data_dir / "demo.db"), data_dir, fetcher=demo_fetcher,
                      notify_fn=lambda t, m: print(f"[通知] {t}: {m}"))
    monitor.poll_once()
    monitor.store.mark_reviewed(cfg.accounts[0].id)
    _serve(monitor, args.port or cfg.settings.port, window=not args.no_window)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="accounthub")
    p.add_argument("--data-dir", help="データ保存先（既定: %%LOCALAPPDATA%%\\AccountHub）")
    p.add_argument("--config", help="設定ファイル（既定: <data-dir>/config.yaml）")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("init")
    a = sub.add_parser("auth")
    a.add_argument("source")
    for name in ("run", "demo"):
        s = sub.add_parser(name)
        s.add_argument("--port", type=int)
        s.add_argument("--no-window", action="store_true", help="ブラウザ／ウィンドウを開かない")
    sub.add_parser("poll")
    args = p.parse_args(argv)
    if args.cmd is None:  # 引数なし（ダブルクリック起動）は run 扱い
        args.cmd, args.port, args.no_window = "run", None, False
    handlers = {"init": cmd_init, "auth": cmd_auth, "run": cmd_run, "poll": cmd_poll,
                "demo": cmd_demo}
    try:
        return handlers[args.cmd](args)
    except (ConfigError, FileNotFoundError, PermissionError) as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
