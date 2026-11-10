"""画面確認用のサンプル通知（架空のデータ。実際の各社メールの文面とは異なる場合があります）。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .parsers import Message

GOOGLE = "Google <no-reply@accounts.google.com>"
MS = "Microsoft account team <account-security-noreply@accountprotection.microsoft.com>"
APPLE = "Apple <noreply@id.apple.com>"


def sample_messages(now: datetime | None = None) -> list[Message]:
    now = now or datetime.now(timezone.utc)

    def m(i, sender, to, subject, body, hours):
        return Message(msg_id=f"demo-{i}", sender=sender, subject=subject, body=body,
                       date=now - timedelta(hours=hours), recipients=[to])

    return [
        m(1, GOOGLE, "security.example@gmail.com", "セキュリティ通知",
          "Galaxy S24 デバイスでの新しいログイン\nsecurity.example@gmail.com\n"
          "お使いの Google アカウントへの新しいログインがありました。", 1),
        m(2, GOOGLE, "security.example@gmail.com", "Security alert",
          "A new sign-in on a Windows device\nsecurity.example@gmail.com", 30),
        m(3, GOOGLE, "finance.example@gmail.com", "Security alert",
          "2-Step Verification settings changed for finance.example@gmail.com", 5),
        m(4, GOOGLE, "game.example@gmail.com", "Security alert",
          "A new sign-in on a Pixel device\ngame.example@gmail.com", 50),
        m(5, MS, "device.example@outlook.jp", "Microsoft アカウントの通常と異なるサインイン アクティビティ",
          "国/地域: 不明\nプラットフォーム: Linux\nブラウザー: Firefox", 12),
        m(6, APPLE, "apple.example@icloud.com",
          "Your Apple Account was used to sign in to iCloud via a web browser",
          "Date and Time: ...\nLocation: Tokyo, Japan", 70),
    ]


def demo_fetcher(source):
    return sample_messages()
