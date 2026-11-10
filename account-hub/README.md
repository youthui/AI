# Account Hub

Google / Microsoft / Apple の複数アカウントのセキュリティ状態を、1つのダッシュボードで監視する Windows 向けアプリです。

## できること

- アカウントの一覧表示（カテゴリ・承認方法・ログインを許可した端末・各社確認ページへのリンク）
- 各社のセキュリティ通知メールを自動で取得し、イベントとして記録（Gmail API・読み取り専用）
- 緊急時だけ Windows に通知する
  - 例: セキュリティ用アカウントに、許可していない端末からログインがあった
- 各社の画面で手動確認した日を記録し、30日（設定で変更可）を過ぎたら「要確認」を表示
- デバイスごとに、どのアカウントでログインを許可しているかを一覧表示

## できないこと（前提）

- **ログイン中の端末一覧や承認方法を自動では取得できない**
  - 個人アカウント向けに、それを返す公式APIを各社が用意していないため
  - 承認方法は設定ファイルに手で書き、端末一覧は各社の画面で確認する（カードのリンクから開ける）
- **通知メールの端末名は「Windows」「Pixel」程度の大まかな表記**
  - 他人の Windows でも「許可端末と一致」と判定されることがある
  - 厳しく見たいアカウントは `severity_overrides: {signin_new: critical}` にして、新しいログインの通知をすべて緊急扱いにする
- 通知メールの文面は各社が予告なく変える
  - 判別できなかった通知も「その他の通知」として必ず記録する
  - 判別キーワードは実際のメールを見て `accounthub/parsers.py` で調整する

## しくみ

```
各アカウントの受信箱
  → (Gmailの自動転送) 集約用Gmail
  → (Gmail API・読み取り専用・5分ごと) Account Hub
  → 解析・判定 → ダッシュボード / Windows通知
```

## セットアップ

### 1. Python

Python 3.11 以上をインストールする（https://www.python.org/ 、インストール時に「Add to PATH」にチェック）。

### 2. Gmail API の準備（初回のみ）

1. https://console.cloud.google.com/ でプロジェクトを作成
2. 「APIとサービス」→「ライブラリ」→ **Gmail API** を有効にする
3. 「OAuth 同意画面」を作成（ユーザーの種類: 外部）
   - テストユーザーに集約用 Gmail を追加
   - **公開ステータスを「本番環境」にする**。「テスト」のままだと、認証が7日ごとに切れる
   - 自分専用の未審査アプリなので、許可するときに警告が出る。自分で作ったアプリであることを確かめて進める
4. 「認証情報」→「OAuth クライアント ID」→ 種類は **デスクトップアプリ** → JSON をダウンロード
5. ダウンロードした JSON を `%LOCALAPPDATA%\AccountHub\client_secret.json` として保存

### 3. 通知メールを集約用 Gmail に転送

監視したい各 Google アカウントで、次の2つを設定する。

1. Gmail の「設定」→「メール転送と POP/IMAP」→ 転送先に集約用 Gmail を追加
   - 集約用 Gmail に確認メールが届くので承認する
2. 「フィルタを作成」で、次の条件のメールを集約用 Gmail に転送する
   ```
   from:(accounts.google.com OR accountprotection.microsoft.com OR id.apple.com OR email.apple.com)
   ```

Microsoft と Apple の通知は、そのアカウントの連絡先メールに届く。連絡先が Gmail であれば、同じ方法で転送する。

**集約用 Gmail の選び方**

- このアプリは集約用 Gmail の全メールを読める権限を持つ
- 普段使っていない専用のアカウントにするのが安全

### 4. 設定と起動

このフォルダで、コマンドプロンプトから次を実行する。

```bat
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m accounthub init
```

1. 作成された `%LOCALAPPDATA%\AccountHub\config.yaml` に、アカウントとデバイスを書く（書き方は `config.example.yaml` を参照）
2. Gmail へのアクセスを許可する（ブラウザが開く）
   ```bat
   .venv\Scripts\python -m accounthub auth hub
   ```
3. 1回だけ取得して、動作を確認する
   ```bat
   .venv\Scripts\python -m accounthub poll
   ```
4. 以降は `start.bat` をダブルクリックで起動する

PC の起動時に自動で立ち上げたい場合は、`Win+R` で `shell:startup` を開き、`start.bat` のショートカットを置く。

### デモ表示（Gmail の設定なしで画面を確認）

```bat
.venv\Scripts\python -m accounthub demo
```

## 設定のポイント

| 項目 | 意味 |
|---|---|
| `allowed_devices` | ログインを許可する端末の ID。空なら制限なし |
| `on_unknown_device` | 許可外・判別できない端末でのログインの重大度 |
| `severity_overrides` | 通知の種別ごとの重大度を上書きする |
| `settings.notify_min` | この重大度以上で Windows に通知する |

通知の種別は次の7つ。

- `signin_new`（新しいログイン）
- `signin_unusual`（不審なログイン）
- `password_change`（パスワード変更）
- `recovery_change`（復旧情報の変更）
- `auth_change`（認証方法の変更）
- `app_access`（アプリ連携）
- `other_security`（その他の通知）

## セキュリティ

- 画面はこのPCの中でしか開けない（`127.0.0.1` でのみ待ち受ける）
  - 他のサイトから操作されないよう、操作のたびに起動ごとのトークンを確認する
  - 外部ドメインからのアクセス（Host ヘッダの偽装）も拒否する
- Gmail の権限は `gmail.readonly` のみ
- 認証トークンは Windows 資格情報マネージャーに保存する（keyring を使用）

## 今後の拡張

- 取得元は `sources` に追加する形で増やせる（現在の対応は Gmail のみ）
- デバイスとアカウントは設定ファイルでまとめて管理しているので、ほかのサービスも `provider: other` で追加できる

## 開発

```bash
pip install -r requirements-dev.txt
python -m pytest
```
