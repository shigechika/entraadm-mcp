# Reference

## 認証方式

どの環境変数が設定されているかで2つのモードを切り替える。

| モード | 条件 | 環境変数 |
|---|---|---|
| app-only | 3つとも設定 | `ENTRAADM_TENANT_ID`、`ENTRAADM_CLIENT_ID`、`ENTRAADM_CLIENT_SECRET` |
| azure-cli | 3つとも未設定 | 現在の `az login` セッションを使う |

app-only 用3変数のうち1つか2つだけの設定は、起動時に設定エラーとなる
（黙って別モードへフォールバックしない）。

任意: `ENTRAADM_MAX_PAGES_DEFAULT`（1-50、既定 50）は、ツール呼び出しで
`max_pages` を明示しなかった場合のログ走査系ツールのページ上限既定値。

任意: `ENTRAADM_DEADLINE`（秒、既定 45、`0` で無効）は、1 回のツール呼び出しの
持ち時間。ホスト型の MCP クライアントは約 60 秒で呼び出しを打ち切るので，走査は
この時間で止まり，1 回の要求のタイムアウトも残り時間で切り，それまでに取れた分を
`capped=true` で返す。`daily_brief` は 2 つの節で 1 つの持ち時間を共有する。
`directory_audits` は `category`（例: `UserManagement`）で Graph 側の絞り込みもできる。

### 必要な Graph 権限

| ツール | 権限 |
|---|---|
| `get_user`（基本フィールド） | `User.Read.All` |
| `signin_logs`、`signin_failure_stats`、`signin_success_stats`、`signin_by_ip`、`directory_audits`、`get_user` の `sign_in_activity` フィールド | `AuditLog.Read.All`（app-only）または **Reports Reader** ディレクトリロール（delegated） |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All`（app-only 専用） |

## ツール

### `health_check()`

引数なし。`{service, version, status, auth_mode, graph, signin_probe}` を返す。
`graph` は基本的な Graph 到達性（`GET /users`、`$top=1` — `User.Read.All` のみで通る）を、`signin_probe` は
サインインログ読み取り可否を追加でプローブする。`status` は両方成功で
`"healthy"`、Graph到達可だがサインインログ読み取り不可で `"degraded"`、
Graph自体に到達不可または認証設定不備で `"error"`。`graph`／`signin_probe` は
それぞれ `{auth: "ok"|"error", detail: str|null}`。

### `get_user(upn)`

アカウントのライフサイクル状態：`accountEnabled`、`userType`、作成日時・
最終パスワード変更日時、オンプレ同期状態、解決済みライセンス名、
（`AuditLog.Read.All`／Reports Reader が利用可能なら）`sign_in_activity`。
存在しないアカウントはエラーではなく `{"found": false, "user_principal_name": upn}` を返す。
`licenses_capped: true` は、このアカウント自身のライセンスを解決する前に SKU カタログの
走査が打ち切られた場合にのみ現れる——このキーがある場合、`licenses` の一部は
解決済みの名前ではなく生の skuId のまま。

### `signin_logs(user, hours=24, result="failure", top=25, max_pages=None)`

このユーザのサインインイベント。`result`: `"failure"`（既定、最頻用途）／
`"success"`／`"all"` — Graph はサインインを `status/errorCode` でサーバ側
フィルタできないため、クライアント側でフィルタする。各イベントの
`error_code` には、手作業で保守している AADSTS コード表から
`error_code_meaning`（例：50126 →「invalid credentials（パスワード相違）」）が
注釈される。`hours` は 1-720（30日 — Entra ID P1 のサインインログ保持期間）に
クランプ。`capped=true` はページ予算が尽きた（または `top` に到達した）ことで
窓全体を走査しきれなかったことを意味する——一致件数が少なく `capped=true` の
場合は「予算内で見つからなかった」のであって「存在しない」ではない。

### `signin_failure_stats(hours=24, max_pages=None)`

テナント全体の失敗集計：AADSTS エラーコード（注釈付き）・失敗ユーザ・アプリ・
送信元IPの上位。`spray_suspects` は、5人以上の異なるユーザに対して失敗している
IP を列挙する——Entra のアカウント単位スマートロックアウトだけでは捉えられない
パターン。`hours` の扱いは上記と同様。

### `signin_success_stats(hours=24, max_pages=None, min_distinct_users=2)`

テナント全体の*成功した*サインインを送信元IPで集計する——`signin_failure_stats`
の対：あちらは誰が攻撃されているかを、こちらは誰かが入られたかを示す。
`shared_ips` は `min_distinct_users` 人以上の異なるアカウントで成功している IP を
列挙する（IP ごとにアカウント名 25 件まで・クライアントアプリ・国・初回/最終時刻）。
`legacy_auth_users` はレガシー認証（`Authenticated SMTP`・`IMAP4`・`POP3` など、
MFA の掛からないプロトコル）で成功したアカウントを列挙する。学内 NAT や VDI も
多数のアカウントを 1 つの IP に載せるので、自組織の出口レンジを除いてから
`shared_ips` を読むこと。ログ走査と `capped` の扱いは `signin_failure_stats` と同じで、
対話型サインインだけを見る（レガシー認証はすべて対話型として記録されるので漏れない。
非対話型のトークン更新は数えない）。

### `signin_by_ip(ip, hours=24, result="all", top=50, max_pages=None)`

1 つの送信元IPからの全サインイン——`spray_suspects` や `shared_ips` に出た IP の
追跡用。Graph は `ipAddress` でサーバ側フィルタできるので、ログ走査でなく 1 回の
軽い問い合わせで済む。`users` はその IP をアカウント別に要約する（成功・失敗・
初回/最終時刻、50 件まで）。`events` は `result`（"all" / "success" / "failure"）に
合う最新 `top` 件で、各行にアカウント名と `signin_logs` と同じ AADSTS の注釈が付く。
`events_truncated` は `top` より多くの該当行を読んだ印（`users` はそれも数えている）。
`ip` は IPv4/IPv6 アドレスとして解釈できる文字列に限る。

### `directory_audits(user=None, hours=24, top=25, max_pages=None)`

ディレクトリ監査証跡：誰が何を（ブロック／解除・属性編集）、いつ行ったか。
`user` を指定すると、そのアカウントが実行者またはターゲットのいずれかである
監査を対象にする——Graph は実行者側のみサーバ側フィルタに対応しているため、
窓全体を取得してクライアント側で両方を照合する（混雑した窓では特定の人物の
監査を見つけるために `max_pages` を大きくする必要がある場合がある）。

### `get_user_auth_methods(upn)`

このアカウントの登録済み認証方式。`mfa_registered` は、パスワード以外の方式
（Authenticator アプリ・電話・FIDO2 セキュリティキー・Windows Hello・
一時アクセスパス・ソフトウェア OATH・プラットフォーム資格情報／パスキー）が
1つ以上登録されていれば `true`。`UserAuthenticationMethod.Read.All`（app-only）が
必要——典型的なロール割り当てでは `az login` 経由の delegated 認証では利用不可。
存在しないアカウントは `get_user` と同様 `{"found": false, "user_principal_name": upn}` を返す。

### `daily_brief(hours=24, max_pages=None, samples=10)`

`signin_failure_stats` と `directory_audits` を、コンパクトな `summary` を添えて
1回でまとめる。片方のセクションの権限エラーはそのセクションだけを劣化させ、
もう片方は全体が返る。両セクションを1回のツール呼び出し内で同期実行する。
`samples` は現状未使用（予約）。

## エラー

全ツールの入口は設定エラーと Graph クライアントのエラーを捕まえて
`{"error": "..."}` を返し、例外を投げない——呼び出し側は常に dict を受け取れる。
`GraphPermissionError` の場合はさらに `missing_permission` が、そのエンドポイントに
実際に必要な Graph 権限またはディレクトリロールの名前を持つ。ページングを伴う
Graph コレクションから組み立てた結果は必ず `capped: bool` を持つ——ページ予算の
打ち切りが「窓を完全に走査した」と見分けがつかなくなることはない。

## CLI

```bash
entraadm-mcp --version   # バージョンを表示
entraadm-mcp --check     # 認証を解決し、Graph・サインインログ到達性をプローブ。exit 0（設定エラー時は 1）
```
