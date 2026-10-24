# entraadm-mcp

[English](README.md) | 日本語

Microsoft Entra ID のサインインログ・監査ログの triage 用 MCP サーバ。同じクレデンシャルで朝の
パトロールが聞く Azure 側の 2 つ——Azure VM はバックアップされているか、Microsoft 365 自体が
いま劣化していないか——にも答える。読み取り専用（侵害されたアカウントをすべての場所からサインアウトさせる
オプトインのツール 1 本だけが例外）。

## 公式の Microsoft MCP Server for Enterprise ではなくこれを使う理由

Microsoft は Entra ID データ向けに [公式 MCP Server for Enterprise](https://learn.microsoft.com/en-us/graph/mcp-server/overview)
を提供している。対話的に操作する管理者には適しているが、無人で動く triage bot には向かない。

- **delegated 認証のみ。** 公式サーバは app-only（クライアントクレデンシャル）認証に対応しておらず、
  サービスアカウントの背後で無人稼働できない。entraadm-mcp は本番では app-only、
  ローカル開発では delegated（`az login`）フォールバックという構成を最初から想定している
- **固定ツールセットではなく汎用 Graph クエリツール。** 公式サーバは、モデルが任意の
  `GET`／スキーマ探索呼び出しを Microsoft Graph へ構成できる1本のツールを公開する。
  人間には柔軟だが、自動 triage プロファイル向けの許可リストには馴染みにくい。
  entraadm-mcp は固定・読み取り専用の14ツールを公開する（ほかにオプトインの書き込みが 1 本。下記）
- **AADSTS の意味翻訳がない。** サインイン失敗は生のエラーコードのまま返ってきて、
  triage には結局ルックアップが必要になる。entraadm-mcp は全てのサインイン失敗に
  コードの意味を注釈する
- **横断集計がない。** Microsoft Graph 自体はサインインを `status/errorCode` で
  サーバ側フィルタできず、パスワードスプレー検知の機能も無い。`signin_failure_stats` は
  クライアント側で集計し、多数の異なるユーザに対して失敗しているIPを検知する
  — Entra のアカウント単位スマートロックアウトだけでは捉えられないパターン

## ツール

| ツール | 何に答えるか |
|---|---|
| `health_check` | Graph に到達できるか、このクレデンシャルでサインインログが読めるか |
| `get_user` | このアカウントは有効か、オンプレ同期されているか、ライセンスは何か |
| `signin_logs` | このユーザのサインインがなぜ失敗（または成功）したか、AADSTS コードの意味付き |
| `signin_failure_stats` | テナント全体の失敗集計：エラーコード・ユーザ・アプリ・送信元IPの上位、およびパスワードスプレーの疑い |
| `signin_success_stats` | テナント全体の成功を送信元IPで集計：複数アカウントが共有するIP、レガシー認証（SMTP/IMAP）での成功——突破を見つけるための視点 |
| `signin_by_ip` | 1 つの送信元IPからの全サインイン：そこから誰が入り、誰が試され、いつか |
| `directory_audits` | ディレクトリで誰が何を変更したか（ブロック／解除・属性編集）、いつか |
| `get_user_auth_methods` | このアカウントで MFA が実際に登録されているか |
| `list_subscriptions` | このクレデンシャルから見える Azure サブスクリプションはどれか（ARM） |
| `vm_backup_status` | Azure Backup で保護されている Azure VM はどれか、直近のバックアップは成功したか、復旧ポイントが古くなっていないか（ARM） |
| `vm_backup_policies` | Azure VM のバックアップポリシーのスケジュールと保持期間（ARM） |
| `vm_activity` | この Azure VM を再起動したのは人か Azure（ホスト障害・メンテナンス）か。指定した時間帯のアクティビティログとリソース正常性（ARM） |
| `m365_service_health` | Microsoft 365 のサービスが劣化していないか、どのインシデント・アドバイザリが開いているか |
| `daily_brief` | `m365_service_health`・`signin_failure_stats`・`directory_audits` を1回でまとめたサマリ |

上のツールはすべて読み取り専用。状態を変えるツールが 1 本だけあり、既定では無効:

| ツール | 何をするか |
|---|---|
| `revoke_sign_in_sessions` | 1 アカウントをすべての場所からサインアウトさせる（Graph `revokeSignInSessions`：リフレッシュトークンとセッション Cookie を無効化）。侵害が確定したときに使う。`ENTRAADM_ENABLE_REVOKE_SESSIONS=1` のときだけ登録される |

先に userPrincipalName の完全一致でアカウントを引き、ゲストは断る。結果のキーはいつも同じで、
`revoked` と `not_covered` を必ず含む。アカウントの無効化・パスワードのリセット・MFA 方式の削除はしない。
発行済みのアクセストークンは期限（通常 1 時間程度）まで使える。`revoked` は、Graph が認めたら `true`、
何もしていなければ `false`（断った・要求を送る前に期限切れ・Graph が 4xx）、結果が分からなければ `null`
（通信エラーで応答が失われた・再試行後も 5xx・要求を送った後に期限切れ・成功の応答が読めない）。
`null` のときはもう一度呼んでも安全（失効は冪等）。独自の承認の段を持たない配備（共有のゲートウェイなど）では
このスイッチを設定しないこと（`tools/list` にも出なくなる）。アカウントのブロック解除と
パスワードのリセットは引き続きスコープ外。

Azure Resource Manager の 4 ツールを Entra の名を持つサーバに置いているのは意図的。同じアプリ登録・
同じ `azure-identity` のクレデンシャル（トークンのスコープが `https://management.azure.com/.default` に
なるだけ）・同じ配備で動き、同じ `health_check` で見える。これらのツールのために別サーバを立てると運用面が
倍になる。資源の管理ではなくガバナンスの読み取りであり、Reader ロールの無いサブスクリプションは
`list_subscriptions` に出てこないだけ。

## 認証方式

どの環境変数が設定されているかで2つの認証モードを切り替える。

| モード | 条件 | 環境変数 |
|---|---|---|
| app-only | 3つとも設定 | `ENTRAADM_TENANT_ID`、`ENTRAADM_CLIENT_ID`、`ENTRAADM_CLIENT_SECRET` |
| azure-cli | 3つとも未設定 | （現在の `az login` セッションを使う） |

app-only 用3変数のうち1つか2つだけ設定するのは設定ミスとみなし、
意図しない認証モードへ黙ってフォールバックせず起動を拒否する。

### 必要な Graph 権限

| ツール | 権限 | 備考 |
|---|---|---|
| `get_user`（基本フィールド） | `User.Read.All` | |
| `signin_logs`、`signin_failure_stats`、`signin_success_stats`、`signin_by_ip`、`directory_audits`、`get_user` の `sign_in_activity` フィールド | `AuditLog.Read.All`（app-only）または **Reports Reader** ディレクトリロール（delegated） | |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` | app-only 専用。典型的なロール割り当てでは delegated（`az login`）認証では利用不可 |
| `m365_service_health`、`daily_brief` の `service_health` セクション | `ServiceHealth.Read.All` | delegated 認証ではサインインしたユーザにサービス正常性を読める Entra ロール（Service Support Administrator や Global Reader 等）も必要 |
| `revoke_sign_in_sessions`（オプトイン） | `User.RevokeSessions.All`（app-only）または **User Administrator**／**Helpdesk Administrator** ディレクトリロール（delegated。管理者アカウントが対象なら **Privileged Authentication Administrator**） | `ENTRAADM_ENABLE_REVOKE_SESSIONS=1` のときだけ。書き込みの権限なので、このツールが要る配備にだけ付与する。先に行うアカウントの照会には `User.Read.All` が要る。無ければ認証方式に応じた `missing_permission` を返し、何も変わらない |

### 必要な Azure RBAC

| ツール | ロール | 備考 |
|---|---|---|
| `list_subscriptions` | なし | クレデンシャルから見えるものを列挙する。空ならどこにもロールが付いていない |
| `vm_backup_status`、`vm_backup_policies`、`vm_activity` | 各サブスクリプションの **Reader** | `Reader` は `*/read` で、使う全エンドポイントを満たす。`Backup Reader` だけでは足りない（`Microsoft.Compute/virtualMachines/read` が無い）。app-only ならサービスプリンシパルに、azure-cli ならサインインしたユーザに付与する |

Azure RBAC は任意。`health_check` は ARM の到達性と見えるサブスクリプション数を情報扱いの `arm` プローブとして
報告し、`status` は変えない。Entra の triage だけに使う配備は `healthy` のまま。

権限不足でツールがクラッシュすることはない。該当ツール（または該当フィールド）だけが
`{"error": "...", "missing_permission": "..."}` に劣化し、必要なロール・権限を
人間可読の文言で示す。フル権限が付与される前でも `health_check` を含む全ツールが使える。

## セットアップ

```bash
uv tool install entraadm-mcp
# または
pip install entraadm-mcp
```

## 設定

本番・無人稼働では app-only 用の3変数を設定する:

```bash
export ENTRAADM_TENANT_ID=00000000-0000-0000-0000-000000000000
export ENTRAADM_CLIENT_ID=00000000-0000-0000-0000-000000000000
export ENTRAADM_CLIENT_SECRET=your-client-secret
```

またはローカル開発では3つとも未設定のまま `az login` を先に実行する。

任意:

```bash
# ログ走査系ツールのページ上限の既定値（1-50、既定 50）
export ENTRAADM_MAX_PAGES_DEFAULT=50
# 1 回のツール呼び出しの持ち時間（秒、既定 45、0 で無効）。ホスト型クライアントは約 60 秒で打ち切る
export ENTRAADM_DEADLINE=45
# 自組織のアドレス範囲（NAT の出口・事業所・実習室など）。この範囲のスプレー疑いは
# internal_spray_suspects に拠点名付きで分けて出す
export ENTRAADM_SITES_INI=/path/to/sites.ini
# 状態を変える唯一のツール revoke_sign_in_sessions を登録する（ちょうど "1" のときだけ。
# ほかの値では無効）。User.RevokeSessions.All の権限も要る
export ENTRAADM_ENABLE_REVOKE_SESSIONS=1
# 1 つのプロセスで複数のテナントを扱う（下の「複数のテナント」）
export ENTRAADM_CONFIG=/path/to/tenants.ini
```

`ENTRAADM_SITES_INI` は keycloak-mcp の `KEYCLOAK_SITES_INI` と同じ形式なので，1 つの
ファイルを両方で使える（[`sites.ini.example`](sites.ini.example) 参照）。照合は最長一致。
指定したのに読めないときは `health_check` が `degraded` になり，すべての IP を外部扱いにする。
CIDR の誤りも同じく報告するが，正しい範囲はそのまま使う。

### 複数のテナント

gwsadm-mcp が複数の Workspace ドメインを扱うのと同じように，1 つのプロセスで複数の Entra
テナントを扱える。`ENTRAADM_CONFIG` に，テナントごとに `[tenant.<名前>]` の節を持つ INI ファイルを指定する:

```ini
[tenant.staff]
tenant_id = 00000000-0000-0000-0000-000000000001
domains = example.edu
default = true

[tenant.students]
tenant_id = 00000000-0000-0000-0000-000000000002
domains = students.example.edu
; 省略可: 共有のアプリではなく専用のアプリ登録を使う
; client_id = 00000000-0000-0000-0000-000000000003
; client_secret_env = ENTRAADM_STUDENTS_CLIENT_SECRET
```

| キー | 必須 | 意味 |
|---|---|---|
| `tenant_id` | はい | テナントの ID（GUID）か，ドットを含むテナントのドメイン名（例 `contoso.onmicrosoft.com`）。`common`・`organizations`・`consumers` は受け付けない |
| `domains` | はい | このテナントに振り分ける UPN のドメイン（カンマ区切り。完全一致・大文字小文字は区別しない） |
| `default` | 複数あるときは 1 つに | 呼び出しでテナントを指定しないときに使う。節が 1 つならそれが既定 |
| `client_id` と `client_secret_env` | いいえ（両方か，どちらも無しか） | 専用のアプリ。`client_secret_env` はシークレットを入れた環境変数の名前。ファイルにシークレットを書かない |

`client_id` の無い節は env のアプリ（`ENTRAADM_CLIENT_ID`／`ENTRAADM_CLIENT_SECRET`）を使い，
トークンはその節のテナントに対して取る。env のアプリが無ければ，そのテナントの `az login` を使う。
`ENTRAADM_CONFIG` を設定すると `ENTRAADM_TENANT_ID` は使わない。`ENTRAADM_CONFIG` が無ければ，
上の単一テナントの設定のまま変わらない。

1 つのアプリを複数のテナントで使うには，アプリ登録をマルチテナントにし（「サポートされている
アカウントの種類」で任意の組織ディレクトリのアカウント），同じ Graph のアプリケーション権限を付け，
もう一方のテナントの管理者に次の URL で管理者の同意をしてもらう:

```
https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=<app-id>
```

ファイルが読めない，`[tenant.*]` 以外の節や知らないキーがある，`tenant_id` か `domains` が無い，
`tenant_id` が GUID でもドットを含むドメインでもない，
同じドメインを 2 つのテナントが持つ，複数のテナントのうち既定が無い（または 2 つある），の
いずれかなら，サーバは起動せず `--check` も失敗する。`--check` はすべてのテナントを調べる。

振り分け:

- UPN を取るツール（`get_user`・`get_user_auth_methods`・`signin_logs`・`revoke_sign_in_sessions`，
  `user` を指定したときの `directory_audits`）は，UPN のドメインを `domains` に持つテナント（完全一致）で動く。
  どのテナントも持たないドメインは例外ではなく拒否になる: `tenant_configured: false`・`found: null`
  （照会していない）・`configured_domains`。`revoke_sign_in_sessions` では `revoked: false`・`found: null` で，
  何も送らない。`<tenant>.onmicrosoft.com` の UPN をよく引くなら `domains` に入れておく。
- `get_user`・`get_user_auth_methods`・`signin_logs` は `tenant` も取り，UPN のドメインより優先する。
  `*.onmicrosoft.com` や `#EXT#` の UPN，ホストのテナントに記録される B2B ゲストのサインインに使う。
  `revoke_sign_in_sessions` には意図的にこの上書きが無い。書き込みは UPN のドメインを持つテナントにしか向かない。
- テナント全体を見るツール（`signin_failure_stats`・`signin_success_stats`・`signin_by_ip`・
  `directory_audits`・`m365_service_health`）は省略可の `tenant` を取る。省略すると既定のテナント。
  `directory_audits` で `tenant` と，ほかのテナントが持つドメインの `user` を両方指定すると拒否する
  （違うログを探して何も見つからないため）。どのテナントも持たないドメインの `user`（外部・パートナーの
  管理者，ゲスト）は指定のテナントか既定のテナントで探し，結果に `user_domain_claimed: false` を付ける。
- `tenant` は節の名前・そのドメイン・テナント ID のいずれか。テナントのファイルが無いときは `default` か
  env のテナント ID だけを受け付け，ほかは拒否する（`tenant_configured: false`）。
- `health_check` と `daily_brief` はすべてのテナントを見る。最上位のキーはこれまでどおり既定のテナントの
  もので，`tenant` がその名前，`tenants` がテナントごとの結果。呼び出しの時間予算（`ENTRAADM_DEADLINE`）は
  テナントで均等に分ける（既定から順に，残りを残りのテナント数で割る）ので，遅いテナントがほかを止めない。
  応答しないテナントはその項目で `error` になり，`health_check` の `status` は高々 `degraded`。
  `ENTRAADM_DEADLINE=0` では予算が無く，全テナントを最後まで順に調べるので，クライアントの約 60 秒の
  打ち切りを超えうる。
- Azure Resource Manager のツール（`list_subscriptions`・`vm_backup_status`・`vm_backup_policies`・
  `vm_activity`）は既定のテナントだけを見る。
- テナントのファイルを使うと，結果には必ず `tenant` が付く（ARM のツールは既定のテナント，どのテナントも
  選ばなかった拒否は `null`）。env だけのときの結果は変わらない。ただし `revoke_sign_in_sessions` はキーが
  常に同じなので，いつも `tenant`・`tenant_configured`・`configured_domains` を含む。

## 使い方

### Claude Code（プラグイン）

```
/plugin marketplace add shigechika/entraadm-mcp
/plugin install entraadm-mcp@entraadm-mcp
```

### Claude Code（手動設定）

`.mcp.json` に追加:

```json
{
  "mcpServers": {
    "entraadm-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["entraadm-mcp"],
      "env": {
        "ENTRAADM_TENANT_ID": "${ENTRAADM_TENANT_ID:-}",
        "ENTRAADM_CLIENT_ID": "${ENTRAADM_CLIENT_ID:-}",
        "ENTRAADM_CLIENT_SECRET": "${ENTRAADM_CLIENT_SECRET:-}"
      }
    }
  }
}
```

### 直接実行

```bash
entraadm-mcp
```

### CLI オプション

| オプション | 効果 |
|---|---|
| `--version` | バージョンを表示して終了 |
| `--check` | 認証を解決し、Graph 到達性とサインインログ読み取りをプローブしてレポートを出力（ARM の情報行付き）。exit 0（設定エラー時は 1） |

## 補足

- **カバレッジ契約。** ページングを伴う Graph コレクションを扱う結果は、窓が
  完全に走査されなかった場合に必ず `capped` フラグを持つ。部分走査を網羅として
  報告することはない
- **`found: false` はエラーではない。** `get_user` と `get_user_auth_methods` は
  存在しないアカウントに対して `error` キーではなく `{"found": false, ...}` を返す。
  UPN のタイプミスがこのサーバの故障のように見えてはいけない
- **保持期間。** Entra ID P1 のサインイン・監査ログ保持期間は30日。それを超える窓は
  エラーではなく空の結果を返す

## 開発

```bash
uv sync --dev
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
```

### ライブスモークテスト

```bash
uv run python scripts/smoke_test.py
```

読み取り専用（`revoke_sign_in_sessions` は有効でも名前で飛ばす）・ペイロード非出力（ツール名／ステータス／行数のみ）・境界あり
（小さな明示的な窓・ページ上限）— テナントへの書き込みも、1日を超えるログ走査も行わない。

## リリース

このリポジトリは [Conventional Commits](https://www.conventionalcommits.org/) に基づく
[release-please](https://github.com/googleapis/release-please) を使う。`feat:`／`fix:` の
PR を `main` へマージすると release-please がリリース PR を開く（または更新する）。
その PR をマージするとリリースがタグ付けされ、公開パイプライン（PyPI・MCP Registry）が走る。

## ライセンス

MIT
