# entraadm-mcp

[English](README.md) | 日本語

Microsoft Entra ID のサインインログ・監査ログの triage 用 MCP サーバ。読み取り専用。

## 公式の Microsoft MCP Server for Enterprise ではなくこれを使う理由

Microsoft は Entra ID データ向けに [公式 MCP Server for Enterprise](https://learn.microsoft.com/en-us/graph/mcp-server/overview)
を提供している。対話的に操作する管理者には適しているが、無人で動く triage bot には向かない。

- **delegated 認証のみ。** 公式サーバは app-only（クライアントクレデンシャル）認証に対応しておらず、
  サービスアカウントの背後で無人稼働できない。entraadm-mcp は本番では app-only、
  ローカル開発では delegated（`az login`）フォールバックという構成を最初から想定している
- **固定ツールセットではなく汎用 Graph クエリツール。** 公式サーバは、モデルが任意の
  `GET`／スキーマ探索呼び出しを Microsoft Graph へ構成できる1本のツールを公開する。
  人間には柔軟だが、自動 triage プロファイル向けの許可リストには馴染みにくい。
  entraadm-mcp は固定・読み取り専用の7ツールを公開する
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
| `directory_audits` | ディレクトリで誰が何を変更したか（ブロック／解除・属性編集）、いつか |
| `get_user_auth_methods` | このアカウントで MFA が実際に登録されているか |
| `daily_brief` | `signin_failure_stats` と `directory_audits` を1回でまとめたサマリ |

全ツールが読み取り専用。書き込み操作（アカウントのブロック解除・パスワードリセット・
セッション失効）はこのサーバのスコープ外。

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
| `signin_logs`、`signin_failure_stats`、`directory_audits`、`get_user` の `sign_in_activity` フィールド | `AuditLog.Read.All`（app-only）または **Reports Reader** ディレクトリロール（delegated） | |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` | app-only 専用。典型的なロール割り当てでは delegated（`az login`）認証では利用不可 |

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
# ログ走査系ツールのページ上限の既定値（1-50、既定 5）
export ENTRAADM_MAX_PAGES_DEFAULT=5
```

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
| `--check` | 認証を解決し、Graph 到達性とサインインログ読み取りをプローブしてレポートを出力。exit 0（設定エラー時は 1） |

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

読み取り専用・ペイロード非出力（ツール名／ステータス／行数のみ）・境界あり
（小さな明示的な窓・ページ上限）— テナントへの書き込みも、1日を超えるログ走査も行わない。

## リリース

このリポジトリは [Conventional Commits](https://www.conventionalcommits.org/) に基づく
[release-please](https://github.com/googleapis/release-please) を使う。`feat:`／`fix:` の
PR を `main` へマージすると release-please がリリース PR を開く（または更新する）。
その PR をマージするとリリースがタグ付けされ、公開パイプライン（PyPI・MCP Registry）が走る。

## ライセンス

MIT
