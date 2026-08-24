# entraadm-mcp

Microsoft Entra ID のサインインログ・監査ログの triage 用 MCP サーバ。読み取り専用。

「なぜこの人がサインインできないのか」という問い合わせを、人間が手作業でサインインログを引き、
AADSTS コードを翻訳し、ディレクトリの監査証跡を確認する——という3段階の作業なしで triage
できるように作った。この3段階が実際に発生し、このサーバの起点になった 2026-08-21 の
サポート事案がある。

## 公式の Microsoft MCP Server for Enterprise ではなくこれを使う理由

Microsoft は Entra ID データ向けに
[公式 MCP Server for Enterprise](https://learn.microsoft.com/en-us/graph/mcp-server/overview)
を提供している。対話的に操作する管理者には適しているが、無人で動く triage bot には向かない。

- **delegated 認証のみ** — app-only（クライアントクレデンシャル）に非対応で、
  サービスアカウントの背後で無人稼働できない。entraadm-mcp はその用途向けに作られている
- **固定ツールセットではなく汎用 Graph クエリツール** — 公式サーバはモデルが任意の
  Graph 呼び出しを構成できる1本のツールを公開し、自動 triage プロファイルの
  許可リストには馴染みにくい
- **AADSTS の意味翻訳も横断集計もない** — サインイン失敗は生のコードのまま返り、
  Microsoft Graph 自体はサインインを `status/errorCode` でサーバ側フィルタできず、
  パスワードスプレーのパターンも検知しない

## ツール

| ツール | 用途 |
|---|---|
| `health_check` | Graph に到達できるか、このクレデンシャルでサインインログが読めるか |
| `get_user` | アカウントのライフサイクル状態：有効性・オンプレ同期・パスワード経過日数・ライセンス・サインイン状況 |
| `signin_logs` | このユーザのサインインイベント。各 AADSTS エラーコードに意味の注釈付き |
| `signin_failure_stats` | テナント全体の失敗集計：エラーコード・ユーザ・アプリ・送信元IPの上位、およびパスワードスプレーの疑い |
| `directory_audits` | ディレクトリで誰が何を変更したか（ブロック／解除・属性編集）、いつか |
| `get_user_auth_methods` | このアカウントで MFA が実際に登録されているか |
| `daily_brief` | `signin_failure_stats` と `directory_audits` を1回でまとめたサマリ |

全ツールが読み取り専用。このサーバに書き込み系ツールは無い——アカウントのブロック解除・
パスワードリセット・セッション失効はすべてスコープ外。

## 設計上の要点

**環境変数の組み合わせで2つの認証モードを切り替える。** `ENTRAADM_TENANT_ID`／
`_CLIENT_ID`／`_CLIENT_SECRET` の3つとも設定すると app-only
（`ClientSecretCredential`）——無人デプロイの本番経路。3つとも未設定なら現在の
`az login` セッション経由の delegated 認証（`AzureCliCredential`）——ローカル開発に便利だが
全ツールが動くわけではない（`get_user_auth_methods` が必要とするアプリケーション権限には、
典型的なロール割り当てでは delegated 版が存在しない）。3つのうち1つか2つだけの設定は
設定ミスとして扱い、黙って別モードへフォールバックしない。

**権限不足は劣化させる。クラッシュはしない。** `AuditLog.Read.All`（または delegated 認証下の
Reports Reader ロール）を必要とするツールは、その不足を
`{"error": "...", "missing_permission": "..."}` として、何を付与すべきかを人間可読な
文言で報告する——スタックトレースでも汎用的な「forbidden」でもない。`health_check` の
`signin_probe` フィールドがサーバレベルで同じ不足を報告する（`status: "degraded"`）ので、
呼び出し側は他のツールを試す前にそれを知ることができる。

**存在しないアカウントは通常の答えであり、エラーではない。** `get_user` と
`get_user_auth_methods` は、タイプミスや存在しない userPrincipalName に対して
`{"found": false, ...}` を返す。実際の失敗（不正な入力形状・Graph 到達不能・権限不足）で
使う `error` キーとは区別される。

**サインインログの保持期間は30日（Entra ID P1）。** それを超える窓はエラーではなく
空の結果を返す——そこには何も無いというのは正当な答えである。

## 次に読むもの

- [Reference](reference.md) — 全ツールのパラメータ・認証方式・CLI 利用法
