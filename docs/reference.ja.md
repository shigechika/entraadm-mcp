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

任意: `ENTRAADM_SITES_INI` は自組織のアドレス範囲を書いた INI ファイル。形式は
keycloak-mcp の `KEYCLOAK_SITES_INI` と同じ（拠点ごとに 1 セクション，`name` は任意，
`ipv4`／`ipv6` にカンマ区切りの CIDR）。照合は最長一致で，ファイルが変わると読み直す。
読めないファイル・範囲の無いファイルはエラーとして報告する。CIDR の誤りも報告するが，正しい範囲はそのまま使う。

### 必要な Graph 権限

| ツール | 権限 |
|---|---|
| `get_user`（基本フィールド） | `User.Read.All` |
| `signin_logs`、`signin_failure_stats`、`signin_success_stats`、`signin_by_ip`、`directory_audits`、`get_user` の `sign_in_activity` フィールド | `AuditLog.Read.All`（app-only）または **Reports Reader** ディレクトリロール（delegated） |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All`（app-only 専用） |
| `m365_service_health`、`daily_brief` の `service_health` セクション | `ServiceHealth.Read.All`（delegated 認証ではサービス正常性を読める Entra ロール——Service Support Administrator や Global Reader 等——も必要） |

### 必要な Azure RBAC

| ツール | ロール |
|---|---|
| `list_subscriptions` | なし（クレデンシャルから見えるものを列挙する） |
| `vm_backup_status`、`vm_backup_policies`、`vm_activity` | 各サブスクリプションの **Reader**（`*/read`。`Backup Reader` だけでは `Microsoft.Compute/virtualMachines/read` が無い） |

Azure RBAC は任意。`health_check` の `arm` プローブは情報扱い。

## ツール

### `health_check()`

引数なし。`{service, version, status, auth_mode, graph, signin_probe, arm, sites}` を返す。
`graph` は基本的な Graph 到達性（`GET /users`、`$top=1` — `User.Read.All` のみで通る）を、`signin_probe` は
サインインログ読み取り可否を追加でプローブする。`status` は両方成功で
`"healthy"`、Graph到達可だがサインインログ読み取り不可で `"degraded"`、
Graph自体に到達不可または認証設定不備で `"error"`。`graph`／`signin_probe` は
それぞれ `{auth: "ok"|"error", detail: str|null}`。`sites` は `ENTRAADM_SITES_INI` の
`{configured, ranges, error}` で，指定したファイルに `error` があると `"healthy"` を
`"degraded"` に下げる。`arm` は `{auth, detail, subscriptions, capped}`（Azure Resource Manager の
`GET /subscriptions` の 1 ページ。`subscriptions` はクレデンシャルから見える数、`capped` は続きのページが
あったか）で情報扱い——Azure RBAC は
このサーバでは任意なので `status` を変えない。ARM が応答しなくても呼び出し全体が止まらないよう，
このプローブだけ 10 秒の予算で走る。

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

`ENTRAADM_SITES_INI` を指定すると，自組織の範囲の IP は `top_ips` に `site`（と
`site_name`）が付き，その範囲のスプレー疑いは `internal_spray_suspects` に移る。
NAT の出口や共用端末に外部の送信元が埋もれないようにするため。`sites` は読み込めたかを示し，
読めないときはすべて `spray_suspects` に残す。`daily_brief` の要約には
内部の疑いの一覧と，ファイルにエラーがあるときの `sites_error` が入る。

### `signin_success_stats(hours=24, max_pages=None, min_distinct_users=2)`

テナント全体の*成功した*サインインを送信元IPで集計する——`signin_failure_stats`
の対：あちらは誰が攻撃されているかを、こちらは誰かが入られたかを示す。
`shared_ips` は `min_distinct_users` 人以上の異なるアカウントで成功している IP を
共有数の多い順に列挙する（IP は 50 件まで、超えたら `shared_ips_capped`。IP ごとに
アカウント名 25 件まで・クライアントアプリ・国・初回/最終時刻）。
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

### `list_subscriptions(max_pages=None)`

このクレデンシャルから見える Azure サブスクリプション（`subscription_id`、`name`、`state`）と
`count`、`capped`。バックアップ系 2 ツールの起点で、両方ともこの一覧の id か表示名を受け取る。
ARM に到達できるのに空なら、どこにも Reader ロールが付いていない。

### `vm_backup_status(subscription=None, stale_hours=36, max_pages=None)`

サブスクリプションの全 VM を、その Recovery Services コンテナーの Azure VM 保護アイテムと
VM の ARM id で結合する（大文字小文字は区別しない）。VM ごとに：`protected` は
`protectionState` が `Protected`／`IRPending`（初回バックアップ待ち。`note` に出る）なら `true`、
アイテムが無い・停止・一時停止・エラーなら `false`（状態は表示する）、アイテムは見つからないが
そのサブスクリプションのコンテナー走査が不完全なら `null`（不明）——部分的な走査から「未保護」を
作らない。`backup_ok` は `lastBackupStatus` が `Completed`／`CompletedWithWarnings` か。`stale` は
`stale_hours` 以内の復旧ポイント（`lastRecoveryPoint`）が無いこと（既定 36 時間は日次ポリシー向け。
週次なら増やす——行に `policy_name` がある）。`backup_ok` が `false` になるのは `Failed` だけで、実行中
（`InProgress`・`Warning`）は `null`。`protectionState` の無いアイテムは VM を `unknown` にし、2 つのコンテナーが
同じ VM のアイテムを持つときは動いている方を採る（`duplicate_items`）。`items_complete` はサブスクリプション
スコープの Reader を前提にする（リソースグループに絞った Reader ではコンテナー一覧が黙って絞られる）。

`subscription` は id か表示名。`None` は見える全サブスクリプションを走査して結合も全体で行うので、
別サブスクリプションのコンテナーに保護されている VM も一致する。1 つ指定したときはその
サブスクリプションのコンテナーだけ（`coverage` に明記）。無い名前は `{"found": false, "subscription",
"listing_capped"}`、複数に一致する表示名は `ambiguous` 付き。一覧が途中で切れているときは表示名の一致も
信用しない（`candidates` に見えた 1 件を出すので id で呼び直す）。サブスクリプションごとに `vm_count`、
`protected`、`unprotected`、`unknown`、`stale`、`failed`、`vms`、`vaults`（それぞれ `capped` 付き）、
`skipped_vaults`（検証に落ちた id・予算が届かなかったコンテナー・読めないコンテナー。理由付き）、
`vms_capped`、`items_complete`、`capped`。読めないサブスクリプションは `{"error", "missing_permission"}`。
全体の結合では、全サブスクリプションのコンテナー走査が完了していない限り一致しない VM は `unknown`
（読めない・届かなかったサブスクリプションも未完了に数え、`summary.failed_subscriptions` と `capped` に出る）。
`orphans` は VM がもう無い保護アイテムで、その VM のサブスクリプションを完全に列挙できたときだけ出す。
残りは `unjoined_items` の数。`skipped` は時間予算が届かなかったサブスクリプション。上に `summary` と `capped`。

コンテナー id は ARM の命名規則で検証してからリクエストのパスに使う。全呼び出しがツールの 1 つの
期限を共有する。

### `vm_backup_policies(subscription=None, max_pages=None)`

コンテナーごとの Azure VM バックアップポリシー：`name`、`vault`、`resource_group`、`policy_type`
（`V1` = `SimpleSchedulePolicy`、`V2` = `SimpleSchedulePolicyV2`）、`schedule`（`frequency`、UTC の
`run_times`、`weekdays`、V2 の hourly は `interval_hours`／`window_start`／`window_hours`）、`retention`
（`LongTermRetentionPolicy` を `daily`／`weekly`／`monthly`／`yearly` のブロックに日付の選び方と
`{count, unit}` の期間付きで、または `SimpleRetentionPolicy`）、`instant_rp_days`、`timezone`、
`protected_item_count`（ARM 自身の数）。知らないスケジュール・保持の型は `{"type": <名前>,
"unparsed": true}` で返す。`subscription` の解決と網羅性のフラグは `vm_backup_status` と同じ。

### `vm_activity(vm, subscription=None, resource_group=None, start=None, end=None, hours=24, max_pages=None)`

1 台の VM に指定した時間帯に何が起きたかを、その VM のサブスクリプションのアクティビティログ
（`Microsoft.Insights/eventtypes/management/values`、サーバ側の絞り込みは `eventTimestamp` だけ）から返す。
`vm` は VM 名で、見えるサブスクリプションを大文字小文字を区別せずに探す。`subscription`（id か表示名）と
`resource_group` で絞れる。名前が一意でなければ `found: false` と候補の `ambiguous` を返す。一部の
サブスクリプションを読み切れなかったとき（`search_complete: false`）は名前を確定しない。見つかった 1 台も `candidates` として返すので、その購読を指定して確かめる。

時間帯は `start`〜`end`（オフセット付きの ISO 時刻。オフセットの無い時刻は UTC と読まずに拒否する）か、
`end` の前の `hours` 時間（既定 24、`end` の既定は現在）。最大 168 時間で、アクティビティログが保つ 90 日以内。
結果は `vm`、`window`（UTC）と次の項目：

- `health`：VM のリソース正常性イベント（`stage`、`title`、`cause`（Azure 起因は `PlatformInitiated`、
  操作やゲスト OS 内からの再起動は `UserInitiated`）、`type`、`current_health`、`previous_health`、
  300 字で切った `details`）
- `vm_operations`：VM とその配下のリソースへの Administrative 操作（`operation`、`status`、`caller`、`resource`）
- `other_operations`：サブスクリプションのほかのリソースへの Administrative 操作（`count`、先頭 50 件の
  `items`、`truncated`）
- `service_health`：サブスクリプションに告知された Azure の障害・メンテナンス
- `other_categories`：残りの件数（Alert、Policy、ほかのリソースの正常性イベントなど）
- `events_read` と `capped`（ページか時間の予算に達した。そのときは空の項目が「何も無かった」証拠にならない）

### `m365_service_health(max_pages=None)`

`services`：Microsoft 365 の各サービスと現在の状態（`healthOverviews`）。`issues`：未解決の
インシデント・アドバイザリを新しい順に（`id`、`title`、`service`、`feature`、`classification`、
`status`、`start`、`last_modified`、`impact`）。`summary` に `degraded_services`（状態が開いているもの——`serviceDegradation`・`serviceInterruption`・
`investigating` 等。Graph が数日残す `serviceRestored` などの解決後の値は数えない）、`services_without_status`、
`open_incidents`、`open_advisories`、`capped`（どちらもページングするので、途中で切れた数は下限）。各セクションは
`{"error", "missing_permission": "ServiceHealth.Read.All"}` に個別に劣化する。メッセージセンター
（`messages`）は別の権限が要るので読まない。

### `daily_brief(hours=24, max_pages=None, samples=10)`

`m365_service_health`・`signin_failure_stats`・`directory_audits` を、コンパクトな `summary` を
添えて1回でまとめる（`service_health` に劣化中のサービス・開いているインシデント数・そのセクションの
`capped`。これは上位の `summary.capped` にも畳み込む）。1 つのセクションの権限エラーはそのセクションだけを劣化させ、残りは全体が返る。
この順に 1 つの期限を共有して同期実行する。Azure VM のバックアップは意図的に入れていない
（ARM の走査が予算を使い切りうるので `vm_backup_status` を別に呼ぶ）。`samples` は現状未使用（予約）。

## エラー

全ツールの入口は設定エラーと API クライアント（Graph・ARM）のエラーを捕まえて
`{"error": "..."}` を返し、例外を投げない——呼び出し側は常に dict を受け取れる。
権限エラーの場合はさらに `missing_permission` が、そのエンドポイントに
実際に必要な Graph 権限・ディレクトリロール・Azure RBAC ロールの名前を持つ。ページングを伴う
Graph・ARM のコレクションから組み立てた結果は必ず `capped: bool` を持つ——ページ予算の
打ち切りが「窓を完全に走査した」と見分けがつかなくなることはない。

## CLI

```bash
entraadm-mcp --version   # バージョンを表示
entraadm-mcp --check     # 認証を解決し、Graph・サインインログ到達性をプローブ（ARM の情報行付き）。exit 0（設定エラー時は 1）
```
