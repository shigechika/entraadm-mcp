# Reference

## Auth model

Two modes, selected by which environment variables are set:

| Mode | When | Env vars |
|---|---|---|
| app-only | All three set | `ENTRAADM_TENANT_ID`, `ENTRAADM_CLIENT_ID`, `ENTRAADM_CLIENT_SECRET` |
| azure-cli | None set | Uses the current `az login` session |

Setting one or two of the three app-only variables raises a configuration
error at startup rather than silently falling back to a different mode.

Optional: `ENTRAADM_MAX_PAGES_DEFAULT` (1-50, default 50) sets the default
page cap for the log-scanning tools when a tool call doesn't pass
`max_pages` explicitly.

Optional: `ENTRAADM_DEADLINE` (seconds, default 45; `0` disables) is the
wall-clock budget of one tool call. A hosted MCP client cuts a call off at
about 60 s, so a scan stops at the budget, each request's timeout is capped at
the time left, and the pages fetched so far come back with `capped=true`.
`daily_brief` shares one budget between its two sections. `directory_audits`
also takes `category` (for example `UserManagement`) to filter on the Graph side.

### Required Graph permissions

| Tool(s) | Permission |
|---|---|
| `get_user` (base fields) | `User.Read.All` |
| `signin_logs`, `signin_failure_stats`, `signin_success_stats`, `signin_by_ip`, `directory_audits`, `get_user`'s `sign_in_activity` field | `AuditLog.Read.All` (app-only) or the **Reports Reader** directory role (delegated) |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` (app-only only) |

## Tools

### `health_check()`

No parameters. Returns `{service, version, status, auth_mode, graph,
signin_probe}`. `graph` probes basic Graph reachability
(`GET /users` with `$top=1` -- needs only `User.Read.All`); `signin_probe` additionally checks sign-in log
access. `status` is `"healthy"` when both succeed, `"degraded"` when Graph
is reachable but sign-in log access is not, `"error"` when Graph itself is
unreachable or auth is misconfigured. `graph`/`signin_probe` are each
`{auth: "ok"|"error", detail: str|null}`.

### `get_user(upn)`

Account lifecycle state: `accountEnabled`, `userType`, creation/last
password-change timestamps, on-premises sync status, resolved license
names, and (if `AuditLog.Read.All`/Reports Reader is available)
`sign_in_activity`. A nonexistent account returns
`{"found": false, "user_principal_name": upn}` rather than an error.
`licenses_capped: true` appears only when the SKU catalog scan was cut
short before resolving one of this account's own licenses -- when
present, one or more `licenses` entries is a raw skuId rather than a
friendly name.

### `signin_logs(user, hours=24, result="failure", top=25, max_pages=None)`

One user's sign-in events. `result`: `"failure"` (default, the common
case), `"success"`, or `"all"` — filtered client-side, since Graph cannot
filter sign-ins on `status/errorCode` server-side. Each event's
`error_code` is annotated with `error_code_meaning` (e.g. 50126 → "invalid
credentials (wrong password)") from a hand-maintained AADSTS code table.
`hours` clamped to 1-720 (30 days — Entra ID P1's sign-in log retention).
`capped=true` means the page budget ran out (or `top` was reached) before
the whole window was scanned — a low match count alongside `capped=true`
means "not found within the budget," not "doesn't exist."

### `signin_failure_stats(hours=24, max_pages=None)`

Tenant-wide failure aggregation: top AADSTS error codes (annotated), top
failing users, top applications, and top source IPs. `spray_suspects` lists
any IP with failed sign-ins against 5 or more distinct users — a pattern
Entra's per-account smart lockout does not catch on its own. `hours`
clamped as above.

### `signin_success_stats(hours=24, max_pages=None, min_distinct_users=2)`

Tenant-wide *successful* sign-in aggregation by source IP — the companion
to `signin_failure_stats`: that one shows who is being attacked, this one
shows whether anyone got in. `shared_ips` lists every IP with successes for
`min_distinct_users` or more distinct accounts (account names up to 25 per
IP, client apps, countries, first/last seen); `legacy_auth_users` lists the
accounts that succeeded over a legacy protocol (`Authenticated SMTP`,
`IMAP4`, `POP3`, …), which carry no MFA. A campus NAT or a VDI farm also puts
many accounts behind one IP, so exclude your own egress ranges before
reading `shared_ips` as a breach. Same log walk and `capped` semantics as
`signin_failure_stats`; like it, this scans interactive sign-ins only (every
legacy-protocol authentication is logged as interactive; non-interactive
token refreshes are not counted).

### `signin_by_ip(ip, hours=24, result="all", top=50, max_pages=None)`

Every sign-in from one source IP — the follow-up to a `spray_suspects` or
`shared_ips` hit. Graph filters on `ipAddress` server-side, so this is one
cheap query rather than a log walk. `users` summarises the IP per account
(successes, failures, first/last seen, up to 50); `events` lists the newest
`top` entries matching `result` ("all" / "success" / "failure"), each with
the account name and the same AADSTS annotation as `signin_logs`.
`events_truncated` means more matching rows were read than `top` returns
(`users` still counts them). `ip` must parse as an IPv4/IPv6 address.

### `directory_audits(user=None, hours=24, top=25, max_pages=None)`

Directory audit trail: who did what (block/unblock, attribute edits), and
when. `user`, when given, matches audits where that account is either the
initiator or a target resource — Graph only supports server-side filtering
on the initiator, so this fetches the window and matches both sides
client-side (a busy window may need a larger `max_pages` to find one
person's audits).

### `get_user_auth_methods(upn)`

Registered authentication methods for one account. `mfa_registered` is
`true` iff at least one non-password method is registered (Authenticator
app, phone, FIDO2 key, Windows Hello, temporary access pass, software OATH,
or platform credential/passkey). Needs `UserAuthenticationMethod.Read.All`
(app-only); not available under `az login`-based delegated auth in a
typical role assignment. A nonexistent account returns
`{"found": false, "user_principal_name": upn}`, same as `get_user`.

### `daily_brief(hours=24, max_pages=None, samples=10)`

One-call summary combining `signin_failure_stats` and `directory_audits`,
with a compact `summary` on top. A permission failure in one section
degrades only that section — the other still returns in full. Runs both
sections synchronously in one tool call; `samples` is currently unused
(reserved).

## Errors

Every tool's entry point catches configuration and Graph-client errors and
returns `{"error": "..."}` rather than raising, so a caller always gets a
dict back. A `GraphPermissionError` additionally sets `missing_permission`
naming the actual Graph permission or directory role that endpoint needs. A
result built from a paged Graph collection always carries `capped: bool` —
a page-budget cutoff is never indistinguishable from "the window was fully
scanned."

## CLI

```bash
entraadm-mcp --version   # print version
entraadm-mcp --check     # resolve auth, probe Graph + sign-in log reachability, exit 0 (or 1 on config error)
```
