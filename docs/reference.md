# Reference

## Auth model

Two modes, selected by which environment variables are set:

| Mode | When | Env vars |
|---|---|---|
| app-only | All three set | `ENTRAADM_TENANT_ID`, `ENTRAADM_CLIENT_ID`, `ENTRAADM_CLIENT_SECRET` |
| azure-cli | None set | Uses the current `az login` session |

Setting one or two of the three app-only variables raises a configuration
error at startup rather than silently falling back to a different mode.

Optional: `ENTRAADM_MAX_PAGES_DEFAULT` (1-50, default 5) sets the default
page cap for the log-scanning tools when a tool call doesn't pass
`max_pages` explicitly.

### Required Graph permissions

| Tool(s) | Permission |
|---|---|
| `get_user` (base fields) | `User.Read.All` |
| `signin_logs`, `signin_failure_stats`, `directory_audits`, `get_user`'s `sign_in_activity` field | `AuditLog.Read.All` (app-only) or the **Reports Reader** directory role (delegated) |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` (app-only only) |

## Tools

### `health_check()`

No parameters. Returns `{service, version, status, auth_mode, graph,
signin_probe}`. `graph` probes basic Graph reachability
(`GET /organization`); `signin_probe` additionally checks sign-in log
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
