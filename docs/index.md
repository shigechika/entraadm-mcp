# entraadm-mcp

MCP server for Microsoft Entra ID sign-in and audit-log triage. Read-only.

Built for triaging "why can't this person sign in" reports without a human
manually pulling sign-in logs, translating AADSTS codes, and checking the
directory audit trail by hand — three separate steps that closed a real
2026-08-21 support case at this server's origin.

## Why this instead of the official Microsoft MCP Server for Enterprise

Microsoft ships an
[official MCP Server for Enterprise](https://learn.microsoft.com/en-us/graph/mcp-server/overview)
for Entra ID data. It is a good fit for an interactive admin at a keyboard,
and not a fit for an unattended triage bot:

- **Delegated auth only** — no app-only (client credentials) support, so it
  cannot run headless behind a service account. entraadm-mcp is built for
  that case.
- **A general-purpose Graph query tool, not a fixed tool set** — the
  official server exposes one tool that lets the model construct arbitrary
  Graph calls, which is awkward to put behind an allow-list for an
  automated triage profile.
- **No AADSTS translation and no cross-request aggregation** — sign-in
  failures come back as raw codes, and Microsoft Graph itself cannot filter
  sign-ins on `status/errorCode` server-side or flag password-spray
  patterns.

## Tools

| Tool | Purpose |
|---|---|
| `health_check` | Is Graph reachable, and can this credential read sign-in logs? |
| `get_user` | Account lifecycle state: enabled, on-prem sync, password age, licenses, sign-in activity |
| `signin_logs` | One user's sign-in events, each AADSTS error code annotated with what it means |
| `signin_failure_stats` | Tenant-wide failure aggregation: top error codes, users, apps, source IPs, and password-spray suspects |
| `directory_audits` | Who changed what in the directory (block/unblock, attribute edits), and when |
| `get_user_auth_methods` | Is MFA actually registered for this account? |
| `daily_brief` | One-call summary combining `signin_failure_stats` and `directory_audits` |

All tools are read-only. There is no write/mutating tool in this server —
unblocking an account, resetting a password, and revoking a session are all
out of scope.

## Design notes

**Two auth modes, chosen by which env vars are set.** All three of
`ENTRAADM_TENANT_ID`/`_CLIENT_ID`/`_CLIENT_SECRET` selects app-only
(`ClientSecretCredential`) — the production path for a headless deployment.
None of the three selects delegated auth via the current `az login` session
(`AzureCliCredential`) — convenient for local development, but not every
tool works under it (`get_user_auth_methods` needs an application
permission that has no delegated equivalent in a typical role assignment).
Setting one or two of the three is treated as a configuration error, not a
silent fallback.

**A missing permission degrades, it never crashes.** Every tool that needs
`AuditLog.Read.All` (or, under delegated auth, the Reports Reader directory
role) reports the gap as `{"error": "...", "missing_permission": "..."}`
with a human-readable explanation of what to grant — not a stack trace, and
not a generic "forbidden." `health_check`'s `signin_probe` field reports
this same gap at the server level (`status: "degraded"`) so a caller knows
before trying any of the other tools.

**A nonexistent account is a normal answer, not an error.** `get_user` and
`get_user_auth_methods` respond to a typo'd or nonexistent
userPrincipalName with `{"found": false, ...}`, distinct from the `error`
key used for an actual failure (bad input shape, unreachable Graph, missing
permission).

**Sign-in log retention is 30 days (Entra ID P1).** A window beyond that
returns an empty result, not an error — there's nothing there to find, and
that's a legitimate answer.

## Next steps

- [Reference](reference.md) — every tool's parameters, the auth model, and CLI usage
