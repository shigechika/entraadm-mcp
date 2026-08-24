<!-- mcp-name: io.github.shigechika/entraadm-mcp -->

# entraadm-mcp

English | [日本語](README.ja.md)

MCP server for Microsoft Entra ID sign-in and audit-log triage. Read-only.

## Why this instead of the official Microsoft MCP Server for Enterprise

Microsoft ships an [official MCP Server for Enterprise](https://learn.microsoft.com/en-us/graph/mcp-server/overview)
for Entra ID data. It is a good fit for an interactive admin at a keyboard,
and is not a fit for an unattended triage bot:

- **Delegated auth only.** The official server does not support app-only
  (client credentials) auth, so it cannot run headless behind a service
  account. entraadm-mcp is built for that case: app-only in production, with
  a delegated (`az login`) fallback for local development.
- **A general-purpose Graph query tool, not a fixed tool set.** The official
  server exposes one tool that lets the model construct arbitrary
  `GET`/schema-discovery calls against Microsoft Graph. That is flexible for
  a human, and awkward to put behind an allow-list for an automated triage
  profile. entraadm-mcp exposes seven fixed, read-only tools instead.
- **No AADSTS translation.** Sign-in failures come back as raw error codes;
  triage still needs a lookup table. entraadm-mcp annotates every sign-in
  failure with what the code actually means.
- **No cross-request aggregation.** Microsoft Graph itself cannot filter
  sign-ins on `status/errorCode` server-side, and has no built-in
  password-spray view. `signin_failure_stats` aggregates client-side and
  flags IPs with failed sign-ins against many distinct users — the pattern
  Entra's per-account smart lockout does not catch on its own.

## Tools

| Tool | What it answers |
|---|---|
| `health_check` | Is Graph reachable, and can this credential read sign-in logs? |
| `get_user` | Is this account enabled, synced from on-prem, and what are its licenses? |
| `signin_logs` | Why did this user's sign-in fail (or succeed), with the AADSTS code translated? |
| `signin_failure_stats` | Tenant-wide failure aggregation: top error codes, users, apps, source IPs, and password-spray suspects |
| `directory_audits` | Who changed what in the directory (block/unblock, attribute edits), and when? |
| `get_user_auth_methods` | Is MFA actually registered for this account? |
| `daily_brief` | One-call summary combining `signin_failure_stats` and `directory_audits` |

Every tool is read-only. Write operations (unblocking an account, resetting a
password, revoking a session) are out of scope for this server.

## Auth model

Two auth modes, selected by which environment variables are set:

| Mode | When | Env vars |
|---|---|---|
| app-only | All three set | `ENTRAADM_TENANT_ID`, `ENTRAADM_CLIENT_ID`, `ENTRAADM_CLIENT_SECRET` |
| azure-cli | None set | (uses the current `az login` session) |

Setting one or two of the three app-only variables is a configuration error
and the server refuses to start, rather than silently falling back to a
different auth mode than intended.

### Required Graph permissions

| Tool(s) | Permission | Notes |
|---|---|---|
| `get_user` (base fields) | `User.Read.All` | |
| `signin_logs`, `signin_failure_stats`, `directory_audits`, `get_user`'s `sign_in_activity` field | `AuditLog.Read.All` (app-only) or the **Reports Reader** directory role (delegated) | |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` | App-only only; not available under delegated (`az login`) auth in a typical tenant role assignment |

A missing permission never crashes a tool. It degrades that tool (or that
one field) to `{"error": "...", "missing_permission": "..."}` with a
human-readable explanation of what role or permission is needed, so
`health_check` and every other tool stay usable even before full permissions
are granted.

## Setup

```bash
uv tool install entraadm-mcp
# or
pip install entraadm-mcp
```

## Configuration

Set the three app-only variables for production/unattended use:

```bash
export ENTRAADM_TENANT_ID=00000000-0000-0000-0000-000000000000
export ENTRAADM_CLIENT_ID=00000000-0000-0000-0000-000000000000
export ENTRAADM_CLIENT_SECRET=your-client-secret
```

Or leave all three unset and run `az login` first for local development.

Optional:

```bash
# Default page cap for the log-scanning tools (1-50, default 5).
export ENTRAADM_MAX_PAGES_DEFAULT=5
```

## Usage

### Claude Code (plugin)

```
/plugin marketplace add shigechika/entraadm-mcp
/plugin install entraadm-mcp@entraadm-mcp
```

### Claude Code (manual)

Add to `.mcp.json`:

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

### Direct execution

```bash
entraadm-mcp
```

### CLI options

| Option | Effect |
|---|---|
| `--version` | Print the version and exit |
| `--check` | Resolve auth, probe Graph reachability and sign-in log access, print a report, exit 0 (or 1 on config error) |

## Notes

- **Coverage contract.** Every result that walks a paged Graph collection
  carries a `capped` boolean when its window was not fully scanned — a
  partial scan is never reported as if it were exhaustive.
- **`found: false` is not an error.** `get_user` and `get_user_auth_methods`
  answer a nonexistent account with `{"found": false, ...}`, not an `error`
  key — a typo'd userPrincipalName should never look like this server being
  broken.
- **Retention.** Entra ID P1 retains sign-in and directory audit logs for 30
  days. A window beyond that returns an empty result, not an error.

## Development

```bash
uv sync --dev
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
```

### Live smoke test

```bash
uv run python scripts/smoke_test.py
```

Read-only, no payloads printed (tool names/statuses/row counts only), and
bounded (small explicit windows/page caps) — nothing here writes to the
tenant or scans more than a day of logs.

## Releasing

This repository uses [release-please](https://github.com/googleapis/release-please)
driven by [Conventional Commits](https://www.conventionalcommits.org/). Merge
a `feat:`/`fix:` PR to `main`, and release-please opens (or updates) a
release PR; merging that PR tags a release and triggers the publish pipeline
(PyPI, MCP Registry).

## License

MIT
