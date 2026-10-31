<!-- mcp-name: io.github.shigechika/entraadm-mcp -->

# entraadm-mcp

English | [日本語](README.ja.md)

MCP server for Microsoft Entra ID sign-in and audit-log triage, plus the two
Azure-side questions a morning patrol asks with the same credential: are our
Azure VMs backed up, and is Microsoft 365 itself degraded right now. Read-only,
except for one opt-in tool that signs a compromised account out everywhere.

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
  profile. entraadm-mcp exposes fifteen fixed, read-only tools instead (plus one
  opt-in write, below).
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
| `signin_success_stats` | Tenant-wide success aggregation by source IP: IPs shared by several accounts, legacy-auth (SMTP/IMAP) successes — the view that finds a breach |
| `compromise_suspects` | Which accounts were probably taken over: an outside IP that sprayed many accounts and got into some (`spray_breaches`), successes from outside the home countries (`foreign_successes`, high when over a legacy protocol, through Azure CLI / PowerShell, or from 3+ countries within 24 hours), and Microsoft's own risky users when the tenant has Entra ID P2 |
| `signin_by_ip` | Every sign-in from one source IP: who got in from it, who was tried, and when |
| `directory_audits` | Who changed what in the directory (block/unblock, attribute edits), and when? |
| `get_user_auth_methods` | Is MFA actually registered for this account? |
| `list_subscriptions` | Which Azure subscriptions can this credential see? (ARM) |
| `vm_backup_status` | Which Azure VMs are backed up by Azure Backup, did the last backup succeed, and is any recovery point stale? (ARM) |
| `vm_backup_policies` | What schedule and retention do the Azure VM backup policies have? (ARM) |
| `vm_activity` | Did someone restart this Azure VM, or did Azure (host failure, maintenance)? Activity log and Resource Health for a time window (ARM) |
| `m365_service_health` | Is a Microsoft 365 service degraded, and which incidents and advisories are open? |
| `daily_brief` | One-call summary combining `m365_service_health`, `signin_failure_stats`, `directory_audits` and `compromise_suspects` (counts and top 5) |

Every tool above is read-only. One state-changing tool exists and is off by
default:

| Tool | What it does |
|---|---|
| `revoke_sign_in_sessions` | Signs one account out everywhere (Graph `revokeSignInSessions`: refresh tokens and session cookies are invalidated). For a confirmed compromise. Registered only when `ENTRAADM_ENABLE_REVOKE_SESSIONS=1` |

It looks the account up by exact userPrincipalName first and refuses a guest.
Every result has the same keys, including `revoked` and `not_covered`: it does
not disable the account, reset the password or remove MFA methods, and access
tokens already issued keep working until they expire (typically about an
hour). `revoked` is `true` when Graph confirmed it, `false` when nothing was
done (a refusal, a deadline before the request was sent, a 4xx from Graph), and
`null` when the outcome is unknown (a response lost to a network error, a 5xx
after the retries, a deadline after the request was sent, an unreadable success
answer); calling again is then safe, revocation is idempotent. Leave the
switch unset on any deployment that is not behind its own approval step (a
shared gateway, for instance) -- the tool is then absent from `tools/list`.
Unblocking an account and resetting a password stay out of scope.

The four Azure Resource Manager tools live in an Entra-named server on
purpose: they use the same app registration and the same `azure-identity`
credential object (a second token scope, `https://management.azure.com/.default`),
run in the same deployment and are covered by the same `health_check`. A
separate server for these tools would double the operational surface. They
are governance reads, not resource management; a subscription the credential
has no Reader role on simply does not appear in `list_subscriptions`.

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
| `signin_logs`, `signin_failure_stats`, `signin_success_stats`, `compromise_suspects`, `signin_by_ip`, `directory_audits`, `get_user`'s `sign_in_activity` field | `AuditLog.Read.All` (app-only) or the **Reports Reader** directory role (delegated) | |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` | App-only only; not available under delegated (`az login`) auth in a typical tenant role assignment |
| `m365_service_health`, `daily_brief`'s `service_health` section | `ServiceHealth.Read.All` | Under delegated auth the signed-in user also needs an Entra role that may read service health (for example Service Support Administrator or Global Reader) |
| `compromise_suspects`' `microsoft_risky_users`, the `identity_protection` probe (health_check, daily_brief) | `IdentityRiskyUser.Read.All` | Optional. Identity Protection needs **Entra ID P2**: without it Graph answers 403 "not licensed" and the probe reports `not_licensed`; nothing else changes |
| `revoke_sign_in_sessions` (opt-in) | `User.RevokeSessions.All` (app-only) or the **User Administrator** / **Helpdesk Administrator** directory role (delegated; **Privileged Authentication Administrator** for an administrator account) | Only when `ENTRAADM_ENABLE_REVOKE_SESSIONS=1`. A write permission: grant it only to a deployment that needs the tool. The account lookup before it needs `User.Read.All`. Without the permission the tool answers `missing_permission` for the auth mode in use and nothing changes |

### Required Azure RBAC

| Tool(s) | Role | Notes |
|---|---|---|
| `list_subscriptions` | none | Lists whatever the credential can see; an empty list means no role has been granted anywhere yet |
| `vm_backup_status`, `vm_backup_policies`, `vm_activity` | **Reader** on each subscription | `Reader` is `*/read` and covers every endpoint used. `Backup Reader` alone is not enough (it has no `Microsoft.Compute/virtualMachines/read`). Granted to the service principal (app-only) or to the signed-in user (azure-cli) |

Azure RBAC is optional: `health_check` reports ARM reachability and the number
of visible subscriptions as an informational `arm` probe that never changes
`status`, so a deployment used only for Entra triage stays `healthy`.

A missing permission never crashes a tool. It degrades that tool (or that
one field) to `{"error": "...", "missing_permission": "..."}` with a
human-readable explanation of what role or permission is needed, so
`health_check` and every other tool stay usable even before full permissions
are granted.


**Identity Protection (Entra ID P2).** `compromise_suspects` adds Microsoft's own
risk verdicts when the tenant has them: a cheap `riskyUsers?$top=1` probe
classifies each tenant as `licensed`, `not_licensed` (403 "not licensed": no
Entra ID P2), `no_permission` (other 403: no `IdentityRiskyUser.Read.All`) or
`error`; `licensed` and `not_licensed` are cached for an hour (a 200 whose rows
say `riskLevel: hidden` also means no P2). The endpoint itself is probed:
`/subscribedSkus` can be refused and a SKU list would still have to be mapped to
P2. `health_check` reports it per tenant
without changing `status`, and `daily_brief`'s summary per tenant, so the day
P2 appears is noticed. Licensed: `microsoft_risky_users` lists open
(`atRisk` / `confirmedCompromised`) high-risk users and, separately, medium,
marking those also in `spray_breaches` / `foreign_successes`. `counts` are then
distinct accounts over every finding, before the lists are cut: `high` is any
account high here or in Microsoft's high list, `medium` any medium here or in
Microsoft's medium list that is not high (`counts.microsoft_high` /
`microsoft_medium` say how many Microsoft lists). Otherwise the
section is `{available: false, reason}` and nothing else changes -- never read
it as "no risky users".

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
# Default page cap for the log-scanning tools (1-50, default 50).
export ENTRAADM_MAX_PAGES_DEFAULT=50
# Wall-clock budget per tool call in seconds (default 45; 0 disables). A hosted MCP
# client cuts a call off at about 60 s, so a scan stops at the budget and returns
# what it has with capped=true.
export ENTRAADM_DEADLINE=45
# Your own address ranges (NAT egress, offices, labs). Spray suspects inside them are
# listed separately as internal_spray_suspects, labelled with the site.
export ENTRAADM_SITES_INI=/path/to/sites.ini
# The countries your users sign in from (assigned ISO 3166-1 alpha-2 codes). compromise_suspects
# reports successes from elsewhere; unset or with an invalid code, that list is skipped.
export ENTRAADM_HOME_COUNTRIES=JP
# Register revoke_sign_in_sessions, the one state-changing tool (exactly "1"; anything
# else leaves it off). Also needs the User.RevokeSessions.All permission.
export ENTRAADM_ENABLE_REVOKE_SESSIONS=1
# Serve several tenants from one process (see "Several tenants" below).
export ENTRAADM_CONFIG=/path/to/tenants.ini
```

`ENTRAADM_SITES_INI` uses the same format as keycloak-mcp's `KEYCLOAK_SITES_INI`,
so one file can serve both (see [`sites.ini.example`](sites.ini.example)). Lookups are
longest-prefix. A file that is set but cannot be read makes `health_check` report
`degraded`, and every IP is then treated as external. An invalid CIDR is reported the
same way, but the valid ranges are still used.

### Several tenants

One process can serve several Entra tenants, the way gwsadm-mcp serves several
Workspace domains. Point `ENTRAADM_CONFIG` at an INI file with one
`[tenant.<name>]` section per tenant:

```ini
[tenant.staff]
tenant_id = 00000000-0000-0000-0000-000000000001
domains = example.edu
default = true

[tenant.students]
tenant_id = 00000000-0000-0000-0000-000000000002
domains = students.example.edu
; optional: an app registration of its own instead of the shared one
; client_id = 00000000-0000-0000-0000-000000000003
; client_secret_env = ENTRAADM_STUDENTS_CLIENT_SECRET
```

| Key | Required | Meaning |
|---|---|---|
| `tenant_id` | yes | The tenant's id (GUID) or a domain name of it (with a dot, e.g. `contoso.onmicrosoft.com`); `common`, `organizations` and `consumers` are refused |
| `domains` | yes | Comma-separated UPN domains routed to this tenant (exact match, any case) |
| `default` | on one section when there are several | The tenant used when a call names none; a single section is the default anyway |
| `client_id` + `client_secret_env` | no, both or neither | An app of its own; `client_secret_env` names the env var holding its secret. Never put a secret in the file |

A section without `client_id` reuses the env app (`ENTRAADM_CLIENT_ID` /
`ENTRAADM_CLIENT_SECRET`), with the token requested from that section's
tenant; with no env app it uses `az login` in that tenant. `ENTRAADM_TENANT_ID`
is not used when `ENTRAADM_CONFIG` is set. Unset `ENTRAADM_CONFIG` keeps the
single-tenant setup above unchanged.

To share one app across tenants, make the app registration multi-tenant
(*Supported account types*: accounts in any organizational directory), add the
same Graph application permissions, then have an administrator of each other
tenant grant admin consent:

```
https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=<app-id>
```

The server refuses to start, and `--check` fails, when the file is unreadable,
has a section that is not `[tenant.*]` or an unknown key, misses `tenant_id` or
`domains`, has a `tenant_id` that is neither a GUID nor a dotted domain, gives one domain to two tenants, or has no default (or two) among
several tenants. `--check` probes every tenant.

Routing:

- A tool that takes a UPN (`get_user`, `get_user_auth_methods`, `signin_logs`,
  `revoke_sign_in_sessions`, and `directory_audits` when `user` is given) works
  in the tenant whose `domains` holds the UPN's domain (exact match). A domain
  no tenant claims is a refusal, not an exception: `tenant_configured: false`,
  `found: null` (no lookup ran) and the `configured_domains`. For
  `revoke_sign_in_sessions`: `revoked: false`, `found: null`, nothing is sent.
  List `<tenant>.onmicrosoft.com` in `domains` if such UPNs are looked up often.
- `get_user`, `get_user_auth_methods` and `signin_logs` also take `tenant`,
  which wins over the UPN's domain: for a `*.onmicrosoft.com` or `#EXT#` UPN,
  or a B2B guest whose sign-ins are logged in the host tenant.
  `revoke_sign_in_sessions` has no such override on purpose: a write is only
  ever aimed at the tenant that owns the UPN's domain.
- A tenant-wide tool (`signin_failure_stats`, `signin_success_stats`, `compromise_suspects`,
  `signin_by_ip`, `directory_audits`, `m365_service_health`) takes an optional
  `tenant`; default the default tenant. `directory_audits` with both `tenant`
  and a `user` whose domain another tenant claims is refused (it would search
  the wrong log and find nothing); a `user` whose domain no tenant claims (an
  external or partner admin, a guest) is searched in the given or default
  tenant, and the result says `user_domain_claimed: false`.
- `tenant` is a section name, one of its domains, or its tenant id. Without a
  tenant file it may be `default` or the env tenant id; anything else is
  refused (`tenant_configured: false`).
- `health_check` and `daily_brief` cover every tenant. Their top-level keys stay
  the default tenant's, as before; `tenant` names it and `tenants` holds the
  per-tenant results. The call budget (`ENTRAADM_DEADLINE`) is split evenly
  among the tenants (default first, each taking a share of what is left), so a
  slow tenant cannot stall the others; a tenant that does not answer is an
  `error` in its own entry, and makes `health_check`'s `status` at most
  `degraded`. With `ENTRAADM_DEADLINE=0` there is no budget: every tenant is
  scanned in full, one after another, which can outlast a client's ~60 s cutoff.
- The Azure Resource Manager tools (`list_subscriptions`, `vm_backup_status`,
  `vm_backup_policies`, `vm_activity`) serve the default tenant only.
- With a tenant file, every result names its `tenant` (the ARM tools: the
  default tenant; a refusal that picked none: `null`). Env-only results are
  unchanged, except that `revoke_sign_in_sessions` always carries `tenant`,
  `tenant_configured` and `configured_domains` (its keys never vary).

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

### Codex

```bash
codex mcp add entraadm-mcp \
  --env ENTRAADM_TENANT_ID=your-tenant-id \
  --env ENTRAADM_CLIENT_ID=your-client-id \
  --env ENTRAADM_CLIENT_SECRET=your-client-secret \
  -- uvx entraadm-mcp
```

Any other MCP client that launches stdio servers works the same way: give it
`uvx entraadm-mcp` as the command and set the `ENTRAADM_*` variables from
[Configuration](#configuration) in its environment.

### Direct execution

```bash
entraadm-mcp
```

### CLI options

| Option | Effect |
|---|---|
| `--version` | Print the version and exit |
| `--check` | Resolve auth, probe Graph reachability and sign-in log access, print a report (plus an informational ARM line), exit 0 (or 1 on config error) |
| `archive-signins --dir DIR` | Keep the sign-in log past Entra's 30 days: write each ended UTC slot to `DIR/<tenant>/<slot>.jsonl.gz` (run it daily; see the [reference](https://shigechika.github.io/entraadm-mcp/reference/#archive-signins)) |

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

Read-only (`revoke_sign_in_sessions` is skipped by name even when enabled), no
payloads printed (tool names/statuses/row counts only), and bounded (small explicit windows/page caps) — nothing here writes to the
tenant or scans more than a day of logs.

## Releasing

This repository uses [release-please](https://github.com/googleapis/release-please)
driven by [Conventional Commits](https://www.conventionalcommits.org/). Merge
a `feat:`/`fix:` PR to `main`, and release-please opens (or updates) a
release PR; merging that PR tags a release and triggers the publish pipeline
(PyPI, MCP Registry).

## License

MIT
