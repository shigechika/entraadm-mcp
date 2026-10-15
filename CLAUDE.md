# CLAUDE.md

## Overview

MCP server for Microsoft Entra ID (Azure AD) sign-in and audit-log triage,
plus Azure VM backup posture (Azure Resource Manager) and Microsoft 365
service health. Transport is stdio only. All 13 tools are read-only — there
is no write/mutating tool. Auth is env-var driven (see below); no config file. The
one optional data file is `ENTRAADM_SITES_INI` (the tenant's own address
ranges, same format as keycloak-mcp's `KEYCLOAK_SITES_INI`), loaded by
`entraadm_mcp/sites.py` with longest-prefix lookup.

## Commands

```bash
uv sync --dev
uv run pytest -v                  # all tests
uv run ruff check .               # lint (gated in CI)
uv run ruff format --check .      # format (gated in CI)
uv run entraadm-mcp --check       # resolve auth + probe Graph reachability
uv run python scripts/smoke_test.py   # live smoke test against a real tenant
```

## Architecture

- `entraadm_mcp/config.py` — `AuthConfig.from_env()`: all three of
  `ENTRAADM_TENANT_ID`/`_CLIENT_ID`/`_CLIENT_SECRET` set selects app-only
  (`ClientSecretCredential`); none set selects `azure-cli`
  (`AzureCliCredential`); one or two set raises `ConfigError` (never a
  silent fallback to the wrong mode). `max_pages_default()` reads
  `ENTRAADM_MAX_PAGES_DEFAULT`, clamped to `[MIN_MAX_PAGES, MAX_MAX_PAGES]`
  = `[1, 50]`, falling back to `DEFAULT_MAX_PAGES` = 5 on anything unparsable.
- `entraadm_mcp/client.py` — `_RestClient` is the shared bearer-token
  client (token acquisition/caching with `_TOKEN_REFRESH_MARGIN_SECONDS` =
  300, retry budgets, the deadline-bounded request, `get()`/`get_paged()`
  returning `(items, capped)`); `GraphClient` (Graph v1.0,
  `@odata.nextLink`) and `ArmClient` (`https://management.azure.com`, bare
  `nextLink`, `api-version` from `ARM_API_VERSIONS` on every call,
  `AuthorizationFailed` → the Reader-role hint `ARM_ROLE_HINT`) subclass it.
  The two share one credential object and each caches its own scope's
  token. `get_paged` refuses to follow a continuation link whose
  scheme/host/port differ from the client's base URL (it would hand the
  bearer token to that host) — `ApiError`, not followed. The exception
  hierarchy is `ApiError`/`ApiDeadline`/`ApiAuthError`/`ApiPermissionError`;
  `GraphError` etc. are aliases kept for the older imports. `odata_quote()`/`validate_upn()` are the injection defenses —
  every `$filter` built from tool input goes through one or both; MCP tool
  input is treated as adversarial. HTTP 403 is translated via
  `_PERMISSION_HINTS` into an actionable message (which Graph role/permission
  is missing); unmapped codes fall back to `"{code}: {message}"`, never a raw
  stack trace. 429 retries once (respecting `Retry-After`); 5xx retries twice
  with exponential backoff. `credential`/`http_client` constructor params
  are `# injectable for tests` (respx-mocked httpx, a stub credential).
- `entraadm_mcp/server.py` — `MCPServer("entraadm-mcp")` with 13 tools.
  `AADSTS_CODES` is a hand-maintained dict (not exhaustive) annotating
  sign-in failure codes; missing codes return `meaning: null`, never hidden.
  `_state = {"client": None, "arm": None}` holds the two test-injection
  points (`monkeypatch.setitem`; the `inject` fixture always puts a
  `FakeArmClient` in `arm`, because `health_check` probes ARM too and a real
  `AzureCliCredential` would shell out to `az`). Every tool's entry point catches
  `(ConfigError, GraphError)` and returns `{"error": str(e)}`;
  `GraphPermissionError` specifically adds `missing_permission` naming the
  actual Graph permission that endpoint needs (not a single global constant
  — `get_user_auth_methods` needs a different one than the sign-in/audit
  tools). Every paged result carries `capped: bool`.

## Conventions

- **`found: false`, not `error`, for "no such account".** `get_user` and
  `get_user_auth_methods` answer a nonexistent userPrincipalName with
  `{"found": false, "user_principal_name": upn}`. This is deliberate, not an
  oversight: a live smoke-test harness (and, more importantly, an automated
  triage consumer) must be able to tell "this tool is broken" from "this
  account genuinely doesn't exist" — conflating the two under one `error` key
  makes a typo'd UPN in a triage report look like a server failure.
- **`directory_audits`' `user` filter matches both sides.** Graph's
  `directoryAudits` only supports server-side `$filter` on the *initiator*
  (`initiatedBy/user/userPrincipalName`), not on `targetResources`. Rather
  than silently limiting the tool to "audits this person performed" (which
  is not what "did anything happen to this account" triage needs),
  `directory_audits` fetches the window unfiltered-by-user and matches both
  `initiatedBy` and `targetResources` client-side (`_matches_user`). This
  means a busy window needs a larger `max_pages` budget to find one specific
  user's audits than the sign-in tools do for the same window.
- **Nothing from an ARM response or from tool input reaches a URL path
  unvalidated.** `subscription` is resolved against `list_subscriptions`
  and only ARM's own GUID-checked id is interpolated; vault ids must match
  `_VAULT_ID_RE` (built from the resource-group and vault naming rules, not
  `[^/]+` — a group made only of periods is rejected while `rg..prod`,
  `.prod` and non-ASCII letters pass, and the subscription GUID must be the
  one being scanned) or they go to `skipped_vaults` and are never requested. The VM ↔ protected-item
  join lower-cases both ids (ARM casing differs between Compute and
  RecoveryServices).
- **A partial scan never produces a false diagnosis.** In
  `vm_backup_status` a VM with no protected item is `protected: false` only
  when the vault scan it could have appeared in was complete — the named
  subscription's, or in the global join every subscription's (an unreadable
  or unreached subscription counts as incomplete and sets `capped`);
  otherwise `null` (unknown). Orphans are reported only when the VM listing
  was complete.
  Unknown schedule/retention types in `vm_backup_policies` come back as
  `{"type", "unparsed": true}`, never dropped. Projection goes through
  `_str`/`_int`/`_dict`/`_parse_iso`, which turn a wrong type or a malformed
  timestamp into `null`, never an exception.
- **`health_check`'s `arm` probe is informational.** It never moves
  `status`: Azure RBAC is optional, and a deployment used only for Entra
  triage must not sit at `degraded` forever. `--check` prints the matching
  `Info:` line without changing the exit code.
- **`daily_brief` carries `m365_service_health` and not VM backup.** Service
  health is two small reads and runs first; the ARM fan-out is the one scan
  that could exhaust the shared budget, so callers invoke `vm_backup_status`
  separately.
- **`daily_brief` is synchronous, unlike the sibling gwsadm-mcp's
  job+poll `daily_brief_start`/`_result`.** If a tenant's sign-in volume
  makes this exceed a client's tool-call timeout, port that pattern here —
  see Roadmap below.
- Tests use two styles: `tests/test_client.py` mocks httpx via `respx`
  (`@respx.mock`, since `GraphClient` builds a real `httpx.Client` when no
  `http_client` is injected — respx patches the transport globally, no
  wiring needed) with a `FakeCredential` stub; `tests/test_server.py`
  injects a hand-written `FakeGraphClient` via
  `monkeypatch.setitem(server._state, "client", ...)` and calls tool
  functions directly (`server.get_user(...)`, not through any MCP transport
  wrapper — `@mcp.tool()` leaves the function callable). Do not use
  `unittest.mock.patch` for either.
- `scripts/smoke_harness.py` is copied verbatim from the sibling MCP
  servers that share it (currently gwsadm-mcp) and excluded from `ruff
  format` (see `pyproject.toml`) so future syncs stay a clean diff, not a
  reformat. Don't hand-edit it; port changes from the sibling repo.
- `scripts/smoke_probes.py` has **no directory-listing tool to discover a
  real account from** (unlike gwsadm-mcp's `suspended_accounts`/
  `login_audit`), so `get_user`/`get_user_auth_methods`/`signin_logs`
  probes build a syntactically valid, guaranteed-nonexistent
  userPrincipalName in the RFC 2606 reserved `example.invalid` domain
  instead. Never write an address-shaped literal directly in that file —
  `tests/test_smoke_probes.py::test_no_tenant_specific_literals_in_specs`
  scans the raw source text for one, regardless of whether it's inside a
  comment. Build any such value via string concatenation/f-string
  interpolation at runtime, in an `args_factory`, never as a static
  `Probe.args` value.
- This repository is **public**. Never write a real tenant ID, app
  registration client ID, or real userPrincipalName into code, tests,
  commits, PRs, or issues.

## Roadmap (deliberately not in the initial release)

- `daily_brief_start`/`daily_brief_result` job+poll, if `daily_brief`'s
  synchronous runtime proves too slow against a real tenant's sign-in
  volume.
- `mfa_registration_stats()` — tenant-wide MFA registration rate (the
  `/reports/authenticationMethods/userRegistrationDetails` endpoint), as a
  counterpart to `get_user_auth_methods`'s per-account view.
- Richer sync-diagnostic fields on `get_user` (beyond
  `on_premises_sync_enabled`/`on_premises_last_sync_date_time`) and triage
  hints attached to specific AADSTS codes (e.g. "compare this timestamp
  against the KeyCloak-side password-change event").
- Write tools (unblock an account, force a password reset, revoke a
  session), Identity Protection (`riskyUsers`, needs an Entra ID P2 licence
  — the API answers 403 "tenant is not licensed" without it, so do not add
  the tool before confirming the licence), Conditional Access policy reads
  (`Policy.Read.All`), the message center (`ServiceMessage.Read.All`) — none
  needed for the triage use case this server exists for; add only if that
  need is demonstrated.
- The Azure Backup field names (`AzureIaaSVMProtectedItem`, the V1/V2
  schedule and `LongTermRetentionPolicy` shapes) were taken from the REST
  reference and the respx/fake fixtures; confirm them against a live
  subscription that has protected VMs when one becomes reachable.
