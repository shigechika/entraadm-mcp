# CLAUDE.md

## Overview

MCP server for Microsoft Entra ID (Azure AD) sign-in and audit-log triage.
Transport is stdio only. All 7 tools are read-only — there is no
write/mutating tool. Auth is env-var driven (see below); no config file.

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
- `entraadm_mcp/client.py` — `GraphClient`: token acquisition/caching
  (`_TOKEN_REFRESH_MARGIN_SECONDS` = 300), `get()`/`get_paged()` (the latter
  follows `@odata.nextLink` and returns `(items, capped)`), and error
  translation. `odata_quote()`/`validate_upn()` are the injection defenses —
  every `$filter` built from tool input goes through one or both; MCP tool
  input is treated as adversarial. HTTP 403 is translated via
  `_PERMISSION_HINTS` into an actionable message (which Graph role/permission
  is missing); unmapped codes fall back to `"{code}: {message}"`, never a raw
  stack trace. 429 retries once (respecting `Retry-After`); 5xx retries twice
  with exponential backoff. `credential`/`http_client` constructor params
  are `# injectable for tests` (respx-mocked httpx, a stub credential).
- `entraadm_mcp/server.py` — `FastMCP("entraadm-mcp")` with 7 tools.
  `AADSTS_CODES` is a hand-maintained dict (not exhaustive) annotating
  sign-in failure codes; missing codes return `meaning: null`, never hidden.
  `_state = {"client": None}` is the sole test-injection point
  (`monkeypatch.setitem`). Every tool's entry point catches
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
  session), Identity Protection (`riskyUsers`, needs Entra ID P2),
  Conditional Access policy reads (`Policy.Read.All`) — none needed for the
  triage use case this server exists for; add only if that need is
  demonstrated.
