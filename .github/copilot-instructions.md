# Copilot review instructions — entraadm-mcp

This repo is a stdio MCP server ([MCPServer](https://github.com/modelcontextprotocol/python-sdk), mcp 2.x)
for Microsoft Entra ID sign-in and audit-log triage, plus Azure VM backup
posture (Azure Resource Manager) and Microsoft 365 service health. The
default tools are read-only. The one state-changing tool,
`revoke_sign_in_sessions`, is registered only when
`ENTRAADM_ENABLE_REVOKE_SESSIONS=1` (exactly "1") and re-checks that switch
inside the function; the approval step lives in the caller that enables it,
not in this server. There is no account unblock or password reset.

One process may serve several Entra tenants: `ENTRAADM_CONFIG` names an INI
file of `[tenant.<name>]` sections (`config.load_tenants()`). UPN-taking tools
route by the UPN's domain through `@_tenant_scoped`; tenant-wide tools take a
`tenant` argument; an unclaimed domain or unknown tenant is a
`tenant_configured: false` refusal with `found: null` (never `found: false`,
which means "no such account"), never an exception or a silent fallback to
the default tenant (flag any change that falls back -- it would act on the
wrong tenant). The only deliberate fallback is `directory_audits` with a
`user` no tenant claims (an external admin), which says
`user_domain_claimed: false`. `revoke_sign_in_sessions` must keep having no
`tenant` override. Per-tenant work in `health_check` / `daily_brief` must stay
under a share of the call budget. The ARM tools serve the default tenant only. Without the file,
output must stay unchanged (no `tenant` key), except
`revoke_sign_in_sessions`, whose fixed key set always includes `tenant`,
`tenant_configured` and `configured_domains`.

Two clients share one `_RestClient` base in `entraadm_mcp/client.py`:
`GraphClient` (Graph v1.0, `@odata.nextLink`) and `ArmClient`
(`https://management.azure.com`, bare `nextLink`, `api-version` on every
call). They share one credential object and each caches its own scope's
token. The exception hierarchy is `ApiError` / `ApiDeadline` /
`ApiAuthError` / `ApiPermissionError` / `ApiTransportError` /
`ApiServerError` / `ApiResponseError`; `GraphError` and friends are aliases.
Every `ApiError` carries `may_have_applied`: True when an attempt may have
been acted on (a lost response, a 5xx, a deadline after sending, an
unreadable success body). For a state-changing tool, flag any change that
collapses these into a plain `GraphError` "not done" -- the unknown outcome
must stay distinguishable (`revoked: null` in `revoke_sign_in_sessions`).

## What to flag

- **A `$filter` string built with plain f-string interpolation instead of
  `odata_quote()`.** Every OData filter in `entraadm_mcp/server.py` that
  embeds tool-caller input (a userPrincipalName, a search term) wraps that
  value with `client.odata_quote()` first. Tool arguments are MCP-input,
  effectively LLM-driven, and must be treated as adversarial — an
  unescaped value lets a crafted UPN like `a' or '1'='1` reshape the query.
  A new filter-building call site that skips `odata_quote()` is an
  injection gap.
- **A UPN-typed argument used before `validate_upn()`.** Every tool taking
  a `user`/`upn` parameter calls `validate_upn()` before using it — this
  both rejects malformed input early and, together with `_find_user()`
  routing lookups through `$filter` rather than interpolating the value
  into a URL path segment, prevents a value containing `/` from reshaping
  the request path. A new per-user tool that skips this, or that builds a
  path like `f"/users/{upn}"` directly instead of going through
  `_find_user()`/`_resolve_user_id()`, is a gap.
- **Print/log statements, or anything writing to stdout.** This is a stdio
  MCP server: stdout is the JSON-RPC channel. A `print()` (including a
  stray debug print) corrupts every message after it. Diagnostics belong
  in an exception message returned to the caller, not on stdout.
- **A client secret, access token, or full exception text from
  `azure-identity`/`httpx` reaching a tool's return value.**
  `client.py`'s `_access_token()` catches credential failures and re-raises
  as `GraphAuthError(f"... ({type(e).__name__})")` — deliberately dropping
  the original exception's message text, since `azure-identity` exceptions
  can echo back configuration values. A new catch site that includes
  `str(e)` from a credential call, or that logs/returns a raw `Authorization`
  header, is a leak.
- **A tool that returns `{"error": ...}` for "no such account".**
  `get_user`/`get_user_auth_methods` deliberately answer a nonexistent
  userPrincipalName with `{"found": false, "user_principal_name": upn}`,
  not an `error` key (see CLAUDE.md's Conventions section for why). A new
  per-user tool, or an edit to these two, that collapses "not found" into
  the generic error path breaks that contract.
- **A permission-error catch that doesn't set a *correct*
  `missing_permission`, or sets it for a non-permission failure.** Each
  tool hardcodes what its own call needs: `AuditLog.Read.All` for the
  sign-in/audit tools, `UserAuthenticationMethod.Read.All` for
  `get_user_auth_methods`, `ServiceHealth.Read.All` for
  `m365_service_health`, and the Azure RBAC hint `ARM_ROLE_HINT` (Reader on
  the subscription) for the ARM tools via `_arm_error()`. Copy-pasting one
  tool's except-block into another without updating the permission is a
  real bug. The hint belongs only on `ApiPermissionError`: a 5xx, a network
  failure or a rejected token caught as plain `ApiError` must not claim a
  missing permission.
- **A continuation link followed without the same-origin check.**
  `_RestClient.get_paged()` attaches the bearer token to every request and
  refuses a `nextLink` whose scheme/host/port differ from the client's base
  URL (including a scheme-relative `//host/...`). New paging code that
  calls `_request()` on a server-supplied URL without `_same_origin()`
  would hand the token to that host.
- **An ARM id or tool argument interpolated into a URL path without
  validation.** `subscription` is resolved against `list_subscriptions`
  and only ARM's own GUID-checked `subscriptionId` reaches a path. Vault
  ids must match `_VAULT_ID_RE` (built from the resource-group and vault
  naming rules, and the GUID must be the subscription being scanned) or
  they go to `skipped_vaults` unrequested. A `[^/]+`-style pattern, or a
  path built from a display name, is an injection gap.
- **A partial scan turned into a definite diagnosis.** In
  `vm_backup_status` a VM with no protected item is `protected: false`
  only when the vault scan it could have appeared in completed (the named
  subscription's, or every subscription's in the global join); otherwise
  `null`. Orphans need a complete VM listing. A change that defaults an
  unknown to `false`, or drops a failed/skipped subscription from
  `capped` / `failed_subscriptions`, reintroduces the false "unprotected"
  this server is built to avoid. Projections go through
  `_str` / `_int` / `_dict` / `_parse_iso`, which turn a wrong type into
  `null`; direct chained indexing of an ARM `properties` body is a crash
  waiting for a schema change.
- **Something that makes the ARM probe move `health_check.status`.** The
  `arm` probe is informational by design (Azure RBAC is optional) and runs
  under its own `_ARM_PROBE_SECONDS` budget.
- **A new paged Graph call that doesn't propagate `capped`.** Every result
  built from `client.get_paged()` includes a `capped: bool` field, so a
  page-budget cutoff is never indistinguishable from "the window was fully
  scanned and this is everything." A new tool or section that drops this
  is a silent-truncation gap.
- **A literal email/domain/IP-shaped string added to
  `scripts/smoke_probes.py`.** That file is scanned by
  `tests/test_smoke_probes.py::test_no_tenant_specific_literals_in_specs`
  for exactly this, including inside comments — this repository is public
  and must never name a real tenant, account, or app registration. A
  probe needing a per-account argument must build it in an `args_factory`
  at run time (see the existing `_fake_user_arg`/`_fake_upn_arg`), never
  as a static literal.

## Not a concern here

- Auth is env-var driven for one tenant
  (`ENTRAADM_TENANT_ID`/`_CLIENT_ID`/`_CLIENT_SECRET` for app-only, or none
  of the three for `az login`-based delegated auth); `config.py`'s
  `AuthConfig.from_env()` / `load_tenants()` are the only places that read
  them. The optional `ENTRAADM_CONFIG` file holds tenant ids, domains and the
  NAME of an env var for a per-tenant secret, never a secret itself.
- Any new state-changing tool must be opt-in the same way (absent from
  `tools/list` unless its switch is set), look the target up by exact
  identifier before acting, and be listed in `STATE_CHANGING` with a
  `skip=` probe so the smoke test never calls it.
- `msgraph-sdk`/`kiota` and the `azure-mgmt-*` SDKs are intentionally not
  dependencies — Graph and ARM calls go through the hand-rolled clients in
  `client.py` (httpx + manual paging/error translation) so tests can mock
  `httpx` directly with `respx`. Don't suggest migrating a call site to an
  SDK as a "cleanup."
- ARM tools living in an Entra-named server is deliberate (same app
  registration, same credential, same deployment); don't suggest
  splitting them out.
