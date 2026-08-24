# Copilot review instructions — entraadm-mcp

This repo is a stdio MCP server ([FastMCP](https://github.com/modelcontextprotocol/python-sdk))
for Microsoft Entra ID sign-in and audit-log triage. All 7 tools are
read-only — there is no write/mutating tool in this server (no account
unblock, password reset, or session revoke), and no approval-gate or
write-tool allowlist to worry about.

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
- **A `GraphPermissionError` catch that doesn't set a *correct*
  `missing_permission`.** Each tool hardcodes the actual Graph permission
  its own call needs (`AuditLog.Read.All` for the sign-in/audit tools,
  `UserAuthenticationMethod.Read.All` for `get_user_auth_methods`) — there
  is no single global constant, because different tools genuinely need
  different permissions. Copy-pasting one tool's except-block into another
  without updating the permission name is a real bug, not a style nit.
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

- No config file — auth is entirely env-var driven
  (`ENTRAADM_TENANT_ID`/`_CLIENT_ID`/`_CLIENT_SECRET` for app-only, or none
  of the three for `az login`-based delegated auth). `config.py`'s
  `AuthConfig.from_env()` is the only place that reads these.
- No write/mutating tools, so there is no approval-gate or write-tool
  allowlist pattern (unlike some other servers in this fleet) to check.
- `msgraph-sdk`/`kiota` are intentionally not a dependency — Graph calls go
  through the hand-rolled `GraphClient` in `client.py` (httpx + manual
  paging/error translation) so tests can mock `httpx` directly with
  `respx`. Don't suggest migrating a call site to the SDK as a "cleanup."
