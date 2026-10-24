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

Optional: `ENTRAADM_SITES_INI` names an INI file of your own address ranges, in
the same format as keycloak-mcp's `KEYCLOAK_SITES_INI` (one section per site,
optional `name`, comma-separated `ipv4` / `ipv6` CIDRs). Lookups are
longest-prefix, and the file is re-read when it changes. An unreadable file or
a file with no ranges is reported as an error. An invalid CIDR is reported too,
but the valid ranges are still used.

### Required Graph permissions

| Tool(s) | Permission |
|---|---|
| `get_user` (base fields) | `User.Read.All` |
| `signin_logs`, `signin_failure_stats`, `signin_success_stats`, `signin_by_ip`, `directory_audits`, `get_user`'s `sign_in_activity` field | `AuditLog.Read.All` (app-only) or the **Reports Reader** directory role (delegated) |
| `get_user_auth_methods` | `UserAuthenticationMethod.Read.All` (app-only only) |
| `m365_service_health`, `daily_brief`'s `service_health` section | `ServiceHealth.Read.All` (delegated auth also needs an Entra role that may read service health, e.g. Service Support Administrator or Global Reader) |
| `revoke_sign_in_sessions` (opt-in, `ENTRAADM_ENABLE_REVOKE_SESSIONS=1`) | `User.RevokeSessions.All` (app-only) or the User Administrator / Helpdesk Administrator directory role (delegated; Privileged Authentication Administrator for an administrator account). A write permission; grant it only where the tool is enabled. The lookup before it needs `User.Read.All` |

### Required Azure RBAC

| Tool(s) | Role |
|---|---|
| `list_subscriptions` | none (lists what the credential can see) |
| `vm_backup_status`, `vm_backup_policies`, `vm_activity` | **Reader** on each subscription (`*/read`; `Backup Reader` alone lacks `Microsoft.Compute/virtualMachines/read`) |

Azure RBAC is optional; `health_check`'s `arm` probe is informational.

### Several tenants

`ENTRAADM_CONFIG` names an INI file with one `[tenant.<name>]` section per
tenant (`tenant_id`, `domains`, optional `default`, optional `client_id` +
`client_secret_env`); see the README's "Several tenants" for the format, the
multi-tenant app and admin consent
(`https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=<app-id>`).
A UPN-taking tool works in the tenant claiming the UPN's domain (an unclaimed
domain: `tenant_configured: false`, `found: null`, `configured_domains`);
`get_user`, `get_user_auth_methods` and `signin_logs` take a `tenant` override,
`revoke_sign_in_sessions` deliberately none. The tenant-wide tools take
`tenant` (section name, domain or tenant id; env-only: `default` or the env
tenant id), default the default tenant; `directory_audits` refuses a `tenant`
that another tenant's `user` contradicts and searches an unclaimed `user` in
the given or default tenant (`user_domain_claimed: false`). `health_check` /
`daily_brief` keep the default tenant's keys on top, add `tenant` and
`tenants`, and split the call budget evenly among the tenants
(`ENTRAADM_DEADLINE=0`: unbounded). The ARM tools serve the default tenant
only. With a tenant file every result names its `tenant`.

## Tools

### `health_check()`

No parameters. Returns `{service, version, status, auth_mode, graph,
signin_probe, arm, sites}`. `graph` probes basic Graph reachability
(`GET /users` with `$top=1` -- needs only `User.Read.All`); `signin_probe` additionally checks sign-in log
access. `status` is `"healthy"` when both succeed, `"degraded"` when Graph
is reachable but sign-in log access is not, `"error"` when Graph itself is
unreachable or auth is misconfigured. `graph`/`signin_probe` are each
`{auth: "ok"|"error", detail: str|null}`. `sites` is `{configured, ranges,
error}` for `ENTRAADM_SITES_INI`; a configured file with an `error` turns a
`"healthy"` status into `"degraded"`. `arm` is `{auth, detail, subscriptions,
capped}` (one page of `GET /subscriptions` on Azure Resource Manager;
`subscriptions` is how many the credential can see, `capped` whether more
pages existed) and is informational: it never changes `status`,
because Azure RBAC is optional for this server. It runs under its own
10-second budget so an unresponsive ARM cannot stall the whole call.

### `get_user(upn, tenant=None)`

Account lifecycle state: `accountEnabled`, `userType`, creation/last
password-change timestamps, on-premises sync status, resolved license
names, and (if `AuditLog.Read.All`/Reports Reader is available)
`sign_in_activity`. A nonexistent account returns
`{"found": false, "user_principal_name": upn}` rather than an error.
`licenses_capped: true` appears only when the SKU catalog scan was cut
short before resolving one of this account's own licenses -- when
present, one or more `licenses` entries is a raw skuId rather than a
friendly name.

### `signin_logs(user, hours=24, result="failure", top=25, max_pages=None, tenant=None)`

One user's sign-in events. `result`: `"failure"` (default, the common
case), `"success"`, or `"all"` — filtered client-side, since Graph cannot
filter sign-ins on `status/errorCode` server-side. Each event's
`error_code` is annotated with `error_code_meaning` (e.g. 50126 → "invalid
credentials (wrong password)") from a hand-maintained AADSTS code table.
`hours` clamped to 1-720 (30 days — Entra ID P1's sign-in log retention).
`capped=true` means the page budget ran out (or `top` was reached) before
the whole window was scanned — a low match count alongside `capped=true`
means "not found within the budget," not "doesn't exist."

### `signin_failure_stats(hours=24, max_pages=None, tenant=None)`

Tenant-wide failure aggregation: top AADSTS error codes (annotated), top
failing users, top applications, and top source IPs. `spray_suspects` lists
any IP with failed sign-ins against 5 or more distinct users — a pattern
Entra's per-account smart lockout does not catch on its own. `hours`
clamped as above.

With `ENTRAADM_SITES_INI` set, IPs inside your own ranges get `site` (and
`site_name`) in `top_ips`, and suspects inside them move to
`internal_spray_suspects`, so that a NAT egress or shared workstations do not
bury an outside source. `sites` reports whether the file loaded; when it cannot
be read, every suspect stays in `spray_suspects`. `daily_brief`'s summary carries
the internal suspects too, and `sites_error` when the file has an error.

### `signin_success_stats(hours=24, max_pages=None, min_distinct_users=2, tenant=None)`

Tenant-wide *successful* sign-in aggregation by source IP — the companion
to `signin_failure_stats`: that one shows who is being attacked, this one
shows whether anyone got in. `shared_ips` lists the IPs with successes for
`min_distinct_users` or more distinct accounts, most-shared first (up to 50
IPs, `shared_ips_capped` when more qualified; account names up to 25 per
IP, client apps, countries, first/last seen); `legacy_auth_users` lists the
accounts that succeeded over a legacy protocol (`Authenticated SMTP`,
`IMAP4`, `POP3`, …), which carry no MFA. A campus NAT or a VDI farm also puts
many accounts behind one IP, so exclude your own egress ranges before
reading `shared_ips` as a breach. Same log walk and `capped` semantics as
`signin_failure_stats`; like it, this scans interactive sign-ins only (every
legacy-protocol authentication is logged as interactive; non-interactive
token refreshes are not counted).

### `signin_by_ip(ip, hours=24, result="all", top=50, max_pages=None, tenant=None)`

Every sign-in from one source IP — the follow-up to a `spray_suspects` or
`shared_ips` hit. Graph filters on `ipAddress` server-side, so this is one
cheap query rather than a log walk. `users` summarises the IP per account
(successes, failures, first/last seen, up to 50); `events` lists the newest
`top` entries matching `result` ("all" / "success" / "failure"), each with
the account name and the same AADSTS annotation as `signin_logs`.
`events_truncated` means more matching rows were read than `top` returns
(`users` still counts them). `ip` must parse as an IPv4/IPv6 address.

### `directory_audits(user=None, hours=24, top=25, max_pages=None, category=None, tenant=None)`

Directory audit trail: who did what (block/unblock, attribute edits), and
when. `user`, when given, matches audits where that account is either the
initiator or a target resource — Graph only supports server-side filtering
on the initiator, so this fetches the window and matches both sides
client-side (a busy window may need a larger `max_pages` to find one
person's audits).

### `get_user_auth_methods(upn, tenant=None)`

Registered authentication methods for one account. `mfa_registered` is
`true` iff at least one non-password method is registered (Authenticator
app, phone, FIDO2 key, Windows Hello, temporary access pass, software OATH,
or platform credential/passkey). Needs `UserAuthenticationMethod.Read.All`
(app-only); not available under `az login`-based delegated auth in a
typical role assignment. A nonexistent account returns
`{"found": false, "user_principal_name": upn}`, same as `get_user`.

### `list_subscriptions(max_pages=None)`

The Azure subscriptions this credential can see (`subscription_id`, `name`,
`state`), with `count` and `capped`. The discovery anchor for the two backup
tools, which accept a subscription id or display name from this list. An
empty list with ARM reachable means no Reader role has been granted anywhere.

### `vm_backup_status(subscription=None, stale_hours=36, max_pages=None)`

Joins every VM of a subscription with the Azure-VM protected items of its
Recovery Services vaults, on the VM's ARM id (case-insensitively). Per VM:
`protected` is `true` for `protectionState` `Protected` / `IRPending` (first
backup pending, `note` says so), `false` when no item exists or protection is
stopped / paused / in error (the state is shown), and `null` (unknown) when no
item was found but the vault scan of that subscription was incomplete — a
partial scan never produces a false "unprotected". `backup_ok` is whether
`lastBackupStatus` is `Completed` / `CompletedWithWarnings`; `stale` means no
recovery point (`lastRecoveryPoint`) within `stale_hours` (default 36 h, suits
daily policies; raise it for weekly ones — `policy_name` is in the row).
`backup_ok` is `false` only for `Failed`; a backup in flight (`InProgress`,
`Warning`) leaves it `null`. An item whose `protectionState` is missing makes
the VM `unknown`; when two vaults hold an item for one VM the live one wins
(`duplicate_items`). `items_complete` assumes the subscription-scope Reader
role: a Reader scoped to resource groups gets a silently filtered vault
listing.

`subscription` is an id or display name; `None` scans every visible
subscription and joins globally, so a VM backed up to a vault in another
subscription is matched. With one subscription named, only its vaults are
scanned (`coverage` says so). An unknown name returns `{"found": false,
"subscription", "listing_capped"}`; a display name matching several
subscriptions adds `ambiguous`; a name matched on a capped listing is not
trusted either (`candidates` names the match seen — retry by id). Per subscription: `vm_count`, `protected`,
`unprotected`, `unknown`, `stale`, `failed`, `vms`, `vaults` (each with its
own `capped`), `skipped_vaults` (an id that failed validation, a vault the
budget did not reach, or one the credential cannot read, with the reason),
`vms_capped`, `items_complete`, `capped`; or `{"error", "missing_permission"}`
when that subscription is unreadable. In the global join an unmatched VM is
`unknown` unless every subscription's vault scan completed (an unreadable or
unreached subscription counts as incomplete, and `summary.failed_subscriptions`
and `capped` say so). `orphans` are protected items whose VM
no longer exists, reported only when that VM's subscription was listed
completely; `unjoined_items` counts the rest. `skipped` lists the
subscriptions the wall-clock budget did not reach; `summary` and `capped`
on top.

Every vault id is validated against the ARM naming rules before it is used in
a request path; every call shares the tool's one deadline.

### `vm_backup_policies(subscription=None, max_pages=None)`

Per Recovery Services vault, the Azure-VM backup policies: `name`, `vault`,
`resource_group`, `policy_type` (`V1` = `SimpleSchedulePolicy`, `V2` =
`SimpleSchedulePolicyV2`), `schedule` (`frequency`, `run_times` in UTC,
`weekdays`, or for V2 hourly `interval_hours` / `window_start` /
`window_hours`), `retention` (`LongTermRetentionPolicy` as `daily` / `weekly`
/ `monthly` / `yearly` blocks with their day selection and `{count, unit}`
duration, or `SimpleRetentionPolicy`), `instant_rp_days`, `timezone` and
`protected_item_count` (ARM's own count). A schedule or retention type this
server does not know comes back as `{"type": <name>, "unparsed": true}`.
Same `subscription` resolution and coverage flags as `vm_backup_status`.

### `vm_activity(vm, subscription=None, resource_group=None, start=None, end=None, hours=24, max_pages=None)`

What happened to one VM in a time window, from the activity log of its
subscription (`Microsoft.Insights/eventtypes/management/values`). Two reads,
each filtered server-side on `eventTimestamp`: one also on the VM's resource
group (`resourceGroupName eq`), so a busy subscription cannot crowd the VM's
own events out of the page budget, and one over the whole subscription.

`vm` is the VM name, matched case-insensitively over the visible
subscriptions; `subscription` (id or display name) and `resource_group`
narrow it. A name that is not unique returns `found: false` with `ambiguous`
candidates. A partial listing (`search_complete: false`, `capped: true`,
`search_errors` naming each subscription whose listing failed, with
`missing_permission` when that is the cause) never resolves a name: one match
there comes back as `candidates`, to be confirmed by naming its subscription.
Without `subscription` every visible subscription is listed, and that search
may use at most half of the call's time budget.

The window is `start`..`end` (ISO timestamps with an explicit offset; seconds
may be omitted; a bare local time is rejected rather than read as UTC), or the
`hours` before `end` (default 24, `end` defaults to now); at most 168 hours
and within the 90 days the activity log keeps. The result has `vm`, `window`
(UTC), and:

- `health` (resource-group read): Resource Health events of the VM (`stage`,
  `title`, `cause` — `PlatformInitiated` for Azure, `UserInitiated` for an
  operation or a reboot from inside the guest —, `type`, `current_health`,
  `previous_health`, `details` cut at 300 characters);
- `vm_operations` (resource-group read): Administrative events on the VM and
  its sub-resources (`operation`, `status`, `caller`, `resource`,
  `correlation_id`; one operation usually logs several events);
- `other_operations` (subscription read): Administrative events on the rest
  of the subscription (`count` of events, `operations` = distinct correlation
  ids, the newest 50 `items`, `truncated`);
- `service_health`: Azure incidents and maintenance announced to the
  subscription;
- `other_categories`: counts of the rest (Alert, Policy, other resources'
  health events, ...);
- `events_read`, `capped_reads` (`resource_group`, `subscription`) and
  `capped` (either read hit the page or time budget, or the subscription read
  failed — `subscription_read_error` then says why): an empty section is then
  not proof that nothing happened.

### `m365_service_health(max_pages=None, tenant=None)`

`services`: one row per Microsoft 365 service with its current status
(`healthOverviews`); `issues`: the unresolved incidents and advisories,
newest first (`id`, `title`, `service`, `feature`, `classification`,
`status`, `start`, `last_modified`, `impact`). `summary` carries
`degraded_services` (services whose status is an open one — `serviceDegradation`,
`serviceInterruption`, `investigating`, …; the post-resolution values Graph
keeps for days such as `serviceRestored` are not counted),
`services_without_status`, `open_incidents`, `open_advisories` and `capped`
(both collections page; a capped scan is a lower bound). Each section degrades on
its own with `{"error", "missing_permission": "ServiceHealth.Read.All"}`.
The message center (`messages`) needs another permission and is not read.

### `daily_brief(hours=24, max_pages=None, samples=10)`

One-call summary combining `m365_service_health`, `signin_failure_stats`
and `directory_audits`, with a compact `summary` on top (`service_health`
holds the degraded services, the open incident count and that section's
`capped`, which is also folded into the top-level `summary.capped`). A permission failure in one section degrades only that section —
the others still return in full. The sections run in that order,
synchronously, under one shared deadline; Azure VM backup is deliberately
not a section (its ARM fan-out could exhaust the budget — call
`vm_backup_status` separately). `samples` is currently unused (reserved).

## Errors

Every tool's entry point catches configuration and API-client errors (Graph
and ARM) and returns `{"error": "..."}` rather than raising, so a caller
always gets a dict back. A permission error additionally sets
`missing_permission` naming the actual Graph permission, directory role or
Azure RBAC role that endpoint needs. A result built from a paged Graph or
ARM collection always carries `capped: bool` —
a page-budget cutoff is never indistinguishable from "the window was fully
scanned."

## CLI

```bash
entraadm-mcp --version   # print version
entraadm-mcp --check     # resolve auth, probe Graph + sign-in log reachability (plus an ARM info line), exit 0 (or 1 on config error)
```
