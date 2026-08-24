"""entraadm-mcp MCP server — Microsoft Entra ID sign-in/audit-log triage (read-only).

Tools:

- ``health_check``          — fleet-standard status/service/version + graph/signin_probe
- ``get_user``               — one account's lifecycle state: enabled, sync, password age,
  licenses, sign-in activity
- ``signin_logs``            — one user's sign-in events, AADSTS-annotated
- ``signin_failure_stats``   — tenant-wide failure aggregation, incl. password-spray suspects
- ``directory_audits``       — who did what (block/unblock/attribute changes), and to whom
- ``get_user_auth_methods``  — MFA registration state for one user
- ``daily_brief``            — one-call summary combining signin_failure_stats + directory_audits

Coverage contract: every result section that walks a paged Graph collection
carries a ``capped`` boolean when its window was not fully scanned, so
partial coverage is never mistaken for "nothing more to find". A permission
failure degrades only the section that hit it (``{"error": ...,
"missing_permission": ...}``), never the whole tool result.
"""

from __future__ import annotations

import collections
import datetime
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from entraadm_mcp import __version__
from entraadm_mcp.client import (
    GraphClient,
    GraphError,
    GraphPermissionError,
    odata_quote,
    validate_upn,
)
from entraadm_mcp.config import (
    MAX_MAX_PAGES,
    MIN_MAX_PAGES,
    AuthConfig,
    ConfigError,
    max_pages_default,
)

mcp = FastMCP("entraadm-mcp")

#: Injection point for tests: monkeypatch.setitem(server._state, "client", FakeGraphClient(...)).
_state: dict[str, Any] = {"client": None}

_MIN_HOURS = 1
#: Entra ID P1 sign-in/audit log retention is 30 days; a longer window returns nothing, not an error.
_MAX_HOURS = 720
_MIN_TOP = 1
_MAX_TOP = 500
_SPRAY_MIN_DISTINCT_USERS = 5

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

#: AADSTS error codes worth annotating in triage output. Not exhaustive -- a
#: code missing from this dict is returned with meaning=None, never hidden.
#: Source: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
AADSTS_CODES: dict[int, str] = {
    50034: "user account does not exist in this directory",
    50053: "account locked (smart lockout, or too many failed attempts)",
    50055: "password expired",
    50057: "account disabled",
    50058: "no active session (interrupt, informational -- not a failure by itself)",
    50072: "MFA enrollment required (tenant conditional access policy)",
    50074: "strong authentication (MFA) challenge required",
    50076: "MFA challenge required (user already has MFA registered)",
    50079: "MFA enrollment required (per-user MFA)",
    50097: "device authentication/registration required (conditional access)",
    50105: "user is not assigned to the requested application",
    50126: "invalid credentials (wrong password)",
    50128: "tenant not found (invalid domain in the request)",
    50133: "session invalidated by a recent password change",
    53003: "blocked by a Conditional Access policy",
    65001: "user or admin has not consented to the application",
    700016: "application not found in this tenant's directory",
    7000218: "client assertion or client secret missing from the token request",
    80012: "on-premises policy violation (Password Hash Sync / Pass-Through Authentication)",
    90002: "tenant not found (invalid tenant identifier in the request)",
}


def _clamp_hours(hours: int) -> int:
    return max(_MIN_HOURS, min(_MAX_HOURS, hours))


def _clamp_top(top: int) -> int:
    return max(_MIN_TOP, min(_MAX_TOP, top))


def _resolve_max_pages(max_pages: int | None) -> int:
    if max_pages is None:
        return max_pages_default()
    return max(MIN_MAX_PAGES, min(MAX_MAX_PAGES, max_pages))


def _since(hours: int) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _client() -> GraphClient:
    if _state["client"] is None:
        _state["client"] = GraphClient(AuthConfig.from_env())
    return _state["client"]


def _find_user(client: GraphClient, upn: str, select: str) -> dict | None:
    """Look up one user by exact userPrincipalName via $filter (never via path interpolation).

    A UPN is untrusted MCP input; embedding it directly into a URL path
    segment (``/users/{upn}``) would let a value containing "/" reshape the
    request path. Routing it through $filter with ``odata_quote`` keeps
    escaping in one place (see client.odata_quote) and lets httpx handle
    query-string encoding normally.
    """
    body = client.get(
        "/users",
        params={"$filter": f"userPrincipalName eq {odata_quote(upn)}", "$select": select},
    )
    values = body.get("value", [])
    return values[0] if values else None


def _resolve_user_id(client: GraphClient, upn: str) -> str | None:
    """Resolve a UPN to its Graph object id, or None if no such user exists.

    A nonexistent user is a normal, valid answer to "does this account
    exist" -- not a Graph-client failure -- so it comes back as None rather
    than a raised error; callers turn that into ``{"found": False, ...}``
    instead of ``{"error": ...}``. GraphError is still raised for a genuine
    anomaly: Graph returning something that isn't GUID-shaped where an id is
    expected (defense in depth, since that id is about to be interpolated
    into a URL path).
    """
    user = _find_user(client, upn, "id")
    if user is None:
        return None
    user_id = user.get("id", "")
    if not _GUID_RE.match(user_id):
        raise GraphError("unexpected id shape returned by Graph for this user")
    return user_id


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


@mcp.tool()
def health_check() -> dict:
    """Fleet-standard health probe: service/version/status plus two independent Graph probes.

    ``graph`` confirms Microsoft Graph is reachable at all (``GET /users``
    with ``$top=1`` -- needs only ``User.Read.All``, the minimum permission
    every deployment of this server needs anyway). ``signin_probe`` additionally confirms the current
    credential can read sign-in logs -- the permission every other tool here
    except ``get_user`` depends on. Both probes always run, independently of
    each other: a tenant that has AuditLog.Read.All but not (yet) the
    baseline User.Read.All would otherwise have this report "Graph
    unreachable" -- a fabricated diagnosis, since Graph plainly *is*
    reachable if the other probe succeeds. ``status`` is derived from the
    two outcomes: ``healthy`` when both succeed, ``degraded`` when exactly
    one does (Graph is reachable but some permission is missing), ``error``
    only when neither does.

    Read-only. Always returns the same keys regardless of outcome (``detail``
    is null on success, a translated message on failure), so a caller never
    has to branch on which keys are present.
    """
    try:
        client = _client()
    except ConfigError as e:
        detail = str(e)
        return {
            "service": "entraadm-mcp",
            "version": __version__,
            "status": "error",
            "auth_mode": "unknown",
            "graph": {"auth": "error", "detail": detail},
            "signin_probe": {"auth": "error", "detail": detail},
        }

    graph = client.check()
    signin_probe = client.probe_signin_access()
    ok_count = sum(1 for probe in (graph, signin_probe) if probe["auth"] == "ok")
    status = "healthy" if ok_count == 2 else "degraded" if ok_count == 1 else "error"

    return {
        "service": "entraadm-mcp",
        "version": __version__,
        "status": status,
        "auth_mode": client.mode,
        "graph": graph,
        "signin_probe": signin_probe,
    }


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------

_USER_SELECT = ",".join(
    [
        "id",
        "displayName",
        "userPrincipalName",
        "accountEnabled",
        "userType",
        "createdDateTime",
        "lastPasswordChangeDateTime",
        "onPremisesSyncEnabled",
        "onPremisesLastSyncDateTime",
        "assignedLicenses",
    ]
)

#: skuId -> skuPartNumber, populated lazily from /subscribedSkus and kept for
#: the process lifetime (the tenant's SKU catalog changes rarely, if ever,
#: while this server runs).
_license_cache: dict[str, str] = {}


def _resolve_license_names(client: GraphClient, sku_ids: list[str]) -> tuple[list[str], bool]:
    """Resolve skuIds to skuPartNumbers, reporting whether any requested id is still unresolved due to a capped scan.

    ``ENTRAADM_MAX_PAGES_DEFAULT`` is honored here like every other paged
    call (consistency), but a low value set to bound log-scanning cost has
    nothing to do with the size of the tenant's SKU catalog -- a capped
    ``/subscribedSkus`` fetch must not silently show a raw GUID in place of
    a license name with no indication anything was cut short. The returned
    bool is True only when the fetch was actually capped *and* at least one
    of the caller's own ``sku_ids`` is still unresolved after it -- a capped
    scan that happened to cover everything the caller needed is not
    misleading and shouldn't be flagged.
    """
    unresolved = [s for s in sku_ids if s not in _license_cache]
    fetch_capped = False
    if unresolved:
        try:
            skus, fetch_capped = client.get_paged("/subscribedSkus", max_pages=_resolve_max_pages(None))
        except GraphError:
            # Best effort: license names are a convenience, not the point of
            # get_user. Unresolved ids fall back to the raw id below.
            skus = []
        for sku in skus:
            sku_id = sku.get("skuId")
            if sku_id:
                _license_cache[sku_id] = sku.get("skuPartNumber", sku_id)
    still_unresolved = any(s not in _license_cache for s in sku_ids)
    return [_license_cache.get(s, s) for s in sku_ids], fetch_capped and still_unresolved


def _user_entry(u: dict, license_names: list[str], licenses_capped: bool) -> dict:
    entry = {
        "found": True,
        "id": u.get("id"),
        "display_name": u.get("displayName"),
        "user_principal_name": u.get("userPrincipalName"),
        "account_enabled": u.get("accountEnabled"),
        "user_type": u.get("userType"),
        "created_date_time": u.get("createdDateTime"),
        "last_password_change_date_time": u.get("lastPasswordChangeDateTime"),
        "on_premises_sync_enabled": u.get("onPremisesSyncEnabled"),
        "on_premises_last_sync_date_time": u.get("onPremisesLastSyncDateTime"),
        "licenses": license_names,
    }
    if licenses_capped:
        # Present only when true: a raw skuId slipped into `licenses` above
        # because the tenant's SKU catalog scan was capped before this
        # user's license(s) could be resolved to a friendly name.
        entry["licenses_capped"] = True
    return entry


@mcp.tool()
def get_user(upn: str) -> dict:
    """One account's identity/lifecycle state -- the first thing to check on any triage report.

    ``account_enabled=false`` means the account itself is the whole story;
    stop there. A stale ``last_password_change_date_time`` alongside a fresh
    "wrong password" complaint (AADSTS50126 in ``signin_logs``) is the most
    common on-the-ground pattern: the password changed or expired somewhere,
    and a cached credential on one device is now stale.
    ``on_premises_sync_enabled=true`` means this account is synced from an
    on-premises directory (Entra Connect) -- Entra is a downstream copy of
    its password via Password Hash Sync, not the source of truth.
    ``licenses`` names are resolved from the tenant's SKU catalog
    (``/subscribedSkus``, page budget from ``ENTRAADM_MAX_PAGES_DEFAULT``);
    ``licenses_capped: true`` appears only when that scan was cut short
    before resolving one of this account's own licenses -- when present,
    one or more ``licenses`` entries is a raw skuId rather than a friendly
    name.

    ``sign_in_activity`` needs an additional Graph read (AuditLog.Read.All
    application permission, or -- for azure-cli auth -- the Reports Reader
    directory role) beyond what the rest of this tool needs. If that
    permission is missing, every other field above still returns and
    ``sign_in_activity`` alone degrades to ``{"error": ...,
    "missing_permission": "AuditLog.Read.All"}``.

    A nonexistent account is a normal answer, not a tool failure: the result
    is ``{"found": false, "user_principal_name": upn}`` rather than an
    ``error`` key, so a typo'd UPN in a triage report cannot be mistaken for
    this tool being broken.

    Read-only (User.Read.All application permission, or an equivalent
    delegated read). Requires an exact userPrincipalName, not a display name
    or partial match.

    Args:
        upn: The account's userPrincipalName, e.g. "user@example.edu".
    """
    try:
        validate_upn(upn)
        client = _client()
        user = _find_user(client, upn, _USER_SELECT)
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    if user is None:
        return {"found": False, "user_principal_name": upn}

    sku_ids = [lic.get("skuId") for lic in user.get("assignedLicenses") or [] if lic.get("skuId")]
    license_names, licenses_capped = _resolve_license_names(client, sku_ids)
    entry = _user_entry(user, license_names, licenses_capped)

    try:
        activity = _find_user(client, upn, "signInActivity")
        entry["sign_in_activity"] = (activity or {}).get("signInActivity")
    except GraphPermissionError as e:
        entry["sign_in_activity"] = {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except GraphError as e:
        entry["sign_in_activity"] = {"error": str(e)}

    return entry


# ---------------------------------------------------------------------------
# signin_logs
# ---------------------------------------------------------------------------

_SIGNIN_SELECT = ",".join(
    [
        "createdDateTime",
        "appDisplayName",
        "clientAppUsed",
        "ipAddress",
        "location",
        "status",
        "conditionalAccessStatus",
        "deviceDetail",
        "isInteractive",
    ]
)


def _error_code_of(row: dict) -> Any:
    return (row.get("status") or {}).get("errorCode")


def _row_matches(row: dict, result: str) -> bool:
    if result == "all":
        return True
    is_failure = _error_code_of(row) not in (0, None)
    return is_failure if result == "failure" else not is_failure


def _signin_entry(s: dict) -> dict:
    status = s.get("status") or {}
    device = s.get("deviceDetail") or {}
    location = s.get("location") or {}
    error_code = status.get("errorCode")
    return {
        "created_date_time": s.get("createdDateTime"),
        "app_display_name": s.get("appDisplayName"),
        "client_app_used": s.get("clientAppUsed"),
        "ip_address": s.get("ipAddress"),
        "city": location.get("city"),
        "country_or_region": location.get("countryOrRegion"),
        "error_code": error_code,
        "error_code_meaning": AADSTS_CODES.get(error_code) if isinstance(error_code, int) else None,
        "failure_reason": status.get("failureReason"),
        "conditional_access_status": s.get("conditionalAccessStatus"),
        "device_os": device.get("operatingSystem"),
        "device_browser": device.get("browser"),
        "is_interactive": s.get("isInteractive"),
    }


@mcp.tool()
def signin_logs(
    user: str,
    hours: int = 24,
    result: str = "failure",
    top: int = 25,
    max_pages: int | None = None,
) -> dict:
    """One user's recent sign-in events, AADSTS-annotated.

    The most direct answer to "why can't this person log in": each entry's
    ``error_code_meaning`` translates the raw AADSTS code (e.g. 50126 ->
    "invalid credentials (wrong password)") so triage rarely needs a second
    lookup. ``result`` filters client-side after the Graph fetch (Graph
    cannot filter sign-ins on status/errorCode server-side): "failure" (the
    default) keeps only failed attempts, "success" keeps only clean ones,
    "all" keeps everything.

    Because the filter is client-side, this walks pages until it has
    collected ``top`` matching entries or exhausts ``max_pages`` -- a mostly-
    successful user can otherwise mean paging through hundreds of rows to
    find a handful of failures. ``capped=true`` means the page budget ran out
    (or ``top`` was reached) before the whole window was scanned; a low match
    count alongside ``capped=true`` is evidence of "no more found within the
    budget", not "no more exist".

    Read-only (AuditLog.Read.All application permission, or -- for azure-cli
    auth -- the Reports Reader directory role). Entra ID P1 retains sign-in
    logs for 30 days; ``hours`` beyond that returns an empty result, not an
    error.

    Args:
        user: The account's userPrincipalName.
        hours: How far back to look, clamped to [1, 720] (30 days).
        result: "failure" (default), "success", or "all".
        top: Maximum matching entries to return, clamped to [1, 500].
        max_pages: Page budget for the client-side filter walk (default: ENTRAADM_MAX_PAGES_DEFAULT).
    """
    try:
        validate_upn(user)
    except GraphError as e:
        return {"error": str(e)}
    if result not in ("failure", "success", "all"):
        return {"error": f"result must be 'failure', 'success', or 'all' (got {result!r})"}

    hours = _clamp_hours(hours)
    top = _clamp_top(top)
    pages_budget = _resolve_max_pages(max_pages)
    filter_expr = f"userPrincipalName eq {odata_quote(user)} and createdDateTime ge {_since(hours)}"

    try:
        client = _client()
    except ConfigError as e:
        return {"error": str(e)}

    matched: list[dict] = []
    url: str | None = "/auditLogs/signIns"
    query: dict | None = {
        "$filter": filter_expr,
        "$select": _SIGNIN_SELECT,
        "$orderby": "createdDateTime desc",
    }
    pages = 0
    # Set when `top` is reached mid-page AND at least one further row in
    # that same already-fetched page also matches the filter -- a page can
    # hold more matching rows than `top` even when Graph never offers a
    # next page, so `url is not None` alone misses that case. Checking
    # `rows[i:]` costs nothing extra (already in memory) and avoids the
    # opposite mistake: marking capped=true just because trailing rows were
    # left unread, when none of them would have matched anyway.
    truncated_within_page = False
    try:
        while url is not None and pages < pages_budget and len(matched) < top:
            body = client.get(url, params=query)
            rows = body.get("value", [])
            for i, row in enumerate(rows):
                if len(matched) >= top:
                    if any(_row_matches(r, result) for r in rows[i:]):
                        truncated_within_page = True
                    break
                if _row_matches(row, result):
                    matched.append(_signin_entry(row))
            url = body.get("@odata.nextLink")
            query = None  # nextLink already carries the full query string
            pages += 1
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except GraphError as e:
        return {"error": str(e)}

    return {
        "window_hours": hours,
        "result_filter": result,
        "count": len(matched),
        "capped": url is not None or truncated_within_page,
        "events": matched,
    }


# ---------------------------------------------------------------------------
# signin_failure_stats
# ---------------------------------------------------------------------------

_STATS_SELECT = ",".join(["createdDateTime", "userPrincipalName", "appDisplayName", "ipAddress", "status"])


@mcp.tool()
def signin_failure_stats(hours: int = 24, max_pages: int | None = None) -> dict:
    """Tenant-wide sign-in failure aggregation -- the Entra ID counterpart to the RADIUS failure patrol.

    Aggregates failed sign-ins across the whole tenant into four views: top
    AADSTS error codes (with the same meaning annotations as
    ``signin_logs``), top failing users, top applications, and top source
    IPs. ``spray_suspects`` flags any IP with failed sign-ins against 5 or
    more distinct users -- Entra's smart lockout is per-account, so a
    low-and-slow password spray from one IP across many accounts does not
    trip it the way a brute force against one account does; this is the
    observation a per-account view cannot make on its own. This mirrors the
    KeyCloak-side spray detection this fleet already relies on; neither the
    official Microsoft MCP Server for Enterprise nor Graph itself offers this
    aggregation.

    Read-only (AuditLog.Read.All application permission, or -- for azure-cli
    auth -- the Reports Reader directory role). Graph cannot filter sign-ins
    on status/errorCode server-side, so this walks up to ``max_pages`` of the
    full sign-in log for the window and aggregates client-side --
    ``capped=true`` means the page budget ran out before the window was
    fully scanned, so the counts below are a sample of the window, not a
    census of it.

    Args:
        hours: How far back to look, clamped to [1, 720] (30 days).
        max_pages: Page budget (default: ENTRAADM_MAX_PAGES_DEFAULT).
    """
    hours = _clamp_hours(hours)
    pages_budget = _resolve_max_pages(max_pages)
    filter_expr = f"createdDateTime ge {_since(hours)}"

    try:
        client = _client()
        rows, capped = client.get_paged(
            "/auditLogs/signIns",
            params={"$filter": filter_expr, "$select": _STATS_SELECT},
            max_pages=pages_budget,
        )
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    error_counts: collections.Counter = collections.Counter()
    user_counts: collections.Counter = collections.Counter()
    app_counts: collections.Counter = collections.Counter()
    ip_counts: collections.Counter = collections.Counter()
    ip_users: dict[str, set] = collections.defaultdict(set)

    for row in rows:
        error_code = _error_code_of(row)
        if error_code in (0, None):
            continue
        error_counts[error_code] += 1
        upn = row.get("userPrincipalName")
        if upn:
            user_counts[upn] += 1
        app = row.get("appDisplayName")
        if app:
            app_counts[app] += 1
        ip = row.get("ipAddress")
        if ip:
            ip_counts[ip] += 1
            if upn:
                ip_users[ip].add(upn)

    top_error_codes = [
        {"error_code": code, "meaning": AADSTS_CODES.get(code) if isinstance(code, int) else None, "count": count}
        for code, count in error_counts.most_common(10)
    ]
    top_failing_users = [{"user_principal_name": u, "count": c} for u, c in user_counts.most_common(10)]
    top_apps = [{"app_display_name": a, "count": c} for a, c in app_counts.most_common(5)]
    top_ips = [
        {"ip_address": ip, "count": c, "distinct_users": len(ip_users.get(ip, ()))}
        for ip, c in ip_counts.most_common(10)
    ]
    spray_suspects = sorted(
        (
            {"ip_address": ip, "distinct_users": len(users), "attempts": ip_counts[ip]}
            for ip, users in ip_users.items()
            if len(users) >= _SPRAY_MIN_DISTINCT_USERS
        ),
        key=lambda s: s["distinct_users"],
        reverse=True,
    )

    return {
        "window_hours": hours,
        "capped": capped,
        "total_failures": sum(error_counts.values()),
        # len(user_counts), not len(top_failing_users): the latter is
        # truncated to most_common(10), which would silently cap this count
        # at 10 regardless of how many distinct users actually failed --
        # understating incident/spray blast radius in the one field a
        # morning triage skim reads first.
        "distinct_failing_users": len(user_counts),
        "top_error_codes": top_error_codes,
        "top_failing_users": top_failing_users,
        "top_apps": top_apps,
        "top_ips": top_ips,
        "spray_suspects": spray_suspects,
    }


# ---------------------------------------------------------------------------
# directory_audits
# ---------------------------------------------------------------------------

_AUDIT_SELECT = ",".join(
    ["activityDateTime", "activityDisplayName", "category", "result", "initiatedBy", "targetResources"]
)


def _actor_entry(initiated_by: dict | None) -> dict:
    initiated_by = initiated_by or {}
    user = initiated_by.get("user") or {}
    app = initiated_by.get("app") or {}
    if user.get("userPrincipalName"):
        return {
            "type": "user",
            "user_principal_name": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
        }
    if app.get("displayName"):
        return {"type": "app", "display_name": app.get("displayName")}
    return {"type": "unknown"}


def _target_entries(targets: list[dict] | None) -> list[dict]:
    return [
        {"type": t.get("type"), "user_principal_name": t.get("userPrincipalName"), "display_name": t.get("displayName")}
        for t in targets or []
    ]


def _audit_entry(a: dict) -> dict:
    return {
        "activity_date_time": a.get("activityDateTime"),
        "activity_display_name": a.get("activityDisplayName"),
        "category": a.get("category"),
        "result": a.get("result"),
        "initiated_by": _actor_entry(a.get("initiatedBy")),
        "target_resources": _target_entries(a.get("targetResources")),
    }


def _matches_user(a: dict, user: str) -> bool:
    user = user.lower()
    initiator = (a.get("initiatedBy") or {}).get("user") or {}
    if (initiator.get("userPrincipalName") or "").lower() == user:
        return True
    return any((t.get("userPrincipalName") or "").lower() == user for t in a.get("targetResources") or [])


@mcp.tool()
def directory_audits(user: str | None = None, hours: int = 24, top: int = 25, max_pages: int | None = None) -> dict:
    """Who did what to the directory, and when -- the operator-side counterpart to signin_logs.

    Every admin action against a user object (block/unblock, password reset,
    role assignment, attribute edits) appears here, naming the actor
    (``initiated_by``) and the affected object(s) (``target_resources``).
    This is the record a manual "unblock and reset" intervention -- like the
    one that closed the 2026-08-21 case this server exists to shorten --
    leaves behind; it is how a later triage can tell "already handled by a
    human" from "still open".

    ``user``, when given, matches audits where that account is either the
    initiator or a target resource. Graph's directoryAudits endpoint only
    supports server-side ``$filter`` on the *initiator*
    (``initiatedBy/user/userPrincipalName``), not on ``targetResources``, so
    this fetches the full time window and matches both sides client-side --
    a window with many unrelated admin actions can need a larger
    ``max_pages`` budget than ``signin_logs``/``signin_failure_stats`` to
    find one specific user's audits; ``capped=true`` warns when that budget
    ran out before the window was fully scanned.

    Read-only (AuditLog.Read.All application permission, or -- for azure-cli
    auth -- the Reports Reader directory role). Entra ID retains directory
    audit logs for 30 days, same as sign-in logs.

    Args:
        user: Restrict to audits naming this userPrincipalName as actor or target (default: all).
        hours: How far back to look, clamped to [1, 720] (30 days).
        top: Maximum records to return, clamped to [1, 500].
        max_pages: Page budget (default: ENTRAADM_MAX_PAGES_DEFAULT).
    """
    if user is not None:
        try:
            validate_upn(user)
        except GraphError as e:
            return {"error": str(e)}

    hours = _clamp_hours(hours)
    top = _clamp_top(top)
    pages_budget = _resolve_max_pages(max_pages)
    filter_expr = f"activityDateTime ge {_since(hours)}"

    try:
        client = _client()
        rows, capped = client.get_paged(
            "/auditLogs/directoryAudits",
            params={"$filter": filter_expr, "$select": _AUDIT_SELECT},
            max_pages=pages_budget,
        )
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    if user is not None:
        rows = [a for a in rows if _matches_user(a, user)]

    truncated = len(rows) > top
    entries = [_audit_entry(a) for a in rows[:top]]
    return {"window_hours": hours, "capped": capped or truncated, "count": len(entries), "events": entries}


# ---------------------------------------------------------------------------
# get_user_auth_methods
# ---------------------------------------------------------------------------

_METHOD_TYPE_NAMES = {
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "microsoftAuthenticator",
    "#microsoft.graph.phoneAuthenticationMethod": "phone",
    "#microsoft.graph.fido2AuthenticationMethod": "fido2",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHello",
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod": "temporaryAccessPass",
    "#microsoft.graph.emailAuthenticationMethod": "email",
    "#microsoft.graph.passwordAuthenticationMethod": "password",
    "#microsoft.graph.softwareOathAuthenticationMethod": "softwareOath",
    "#microsoft.graph.platformCredentialAuthenticationMethod": "platformCredential",
}


def _method_entry(m: dict) -> dict:
    odata_type = m.get("@odata.type", "")
    return {"type": _METHOD_TYPE_NAMES.get(odata_type, odata_type), "id": m.get("id")}


@mcp.tool()
def get_user_auth_methods(upn: str) -> dict:
    """Registered authentication methods for one account -- is MFA actually set up?

    ``mfa_registered`` answers "would this account survive a password-spray
    hit": True iff at least one non-password method is registered
    (Authenticator app, phone, FIDO2 security key, Windows Hello, a
    temporary access pass, software OATH token, or a platform
    credential/passkey). ``password`` itself is excluded from that count --
    every account has one, so its presence alone says nothing about MFA
    coverage.

    A nonexistent account is a normal answer, not a tool failure: the result
    is ``{"found": false, "user_principal_name": upn}`` rather than an
    ``error`` key, matching ``get_user``'s contract.

    Read-only (UserAuthenticationMethod.Read.All application permission).
    This endpoint is app-only only: it is not exposed to delegated
    (azure-cli) auth under this tenant's current role assignment, so it
    degrades to a permission error under azure-cli auth even when other
    tools work.

    Args:
        upn: The account's userPrincipalName.
    """
    try:
        validate_upn(upn)
        client = _client()
        user_id = _resolve_user_id(client, upn)
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    if user_id is None:
        return {"found": False, "user_principal_name": upn}

    try:
        methods, capped = client.get_paged(
            f"/users/{user_id}/authentication/methods", max_pages=_resolve_max_pages(None)
        )
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "UserAuthenticationMethod.Read.All"}
    except GraphError as e:
        return {"error": str(e)}

    entries = [_method_entry(m) for m in methods]
    mfa_registered = any(e["type"] != "password" for e in entries)
    return {"found": True, "methods": entries, "mfa_registered": mfa_registered, "capped": capped}


# ---------------------------------------------------------------------------
# daily_brief
# ---------------------------------------------------------------------------


@mcp.tool()
def daily_brief(hours: int = 24, max_pages: int | None = None, samples: int = 10) -> dict:
    """One-call morning-patrol summary: sign-in failures, spray suspects, and admin actions.

    Combines ``signin_failure_stats`` and ``directory_audits`` into one
    result with a compact ``summary`` on top, matching the shape of this
    fleet's other ``daily_brief`` tools. A permission failure in one section
    degrades only that section's contribution to ``summary`` -- the other
    section still returns in full.

    Runs both sections synchronously in one tool call, unlike the sibling
    gwsadm-mcp's job+poll ``daily_brief``. If this proves too slow for a
    tenant's sign-in volume against the client's tool-call timeout, port
    that job+poll pattern here (tracked in this repo's CLAUDE.md Roadmap).

    Args:
        hours: How far back to look, clamped to [1, 720] (30 days).
        max_pages: Page budget passed to both sections (default: ENTRAADM_MAX_PAGES_DEFAULT).
        samples: Reserved for a future drill-down sample size; currently unused.
    """
    del samples  # accepted for shape-parity with the fleet's daily_brief tools; not yet used
    hours = _clamp_hours(hours)

    stats = signin_failure_stats(hours=hours, max_pages=max_pages)
    audits = directory_audits(hours=hours, max_pages=max_pages)

    if "error" in stats:
        summary: dict = {"sign_in_failures": stats}
    else:
        summary = {
            "sign_in_failures": stats["total_failures"],
            "distinct_failing_users": stats["distinct_failing_users"],
            "top_error_codes": stats["top_error_codes"][:5],
            "spray_suspects": stats["spray_suspects"],
            "capped": stats["capped"],
        }

    if "error" in audits:
        summary["admin_actions"] = audits
    else:
        summary["admin_actions"] = audits["count"]
        summary["capped"] = summary.get("capped", False) or audits["capped"]

    return {
        "window_hours": hours,
        "summary": summary,
        "signin_failure_stats": stats,
        "directory_audits": audits,
    }
