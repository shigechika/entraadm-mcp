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
import contextvars
import datetime
import functools
import inspect
import ipaddress
import re
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError

from entraadm_mcp import __version__
from entraadm_mcp.client import (
    GraphClient,
    GraphDeadline,
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
    deadline_seconds,
    max_pages_default,
)


def _expose_errors(fn):
    """Wrap a tool so any exception reaches the model as a ToolError with its message.

    mcp 1.x returned the exception text for every failing tool. mcp 2.x hides it
    (the model sees only "Error executing tool <name>") unless a ToolError is raised.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    else:

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    return wrapper


class _Server(MCPServer):
    """MCPServer whose tools report their exception messages (see _expose_errors)."""

    def tool(self, *args, **kwargs):
        register = super().tool(*args, **kwargs)

        def decorator(fn):
            register(_expose_errors(fn))
            return fn

        return decorator


mcp = _Server("entraadm-mcp", version=__version__)

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


# One wall-clock budget per tool call. daily_brief sets it once so its two
# sections share it instead of each taking the full budget.
_CALL_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar("entraadm_deadline", default=None)


def _new_deadline() -> float | None:
    secs = deadline_seconds()
    return None if secs is None else time.monotonic() + secs


def _current_deadline() -> float | None:
    """The budget set by an enclosing daily_brief, else a fresh one for this call."""
    inherited = _CALL_DEADLINE.get()
    return inherited if inherited is not None else _new_deadline()


def _with_call_deadline(fn):
    """Give a tool one wall-clock budget shared by all the Graph calls it makes."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = _CALL_DEADLINE.set(_current_deadline())
        try:
            return fn(*args, **kwargs)
        finally:
            _CALL_DEADLINE.reset(token)

    return wrapper


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
        deadline=_current_deadline(),
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
            skus, fetch_capped = client.get_paged(
                "/subscribedSkus", max_pages=_resolve_max_pages(None), deadline=_current_deadline()
            )
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
@_with_call_deadline
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
    deadline = _current_deadline()
    try:
        while url is not None and pages < pages_budget and len(matched) < top:
            try:
                body = client.get(url, params=query, deadline=deadline)
            except GraphDeadline:
                break
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
# signin_by_ip
# ---------------------------------------------------------------------------

_BY_IP_USERS_LIMIT = 50


@mcp.tool()
def signin_by_ip(ip: str, hours: int = 24, result: str = "all", top: int = 50, max_pages: int | None = None) -> dict:
    """Every sign-in from one source IP: who got in from it, who was tried, and when.

    The follow-up to a ``spray_suspects`` or ``shared_ips`` hit: Graph can
    filter sign-ins on ``ipAddress`` server-side, so this is one cheap
    query, not a log walk. ``users`` summarises the IP per account
    (successes, failures, first/last seen, up to 50 accounts) over every row
    fetched; ``events`` lists the newest ``top`` entries that match
    ``result`` ("all" by default, or "success" / "failure"), each carrying
    the account name and the same AADSTS annotation as ``signin_logs``.
    ``capped=true`` means the page budget or the deadline ran out before the
    window was fully read; ``events_truncated=true`` means more matching
    rows were read than ``top`` returns (the ``users`` summary still counts
    them).

    Read-only (AuditLog.Read.All application permission, or -- for azure-cli
    auth -- the Reports Reader directory role).

    Args:
        ip: The source IPv4 or IPv6 address, exactly as the sign-in log shows it.
        hours: How far back to look, clamped to [1, 720] (30 days).
        result: "all" (default), "success", or "failure" -- which events to list.
        top: Maximum events to return, clamped to [1, 500].
        max_pages: Page budget (default: ENTRAADM_MAX_PAGES_DEFAULT).
    """
    # validate only: keep the caller's spelling, because Graph compares the
    # ipAddress string literally and an expanded IPv6 form from the log would
    # not match its compressed form
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"ip must be an IPv4 or IPv6 address (got {ip!r})"}
    if result not in ("failure", "success", "all"):
        return {"error": f"result must be 'failure', 'success', or 'all' (got {result!r})"}

    hours = _clamp_hours(hours)
    top = _clamp_top(top)
    pages_budget = _resolve_max_pages(max_pages)
    filter_expr = f"ipAddress eq {odata_quote(ip)} and createdDateTime ge {_since(hours)}"

    try:
        client = _client()
        rows, capped = client.get_paged(
            "/auditLogs/signIns",
            params={
                "$filter": filter_expr,
                "$select": _SIGNIN_SELECT + ",userPrincipalName",
                "$orderby": "createdDateTime desc",
            },
            max_pages=pages_budget,
            deadline=_current_deadline(),
        )
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    per_user: dict[str, dict] = {}
    client_counts: collections.Counter = collections.Counter()
    countries: set = set()
    matched: list[dict] = []
    matched_total = 0
    successes = failures = 0
    for row in rows:
        upn = row.get("userPrincipalName") or ""
        when = row.get("createdDateTime") or ""
        ok = _row_matches(row, "success")
        if ok:
            successes += 1
        else:
            failures += 1
        if upn:
            u = per_user.setdefault(
                upn, {"user_principal_name": upn, "successes": 0, "failures": 0, "first_seen": when, "last_seen": when}
            )
            u["successes" if ok else "failures"] += 1
            if when:
                u["first_seen"] = min(u["first_seen"] or when, when)
                u["last_seen"] = max(u["last_seen"] or when, when)
        if ok and row.get("clientAppUsed"):
            client_counts[row["clientAppUsed"]] += 1
        country = (row.get("location") or {}).get("countryOrRegion")
        if country:
            countries.add(country)
        if _row_matches(row, result):
            matched_total += 1
            if len(matched) < top:
                entry = _signin_entry(row)
                entry["user_principal_name"] = upn or None
                matched.append(entry)

    users = sorted(per_user.values(), key=lambda u: (-u["successes"], -u["failures"], u["user_principal_name"]))
    return {
        "ip_address": ip,
        "window_hours": hours,
        "result_filter": result,
        "capped": capped,
        "total_rows": len(rows),
        "successes": successes,
        "failures": failures,
        "distinct_users": len(users),
        "countries": sorted(countries),
        "success_client_apps": [{"client_app": c, "count": n} for c, n in client_counts.most_common(5)],
        "users": users[:_BY_IP_USERS_LIMIT],
        "users_capped": len(users) > _BY_IP_USERS_LIMIT,
        "count": len(matched),
        "events_truncated": matched_total > len(matched),
        "events": matched,
    }


# ---------------------------------------------------------------------------
# signin_failure_stats
# ---------------------------------------------------------------------------

_STATS_SELECT = ",".join(["createdDateTime", "userPrincipalName", "appDisplayName", "ipAddress", "status"])


@mcp.tool()
def signin_failure_stats(hours: int = 24, max_pages: int | None = None) -> dict:
    """Tenant-wide sign-in failure aggregation -- the Entra ID counterpart to the RADIUS failure patrol.

    Time-bounded (ENTRAADM_DEADLINE, default 45 s): on a wide window or a busy day the scan
    stops early and ``capped=true`` marks the counts as a lower bound; narrow ``hours`` for a
    full count.

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
            deadline=_current_deadline(),
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
# signin_success_stats
# ---------------------------------------------------------------------------

_SUCCESS_SELECT = ",".join(
    ["createdDateTime", "userPrincipalName", "appDisplayName", "clientAppUsed", "ipAddress", "location", "status"]
)
# Entra's "legacy authentication" client apps: no MFA, no Conditional Access
# device signals, and the protocols credential-stuffing tools drive.
_LEGACY_AUTH_CLIENTS = frozenset(
    {
        "Authenticated SMTP",
        "Autodiscover",
        "Exchange ActiveSync",
        "Exchange Online PowerShell",
        "Exchange Web Services",
        "IMAP4",
        "MAPI Over HTTP",
        "Offline Address Book",
        "Other clients",
        "Outlook Anywhere (RPC over HTTP)",
        "Outlook Service",
        "POP3",
        "Reporting Web Services",
    }
)
_SHARED_IP_MIN_DISTINCT_USERS = 2
_SHARED_IP_USERS_LIMIT = 25
_LEGACY_USERS_LIMIT = 50
_SHARED_IPS_LIMIT = 50


@mcp.tool()
def signin_success_stats(hours: int = 24, max_pages: int | None = None, min_distinct_users: int = 2) -> dict:
    """Tenant-wide *successful* sign-in aggregation by source IP -- the view that finds a breach.

    ``signin_failure_stats`` shows who is being attacked; this shows whether
    anyone got in. The breach signature is one source IP signing in
    successfully as several different accounts, most often over a legacy
    protocol (``clientAppUsed`` such as "Authenticated SMTP" or "IMAP4",
    which carry no MFA). ``shared_ips`` lists the IPs with successes for
    ``min_distinct_users`` or more distinct accounts, most-shared first (up
    to 50 IPs, ``shared_ips_capped`` when more qualified; account names up
    to 25 per IP), with the client apps and the countries seen.
    ``legacy_auth_users`` lists the accounts that succeeded over a legacy
    protocol at all, with how many IPs and countries they came from.

    A campus NAT, a VDI farm or a shared proxy also puts many accounts
    behind one IP, so a shared IP is a lead, not a verdict: the caller
    excludes its own egress ranges and reads the client apps and countries
    before calling anything a breach. Graph cannot filter sign-ins on
    ``status/errorCode`` server-side, so like ``signin_failure_stats`` this
    walks the sign-in log for the window and aggregates client-side. The
    walk covers interactive sign-ins only (Graph's default listing): every
    legacy-protocol authentication is logged as interactive, so none is
    missed, but non-interactive token refreshes are not counted;
    ``capped=true`` means the page budget or the deadline (ENTRAADM_DEADLINE,
    default 45 s) ran out first and the counts are a lower bound -- narrow
    ``hours`` for a full count.

    Read-only (AuditLog.Read.All application permission, or -- for azure-cli
    auth -- the Reports Reader directory role).

    Args:
        hours: How far back to look, clamped to [1, 720] (30 days).
        max_pages: Page budget (default: ENTRAADM_MAX_PAGES_DEFAULT).
        min_distinct_users: Distinct accounts an IP needs to appear in
            ``shared_ips`` (default 2, clamped to >= 2).
    """
    hours = _clamp_hours(hours)
    pages_budget = _resolve_max_pages(max_pages)
    min_distinct_users = max(_SHARED_IP_MIN_DISTINCT_USERS, int(min_distinct_users))
    filter_expr = f"createdDateTime ge {_since(hours)}"

    try:
        client = _client()
        rows, capped = client.get_paged(
            "/auditLogs/signIns",
            params={"$filter": filter_expr, "$select": _SUCCESS_SELECT},
            max_pages=pages_budget,
            deadline=_current_deadline(),
        )
    except GraphPermissionError as e:
        return {"error": str(e), "missing_permission": "AuditLog.Read.All"}
    except (ConfigError, GraphError) as e:
        return {"error": str(e)}

    total = 0
    users: set = set()
    client_counts: collections.Counter = collections.Counter()
    ip_counts: collections.Counter = collections.Counter()
    ip_users: dict[str, set] = collections.defaultdict(set)
    ip_clients: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    ip_countries: dict[str, set] = collections.defaultdict(set)
    ip_first: dict[str, str] = {}
    ip_last: dict[str, str] = {}
    legacy_counts: collections.Counter = collections.Counter()
    legacy_ips: dict[str, set] = collections.defaultdict(set)
    legacy_countries: dict[str, set] = collections.defaultdict(set)
    legacy_last: dict[str, str] = {}

    for row in rows:
        if _error_code_of(row) != 0:
            continue
        total += 1
        upn = row.get("userPrincipalName") or ""
        if upn:
            users.add(upn)
        client_app = row.get("clientAppUsed") or ""
        if client_app:
            client_counts[client_app] += 1
        country = (row.get("location") or {}).get("countryOrRegion") or ""
        when = row.get("createdDateTime") or ""
        ip = row.get("ipAddress")
        if ip:
            ip_counts[ip] += 1
            if upn:
                ip_users[ip].add(upn)
            if client_app:
                ip_clients[ip][client_app] += 1
            if country:
                ip_countries[ip].add(country)
            if when:
                # rows arrive newest first, but do not rely on it
                if ip not in ip_first or when < ip_first[ip]:
                    ip_first[ip] = when
                if ip not in ip_last or when > ip_last[ip]:
                    ip_last[ip] = when
        if upn and client_app in _LEGACY_AUTH_CLIENTS:
            legacy_counts[upn] += 1
            if ip:
                legacy_ips[upn].add(ip)
            if country:
                legacy_countries[upn].add(country)
            if when and when > legacy_last.get(upn, ""):
                legacy_last[upn] = when

    shared_ips = []
    for ip, ip_user_set in sorted(ip_users.items(), key=lambda kv: (-len(kv[1]), -ip_counts[kv[0]], kv[0])):
        if len(ip_user_set) < min_distinct_users:
            continue
        names = sorted(ip_user_set)
        shared_ips.append(
            {
                "ip_address": ip,
                "successes": ip_counts[ip],
                "distinct_users": len(names),
                "users": names[:_SHARED_IP_USERS_LIMIT],
                "users_capped": len(names) > _SHARED_IP_USERS_LIMIT,
                "client_apps": [{"client_app": c, "count": n} for c, n in ip_clients[ip].most_common(3)],
                "legacy_auth": any(c in _LEGACY_AUTH_CLIENTS for c in ip_clients[ip]),
                "countries": sorted(ip_countries[ip]),
                "first_seen": ip_first.get(ip),
                "last_seen": ip_last.get(ip),
            }
        )

    legacy_sorted = sorted(legacy_counts.items(), key=lambda kv: (-len(legacy_ips[kv[0]]), -kv[1], kv[0]))
    legacy_auth_users = [
        {
            "user_principal_name": upn,
            "successes": n,
            "distinct_ips": len(legacy_ips[upn]),
            "countries": sorted(legacy_countries[upn]),
            "last_seen": legacy_last.get(upn),
        }
        for upn, n in legacy_sorted[:_LEGACY_USERS_LIMIT]
    ]

    return {
        "window_hours": hours,
        "capped": capped,
        "total_successes": total,
        "distinct_users": len(users),
        "top_client_apps": [{"client_app": c, "count": n} for c, n in client_counts.most_common(10)],
        "legacy_auth_successes": sum(legacy_counts.values()),
        "legacy_auth_users": legacy_auth_users,
        "legacy_auth_users_capped": len(legacy_sorted) > _LEGACY_USERS_LIMIT,
        "shared_ips_total": len(shared_ips),
        "shared_ips": shared_ips[:_SHARED_IPS_LIMIT],
        "shared_ips_capped": len(shared_ips) > _SHARED_IPS_LIMIT,
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
def directory_audits(
    user: str | None = None,
    hours: int = 24,
    top: int = 25,
    max_pages: int | None = None,
    category: str | None = None,
) -> dict:
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

    Time-bounded: the scan stops after ENTRAADM_DEADLINE seconds (default 45)
    and returns what it has with ``capped=true``. Over several days the log is
    dominated by device-registration noise ("Update device"), so pass
    ``category`` (for example ``UserManagement``, ``RoleManagement``,
    ``GroupManagement``, ``ApplicationManagement``) to have Graph filter
    server-side; that keeps a multi-day window inside the budget.

    Args:
        category: Only this Graph audit category (letters only; default: all).
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
    if category is not None:
        if not re.fullmatch(r"[A-Za-z]{1,40}", category):
            return {"error": "category must be letters only (e.g. UserManagement)"}
        filter_expr += f" and category eq {odata_quote(category)}"

    try:
        client = _client()
        rows, capped = client.get_paged(
            "/auditLogs/directoryAudits",
            params={"$filter": filter_expr, "$select": _AUDIT_SELECT},
            max_pages=pages_budget,
            deadline=_current_deadline(),
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
@_with_call_deadline
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
            f"/users/{user_id}/authentication/methods",
            max_pages=_resolve_max_pages(None),
            deadline=_current_deadline(),
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

    token = _CALL_DEADLINE.set(_new_deadline())
    try:
        # The audit log is the small, fast scan and the sign-in scan is the one that can use
        # the whole budget, so audits run first: a slow sign-in scan cannot leave the audit
        # section starting with an expired budget and reporting an empty list.
        audits = directory_audits(hours=hours, max_pages=max_pages)
        stats = signin_failure_stats(hours=hours, max_pages=max_pages)
    finally:
        _CALL_DEADLINE.reset(token)

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
