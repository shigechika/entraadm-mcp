"""entraadm-mcp MCP server — Microsoft Entra ID sign-in/audit-log triage (read-only).

Tools:

- ``health_check``          — fleet-standard status/service/version + graph/signin_probe
- ``get_user``               — one account's lifecycle state: enabled, sync, password age,
  licenses, sign-in activity
- ``signin_logs``            — one user's sign-in events, AADSTS-annotated
- ``signin_failure_stats``   — tenant-wide failure aggregation, incl. password-spray suspects
- ``directory_audits``       — who did what (block/unblock/attribute changes), and to whom
- ``get_user_auth_methods``  — MFA registration state for one user
- ``list_subscriptions``     — the Azure subscriptions this credential can see (ARM)
- ``vm_backup_status``       — which Azure VMs are backed up, and whether the last backup succeeded (ARM)
- ``vm_backup_policies``     — schedule and retention of the Azure VM backup policies (ARM)
- ``m365_service_health``    — Microsoft 365 service status and open incidents
- ``daily_brief``            — one-call summary combining m365_service_health,
  signin_failure_stats and directory_audits

Coverage contract: every result section that walks a paged Graph or ARM collection
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

from entraadm_mcp import __version__, sites
from entraadm_mcp.client import (
    ARM_API_VERSIONS,
    ARM_ROLE_HINT,
    ApiError,
    ApiPermissionError,
    ArmClient,
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

#: Injection points for tests: monkeypatch.setitem(server._state, "client", FakeGraphClient(...))
#: and, for the ARM-backed tools, monkeypatch.setitem(server._state, "arm", FakeArmClient(...)).
_state: dict[str, Any] = {"client": None, "arm": None}

_MIN_HOURS = 1
#: Entra ID P1 sign-in/audit log retention is 30 days; a longer window returns nothing, not an error.
_MAX_HOURS = 720
_MIN_TOP = 1
_MAX_TOP = 500
_SPRAY_MIN_DISTINCT_USERS = 5

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
#: Budget of health_check's informational ARM probe: short, so an unresponsive ARM
#: cannot push the whole health_check past the client's tool-call timeout.
_ARM_PROBE_SECONDS = 10.0

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


def _arm() -> ArmClient:
    """The ARM client, sharing the Graph client's credential (each caches its own scope's token)."""
    if _state["arm"] is None:
        _state["arm"] = ArmClient(AuthConfig.from_env(), credential=getattr(_client(), "credential", None))
    return _state["arm"]


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

    ``sites`` reports the optional ENTRAADM_SITES_INI table
    (``configured``, ``ranges``, ``error``). A configured file that fails to
    load is an ``error`` here and leaves ``status`` no better than
    ``degraded``: without it every internal IP would be reported as an
    external spray suspect.

    ``arm`` is a third, informational probe (Azure Resource Manager
    reachable, and how many subscriptions this credential can see). It
    never moves ``status``: Azure RBAC is optional for this server, and a
    deployment used only for Entra triage must not sit at ``degraded``
    forever because nobody granted it a Reader role. It runs last under its
    own short budget (``_ARM_PROBE_SECONDS``) so an unresponsive ARM cannot
    push this whole call past the client's tool-call timeout. The budget
    bounds the request, not the first token acquisition (azure-identity is
    synchronous; in azure-cli mode it shells out to ``az``), which is the
    same limit every tool here has.
    """
    site_status = sites.load().status()
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
            "arm": {"auth": "error", "detail": detail, "subscriptions": None, "capped": None},
            "sites": site_status,
        }

    graph = client.check()
    signin_probe = client.probe_signin_access()
    arm = _arm().check(deadline=time.monotonic() + _ARM_PROBE_SECONDS)
    ok_count = sum(1 for probe in (graph, signin_probe) if probe["auth"] == "ok")
    status = "healthy" if ok_count == 2 else "degraded" if ok_count == 1 else "error"
    if status == "healthy" and site_status["error"] is not None:
        status = "degraded"

    return {
        "service": "entraadm-mcp",
        "version": __version__,
        "status": status,
        "auth_mode": client.mode,
        "graph": graph,
        "signin_probe": signin_probe,
        "arm": arm,
        "sites": site_status,
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

    When ENTRAADM_SITES_INI names the tenant's own address ranges, IPs inside
    them get ``site`` (and ``site_name``) in ``top_ips``, and suspects inside
    them move from ``spray_suspects`` to ``internal_spray_suspects``: a NAT
    egress or a room of shared workstations fails for many users every day,
    and would otherwise bury an outside source. Internal suspects are kept,
    not dropped, because an internal host can be compromised too. ``sites``
    reports whether the file loaded; an invalid CIDR is reported in
    ``sites.error`` while the valid ranges are still used, and a file that
    cannot be read leaves every IP in ``spray_suspects``.

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
    site_table = sites.load()

    def _with_site(entry: dict) -> dict:
        site = site_table.classify(entry["ip_address"])
        if site is not None:
            entry["site"] = site.code
            if site.name:
                entry["site_name"] = site.name
        return entry

    top_ips = [
        _with_site({"ip_address": ip, "count": c, "distinct_users": len(ip_users.get(ip, ()))})
        for ip, c in ip_counts.most_common(10)
    ]
    suspects = sorted(
        (
            _with_site({"ip_address": ip, "distinct_users": len(users), "attempts": ip_counts[ip]})
            for ip, users in ip_users.items()
            if len(users) >= _SPRAY_MIN_DISTINCT_USERS
        ),
        key=lambda s: s["distinct_users"],
        reverse=True,
    )
    # The tenant's own sites (NAT egress, shared workstations) routinely fail
    # for many users at once. Keep them, but in their own list, so that an
    # outside source is not buried among them.
    spray_suspects = [s for s in suspects if "site" not in s]
    internal_spray_suspects = [s for s in suspects if "site" in s]

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
        "internal_spray_suspects": internal_spray_suspects,
        "sites": site_table.status(),
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
# Azure Resource Manager: subscriptions, VM backup posture, backup policies
# ---------------------------------------------------------------------------

_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

#: A Recovery Services vault id as ARM returns it, built from the documented
#: naming rules rather than ``[^/]+``. Resource group: letters and digits in
#: any script, "_", ".", "(", ")", "-", 1-90 characters, not ending in a
#: period, and not a segment made only of periods (so "." and ".." never
#: reach a request path; "rg..prod" and ".prod" are valid names and pass).
#: Vault: ASCII alphanumerics and "-", 2-50. "?", "#", "%", "\\" and whitespace
#: are outside both alphabets. ARM casing varies between responses, hence
#: IGNORECASE; the subscription GUID is compared against the one being
#: scanned by the caller.
_VAULT_ID_RE = re.compile(
    rf"^/subscriptions/(?P<sub>{_GUID})"
    r"/resourceGroups/(?P<rg>(?!\.+/)[\w.()\-]{1,90}(?<!\.))"
    r"/providers/Microsoft\.RecoveryServices/vaults/(?P<vault>[A-Za-z0-9\-]{2,50})$",
    re.IGNORECASE,
)
_RESOURCE_GROUP_IN_ID_RE = re.compile(r"/resourceGroups/([^/]+)/", re.IGNORECASE)
_SUBSCRIPTION_IN_ID_RE = re.compile(rf"^/subscriptions/({_GUID})/", re.IGNORECASE)
_ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$")

#: Server-side filter for the Azure VM workload; a constant, never built from input.
_IAAS_VM_FILTER = "backupManagementType eq 'AzureIaasVM'"
_BACKUP_PARAMS = {"api-version": ARM_API_VERSIONS["backup"], "$filter": _IAAS_VM_FILTER}
#: protectionState values under which backups are running (IRPending = first backup not done yet).
_PROTECTED_STATES = ("Protected", "IRPending")
#: lastBackupStatus values that settle backup_ok. Anything else (InProgress, Warning,
#: an unknown value) is neither a success nor a failure: backup_ok stays null.
_BACKUP_OK_STATUSES = ("Completed", "CompletedWithWarnings")
_BACKUP_FAILED_STATUSES = ("Failed",)
_DEFAULT_STALE_HOURS = 36
_MIN_STALE_HOURS = 1
_MAX_STALE_HOURS = 24 * 400


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _str_list(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _props(resource: Any) -> dict:
    return _dict(_dict(resource).get("properties"))


def _parse_iso(value: Any) -> datetime.datetime | None:
    """Parse an ARM/Graph timestamp into an aware datetime; anything malformed is None, never an exception."""
    if not isinstance(value, str):
        return None
    match = _ISO_RE.match(value.strip())
    if not match:
        return None
    base, frac, tz = match.groups()
    text = base + (f".{frac[:6].ljust(6, '0')}" if frac else "") + ("+00:00" if tz in (None, "Z") else tz)
    try:
        return datetime.datetime.fromisoformat(text)
    except ValueError:
        return None


def _clamp_stale_hours(hours: int) -> int:
    return max(_MIN_STALE_HOURS, min(_MAX_STALE_HOURS, hours))


def _arm_error(e: Exception) -> dict:
    out: dict = {"error": str(e)}
    if isinstance(e, ApiPermissionError):
        out["missing_permission"] = ARM_ROLE_HINT
    return out


def _budget_left() -> bool:
    deadline = _current_deadline()
    return deadline is None or deadline - time.monotonic() > 0


def _subscription_entry(s: dict) -> dict:
    sid = _str(s.get("subscriptionId"))
    if sid is None or not _GUID_RE.match(sid):
        # Defense in depth: this id is about to be interpolated into URL paths.
        raise ApiError("unexpected subscription id shape returned by ARM")
    return {"subscription_id": sid.lower(), "name": _str(s.get("displayName")), "state": _str(s.get("state"))}


def _list_subscriptions(arm: ArmClient, max_pages: int) -> tuple[list[dict], bool]:
    raw, capped = arm.get_paged(
        "/subscriptions",
        params={"api-version": ARM_API_VERSIONS["subscriptions"]},
        max_pages=max_pages,
        deadline=_current_deadline(),
    )
    return [_subscription_entry(s) for s in raw], capped


def _resolve_subscriptions(
    arm: ArmClient, subscription: str | None, max_pages: int
) -> tuple[list[dict], bool, dict | None]:
    """Resolve the ``subscription`` argument against what this credential can see.

    Returns ``(targets, listing_capped, not_found)``. ``subscription`` is an
    untrusted MCP input: it is only ever compared against the ids and
    display names ARM returned, and the id that reaches a URL path is ARM's
    own (GUID-checked) one. ``None`` means every visible subscription. An id
    resolves even on a capped listing; a display name only on a complete one
    (``candidates`` then names the one match seen, so the caller can retry
    by id).
    """
    subs, capped = _list_subscriptions(arm, max_pages)
    if subscription is None:
        return subs, capped, None
    wanted = subscription.strip()
    by_id = [s for s in subs if s["subscription_id"] == wanted.lower()]
    if by_id:
        return by_id[:1], capped, None  # an id is unique by construction, even on a partial listing
    matches = [s for s in subs if s["name"] == wanted]
    # A display name is not unique: one match on a complete listing resolves it; on a
    # capped listing a same-named subscription may sit on an unread page, so it does not.
    if len(matches) == 1 and not capped:
        return matches, capped, None
    not_found: dict = {"found": False, "subscription": subscription, "listing_capped": capped}
    if matches:
        not_found["ambiguous" if len(matches) > 1 else "candidates"] = [s["subscription_id"] for s in matches]
    return [], capped, not_found


@mcp.tool()
@_with_call_deadline
def list_subscriptions(max_pages: int | None = None) -> dict:
    """The Azure subscriptions this credential can see, as ARM lists them.

    Read-only (``GET /subscriptions``; needs no RBAC beyond being able to see a
    subscription at all). The discovery anchor for ``vm_backup_status`` and
    ``vm_backup_policies``: both accept a subscription id or display name from
    this list. An empty list with ``auth`` working means no Reader role has
    been granted anywhere yet. ``capped`` marks a listing cut short by the page
    budget.
    """
    try:
        subs, capped = _list_subscriptions(_arm(), _resolve_max_pages(max_pages))
    except (ConfigError, ApiError) as e:
        return _arm_error(e)
    return {"count": len(subs), "capped": capped, "subscriptions": subs}


def _scan_vaults(arm: ArmClient, sub: dict, max_pages: int, collection: str, params: dict) -> dict:
    """List one subscription's Recovery Services vaults and, per vault, one backup collection.

    ``collection`` is ``backupProtectedItems`` or ``backupPolicies``. Returns
    ``{"vaults", "rows", "skipped_vaults", "complete"}``: ``rows`` is a list of
    ``(vault_entry, resource)``; ``complete`` is False when the vault listing was
    capped, a vault was skipped, or any vault's collection was capped -- the
    callers must then not treat an absent row as proof of absence. ``complete``
    assumes the documented subscription-scope Reader role: a Reader scoped to
    some resource groups gets a vault listing silently filtered to those
    groups, which this scan cannot tell from a complete one. A vault id
    that does not match ``_VAULT_ID_RE`` (or names another subscription) is
    never requested. A subscription-level ApiError propagates to the caller.
    """
    sid = sub["subscription_id"]
    raw_vaults, capped = arm.get_paged(
        f"/subscriptions/{sid}/providers/Microsoft.RecoveryServices/vaults",
        params={"api-version": ARM_API_VERSIONS["vaults"]},
        max_pages=max_pages,
        deadline=_current_deadline(),
    )
    vaults: list[dict] = []
    rows: list[tuple[dict, dict]] = []
    skipped: list[dict] = []
    complete = not capped
    for v in raw_vaults:
        vid = _str(_dict(v).get("id")) or ""
        match = _VAULT_ID_RE.match(vid)
        if not match or match.group("sub").lower() != sid:
            skipped.append({"id": vid[:200], "reason": "id did not match the vault id pattern"})
            complete = False
            continue
        vault = {
            "id": vid.lower(),
            "name": match.group("vault"),
            "resource_group": match.group("rg"),
            "location": _str(v.get("location")),
            "capped": False,
        }
        if not _budget_left():
            skipped.append({"id": vid.lower(), "reason": "deadline"})
            complete = False
            continue
        try:
            items, items_capped = arm.get_paged(
                f"{vid}/{collection}", params=params, max_pages=max_pages, deadline=_current_deadline()
            )
        except ApiError as e:
            # One unreadable vault (RBAC scoped to a resource group, a vault deleted
            # between the listing and the read, a 5xx past the retry budget) must not
            # hide the readable ones, be mistaken for an empty one, or discard the
            # subscription's VM listing that already succeeded.
            skipped.append({"id": vid.lower(), "reason": str(e)})
            complete = False
            continue
        vault["capped"] = items_capped
        complete = complete and not items_capped
        vaults.append(vault)
        rows.extend((vault, item) for item in items if isinstance(item, dict))
    return {"vaults": vaults, "rows": rows, "skipped_vaults": skipped, "complete": complete}


def _vm_row(vm: dict, match: tuple[dict, dict] | None, items_complete: bool, now, stale_hours: int) -> dict:
    vid = (_str(vm.get("id")) or "").lower()
    rg = _RESOURCE_GROUP_IN_ID_RE.search(vid)
    row: dict = {
        "name": _str(vm.get("name")),
        "resource_group": rg.group(1) if rg else None,
        "location": _str(vm.get("location")),
        "id": vid,
        "protected": None,
        "vault": None,
        "policy_name": None,
        "protection_state": None,
        "health_status": None,
        "last_backup_status": None,
        "backup_ok": None,
        "last_backup_time": None,
        "last_recovery_point": None,
        "stale": None,
    }
    if match is None:
        if items_complete:
            row["protected"] = False
        else:
            row["note"] = "no protected item found, but the vault scan of this subscription was incomplete"
        return row
    item, vault = match
    p = _props(item)
    state = _str(p.get("protectionState"))
    row.update(
        vault=vault["name"],
        policy_name=_str(p.get("policyName")),
        protection_state=state,
        health_status=_str(p.get("healthStatus")),
        last_backup_status=_str(p.get("lastBackupStatus")),
        last_backup_time=_str(p.get("lastBackupTime")),
        last_recovery_point=_str(p.get("lastRecoveryPoint")),
    )
    if state is None:
        # An item exists but its state is unreadable: unknown, not "unprotected".
        row["note"] = "protected item found but its protectionState is missing"
        return row
    row["protected"] = state in _PROTECTED_STATES
    if state == "IRPending":
        row["note"] = "initial backup pending"
        return row
    status = row["last_backup_status"]
    if status in _BACKUP_OK_STATUSES:
        row["backup_ok"] = True
    elif status in _BACKUP_FAILED_STATUSES:
        row["backup_ok"] = False
    if row["protected"]:
        recovery_point = _parse_iso(row["last_recovery_point"])
        row["stale"] = recovery_point is None or (now - recovery_point) > datetime.timedelta(hours=stale_hours)
    return row


def _count_vms(rows: list[dict]) -> dict:
    return {
        "vm_count": len(rows),
        "protected": sum(1 for r in rows if r["protected"] is True),
        "unprotected": sum(1 for r in rows if r["protected"] is False),
        "unknown": sum(1 for r in rows if r["protected"] is None),
        "stale": sum(1 for r in rows if r["stale"] is True),
        "failed": sum(1 for r in rows if r["backup_ok"] is False),
    }


@mcp.tool()
@_with_call_deadline
def vm_backup_status(
    subscription: str | None = None, stale_hours: int = _DEFAULT_STALE_HOURS, max_pages: int | None = None
) -> dict:
    """Which Azure VMs are backed up by Azure Backup, and whether the last backup succeeded.

    Joins every VM of a subscription (``Microsoft.Compute/virtualMachines``)
    with the Azure-VM protected items of its Recovery Services vaults, on the
    VM's ARM id (case-insensitively; ARM casing differs between the two
    services). Read-only; needs the Reader role on the subscription.

    Per VM:

    - ``protected``: ``true`` when a protected item exists with
      ``protectionState`` ``Protected`` or ``IRPending`` (first backup not done
      yet, ``note`` says so); ``false`` when there is none, or it is
      ``ProtectionStopped`` / ``ProtectionPaused`` / ``ProtectionError`` (data
      may be retained, backups are not running -- the state is shown);
      ``null`` (unknown) when no item was found but the vault scan was
      incomplete (``capped``, a skipped vault, an unreadable or unreached
      subscription -- in the global join, any subscription's) -- a partial
      scan never produces a false "unprotected".
    - ``backup_ok``: ``true`` for ``lastBackupStatus`` ``Completed`` /
      ``CompletedWithWarnings``, ``false`` for ``Failed``, ``null`` before any
      backup ran or while one is running (``InProgress``, ``Warning``, an
      unknown value). An item whose ``protectionState`` is missing is
      ``protected: null`` with a note. When two vaults hold an item for one
      VM, the one still backing up wins (``duplicate_items`` counts them).
    - ``stale``: no recovery point (``lastRecoveryPoint``, the proof of a
      successful backup) within ``stale_hours``. The default 36 h suits daily
      policies; raise it for weekly ones (``policy_name`` is in the row).

    ``subscription`` is an id or display name from ``list_subscriptions``;
    ``None`` scans every visible subscription and joins globally, so a VM
    backed up to a vault in another subscription is matched. With one
    subscription named, only its vaults are scanned (``coverage`` says so).
    An unknown or ambiguous name returns ``found: false``.

    ``orphans`` are protected items whose VM no longer exists (backup data
    retained for a deleted VM), reported only when that VM's subscription was
    listed completely. One subscription's permission error is reported on its
    own entry; the others still return. When the wall-clock budget runs out,
    the remaining subscriptions are listed under ``skipped`` and ``capped`` is
    set.
    """
    stale_hours = _clamp_stale_hours(stale_hours)
    pages = _resolve_max_pages(max_pages)
    try:
        arm = _arm()
        targets, listing_capped, not_found = _resolve_subscriptions(arm, subscription, pages)
    except (ConfigError, ApiError) as e:
        return _arm_error(e)
    if not_found is not None:
        return not_found

    now = datetime.datetime.now(datetime.timezone.utc)
    entries: list[dict] = []
    skipped: list[dict] = []
    raw_vms: dict[str, list[dict]] = {}
    matches: dict[str, tuple[dict, dict]] = {}  # lower-cased VM id -> (protected item, vault)
    item_subscription: dict[str, str] = {}  # lower-cased VM id -> subscription whose vault holds it
    duplicate_items = 0
    for sub in targets:
        sid = sub["subscription_id"]
        if not _budget_left():
            skipped.append({"subscription_id": sid, "name": sub["name"], "reason": "deadline"})
            continue
        try:
            vms, vms_capped = arm.get_paged(
                f"/subscriptions/{sid}/providers/Microsoft.Compute/virtualMachines",
                params={"api-version": ARM_API_VERSIONS["virtualMachines"]},
                max_pages=pages,
                deadline=_current_deadline(),
            )
            scan = _scan_vaults(arm, sub, pages, "backupProtectedItems", _BACKUP_PARAMS)
        except ApiError as e:
            entries.append({"subscription_id": sid, "name": sub["name"], **_arm_error(e)})
            continue
        raw_vms[sid] = [vm for vm in vms if isinstance(vm, dict)]
        for vault, item in scan["rows"]:
            p = _props(item)
            key = (_str(p.get("virtualMachineId")) or _str(p.get("sourceResourceId")) or "").lower()
            if not key:
                continue
            if key in matches:
                # Two vaults hold an item for one VM (a stopped item left behind after a
                # move): the one still backing up wins, whatever order ARM listed them in.
                duplicate_items += 1
                if _str(_props(matches[key][0]).get("protectionState")) in _PROTECTED_STATES:
                    continue
            matches[key] = (item, vault)
            item_subscription[key] = sid
        entries.append(
            {
                "subscription_id": sid,
                "name": sub["name"],
                "vms_capped": vms_capped,
                "items_complete": scan["complete"],
                "vaults": scan["vaults"],
                "skipped_vaults": scan["skipped_vaults"],
            }
        )

    vm_ids: set[str] = set()
    totals = _count_vms([])
    failed_subscriptions = sum(1 for e in entries if "error" in e)
    # A subscription that errored or was never reached is missing from the inventory.
    capped = listing_capped or bool(skipped) or failed_subscriptions > 0
    # Global mode joins across subscriptions, so "no item anywhere" is only
    # proof of absence when every subscription's vault scan completed.
    vaults_complete_everywhere = not capped and all(e["items_complete"] for e in entries if "error" not in e)
    for entry in entries:
        if "error" in entry:
            continue
        rows = []
        items_complete = entry["items_complete"] if subscription is not None else vaults_complete_everywhere
        for vm in raw_vms[entry["subscription_id"]]:
            vid = (_str(vm.get("id")) or "").lower()
            vm_ids.add(vid)
            rows.append(_vm_row(vm, matches.get(vid), items_complete, now, stale_hours))
        counts = _count_vms(rows)
        entry.update(counts)
        entry["vms"] = rows
        entry["capped"] = entry["vms_capped"] or not entry["items_complete"]
        capped = capped or entry["capped"]
        for k in totals:
            totals[k] += counts[k]

    complete_vm_listings = {e["subscription_id"] for e in entries if "error" not in e and not e["vms_capped"]}
    orphans: list[dict] = []
    unjoined = 0
    for key, (item, vault) in matches.items():
        if key in vm_ids:
            continue
        owner = _SUBSCRIPTION_IN_ID_RE.match(key)
        if owner is not None and owner.group(1).lower() in complete_vm_listings:
            p = _props(item)
            orphans.append(
                {
                    "name": _str(p.get("friendlyName")),
                    "vm_id": key,
                    "vault": vault["name"],
                    "subscription_id": item_subscription[key],
                    "protection_state": _str(p.get("protectionState")),
                    "last_recovery_point": _str(p.get("lastRecoveryPoint")),
                }
            )
        else:
            unjoined += 1

    coverage = (
        "every visible subscription; the VM/vault join is global"
        if subscription is None
        else "the named subscription's vaults only; a VM backed up to a vault in another subscription "
        "(cross-subscription backup) appears unprotected here -- call without `subscription` for a global join"
    )
    return {
        "stale_hours": stale_hours,
        "coverage": coverage,
        "summary": {
            "subscriptions": len(entries),
            "failed_subscriptions": failed_subscriptions,
            **totals,
            "orphans": len(orphans),
            "capped": capped,
        },
        "subscriptions": entries,
        "skipped": skipped,
        "orphans": orphans,
        "unjoined_items": unjoined,
        "duplicate_items": duplicate_items,
        "capped": capped,
    }


def _duration(value: Any) -> dict | None:
    d = _dict(value)
    if not d:
        return None
    return {"count": _int(d.get("count")), "unit": _str(d.get("durationType"))}


def _schedule_entry(schedule: Any) -> dict:
    s = _dict(schedule)
    kind = _str(s.get("schedulePolicyType"))
    frequency = _str(s.get("scheduleRunFrequency"))
    if kind == "SimpleSchedulePolicy":
        return {
            "type": kind,
            "frequency": frequency,
            "run_times": _str_list(s.get("scheduleRunTimes")),
            "weekdays": _str_list(s.get("scheduleRunDays")),
        }
    if kind == "SimpleSchedulePolicyV2":
        out: dict = {"type": kind, "frequency": frequency}
        if frequency == "Hourly":
            h = _dict(s.get("hourlySchedule"))
            out.update(
                interval_hours=_int(h.get("interval")),
                window_start=_str(h.get("scheduleWindowStartTime")),
                window_hours=_int(h.get("scheduleWindowDuration")),
            )
        elif frequency == "Daily":
            out["run_times"] = _str_list(_dict(s.get("dailySchedule")).get("scheduleRunTimes"))
        elif frequency == "Weekly":
            w = _dict(s.get("weeklySchedule"))
            out.update(weekdays=_str_list(w.get("scheduleRunDays")), run_times=_str_list(w.get("scheduleRunTimes")))
        else:
            out["unparsed"] = True
        return out
    return {"type": kind, "unparsed": True}


def _retention_schedule(block: Any) -> dict:
    """The part of a monthly/yearly LongTermRetentionPolicy block that says *which* days."""
    b = _dict(block)
    out: dict = {"format": _str(b.get("retentionScheduleFormatType"))}
    daily = _dict(b.get("retentionScheduleDaily"))
    days = daily.get("daysOfTheMonth")
    if isinstance(days, list):
        out["days_of_month"] = [
            {"day": _int(_dict(d).get("date")), "is_last": bool(_dict(d).get("isLast"))} for d in days
        ]
    weekly = _dict(b.get("retentionScheduleWeekly"))
    if weekly:
        out["weekdays"] = _str_list(weekly.get("daysOfTheWeek"))
        out["weeks_of_month"] = _str_list(weekly.get("weeksOfTheMonth"))
    months = b.get("monthsOfYear")
    if isinstance(months, list):
        out["months"] = _str_list(months)
    out["retention"] = _duration(b.get("retentionDuration"))
    return out


def _retention_entry(retention: Any) -> dict:
    r = _dict(retention)
    kind = _str(r.get("retentionPolicyType"))
    if kind == "LongTermRetentionPolicy":
        out: dict = {"type": kind}
        daily = _dict(r.get("dailySchedule"))
        if daily:
            out["daily"] = {"retention": _duration(daily.get("retentionDuration"))}
        weekly = _dict(r.get("weeklySchedule"))
        if weekly:
            out["weekly"] = {
                "weekdays": _str_list(weekly.get("daysOfTheWeek")),
                "retention": _duration(weekly.get("retentionDuration")),
            }
        for name in ("monthlySchedule", "yearlySchedule"):
            block = _dict(r.get(name))
            if block:
                out[name.removesuffix("Schedule")] = _retention_schedule(block)
        return out
    if kind == "SimpleRetentionPolicy":
        return {"type": kind, "retention": _duration(r.get("retentionDuration"))}
    return {"type": kind, "unparsed": True}


def _policy_entry(policy: dict, vault: dict) -> dict:
    p = _props(policy)
    return {
        "name": _str(policy.get("name")),
        "vault": vault["name"],
        "resource_group": vault["resource_group"],
        "policy_type": _str(p.get("policyType")),
        "schedule": _schedule_entry(p.get("schedulePolicy")),
        "retention": _retention_entry(p.get("retentionPolicy")),
        "instant_rp_days": _int(p.get("instantRpRetentionRangeInDays")),
        "timezone": _str(p.get("timeZone")),
        "protected_item_count": _int(p.get("protectedItemsCount")),
    }


@mcp.tool()
@_with_call_deadline
def vm_backup_policies(subscription: str | None = None, max_pages: int | None = None) -> dict:
    """Schedule and retention of the Azure VM backup policies in each Recovery Services vault.

    Read-only; needs the Reader role on the subscription. Per policy:
    ``policy_type`` (``V1`` = ``SimpleSchedulePolicy``, ``V2`` =
    ``SimpleSchedulePolicyV2`` with an hourly / daily / weekly schedule),
    ``schedule`` (frequency, run times in UTC, weekdays, or the hourly window),
    ``retention`` (``LongTermRetentionPolicy``: daily / weekly / monthly /
    yearly blocks with their day selection and duration), ``instant_rp_days``,
    ``timezone`` and ``protected_item_count`` (ARM's own count). A schedule or
    retention type this server does not know is returned as
    ``{"type": <name>, "unparsed": true}``, never dropped.

    ``subscription`` is an id or display name from ``list_subscriptions``
    (``None`` = every visible subscription); an unknown or ambiguous name
    returns ``found: false``. Coverage flags as in ``vm_backup_status``:
    ``skipped_vaults`` per subscription, ``skipped`` subscriptions when the
    budget ran out, ``capped`` overall.
    """
    pages = _resolve_max_pages(max_pages)
    try:
        arm = _arm()
        targets, listing_capped, not_found = _resolve_subscriptions(arm, subscription, pages)
    except (ConfigError, ApiError) as e:
        return _arm_error(e)
    if not_found is not None:
        return not_found

    entries: list[dict] = []
    skipped: list[dict] = []
    capped = listing_capped
    total = 0
    for sub in targets:
        sid = sub["subscription_id"]
        if not _budget_left():
            skipped.append({"subscription_id": sid, "name": sub["name"], "reason": "deadline"})
            capped = True
            continue
        try:
            scan = _scan_vaults(arm, sub, pages, "backupPolicies", _BACKUP_PARAMS)
        except ApiError as e:
            entries.append({"subscription_id": sid, "name": sub["name"], **_arm_error(e)})
            capped = True  # part of the inventory is missing
            continue
        policies = [_policy_entry(policy, vault) for vault, policy in scan["rows"]]
        total += len(policies)
        capped = capped or not scan["complete"]
        entries.append(
            {
                "subscription_id": sid,
                "name": sub["name"],
                "vaults": scan["vaults"],
                "skipped_vaults": scan["skipped_vaults"],
                "policies": policies,
                "capped": not scan["complete"],
            }
        )
    return {
        "summary": {
            "subscriptions": len(entries),
            "failed_subscriptions": sum(1 for e in entries if "error" in e),
            "policies": total,
            "capped": capped,
        },
        "subscriptions": entries,
        "skipped": skipped,
        "capped": capped,
    }


# ---------------------------------------------------------------------------
# Azure activity log: who did what to a VM, and what Azure itself did to it
# ---------------------------------------------------------------------------

#: The activity log keeps 90 days; one call reads at most a week of it.
_ACTIVITY_RETENTION_DAYS = 90
_ACTIVITY_MAX_HOURS = 24 * 7
_ACTIVITY_DEFAULT_HOURS = 24
#: Administrative operations on other resources of the subscription listed in full up to this many.
_ACTIVITY_OTHER_OPS_LIMIT = 50
_ACTIVITY_DETAIL_CHARS = 300
#: Azure VM names: Linux allows 64 characters, Windows 15 (a subset).
_VM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RESOURCE_GROUP_RE = re.compile(r"^(?!\.+$)[\w.()\-]{1,90}(?<!\.)$")


def _parse_window_time(value: str, label: str) -> datetime.datetime:
    """An ISO timestamp with an explicit offset; a bare local time would be read in the wrong zone."""
    match = _ISO_RE.match(value.strip())
    if not match or match.group(3) is None:
        raise ValueError(f"{label} must be an ISO timestamp with an offset, e.g. 2026-10-21T22:00:00+09:00")
    parsed = _parse_iso(value)
    if parsed is None:
        raise ValueError(f"{label} is not a valid timestamp")
    return parsed


def _activity_window(
    start: str | None, end: str | None, hours: int, now: datetime.datetime
) -> tuple[datetime.datetime, datetime.datetime]:
    end_dt = _parse_window_time(end, "end") if end else now
    start_dt = (
        _parse_window_time(start, "start")
        if start
        else end_dt - datetime.timedelta(hours=max(1, min(_ACTIVITY_MAX_HOURS, hours)))
    )
    if end_dt > now:
        end_dt = now
    if start_dt >= end_dt:
        raise ValueError("start must be before end (and before now)")
    if end_dt - start_dt > datetime.timedelta(hours=_ACTIVITY_MAX_HOURS):
        raise ValueError(f"the window may span at most {_ACTIVITY_MAX_HOURS} hours")
    if start_dt < now - datetime.timedelta(days=_ACTIVITY_RETENTION_DAYS):
        raise ValueError(f"the activity log keeps {_ACTIVITY_RETENTION_DAYS} days; start is older")
    return start_dt, end_dt


def _utc_text(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _value(field: Any) -> str | None:
    """The ``value`` of an activity-log ``{value, localizedValue}`` pair."""
    return _str(_dict(field).get("value"))


def _short(value: Any) -> str | None:
    text = _str(value)
    return text if text is None or len(text) <= _ACTIVITY_DETAIL_CHARS else text[:_ACTIVITY_DETAIL_CHARS] + "…"


def _operation_row(event: dict) -> dict:
    return {
        "time": _str(event.get("eventTimestamp")),
        "operation": _value(event.get("operationName")),
        "status": _value(event.get("status")),
        "caller": _str(event.get("caller")),
        "resource": _str(event.get("resourceId")),
    }


def _health_row(event: dict) -> dict:
    p = _dict(event.get("properties"))
    return {
        "time": _str(event.get("eventTimestamp")),
        "stage": _value(event.get("status")),
        "title": _str(p.get("title")),
        "cause": _str(p.get("cause")),
        "type": _str(p.get("type")),
        "current_health": _str(p.get("currentHealthStatus")),
        "previous_health": _str(p.get("previousHealthStatus")),
        "details": _short(p.get("details")),
    }


def _service_health_row(event: dict) -> dict:
    p = _dict(event.get("properties"))
    return {
        "time": _str(event.get("eventTimestamp")),
        "stage": _str(p.get("stage")) or _value(event.get("status")),
        "title": _str(p.get("title")),
        "incident_type": _str(p.get("incidentType")),
        "tracking_id": _str(p.get("trackingId")),
        "impacted_services": _short(p.get("impactedServices")),
    }


def _find_vm(
    arm: ArmClient, targets: list[dict], name: str, resource_group: str | None, pages: int
) -> tuple[list[dict], bool]:
    """The VMs named ``name`` (case-insensitively) in ``targets``; complete False when a listing fell short."""
    found: list[dict] = []
    complete = True
    for sub in targets:
        if not _budget_left():
            return found, False
        try:
            vms, capped = arm.get_paged(
                f"/subscriptions/{sub['subscription_id']}/providers/Microsoft.Compute/virtualMachines",
                params={"api-version": ARM_API_VERSIONS["virtualMachines"]},
                max_pages=pages,
                deadline=_current_deadline(),
            )
        except ApiError:
            complete = False
            continue
        complete = complete and not capped
        for vm in vms:
            vid = _str(_dict(vm).get("id")) or ""
            sid = _SUBSCRIPTION_IN_ID_RE.match(vid)
            rg = _RESOURCE_GROUP_IN_ID_RE.search(vid)
            if (_str(vm.get("name")) or "").lower() != name.lower() or not sid or not rg:
                continue
            if sid.group(1).lower() != sub["subscription_id"]:
                continue
            if resource_group is not None and rg.group(1).lower() != resource_group.lower():
                continue
            found.append(
                {
                    "name": _str(vm.get("name")),
                    "id": vid,
                    "resource_group": rg.group(1),
                    "subscription_id": sub["subscription_id"],
                    "subscription_name": sub["name"],
                    "location": _str(vm.get("location")),
                }
            )
    return found, complete


@mcp.tool()
@_with_call_deadline
def vm_activity(
    vm: str,
    subscription: str | None = None,
    resource_group: str | None = None,
    start: str | None = None,
    end: str | None = None,
    hours: int = _ACTIVITY_DEFAULT_HOURS,
    max_pages: int | None = None,
) -> dict:
    """What happened to an Azure VM in a time window: operations people ran, and events Azure raised.

    Answers "did someone restart this VM, or did Azure?" from the Azure activity
    log of the VM's subscription. Read-only; needs the Reader role on the
    subscription. Sections:

    - ``health``: Resource Health events of the VM (``cause``
      ``PlatformInitiated`` = Azure, e.g. ``Redeploying due to host failure``;
      ``UserInitiated`` = an operation on the VM).
    - ``vm_operations``: Administrative operations on the VM and its
      sub-resources (restart, deallocate, redeploy, extension changes), with
      ``caller`` (a user principal name or an application id).
    - ``other_operations``: Administrative operations on any other resource
      of the subscription in the window (``count``; ``items`` lists the first
      50). Zero here and in ``vm_operations`` means nobody operated the
      subscription through Azure Resource Manager in the window; it says
      nothing about actions inside the guest OS.
    - ``service_health``: Azure incidents and planned maintenance announced
      to the subscription.
    - ``other_categories``: counts of the remaining categories (Alert,
      Policy, Autoscale, ...).

    ``vm`` is the VM name, matched case-insensitively across the
    subscriptions this credential can see; narrow it with ``subscription``
    (id or display name from ``list_subscriptions``) or ``resource_group``
    when the name is not unique (``ambiguous`` lists the candidates). A
    single match found while some subscription could not be listed
    completely is not taken as unique: it comes back as ``candidates`` with
    ``search_complete: false``, to be confirmed by naming its subscription.
    The window is ``start``..``end`` (ISO timestamps with an offset, e.g.
    ``2026-10-21T21:00:00+09:00``), or the ``hours`` before ``end`` (default
    24; ``end`` defaults to now); at most 168 hours, within the 90 days the
    activity log keeps. Times in the result are UTC as Azure returns them.
    ``capped`` marks a log read cut short by the page or time budget: then
    an empty section is not proof that nothing happened.
    """
    if not isinstance(vm, str) or not _VM_NAME_RE.match(vm.strip()):
        return {"error": "vm must be an Azure VM name (letters, digits, '.', '_', '-'; at most 64 characters)"}
    name = vm.strip()
    if resource_group is not None and not _RESOURCE_GROUP_RE.match(resource_group.strip()):
        return {"error": "resource_group is not a valid resource group name"}
    rg_name = resource_group.strip() if resource_group is not None else None
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        start_dt, end_dt = _activity_window(start, end, hours, now)
    except ValueError as e:
        return {"error": str(e)}
    pages = _resolve_max_pages(max_pages)
    try:
        arm = _arm()
        targets, listing_capped, not_found = _resolve_subscriptions(arm, subscription, pages)
        if not_found is not None:
            return not_found
        matches, search_complete = _find_vm(arm, targets, name, rg_name, pages)
    except (ConfigError, ApiError) as e:
        return _arm_error(e)
    search_complete = search_complete and not listing_capped
    if not matches:
        out: dict = {"found": False, "vm": name, "search_complete": search_complete}
        if not search_complete:
            out["note"] = "not found among the VMs that could be listed; some subscriptions were unreadable or capped"
        return out
    candidates = [{k: m[k] for k in ("id", "subscription_name", "resource_group")} for m in matches]
    if len(matches) > 1:
        return {
            "found": False,
            "vm": name,
            "ambiguous": candidates,
            "note": "pass subscription or resource_group to pick one",
        }
    if not search_complete:
        # One match on a partial listing does not make the name unique: another VM of
        # that name may sit in a subscription or page that could not be read.
        return {
            "found": False,
            "vm": name,
            "search_complete": False,
            "candidates": candidates,
            "note": "some subscriptions could not be listed completely; pass this VM's subscription to confirm it",
        }
    target = matches[0]
    vm_id = target["id"].lower()
    window = {"start": _utc_text(start_dt), "end": _utc_text(end_dt)}
    # The filter is built from the parsed datetimes only, never from the raw input.
    log_filter = f"eventTimestamp ge '{window['start']}' and eventTimestamp le '{window['end']}'"
    try:
        events, capped = arm.get_paged(
            f"/subscriptions/{target['subscription_id']}/providers/Microsoft.Insights/eventtypes/management/values",
            params={"api-version": ARM_API_VERSIONS["activityLog"], "$filter": log_filter},
            max_pages=pages,
            deadline=_current_deadline(),
        )
    except ApiError as e:
        return {"found": True, "vm": target, "window": window, **_arm_error(e)}

    health: list[dict] = []
    vm_operations: list[dict] = []
    other_operations: list[dict] = []
    service_health: list[dict] = []
    other_categories: collections.Counter = collections.Counter()
    for event in events:
        if not isinstance(event, dict):
            continue
        category = _value(event.get("category")) or "Unknown"
        rid = (_str(event.get("resourceId")) or "").lower()
        on_vm = rid == vm_id or rid.startswith(vm_id + "/")
        if category == "ResourceHealth" and on_vm:
            health.append(_health_row(event))
        elif category == "Administrative" and on_vm:
            vm_operations.append(_operation_row(event))
        elif category == "Administrative":
            other_operations.append(_operation_row(event))
        elif category == "ServiceHealth":
            service_health.append(_service_health_row(event))
        else:
            other_categories[category] += 1

    def by_time(rows: list[dict]) -> list[dict]:
        return sorted(rows, key=lambda r: r["time"] or "")

    other_sorted = by_time(other_operations)
    return {
        "found": True,
        "vm": target,
        "window": window,
        "health": by_time(health),
        "vm_operations": by_time(vm_operations),
        "other_operations": {
            "count": len(other_sorted),
            "items": other_sorted[:_ACTIVITY_OTHER_OPS_LIMIT],
            "truncated": len(other_sorted) > _ACTIVITY_OTHER_OPS_LIMIT,
        },
        "service_health": by_time(service_health),
        "other_categories": dict(other_categories),
        "events_read": len(events),
        "capped": capped,
    }


# ---------------------------------------------------------------------------
# m365_service_health
# ---------------------------------------------------------------------------

_SERVICE_HEALTH_PERMISSION = "ServiceHealth.Read.All"
#: healthOverviews statuses that mean an issue is open now. Graph keeps post-resolution
#: values (serviceRestored, postIncidentReviewPublished, falsePositive, resolved,
#: mitigated, ...) on a service for days; those are not "degraded".
_OPEN_HEALTH_STATUSES = (
    "serviceDegradation",
    "serviceInterruption",
    "investigating",
    "restoringService",
    "verifyingService",
    "extendedRecovery",
    "investigationSuspended",
    "confirmed",
    "reported",
)


def _service_health_error(e: Exception) -> dict:
    """A section's error; the permission hint only when the failure was a permission failure."""
    out: dict = {"error": str(e)}
    if isinstance(e, ApiPermissionError):
        out["missing_permission"] = _SERVICE_HEALTH_PERMISSION
    return out


def _issue_entry(issue: dict) -> dict:
    return {
        "id": _str(issue.get("id")),
        "title": _str(issue.get("title")),
        "service": _str(issue.get("service")),
        "feature": _str(issue.get("feature")),
        "classification": _str(issue.get("classification")),
        "status": _str(issue.get("status")),
        "start": _str(issue.get("startDateTime")),
        "last_modified": _str(issue.get("lastModifiedDateTime")),
        "impact": _str(issue.get("impactDescription")),
    }


@mcp.tool()
@_with_call_deadline
def m365_service_health(max_pages: int | None = None) -> dict:
    """Microsoft 365 service status per service, and the open incidents and advisories.

    Two Graph reads (``ServiceHealth.Read.All``): ``healthOverviews`` (one row
    per service with its current status) and the unresolved
    ``serviceAnnouncement/issues``, newest first. A sign-in failure spike reads
    very differently while Entra or Exchange has an open incident, which is
    why ``daily_brief`` carries this section too. Each section degrades on its
    own (``{"error", "missing_permission"}``); ``summary`` is computed from
    whatever came back. ``capped`` means either collection was cut short by
    the page budget, so the counts are lower bounds. The message center
    (``messages``) needs a different permission and is not read.
    """
    pages = _resolve_max_pages(max_pages)
    try:
        client = _client()
    except ConfigError as e:
        return {"error": str(e)}

    capped = False
    services: Any
    issues: Any
    try:
        raw, c = client.get_paged(
            "/admin/serviceAnnouncement/healthOverviews", max_pages=pages, deadline=_current_deadline()
        )
        capped = capped or c
        services = [{"service": _str(_dict(o).get("service")), "status": _str(_dict(o).get("status"))} for o in raw]
    except ApiError as e:
        services = _service_health_error(e)
    try:
        raw, c = client.get_paged(
            "/admin/serviceAnnouncement/issues",
            params={"$filter": "isResolved eq false", "$orderby": "startDateTime desc"},
            max_pages=pages,
            deadline=_current_deadline(),
        )
        capped = capped or c
        issues = [_issue_entry(i) for i in raw if isinstance(i, dict)]
    except ApiError as e:
        issues = _service_health_error(e)

    summary: dict = {"capped": capped}
    if isinstance(services, list):
        # Only an open issue counts; a row without a status is counted so it is not hidden.
        summary["degraded_services"] = [
            s["service"] or "(unnamed service)" for s in services if s["status"] in _OPEN_HEALTH_STATUSES
        ]
        summary["services_without_status"] = sum(1 for s in services if s["status"] is None)
    else:
        summary["degraded_services"] = services
    if isinstance(issues, list):
        summary["open_incidents"] = sum(1 for i in issues if i["classification"] == "incident")
        summary["open_advisories"] = sum(1 for i in issues if i["classification"] == "advisory")
    else:
        summary["open_incidents"] = issues
        summary["open_advisories"] = issues
    return {"summary": summary, "services": services, "issues": issues, "capped": capped}


# ---------------------------------------------------------------------------
# daily_brief
# ---------------------------------------------------------------------------


@mcp.tool()
def daily_brief(hours: int = 24, max_pages: int | None = None, samples: int = 10) -> dict:
    """One-call morning-patrol summary: M365 service health, sign-in failures, spray suspects, admin actions.

    Combines ``m365_service_health``, ``signin_failure_stats`` and
    ``directory_audits`` into one result with a compact ``summary`` on top,
    matching the shape of this fleet's other ``daily_brief`` tools. A
    permission failure in one section degrades only that section's
    contribution to ``summary`` -- the other sections still return in full.
    Azure VM backup is deliberately not a section here: its ARM fan-out is
    the one scan that could exhaust the shared budget, so call
    ``vm_backup_status`` separately.

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
        # Cheapest first: service health is two small reads, the audit log is the small, fast
        # scan and the sign-in scan is the one that can use the whole budget. A slow sign-in
        # scan therefore cannot leave the earlier sections starting with an expired budget and
        # reporting an empty list.
        health = m365_service_health(max_pages=max_pages)
        audits = directory_audits(hours=hours, max_pages=max_pages)
        stats = signin_failure_stats(hours=hours, max_pages=max_pages)
    finally:
        _CALL_DEADLINE.reset(token)

    if "error" in health:
        summary: dict = {"service_health": health}
    else:
        summary = {
            "service_health": {
                "degraded_services": health["summary"]["degraded_services"],
                "open_incidents": health["summary"]["open_incidents"],
                "capped": health["capped"],
            }
        }
    if "error" in stats:
        summary["sign_in_failures"] = stats
    else:
        summary.update(
            sign_in_failures=stats["total_failures"],
            distinct_failing_users=stats["distinct_failing_users"],
            top_error_codes=stats["top_error_codes"][:5],
            spray_suspects=stats["spray_suspects"],
            internal_spray_suspects=stats["internal_spray_suspects"],
            capped=stats["capped"],
        )
        if stats["sites"]["error"] is not None:
            summary["sites_error"] = stats["sites"]["error"]

    if "error" in audits:
        summary["admin_actions"] = audits
    else:
        summary["admin_actions"] = audits["count"]
        summary["capped"] = summary.get("capped", False) or audits["capped"]
    if "error" not in health:
        summary["capped"] = summary.get("capped", False) or health["capped"]

    return {
        "window_hours": hours,
        "summary": summary,
        "m365_service_health": health,
        "signin_failure_stats": stats,
        "directory_audits": audits,
    }
