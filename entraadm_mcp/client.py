"""Synchronous Microsoft Graph client: auth, paging, and error translation.

Deliberately not built on msgraph-sdk/kiota -- that SDK is heavy and its
generated request builders don't play well with the respx-based testing used
throughout this family of servers. Every tool in server.py talks to Graph
exclusively through GraphClient, so the request/response shape (paging,
permission-error translation, retry policy) lives in exactly one place.
"""

from __future__ import annotations

import re
import time

import httpx
from azure.identity import AzureCliCredential, ClientSecretCredential

from .config import DEFAULT_MAX_PAGES, AuthConfig

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

#: Refresh the cached token this many seconds before its real expiry, so a
#: request never starts with a token that expires mid-flight.
_TOKEN_REFRESH_MARGIN_SECONDS = 300

_UPN_LIKE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class GraphError(Exception):
    """Base error for anything that goes wrong talking to Microsoft Graph."""


class GraphAuthError(GraphError):
    """The credential could not produce a usable access token, or Graph rejected it outright."""


class GraphPermissionError(GraphError):
    """Graph rejected the request because the caller lacks a required permission.

    The message is a human-readable translation of Graph's error code (see
    _translate_permission_error), not the raw JSON -- a tool caller should be
    able to act on str(e) directly without parsing anything.
    """


def odata_quote(value: str) -> str:
    """Quote a string for use inside an OData $filter literal.

    MCP tool input is untrusted (an LLM or an automated triage bot constructs
    it), so every value interpolated into a $filter string must be escaped
    the same way SQL string literals are: doubling embedded single quotes.
    """
    return "'" + value.replace("'", "''") + "'"


def validate_upn(value: str) -> str:
    """Reject anything that isn't shaped like a user principal name.

    Raises GraphError (not a bare ValueError) so tool code can catch it
    alongside every other Graph-related failure with one except clause.
    """
    if not _UPN_LIKE.match(value):
        raise GraphError(f"'{value}' is not a user principal name")
    return value


def _build_credential(config: AuthConfig):
    if config.mode == "app-only":
        return ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
        )
    return AzureCliCredential()


#: Graph error codes that mean "wrong role/permission", mapped to actionable
#: guidance. Anything not in this dict falls back to the raw code + message
#: (still no stack trace, no request body) rather than a hardcoded generic string.
_PERMISSION_HINTS = {
    "Authentication_RequestFromUnsupportedUserRole": (
        "insufficient privileges: this endpoint needs the Reports Reader "
        "directory role (delegated, azure-cli auth) or an application "
        "permission such as AuditLog.Read.All (app-only auth)"
    ),
    "accessDenied": (
        "access denied: the signed-in identity or app registration lacks the Graph permission this endpoint requires"
    ),
    "Forbidden": (
        "forbidden: the signed-in identity or app registration lacks the Graph permission this endpoint requires"
    ),
}


def _translate_permission_error(body: dict) -> str:
    error = body.get("error") if isinstance(body, dict) else None
    error = error if isinstance(error, dict) else {}
    code = error.get("code", "")
    hint = _PERMISSION_HINTS.get(code)
    if hint:
        return hint
    message = error.get("message") or "permission denied"
    return f"{code or 'permission denied'}: {message}"


def _parse_retry_after(value: str | None) -> float:
    """Parse a Retry-After header value into a delay in seconds.

    RFC 9110 permits either a delay-seconds integer or an HTTP-date; Graph
    is documented to send only the former, but a defensively-written client
    doesn't crash if that ever changes. An unparsable value degrades to a
    modest fixed backoff rather than raising -- a ValueError here would
    escape as a bare exception, the same class of bug as an uncaught
    httpx.RequestError.
    """
    if value is None:
        return 1.0
    try:
        return float(value)
    except ValueError:
        return 1.0


class GraphClient:
    """Thin Microsoft Graph client: token handling, paging, permission translation.

    Args:
        config: Resolved AuthConfig (see config.AuthConfig.from_env).
        credential: Injectable azure-identity credential (`# injectable for
            tests` -- a stub with a `get_token(*scopes) -> AccessToken`
            method). Defaults to building the real credential for config.mode.
        http_client: Injectable httpx.Client (`# injectable for tests`, used
            with respx). Defaults to a real client against the Graph v1.0 root.
    """

    def __init__(self, config: AuthConfig, credential=None, http_client: httpx.Client | None = None):
        self._config = config
        self._credential = credential if credential is not None else _build_credential(config)
        self._http = http_client if http_client is not None else httpx.Client(base_url=GRAPH_BASE, timeout=30.0)
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def mode(self) -> str:
        """The resolved auth mode ("app-only" or "azure-cli"), surfaced by health_check as auth_mode."""
        return self._config.mode

    def _access_token(self) -> str:
        now = time.time()
        if self._token is not None and self._token_expires_at - now > _TOKEN_REFRESH_MARGIN_SECONDS:
            return self._token
        try:
            token = self._credential.get_token(GRAPH_SCOPE)
        except Exception as e:  # azure-identity raises its own exception hierarchy
            raise GraphAuthError(f"could not obtain a Graph access token ({type(e).__name__})") from e
        self._token = token.token
        self._token_expires_at = token.expires_on
        return self._token

    def _request(self, method: str, url: str, params: dict | None = None) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        # Independent budgets per failure kind, not one shared attempt
        # counter: a network error (or a 5xx) consuming an early "attempt"
        # must not leave a *later* 429 unretried -- each kind gets its own
        # guarantee ("429 retried once", "5xx retried twice") regardless of
        # what happened before it on this call. Termination is still
        # guaranteed: every branch either returns/raises or spends from a
        # budget that monotonically decreases to zero.
        network_retries_left = 2
        server_retries_left = 2
        retried_429 = False
        while True:
            try:
                resp = self._http.request(method, url, params=params, headers=headers)
            except httpx.RequestError as e:
                # A connection/DNS/timeout failure never reaches _parse(), so
                # without this it would propagate as a bare httpx exception --
                # none of the GraphError family a tool's except clause
                # catches, crashing the tool call instead of degrading it.
                if network_retries_left > 0:
                    time.sleep(2 ** (2 - network_retries_left))
                    network_retries_left -= 1
                    continue
                raise GraphError(f"Graph request failed: network error ({type(e).__name__})") from e
            if resp.status_code == 429 and not retried_429:
                retried_429 = True
                time.sleep(_parse_retry_after(resp.headers.get("Retry-After")))
                continue
            if resp.status_code >= 500 and server_retries_left > 0:
                time.sleep(2 ** (2 - server_retries_left))
                server_retries_left -= 1
                continue
            return resp

    def get(self, path: str, params: dict | None = None) -> dict:
        """GET a single Graph resource (no paging). ``path`` is relative to the v1.0 root, e.g. "/users"."""
        resp = self._request("GET", path, params=params)
        return self._parse(resp)

    def get_paged(self, path: str, params: dict | None = None, max_pages: int = DEFAULT_MAX_PAGES) -> tuple[list, bool]:
        """GET a Graph collection, following ``@odata.nextLink`` up to ``max_pages``.

        Returns ``(items, capped)`` where ``capped`` is True iff a nextLink
        still existed when the page budget ran out -- callers must surface
        this so a partial scan is never reported as if it were exhaustive.
        """
        items: list = []
        url: str | None = path
        query = params
        pages = 0
        while url is not None and pages < max_pages:
            resp = self._request("GET", url, params=query)
            body = self._parse(resp)
            items.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
            query = None  # nextLink already carries the full query string
            pages += 1
        capped = url is not None
        return items, capped

    def check(self) -> dict:
        """Cheapest possible Graph round-trip, for health_check's `graph` probe.

        Deliberately ``GET /users`` (not ``/organization``): every deployment
        of this server needs ``User.Read.All`` regardless of auth mode (it's
        the permission ``get_user`` itself needs), so this probe only
        requires what the documented minimum permissions already grant.
        ``/organization`` looks equally cheap but needs the undocumented
        ``Organization.Read.All`` -- an app-only registration holding exactly
        the permissions this README lists would fail that probe and report
        ``status: "error"`` even though every tool actually works.
        """
        try:
            self.get("/users", params={"$top": 1, "$select": "id"})
        except GraphError as e:
            return {"auth": "error", "detail": str(e)}
        return {"auth": "ok", "detail": None}

    def probe_signin_access(self) -> dict:
        """Check whether the current credential can read sign-in logs at all.

        Used by health_check's `signin_probe` to distinguish "Graph reachable"
        (graph: ok) from "Graph reachable but every signin/audit tool will
        fail" (status: degraded).
        """
        try:
            self.get("/auditLogs/signIns", params={"$top": 1})
        except GraphError as e:
            return {"auth": "error", "detail": str(e)}
        return {"auth": "ok", "detail": None}

    def _parse(self, resp: httpx.Response) -> dict:
        if resp.status_code == 401:
            raise GraphAuthError("Graph rejected the access token (401)")
        if resp.status_code == 403:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raise GraphPermissionError(_translate_permission_error(body))
        if resp.status_code >= 400:
            try:
                body = resp.json()
                message = body.get("error", {}).get("message", resp.text[:200])
            except ValueError:
                message = resp.text[:200]
            raise GraphError(f"Graph request failed ({resp.status_code}): {message}")
        return resp.json()
