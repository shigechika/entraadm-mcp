"""Synchronous Microsoft Graph and Azure Resource Manager clients: auth, paging, error translation.

Deliberately not built on msgraph-sdk/kiota or the azure-mgmt-* SDKs -- those
are heavy and their generated request builders don't play well with the
respx-based testing used throughout this family of servers. Every tool in
server.py talks to Graph exclusively through GraphClient and to ARM
exclusively through ArmClient, so the request/response shape (paging,
permission-error translation, retry policy) lives in exactly one place:
``_RestClient``, which both subclass with their own base URL, token scope,
paging key and 403 translation.
"""

from __future__ import annotations

import re
import time

import httpx
from azure.identity import AzureCliCredential, ClientSecretCredential

from .config import DEFAULT_MAX_PAGES, AuthConfig

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"

#: ARM requires ``api-version`` on every request. One constant per resource
#: provider; the tests assert each one is sent (continuation pages carry it
#: inside ``nextLink``).
ARM_API_VERSIONS = {
    "subscriptions": "2022-12-01",
    "virtualMachines": "2024-07-01",
    "vaults": "2023-04-01",
    "backup": "2023-04-01",
    "activityLog": "2015-04-01",
}

#: Refresh the cached token this many seconds before its real expiry, so a
#: request never starts with a token that expires mid-flight.
_TOKEN_REFRESH_MARGIN_SECONDS = 300

_UPN_LIKE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ApiError(Exception):
    """Base error for anything that goes wrong talking to a Microsoft API (Graph or ARM)."""


class ApiDeadline(ApiError):
    """The caller's wall-clock budget ran out before a request could finish."""


class ApiAuthError(ApiError):
    """The credential could not produce a usable access token, or the API rejected it outright."""


class ApiPermissionError(ApiError):
    """The API rejected the request because the caller lacks a required permission or role.

    The message is a human-readable translation of the API's error code (see
    _translate_permission_error / _translate_arm_permission_error), not the
    raw JSON -- a tool caller should be able to act on str(e) directly
    without parsing anything.
    """


#: Historical names, kept so existing imports and ``except`` clauses keep
#: working: the hierarchy predates ArmClient and was named after Graph.
GraphError = ApiError
GraphDeadline = ApiDeadline
GraphAuthError = ApiAuthError
GraphPermissionError = ApiPermissionError


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

#: What an ARM 403 means for this server's tools, as the ``missing_permission``
#: value. ``Reader`` is ``*/read`` and covers every endpoint they use;
#: ``Backup Reader`` alone does not (no ``Microsoft.Compute/virtualMachines/read``).
ARM_ROLE_HINT = "Azure RBAC: Reader role on the subscription"


def _error_of(body) -> dict:
    error = body.get("error") if isinstance(body, dict) else None
    return error if isinstance(error, dict) else {}


def _translate_permission_error(body: dict) -> str:
    error = _error_of(body)
    code = error.get("code", "")
    hint = _PERMISSION_HINTS.get(code)
    if hint:
        return hint
    message = error.get("message") or "permission denied"
    return f"{code or 'permission denied'}: {message}"


def _translate_arm_permission_error(body: dict) -> str:
    error = _error_of(body)
    code = error.get("code", "")
    message = str(error.get("message") or "permission denied")
    if code == "AuthorizationFailed":
        return (
            f"ARM denied the request ({message[:300]}); this credential needs the Reader role "
            "on the subscription (*/read). Backup Reader alone is not enough: the VM list "
            "needs Microsoft.Compute/virtualMachines/read"
        )
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


class _RestClient:
    """Bearer-token REST client shared by GraphClient and ArmClient.

    Subclasses set ``api_name`` (for messages), ``base_url``, ``scope``,
    ``next_link_key`` and override ``_translate_403``. Everything else --
    token caching, retry budgets, the deadline-bounded request, paging -- is
    identical for the two APIs.

    Args:
        config: Resolved AuthConfig (see config.AuthConfig.from_env).
        credential: Injectable azure-identity credential (`# injectable for
            tests` -- a stub with a `get_token(*scopes) -> AccessToken`
            method). Defaults to building the real credential for config.mode.
            One credential object may be shared by a GraphClient and an
            ArmClient; each client caches its own scope's token.
        http_client: Injectable httpx.Client (`# injectable for tests`, used
            with respx). Defaults to a real client against ``base_url``.
    """

    api_name = "API"
    base_url = ""
    scope = ""
    next_link_key = "nextLink"

    def __init__(self, config: AuthConfig, credential=None, http_client: httpx.Client | None = None):
        self._config = config
        self._credential = credential if credential is not None else _build_credential(config)
        self._http = http_client if http_client is not None else httpx.Client(base_url=self.base_url, timeout=30.0)
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def mode(self) -> str:
        """The resolved auth mode ("app-only" or "azure-cli"), surfaced by health_check as auth_mode."""
        return self._config.mode

    @property
    def credential(self):
        """The azure-identity credential, so a second client for another scope can share it."""
        return self._credential

    def _access_token(self) -> str:
        now = time.time()
        if self._token is not None and self._token_expires_at - now > _TOKEN_REFRESH_MARGIN_SECONDS:
            return self._token
        try:
            token = self._credential.get_token(self.scope)
        except Exception as e:  # azure-identity raises its own exception hierarchy
            raise ApiAuthError(f"could not obtain a {self.api_name} access token ({type(e).__name__})") from e
        self._token = token.token
        self._token_expires_at = token.expires_on
        return self._token

    def _request(
        self, method: str, url: str, params: dict | None = None, deadline: float | None = None
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        # Token acquisition (azure-identity, synchronous) cannot itself be bounded: a
        # cold token that blocks past the deadline is noticed here, before any request.
        if deadline is not None and deadline - time.monotonic() <= 0:
            raise ApiDeadline("deadline passed while obtaining the access token")
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
            timeout: float | None = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ApiDeadline("deadline passed before the request could start")
                timeout = min(30.0, max(remaining, 0.05))  # httpx needs a positive value
            try:
                if timeout is None:
                    resp = self._http.request(method, url, params=params, headers=headers)
                else:
                    resp = self._bounded_request(method, url, params, headers, timeout, deadline)
            except httpx.RequestError as e:
                # A connection/DNS/timeout failure never reaches _parse(), so
                # without this it would propagate as a bare httpx exception --
                # none of the ApiError family a tool's except clause
                # catches, crashing the tool call instead of degrading it.
                if network_retries_left > 0:
                    self._sleep_within(2 ** (2 - network_retries_left), deadline)
                    network_retries_left -= 1
                    continue
                raise ApiError(f"{self.api_name} request failed: network error ({type(e).__name__})") from e
            if resp.status_code == 429 and not retried_429:
                retried_429 = True
                self._sleep_within(_parse_retry_after(resp.headers.get("Retry-After")), deadline)
                continue
            if resp.status_code >= 500 and server_retries_left > 0:
                self._sleep_within(2 ** (2 - server_retries_left), deadline)
                server_retries_left -= 1
                continue
            return resp

    def _bounded_request(self, method, url, params, headers, timeout, deadline) -> httpx.Response:
        """One request whose *total* time (connect, headers and body) stops at ``deadline``.

        httpx's timeout is per operation and the read timeout restarts on every chunk, so a
        response that trickles in would outlast it. The body is read chunk by chunk and the
        wall clock is checked between chunks (ApiDeadline past it).
        """
        with self._http.stream(method, url, params=params, headers=headers, timeout=timeout) as resp:
            chunks = []
            for chunk in resp.iter_raw():
                # Checked before taking the next chunk: a body that has just finished
                # arriving is kept even if it ended a little past the deadline.
                if time.monotonic() >= deadline:
                    raise ApiDeadline("deadline passed while reading the response")
                chunks.append(chunk)
            return httpx.Response(
                resp.status_code, headers=resp.headers, content=b"".join(chunks), request=resp.request
            )

    @staticmethod
    def _sleep_within(seconds: float, deadline: float | None) -> None:
        """Sleep, or raise ApiDeadline when the wait would end past ``deadline``."""
        if deadline is not None and time.monotonic() + seconds >= deadline:
            raise ApiDeadline("deadline reached while waiting to retry")
        time.sleep(seconds)

    def get(self, path: str, params: dict | None = None, deadline: float | None = None) -> dict:
        """GET a single resource (no paging). ``path`` is relative to ``base_url``, e.g. "/users"."""
        resp = self._request("GET", path, params=params, deadline=deadline)
        return self._parse(resp)

    def post(self, path: str, deadline: float | None = None) -> dict:
        """POST to an action with no request body (e.g. ``/users/{id}/revokeSignInSessions``).

        Retried like ``get`` (429 once, 5xx and network errors twice), so only
        idempotent actions may use it.
        """
        resp = self._request("POST", path, deadline=deadline)
        return self._parse(resp)

    def _same_origin(self, url: str) -> bool:
        """Whether a continuation URL stays on this client's own API host.

        The bearer token goes on every request this client makes, so a
        ``nextLink`` naming any other scheme/host/port must not be followed:
        it would hand the token to that host. A relative link is fine (httpx
        resolves it against ``base_url``).
        """
        try:
            link = httpx.URL(url)
            base = httpx.URL(self.base_url)
        except (httpx.InvalidURL, TypeError):
            return False
        if not link.host and not link.scheme:
            return True  # path-relative; httpx resolves it against base_url
        # A scheme-relative "//host/path" has a host but no scheme: it is not
        # absolute to httpx, and it names another host.
        return (link.scheme, link.host, link.port) == (base.scheme, base.host, base.port)

    def get_paged(
        self,
        path: str,
        params: dict | None = None,
        max_pages: int = DEFAULT_MAX_PAGES,
        deadline: float | None = None,
    ) -> tuple[list, bool]:
        """GET a collection, following the continuation link up to ``max_pages``.

        Returns ``(items, capped)`` where ``capped`` is True iff a nextLink
        still existed when the page budget ran out -- callers must surface
        this so a partial scan is never reported as if it were exhaustive.

        ``deadline`` is an absolute ``time.monotonic()`` timestamp. When it passes
        (between pages, or while a request or its retry wait is in flight) the pages
        fetched so far are returned with ``capped=True``.

        A continuation link that points at a foreign host raises ApiError
        rather than being followed with the token attached.
        """
        items: list = []
        url: str | None = path
        query = params
        pages = 0
        while url is not None and pages < max_pages:
            try:
                resp = self._request("GET", url, params=query, deadline=deadline)
            except ApiDeadline:
                return items, True
            body = self._parse(resp)
            value = body.get("value", [])
            items.extend(value if isinstance(value, list) else [])
            url = body.get(self.next_link_key)
            if url is not None and not (isinstance(url, str) and self._same_origin(url)):
                raise ApiError(f"{self.api_name} returned a continuation link to a foreign host; not followed")
            query = None  # nextLink already carries the full query string
            pages += 1
        capped = url is not None
        return items, capped

    def _translate_403(self, body: dict) -> str:
        return _translate_permission_error(body)

    def _parse(self, resp: httpx.Response) -> dict:
        if resp.status_code == 401:
            raise ApiAuthError(f"{self.api_name} rejected the access token (401)")
        if resp.status_code == 403:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raise ApiPermissionError(self._translate_403(body))
        if resp.status_code >= 400:
            try:
                body = resp.json()
                message = _error_of(body).get("message", resp.text[:200])
            except ValueError:
                message = resp.text[:200]
            raise ApiError(f"{self.api_name} request failed ({resp.status_code}): {message}")
        try:
            body = resp.json()
        except ValueError:
            raise ApiError(f"{self.api_name} returned a non-JSON body ({resp.status_code})") from None
        return body if isinstance(body, dict) else {"value": body}


class GraphClient(_RestClient):
    """Thin Microsoft Graph client: token handling, paging, permission translation."""

    api_name = "Graph"
    base_url = GRAPH_BASE
    scope = GRAPH_SCOPE
    next_link_key = "@odata.nextLink"

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
        except ApiError as e:
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
        except ApiError as e:
            return {"auth": "error", "detail": str(e)}
        return {"auth": "ok", "detail": None}


class ArmClient(_RestClient):
    """Azure Resource Manager client for the backup-posture tools.

    Same credential object as GraphClient, different token scope. ARM pages
    with a bare ``nextLink`` and reports an RBAC denial as
    ``AuthorizationFailed``; both differences live here.
    """

    api_name = "ARM"
    base_url = ARM_BASE
    scope = ARM_SCOPE
    next_link_key = "nextLink"

    def _translate_403(self, body: dict) -> str:
        return _translate_arm_permission_error(body)

    def check(self, deadline: float | None = None) -> dict:
        """ARM round-trip for health_check's informational ``arm`` probe.

        ``GET /subscriptions`` needs no RBAC at all (it lists what the
        credential can see), so ``auth: ok`` with ``subscriptions: 0`` means
        "ARM reachable, no Reader role granted anywhere yet". ``capped`` is
        True when ARM had more pages than the one this probe reads.
        """
        try:
            # One page via get(), not get_paged(): a deadline that expires before ARM
            # answers must surface as an error here, not as "ok, 0 subscriptions".
            body = self.get(
                "/subscriptions", params={"api-version": ARM_API_VERSIONS["subscriptions"]}, deadline=deadline
            )
        except ApiError as e:
            return {"auth": "error", "detail": str(e), "subscriptions": None, "capped": None}
        value = body.get("value", [])
        count = len(value) if isinstance(value, list) else 0
        return {"auth": "ok", "detail": None, "subscriptions": count, "capped": body.get("nextLink") is not None}
