"""Tests for GraphClient: auth token handling, paging, retries, error translation.

httpx is mocked via respx's global transport patching (``@respx.mock``), so
GraphClient's real ``httpx.Client(base_url=GRAPH_BASE)`` (built when no
``http_client`` is injected) is intercepted transparently -- no need to wire
a custom client through the constructor for these tests.
"""

from collections import namedtuple

import httpx
import pytest
import respx

from entraadm_mcp.client import (
    ARM_API_VERSIONS,
    ARM_BASE,
    ARM_SCOPE,
    GRAPH_BASE,
    GRAPH_SCOPE,
    ApiError,
    ApiPermissionError,
    ArmClient,
    GraphAuthError,
    GraphClient,
    GraphError,
    GraphPermissionError,
    _parse_retry_after,
    odata_quote,
    validate_upn,
)
from entraadm_mcp.config import AuthConfig

AccessToken = namedtuple("AccessToken", ["token", "expires_on"])


class FakeCredential:
    """Stub for an azure-identity credential: injectable for tests.

    ``tokens`` is a list of AccessToken instances or Exception instances,
    consumed in order (the last entry repeats once exhausted).
    """

    def __init__(self, tokens):
        self.tokens = list(tokens)
        self.calls = 0

    def get_token(self, *scopes):
        self.calls += 1
        item = self.tokens[min(self.calls, len(self.tokens)) - 1]
        if isinstance(item, Exception):
            raise item
        return item


def _client(credential=None, now=None, monkeypatch=None):
    cred = credential if credential is not None else FakeCredential([AccessToken("tok", 10_000_000_000)])
    if now is not None:
        monkeypatch.setattr("entraadm_mcp.client.time.time", lambda: now)
    return GraphClient(AuthConfig(mode="azure-cli"), credential=cred), cred


# ---------------------------------------------------------------------------
# odata_quote / validate_upn
# ---------------------------------------------------------------------------


def test_odata_quote_escapes_embedded_single_quotes():
    assert odata_quote("O'Brien") == "'O''Brien'"


def test_odata_quote_wraps_plain_values():
    assert odata_quote("user@example.edu") == "'user@example.edu'"


def test_validate_upn_accepts_a_normal_address():
    assert validate_upn("user@example.edu") == "user@example.edu"


@pytest.mark.parametrize(
    "value",
    [
        "not-an-email",
        "user@",
        "@example.edu",
        "user name@example.edu",  # embedded space
        "a/b@example.edu' or '1'='1",  # attempted filter-injection payload
    ],
)
def test_validate_upn_rejects_non_upn_shapes(value):
    with pytest.raises(GraphError, match="is not a user principal name"):
        validate_upn(value)


def test_parse_retry_after_accepts_delay_seconds():
    assert _parse_retry_after("5") == 5.0


def test_parse_retry_after_falls_back_on_http_date_form():
    assert _parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT") == 1.0


def test_parse_retry_after_falls_back_when_header_absent():
    assert _parse_retry_after(None) == 1.0


# ---------------------------------------------------------------------------
# get / paging
# ---------------------------------------------------------------------------


@respx.mock
def test_get_returns_parsed_json(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(return_value=httpx.Response(200, json={"value": [{"id": "t1"}]}))
    client, _cred = _client(monkeypatch=monkeypatch)
    body = client.get("/organization")
    assert body == {"value": [{"id": "t1"}]}


@respx.mock
def test_get_paged_follows_nextlink_and_reports_not_capped(monkeypatch):
    # respx routes match on path by default (a route registered without an
    # explicit `params=` constraint matches *any* query string for that
    # path), so two requests to the same path -- the initial call and the
    # nextLink follow-up -- both land on one route. `side_effect` returns
    # them in call order instead of registering two URL-string routes that
    # would otherwise both match every request to this path.
    page2_url = f"{GRAPH_BASE}/auditLogs/signIns?$skiptoken=abc"
    route = respx.get(f"{GRAPH_BASE}/auditLogs/signIns")
    route.side_effect = [
        httpx.Response(200, json={"value": [{"id": "1"}], "@odata.nextLink": page2_url}),
        httpx.Response(200, json={"value": [{"id": "2"}]}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)

    items, capped = client.get_paged("/auditLogs/signIns", max_pages=5)

    assert [i["id"] for i in items] == ["1", "2"]
    assert capped is False
    assert route.call_count == 2


@respx.mock
def test_get_paged_stops_at_max_pages_and_reports_capped(monkeypatch):
    page2_url = f"{GRAPH_BASE}/auditLogs/signIns?$skiptoken=abc"
    route = respx.get(f"{GRAPH_BASE}/auditLogs/signIns")
    route.side_effect = [
        httpx.Response(200, json={"value": [{"id": "1"}], "@odata.nextLink": page2_url}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)

    items, capped = client.get_paged("/auditLogs/signIns", max_pages=1)

    assert [i["id"] for i in items] == ["1"]
    assert capped is True
    assert route.call_count == 1


# ---------------------------------------------------------------------------
# token caching
# ---------------------------------------------------------------------------


@respx.mock
def test_token_is_reused_within_expiry_margin(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(return_value=httpx.Response(200, json={}))
    cred = FakeCredential([AccessToken("tok", expires_on=1_000_000 + 3600)])
    client, _cred = _client(credential=cred, now=1_000_000.0, monkeypatch=monkeypatch)

    client.get("/organization")
    client.get("/organization")

    assert cred.calls == 1


@respx.mock
def test_token_is_refreshed_once_inside_the_expiry_margin(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(return_value=httpx.Response(200, json={}))
    cred = FakeCredential(
        [
            AccessToken("tok1", expires_on=1_000_000 + 200),  # < 300s margin from `now`
            AccessToken("tok2", expires_on=1_000_000 + 3600),
        ]
    )
    client, _cred = _client(credential=cred, now=1_000_000.0, monkeypatch=monkeypatch)

    client.get("/organization")
    client.get("/organization")

    assert cred.calls == 2


@respx.mock
def test_credential_failure_raises_graphautherror_without_leaking_secrets(monkeypatch):
    cred = FakeCredential([ValueError("client_secret=super-secret-value is invalid")])
    client, _cred = _client(credential=cred, now=1_000_000.0, monkeypatch=monkeypatch)

    with pytest.raises(GraphAuthError) as excinfo:
        client.get("/organization")

    assert "super-secret-value" not in str(excinfo.value)
    assert "ValueError" in str(excinfo.value)


# ---------------------------------------------------------------------------
# error translation
# ---------------------------------------------------------------------------


@respx.mock
def test_401_raises_graphautherror(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(return_value=httpx.Response(401, json={}))
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphAuthError):
        client.get("/organization")


@respx.mock
def test_403_unsupported_role_gets_translated_to_actionable_hint(monkeypatch):
    respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(
        return_value=httpx.Response(
            403,
            json={"error": {"code": "Authentication_RequestFromUnsupportedUserRole", "message": "denied"}},
        )
    )
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphPermissionError, match="Reports Reader"):
        client.get("/auditLogs/signIns")


@respx.mock
def test_403_unknown_code_falls_back_to_raw_code_and_message(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(
        return_value=httpx.Response(403, json={"error": {"code": "SomeWeirdCode", "message": "nope"}})
    )
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphPermissionError, match="SomeWeirdCode: nope"):
        client.get("/organization")


@respx.mock
def test_other_4xx_raises_grapherror_with_status_and_message(monkeypatch):
    respx.get(f"{GRAPH_BASE}/organization").mock(
        return_value=httpx.Response(404, json={"error": {"message": "not found"}})
    )
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphError, match="404"):
        client.get("/organization")


# ---------------------------------------------------------------------------
# retries
# ---------------------------------------------------------------------------


@respx.mock
def test_429_is_retried_once_then_succeeds(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json={"ok": True}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    body = client.get("/organization")
    assert body == {"ok": True}
    assert route.call_count == 2


@respx.mock
def test_429_is_not_retried_a_second_time(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(429, headers={"Retry-After": "1"}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphError, match="429"):
        client.get("/organization")
    assert route.call_count == 2


@respx.mock
def test_5xx_is_retried_with_backoff_up_to_two_times(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.Response(500),
        httpx.Response(500),
        httpx.Response(200, json={"ok": True}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    body = client.get("/organization")
    assert body == {"ok": True}
    assert route.call_count == 3


@respx.mock
def test_5xx_gives_up_after_three_attempts(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [httpx.Response(500), httpx.Response(500), httpx.Response(500)]
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphError, match="500"):
        client.get("/organization")
    assert route.call_count == 3


@respx.mock
def test_network_error_is_retried_then_raises_grapherror(monkeypatch):
    # httpx.RequestError (DNS failure, connection refused, timeout) is
    # raised by the transport before any httpx.Response exists, so it never
    # reaches _parse() -- without a dedicated catch here it would propagate
    # as a bare httpx exception past every tool's `except GraphError`.
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.ConnectError("connection refused"),
        httpx.ConnectError("connection refused"),
        httpx.ConnectError("connection refused"),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(GraphError, match="network error"):
        client.get("/organization")
    assert route.call_count == 3


@respx.mock
def test_network_error_recovers_on_retry(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [httpx.ReadTimeout("timed out"), httpx.Response(200, json={"ok": True})]
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.get("/organization") == {"ok": True}
    assert route.call_count == 2


@respx.mock
def test_429_is_still_retried_after_an_earlier_network_error(monkeypatch):
    # Regression: a shared attempt counter across failure kinds meant a
    # network error on attempt 0 left a 429 on attempt 1 unretried, since
    # the old check was "attempt == 0" rather than "haven't retried a 429
    # yet". Each failure kind must get its own independent budget.
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.ConnectError("connection refused"),
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json={"ok": True}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.get("/organization") == {"ok": True}
    assert route.call_count == 3


@respx.mock
def test_retry_after_falls_back_to_a_default_delay_when_not_numeric(monkeypatch):
    # RFC 9110 also permits an HTTP-date form for Retry-After. Graph is
    # documented to send only delay-seconds, but a non-numeric value must
    # degrade to a fixed backoff instead of raising ValueError -- which
    # would escape as a bare exception, same class of bug as an uncaught
    # httpx.RequestError.
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda s: None)
    route = respx.get(f"{GRAPH_BASE}/organization")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        httpx.Response(200, json={"ok": True}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.get("/organization") == {"ok": True}
    assert route.call_count == 2


# ---------------------------------------------------------------------------
# check() / probe_signin_access()
# ---------------------------------------------------------------------------


@respx.mock
def test_check_reports_ok(monkeypatch):
    respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.check() == {"auth": "ok", "detail": None}


@respx.mock
def test_check_reports_detail_on_failure(monkeypatch):
    respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(401, json={}))
    client, _cred = _client(monkeypatch=monkeypatch)
    result = client.check()
    assert result["auth"] == "error"
    assert result["detail"]


@respx.mock
def test_check_only_needs_user_read_all_not_organization_read_all(monkeypatch):
    # A deployment holding exactly the documented minimum permissions
    # (User.Read.All) must pass this probe -- Organization.Read.All is a
    # different, undocumented permission and must never be required here.
    respx.get(f"{GRAPH_BASE}/organization").mock(
        return_value=httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}})
    )
    respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.check() == {"auth": "ok", "detail": None}


@respx.mock
def test_probe_signin_access_ok(monkeypatch):
    respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(monkeypatch=monkeypatch)
    assert client.probe_signin_access() == {"auth": "ok", "detail": None}


@respx.mock
def test_probe_signin_access_degrades_on_permission_error(monkeypatch):
    respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(
        return_value=httpx.Response(403, json={"error": {"code": "Authentication_RequestFromUnsupportedUserRole"}})
    )
    client, _cred = _client(monkeypatch=monkeypatch)
    result = client.probe_signin_access()
    assert result["auth"] == "error"
    assert "Reports Reader" in result["detail"]


def test_mode_property_reflects_config():
    client = GraphClient(AuthConfig(mode="azure-cli"), credential=FakeCredential([AccessToken("t", 9_999_999_999)]))
    assert client.mode == "azure-cli"


# ---------------------------------------------------------------------------
# wall-clock deadline
# ---------------------------------------------------------------------------


@respx.mock
def test_get_paged_returns_partial_when_deadline_passes_between_pages(monkeypatch):
    import time

    page2_url = f"{GRAPH_BASE}/auditLogs/signIns?$skiptoken=abc"
    route = respx.get(f"{GRAPH_BASE}/auditLogs/signIns")
    route.side_effect = [
        httpx.Response(200, json={"value": [{"id": "1"}], "@odata.nextLink": page2_url}),
        httpx.Response(200, json={"value": [{"id": "2"}]}),
    ]
    client, _cred = _client(monkeypatch=monkeypatch)
    real = client._request

    def slow_first(method, url, params=None, deadline=None):
        resp = real(method, url, params=params, deadline=deadline)
        time.sleep(0.25)  # the first page eats the whole budget
        return resp

    monkeypatch.setattr(client, "_request", slow_first)

    items, capped = client.get_paged("/auditLogs/signIns", max_pages=5, deadline=time.monotonic() + 0.2)

    assert [i["id"] for i in items] == ["1"]
    assert capped is True
    assert route.call_count == 1


@respx.mock
def test_request_does_not_retry_past_the_deadline(monkeypatch):
    import time

    route = respx.get(f"{GRAPH_BASE}/auditLogs/signIns")
    route.side_effect = httpx.ConnectTimeout("slow")
    client, _cred = _client(monkeypatch=monkeypatch)
    started = time.monotonic()

    items, capped = client.get_paged("/auditLogs/signIns", deadline=time.monotonic() + 1.0)

    assert items == [] and capped is True
    assert route.call_count <= 2  # the 2 s retry wait would end past the 1 s deadline
    assert time.monotonic() - started < 3.0


@respx.mock
def test_no_deadline_keeps_the_default_timeout(monkeypatch):
    respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(monkeypatch=monkeypatch)
    seen = {}
    real = client._http.request

    def spy(method, url, **kwargs):
        seen["has_timeout"] = "timeout" in kwargs
        return real(method, url, **kwargs)

    monkeypatch.setattr(client._http, "request", spy)
    client.get("/users")
    assert seen["has_timeout"] is False


@respx.mock
def test_request_timeout_has_no_one_second_floor(monkeypatch):
    import time

    route = respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(monkeypatch=monkeypatch)
    client.get("/users", deadline=time.monotonic() + 0.3)
    assert route.calls.last.request.extensions["timeout"]["read"] <= 0.3


@respx.mock
def test_deadline_passed_during_token_acquisition_is_partial(monkeypatch):
    import time

    class SlowCredential:
        def get_token(self, *scopes, **kwargs):
            time.sleep(0.3)  # a cold token that eats the budget
            return AccessToken("tok", 10_000_000_000)

    route = respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _client(credential=SlowCredential(), monkeypatch=monkeypatch)
    items, capped = client.get_paged("/auditLogs/signIns", deadline=time.monotonic() + 0.1)
    assert items == [] and capped is True
    assert route.call_count == 0


@respx.mock
def test_trickling_body_is_cut_off_at_the_deadline(monkeypatch):
    import time

    def trickle():
        for _ in range(20):
            time.sleep(0.05)
            yield b" "
        yield b'{"value": []}'

    respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(return_value=httpx.Response(200, content=trickle()))
    client, _cred = _client(monkeypatch=monkeypatch)
    started = time.monotonic()
    items, capped = client.get_paged("/auditLogs/signIns", deadline=time.monotonic() + 0.2)
    assert items == [] and capped is True
    assert time.monotonic() - started < 0.8


# ---------------------------------------------------------------------------
# ArmClient: scope, api-version, nextLink, RBAC translation
# ---------------------------------------------------------------------------


class ScopeRecordingCredential(FakeCredential):
    def __init__(self, tokens):
        super().__init__(tokens)
        self.scopes = []

    def get_token(self, *scopes, **kwargs):
        self.scopes.append(scopes)
        return super().get_token(*scopes)


def _arm_client(credential=None):
    cred = credential if credential is not None else ScopeRecordingCredential([AccessToken("tok", 10_000_000_000)])
    return ArmClient(AuthConfig(mode="azure-cli"), credential=cred), cred


@respx.mock
def test_arm_requests_the_management_scope_and_sends_api_version():
    route = respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(200, json={"value": []}))
    client, cred = _arm_client()
    client.get_paged("/subscriptions", params={"api-version": ARM_API_VERSIONS["subscriptions"]})
    assert cred.scopes == [(ARM_SCOPE,)]
    sent = route.calls[0].request
    assert sent.url.params["api-version"] == ARM_API_VERSIONS["subscriptions"]
    assert sent.headers["Authorization"] == "Bearer tok"


@respx.mock
def test_arm_follows_bare_nextlink_and_keeps_api_version_on_the_continuation():
    page2 = f"{ARM_BASE}/subscriptions?api-version={ARM_API_VERSIONS['subscriptions']}&%24skiptoken=abc"
    route = respx.get(f"{ARM_BASE}/subscriptions")
    route.side_effect = [
        httpx.Response(200, json={"value": [{"subscriptionId": "1"}], "nextLink": page2}),
        httpx.Response(200, json={"value": [{"subscriptionId": "2"}]}),
    ]
    client, _cred = _arm_client()
    items, capped = client.get_paged("/subscriptions", params={"api-version": ARM_API_VERSIONS["subscriptions"]})
    assert [i["subscriptionId"] for i in items] == ["1", "2"]
    assert capped is False
    assert route.calls[1].request.url.params["api-version"] == ARM_API_VERSIONS["subscriptions"]
    assert route.calls[1].request.url.params["$skiptoken"] == "abc"


@respx.mock
def test_arm_reports_capped_when_a_nextlink_remains():
    page2 = f"{ARM_BASE}/subscriptions?api-version=x&%24skiptoken=abc"
    respx.get(f"{ARM_BASE}/subscriptions").mock(
        return_value=httpx.Response(200, json={"value": [{"subscriptionId": "1"}], "nextLink": page2})
    )
    client, _cred = _arm_client()
    items, capped = client.get_paged("/subscriptions", params={"api-version": "x"}, max_pages=1)
    assert len(items) == 1 and capped is True


@respx.mock
@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/subscriptions?api-version=x",
        "http://management.azure.com/subscriptions?api-version=x",
        "https://management.azure.com:8443/subscriptions?api-version=x",
    ],
)
def test_foreign_nextlink_is_not_followed_with_the_token(link):
    # The bearer token goes on every request; a continuation link naming any
    # other scheme/host/port would hand it to that host.
    foreign = respx.get(url__regex=r"^https?://(evil\.example|management\.azure\.com:8443)/.*").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    plain_http = respx.get(url__regex=r"^http://management\.azure\.com/.*").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    respx.get(f"{ARM_BASE}/subscriptions").mock(
        return_value=httpx.Response(200, json={"value": [{"subscriptionId": "1"}], "nextLink": link})
    )
    client, _cred = _arm_client()
    with pytest.raises(ApiError, match="foreign host"):
        client.get_paged("/subscriptions", params={"api-version": "x"}, max_pages=5)
    assert foreign.call_count == 0 and plain_http.call_count == 0


@respx.mock
def test_graph_foreign_nextlink_is_not_followed_either(monkeypatch):
    foreign = respx.get(url__regex=r"^https://evil\.example/.*").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(
        return_value=httpx.Response(
            200, json={"value": [{"id": "1"}], "@odata.nextLink": "https://evil.example/auditLogs/signIns?x=1"}
        )
    )
    client, _cred = _client(monkeypatch=monkeypatch)
    with pytest.raises(ApiError, match="foreign host"):
        client.get_paged("/auditLogs/signIns", max_pages=5)
    assert foreign.call_count == 0


@respx.mock
def test_relative_nextlink_is_followed():
    route = respx.get(f"{ARM_BASE}/subscriptions")
    route.side_effect = [
        httpx.Response(200, json={"value": [{"subscriptionId": "1"}], "nextLink": "/subscriptions?api-version=x&p=2"}),
        httpx.Response(200, json={"value": [{"subscriptionId": "2"}]}),
    ]
    client, _cred = _arm_client()
    items, capped = client.get_paged("/subscriptions", params={"api-version": "x"})
    assert len(items) == 2 and capped is False


@respx.mock
def test_arm_authorization_failed_translates_to_the_reader_role_hint():
    respx.get(f"{ARM_BASE}/subscriptions/s/providers/Microsoft.Compute/virtualMachines").mock(
        return_value=httpx.Response(
            403,
            json={
                "error": {
                    "code": "AuthorizationFailed",
                    "message": "The client does not have authorization to perform action "
                    "'Microsoft.Compute/virtualMachines/read' over scope '/subscriptions/s'",
                }
            },
        )
    )
    client, _cred = _arm_client()
    with pytest.raises(ApiPermissionError) as info:
        client.get("/subscriptions/s/providers/Microsoft.Compute/virtualMachines", params={"api-version": "x"})
    message = str(info.value)
    assert "Reader role" in message and "virtualMachines/read" in message
    assert "Backup Reader alone is not enough" in message


@respx.mock
def test_arm_other_403_codes_fall_back_to_code_and_message():
    respx.get(f"{ARM_BASE}/subscriptions").mock(
        return_value=httpx.Response(403, json={"error": {"code": "DisallowedProvider", "message": "nope"}})
    )
    client, _cred = _arm_client()
    with pytest.raises(ApiPermissionError, match="DisallowedProvider: nope"):
        client.get("/subscriptions", params={"api-version": "x"})


@respx.mock
def test_arm_non_json_error_body_is_reported_without_a_traceback():
    respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(400, text="<html>bad</html>"))
    client, _cred = _arm_client()
    with pytest.raises(ApiError, match=r"ARM request failed \(400\): <html>bad</html>"):
        client.get("/subscriptions", params={"api-version": "x"})


@respx.mock
def test_arm_non_json_success_body_is_an_error_not_a_crash():
    respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(200, text="not json"))
    client, _cred = _arm_client()
    with pytest.raises(ApiError, match="non-JSON"):
        client.get("/subscriptions", params={"api-version": "x"})


@respx.mock
def test_arm_get_paged_folds_an_expired_deadline_into_capped():
    import time

    route = respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(200, json={"value": [{}]}))
    client, _cred = _arm_client()
    items, capped = client.get_paged("/subscriptions", params={"api-version": "x"}, deadline=time.monotonic() - 1)
    assert items == [] and capped is True
    assert route.call_count == 0


@respx.mock
def test_graph_and_arm_share_one_credential_with_separate_token_caches(monkeypatch):
    respx.get(f"{GRAPH_BASE}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(200, json={"value": []}))
    cred = ScopeRecordingCredential([AccessToken("g", 10_000_000_000), AccessToken("a", 10_000_000_000)])
    graph = GraphClient(AuthConfig(mode="azure-cli"), credential=cred)
    arm = ArmClient(AuthConfig(mode="azure-cli"), credential=graph.credential)
    graph.get("/users")
    arm.get("/subscriptions", params={"api-version": "x"})
    graph.get("/users")
    arm.get("/subscriptions", params={"api-version": "x"})
    # one token per scope, each reused on the second call
    assert cred.scopes == [(GRAPH_SCOPE,), (ARM_SCOPE,)]
    assert graph._token == "g" and arm._token == "a"


@respx.mock
def test_arm_check_counts_visible_subscriptions_and_reports_errors():
    respx.get(f"{ARM_BASE}/subscriptions").mock(
        return_value=httpx.Response(200, json={"value": [{"subscriptionId": "1"}, {"subscriptionId": "2"}]})
    )
    client, _cred = _arm_client()
    assert client.check() == {"auth": "ok", "detail": None, "subscriptions": 2, "capped": False}
    respx.get(f"{ARM_BASE}/subscriptions").mock(
        return_value=httpx.Response(200, json={"value": [{"subscriptionId": "1"}], "nextLink": f"{ARM_BASE}/x"})
    )
    assert _arm_client()[0].check()["capped"] is True
    respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(401))
    client, _cred = _arm_client()
    result = client.check()
    assert result["auth"] == "error" and result["subscriptions"] is None and "401" in result["detail"]


@respx.mock
def test_arm_check_reports_an_expired_deadline_as_an_error_not_as_zero_subscriptions():
    import time

    route = respx.get(f"{ARM_BASE}/subscriptions").mock(return_value=httpx.Response(200, json={"value": []}))
    client, _cred = _arm_client()
    result = client.check(deadline=time.monotonic() - 1)
    assert result["auth"] == "error" and result["subscriptions"] is None and "deadline" in result["detail"]
    assert route.call_count == 0
