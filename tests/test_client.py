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
    GRAPH_BASE,
    GraphAuthError,
    GraphClient,
    GraphError,
    GraphPermissionError,
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
