"""Tests for audit_log_search_start / audit_log_search_result.

End to end through a real GraphClient: httpx is mocked with respx (the
transport is patched globally, as in test_client.py) and the client is
injected into ``server._state`` with a stub credential, so these tests see
the exact request each tool sends and the client's own retry policy.
"""

import datetime
import json
from collections import namedtuple

import httpx
import pytest
import respx

import entraadm_mcp.server as server
from entraadm_mcp.client import GRAPH_BASE, GraphClient
from entraadm_mcp.config import AuthConfig, TenantConfig, Tenants

AccessToken = namedtuple("AccessToken", ["token", "expires_on"])

QUERIES_URL = f"{GRAPH_BASE}/security/auditLog/queries"
QUERY_ID = "168ec429-084b-a489-90d8-504a87846305"
QUERY_URL = f"{QUERIES_URL}/{QUERY_ID}"
RECORDS_URL = f"{QUERY_URL}/records"


class FakeCredential:
    def __init__(self, token="tok"):
        self.token = token

    def get_token(self, *scopes):
        return AccessToken(self.token, 10_000_000_000)


def _graph(token="tok"):
    return GraphClient(AuthConfig(mode="app-only"), credential=FakeCredential(token))


@pytest.fixture
def graph(monkeypatch):
    monkeypatch.setattr("entraadm_mcp.client.time.sleep", lambda _s: None)
    monkeypatch.setitem(
        server._state, "tenants", Tenants((TenantConfig("default", AuthConfig("app-only"), default=True),))
    )
    monkeypatch.setitem(server._state, "clients", {})
    client = _graph()
    monkeypatch.setitem(server._state, "client", client)
    return client


def _sent(route) -> dict:
    return json.loads(route.calls.last.request.content)


def _created(**overrides):
    body = {"id": QUERY_ID, "displayName": "entraadm-mcp", "status": "notStarted"}
    body.update(overrides)
    return httpx.Response(201, json=body)


# ---------------------------------------------------------------------------
# audit_log_search_start
# ---------------------------------------------------------------------------


@respx.mock
def test_start_sends_the_filters_and_returns_the_query_id(graph):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    out = server.audit_log_search_start(
        user="someone@example.edu",
        hours=48,
        record_types=["sharePointFileOperation"],
        operations=["FileDownloaded", "New-InboxRule", "Update user."],
        ip_addresses=["203.0.113.7", "2001:db8::1"],
        keyword="invoice",
        service="SharePoint",
        object_ids=["https://files.example.edu/sites/a/doc.docx"],
    )
    assert out["created"] is True and out["query_id"] == QUERY_ID and out["status"] == "notStarted"
    body = _sent(route)
    assert body["@odata.type"] == "#microsoft.graph.security.auditLogQuery"
    assert body["displayName"].startswith("entraadm-mcp ")
    assert body["userPrincipalNameFilters"] == ["someone@example.edu"]
    assert body["recordTypeFilters"] == ["sharePointFileOperation"]
    assert body["operationFilters"] == ["FileDownloaded", "New-InboxRule", "Update user."]
    assert body["ipAddressFilters"] == ["203.0.113.7", "2001:db8::1"]
    assert body["keywordFilter"] == "invoice"
    assert body["serviceFilters"] == ["SharePoint"]
    assert "serviceFilter" not in body
    assert body["objectIdFilters"] == ["https://files.example.edu/sites/a/doc.docx"]
    start = datetime.datetime.fromisoformat(body["filterStartDateTime"].replace("Z", "+00:00"))
    end = datetime.datetime.fromisoformat(body["filterEndDateTime"].replace("Z", "+00:00"))
    assert end - start == datetime.timedelta(hours=48)
    assert out["window_start"] == body["filterStartDateTime"]
    assert out["filters"]["user"] == "someone@example.edu"


@respx.mock
def test_start_leaves_unset_filters_out_of_the_body(graph):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    server.audit_log_search_start(ip_addresses=["198.51.100.1"])
    body = _sent(route)
    assert body["ipAddressFilters"] == ["198.51.100.1"]
    for field in ("userPrincipalNameFilters", "recordTypeFilters", "operationFilters", "keywordFilter"):
        assert field not in body


@respx.mock
def test_start_hours_is_clamped_to_180_days(graph):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    server.audit_log_search_start(user="someone@example.edu", hours=999_999)
    body = _sent(route)
    start = datetime.datetime.fromisoformat(body["filterStartDateTime"].replace("Z", "+00:00"))
    end = datetime.datetime.fromisoformat(body["filterEndDateTime"].replace("Z", "+00:00"))
    assert end - start == datetime.timedelta(days=180)


@respx.mock
def test_start_explicit_window_is_sent_in_utc(graph):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    out = server.audit_log_search_start(
        user="someone@example.edu", start="2026-10-21T22:00:00+09:00", end="2026-10-22T09:00+09:00"
    )
    assert out["created"] is True
    body = _sent(route)
    assert body["filterStartDateTime"] == "2026-10-21T13:00:00Z"
    assert body["filterEndDateTime"] == "2026-10-22T00:00:00Z"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"user": "not-an-address"},
        {"user": "x@example.edu", "start": "2026-10-21T22:00:00"},  # no offset
        {"user": "x@example.edu", "start": "2026-10-22T00:00:00Z", "end": "2026-10-21T00:00:00Z"},
        {"user": "x@example.edu", "start": "2020-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
        {"ip_addresses": ["203.0.113.7/24"]},
        {"ip_addresses": "203.0.113.7"},
        {"ip_addresses": ["198.51.100.1"] * 21},
        {"operations": ["FileDownloaded') or 1 eq 1"]},
        {"operations": [""]},
        {"record_types": ["exchange Item"]},
        {"service": "Exchange; drop"},
        {"keyword": "a" * 257},
        {"keyword": "line\nbreak"},
        {"object_ids": ["x" * 1025]},
        {},
        {"keyword": "   "},
        {"user": " someone@example.edu"},
    ],
)
@respx.mock
def test_start_rejects_bad_input_without_sending_anything(graph, kwargs):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    out = server.audit_log_search_start(**kwargs)
    assert out["created"] is False and out["error"]
    assert route.call_count == 0


@respx.mock
def test_start_403_is_missing_permission(graph):
    respx.post(QUERIES_URL).mock(
        return_value=httpx.Response(403, json={"error": {"code": "Forbidden", "message": "Missing role permissions"}})
    )
    out = server.audit_log_search_start(user="someone@example.edu")
    assert out["created"] is False
    assert "AuditLogsQuery.Read.All" in out["missing_permission"]
    assert "AuditLogsQuery-Exchange.Read.All" in out["missing_permission"]


@respx.mock
def test_start_429_is_reported_as_rate_limited_and_not_retried(graph):
    route = respx.post(QUERIES_URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "120"}, json={"error": {"message": "Too many"}})
    )
    out = server.audit_log_search_start(user="someone@example.edu")
    assert route.call_count == 1
    assert out["created"] is False and out["rate_limited"] is True
    assert out["retry_after_seconds"] == 120.0
    assert "audit search limits" in out["error"]


@respx.mock
def test_start_5xx_is_an_unknown_outcome_not_retried(graph):
    route = respx.post(QUERIES_URL).mock(return_value=httpx.Response(502))
    out = server.audit_log_search_start(user="someone@example.edu")
    assert route.call_count == 1
    assert out["created"] is None and "may have been created" in out["error"]


@respx.mock
def test_start_answer_without_a_guid_id_is_not_trusted(graph):
    respx.post(QUERIES_URL).mock(return_value=httpx.Response(201, json={"id": "../../users", "status": "x"}))
    out = server.audit_log_search_start(user="someone@example.edu")
    assert out["created"] is None and out["query_id"] is None


TWO = Tenants(
    (
        TenantConfig("staff", AuthConfig("app-only"), ("example.edu",), default=True),
        TenantConfig("students", AuthConfig("app-only"), ("students.example.edu",)),
    ),
    from_file=True,
)


@pytest.fixture
def two_tenants(monkeypatch):
    monkeypatch.setitem(server._state, "tenants", TWO)
    monkeypatch.setitem(server._state, "client", _graph("tok-staff"))
    monkeypatch.setitem(server._state, "clients", {"students": _graph("tok-students")})


@respx.mock
def test_start_runs_in_the_tenant_claiming_the_users_domain(two_tenants):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    out = server.audit_log_search_start(user="someone@students.example.edu")
    assert out["tenant"] == "students"
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok-students"


@respx.mock
def test_start_refuses_an_explicit_tenant_that_does_not_own_the_user(two_tenants):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    out = server.audit_log_search_start(user="someone@students.example.edu", tenant="staff")
    assert "error" in out and route.call_count == 0


@respx.mock
def test_result_reads_the_given_tenant(two_tenants):
    route = respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "running"}))
    out = server.audit_log_search_result(QUERY_ID, tenant="students")
    assert out["tenant"] == "students" and out["done"] is False
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok-students"


# ---------------------------------------------------------------------------
# audit_log_search_result
# ---------------------------------------------------------------------------


def _record(i, **overrides):
    row = {
        "id": f"rec-{i}",
        "createdDateTime": f"2026-10-31T0{i % 10}:00:00Z",
        "auditLogRecordType": "sharePointFileOperation",
        "operation": "FileDownloaded",
        "service": "SharePoint",
        "userPrincipalName": "someone@example.edu",
        "userId": "someone@example.edu",
        "clientIp": "203.0.113.7",
        "objectId": "https://files.example.edu/sites/a/doc.docx",
        "auditData": {
            "ClientIP": "203.0.113.7",
            "UserAgent": "Mozilla/5.0",
            "SourceFileName": "doc.docx",
            "SiteUrl": "https://files.example.edu/sites/a/",
            "ResultStatus": "Succeeded",
            "Body": "secret text that must not be returned",
            "Parameters": [{"Name": "ForwardTo", "Value": "outside@example.org"}, {"Name": "Name", "Value": "r"}],
        },
    }
    row.update(overrides)
    return row


def test_result_rejects_a_non_guid_query_id_without_a_request(graph):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(url__startswith=QUERIES_URL)
        out = server.audit_log_search_result("../../users")
        assert "error" in out and route.call_count == 0


@pytest.mark.parametrize("status", ["notStarted", "running"])
@respx.mock
def test_result_while_running_returns_the_status_only(graph, status):
    respx.get(QUERY_URL).mock(
        return_value=httpx.Response(
            200, json={"id": QUERY_ID, "status": status, "operationFilters": ["FileDownloaded"]}
        )
    )
    records = respx.get(RECORDS_URL).mock(return_value=httpx.Response(200, json={"value": []}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["found"] is True and out["status"] == status and out["done"] is False
    assert out["query"]["operations"] == ["FileDownloaded"]
    assert "records" not in out and records.call_count == 0


@pytest.mark.parametrize("status", ["failed", "cancelled"])
@respx.mock
def test_result_failed_or_cancelled_is_done_with_an_error(graph, status):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": status}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["done"] is True and status in out["error"] and "records" not in out


@respx.mock
def test_result_unknown_status_is_done_so_callers_stop_polling(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "unknownFutureValue"}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["status"] == "unknownFutureValue" and out["done"] is True and out["error"]
    assert "records" not in out


@respx.mock
def test_result_succeeded_pages_the_records_and_summarises_them(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    respx.get(RECORDS_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "value": [_record(1), _record(2, clientIp="[2001:db8::5]:443")],
                    "@odata.nextLink": f"{RECORDS_URL}?$skiptoken=p2",
                },
            ),
            httpx.Response(
                200,
                json={
                    "value": [
                        _record(
                            3,
                            operation="New-InboxRule",
                            service="Exchange",
                            auditLogRecordType="exchangeAdmin",
                            clientIp="",
                            objectId="",
                            auditData=json.dumps({"ClientIP": "203.0.113.7:51234", "ObjectId": "rule-1"}),
                        )
                    ]
                },
            ),
        ]
    )
    out = server.audit_log_search_result(QUERY_ID, top=2, max_pages=5)
    assert out["done"] is True and out["capped"] is False
    summary = out["summary"]
    assert summary["total_records"] == 3
    assert summary["first_seen"] == "2026-10-31T01:00:00Z" and summary["last_seen"] == "2026-10-31T03:00:00Z"
    assert {"operation": "FileDownloaded", "count": 2} in summary["by_operation"]
    assert {"service": "Exchange", "count": 1} in summary["by_service"]
    assert {"record_type": "exchangeAdmin", "count": 1} in summary["by_record_type"]
    assert summary["by_user"] == [{"user": "someone@example.edu", "count": 3}]
    by_ip = {e["client_ip"]: e for e in summary["by_client_ip"]}
    assert by_ip["203.0.113.7"]["count"] == 2  # the port is stripped
    assert by_ip["203.0.113.7"]["first_seen"] == "2026-10-31T01:00:00Z"
    assert by_ip["203.0.113.7"]["last_seen"] == "2026-10-31T03:00:00Z"
    assert by_ip["2001:db8::5"]["count"] == 1
    # newest first, cut to top
    assert out["count"] == 2 and out["records_truncated"] is True
    assert [r["id"] for r in out["records"]] == ["rec-3", "rec-2"]
    newest = out["records"][0]
    assert newest["object_id"] is None and newest["details"]["ObjectId"] == "rule-1"
    older = out["records"][1]
    assert older["details"]["UserAgent"] == "Mozilla/5.0"
    assert older["details"]["ParameterNames"] == ["ForwardTo", "Name"]
    assert "ObjectId" not in older["details"]
    rendered = json.dumps(out)
    assert "secret text" not in rendered and "outside@example.org" not in rendered


@respx.mock
def test_result_stops_at_the_page_budget_and_says_capped(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    records = respx.get(RECORDS_URL).mock(
        return_value=httpx.Response(
            200, json={"value": [_record(1)], "@odata.nextLink": f"{RECORDS_URL}?$skiptoken=more"}
        )
    )
    out = server.audit_log_search_result(QUERY_ID, max_pages=2)
    assert records.call_count == 2
    assert out["capped"] is True and out["summary"]["capped"] is True
    assert out["summary"]["total_records"] == 2


@respx.mock
def test_result_cuts_long_strings(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    respx.get(RECORDS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"value": [_record(1, objectId="x" * 5000, auditData={"UserAgent": "u" * 5000, "Extra": "y" * 9})]},
        )
    )
    out = server.audit_log_search_result(QUERY_ID)
    record = out["records"][0]
    assert len(record["object_id"]) == server._AUDIT_TEXT_CHARS + 1
    assert len(record["details"]["UserAgent"]) == server._AUDIT_TEXT_CHARS + 1
    assert "Extra" not in record["details"]


@respx.mock
def test_result_unknown_query_is_found_false(graph):
    respx.get(QUERY_URL).mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFound", "message": "not found"}})
    )
    out = server.audit_log_search_result(QUERY_ID)
    assert out["found"] is False and out["query_id"] == QUERY_ID and "error" not in out


@respx.mock
def test_result_403_is_missing_permission(graph):
    respx.get(QUERY_URL).mock(
        return_value=httpx.Response(403, json={"error": {"code": "Forbidden", "message": "Missing role permissions"}})
    )
    out = server.audit_log_search_result(QUERY_ID)
    assert "AuditLogsQuery.Read.All" in out["missing_permission"]


@respx.mock
def test_result_403_on_the_records_keeps_the_status(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    respx.get(RECORDS_URL).mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["status"] == "succeeded" and "AuditLogsQuery.Read.All" in out["missing_permission"]


@respx.mock
def test_result_429_is_rate_limited(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["rate_limited"] is True


@respx.mock
def test_start_future_end_keeps_the_full_lookback(graph):
    route = respx.post(QUERIES_URL).mock(return_value=_created())
    future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=10)).isoformat()
    out = server.audit_log_search_start(user="someone@example.edu", hours=24, end=future)
    assert out["created"] is True
    sent = _sent(route)
    start = datetime.datetime.fromisoformat(sent["filterStartDateTime"].replace("Z", "+00:00"))
    end = datetime.datetime.fromisoformat(sent["filterEndDateTime"].replace("Z", "+00:00"))
    assert end - start == datetime.timedelta(hours=24)


@respx.mock
def test_start_window_past_standard_retention_carries_a_note(graph):
    respx.post(QUERIES_URL).mock(return_value=_created())
    start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200)).isoformat()
    end = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=190)).isoformat()
    out = server.audit_log_search_start(user="someone@example.edu", start=start, end=end)
    assert out["created"] is True and "Audit (Premium)" in out["note"]


@respx.mock
def test_result_429_while_reading_is_not_called_a_daily_limit(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["rate_limited"] is True and "per day" not in out["error"]


@respx.mock
def test_result_puts_undated_records_last(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    respx.get(RECORDS_URL).mock(
        return_value=httpx.Response(200, json={"value": [_record(1, createdDateTime=None), _record(2), _record(3)]})
    )
    out = server.audit_log_search_result(QUERY_ID, top=2)
    assert [r["id"] for r in out["records"]] == ["rec-3", "rec-2"]


@respx.mock
def test_result_details_do_not_repeat_the_client_ip(graph):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "succeeded"}))
    respx.get(RECORDS_URL).mock(return_value=httpx.Response(200, json={"value": [_record(1)]}))
    rec = server.audit_log_search_result(QUERY_ID)["records"][0]
    assert rec["client_ip"] == "203.0.113.7" and "ClientIP" not in rec["details"]


@pytest.mark.parametrize(
    ("query", "service"),
    [
        ({"serviceFilters": ["Exchange"]}, "Exchange"),
        ({"serviceFilter": "SharePoint"}, "SharePoint"),
        ({}, None),
    ],
)
@respx.mock
def test_result_reads_back_the_service_filter(graph, query, service):
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json={"id": QUERY_ID, "status": "running", **query}))
    assert server.audit_log_search_result(QUERY_ID)["query"]["service"] == service


@pytest.mark.parametrize(
    ("exceeded", "approx", "want_exceeded", "want_approx"),
    [
        (True, 50000, True, 50000),
        (False, "1234", False, 1234),
        (None, None, None, None),
        ("yes", True, None, None),
    ],
)
@respx.mock
def test_result_reports_the_record_count_limit(graph, exceeded, approx, want_exceeded, want_approx):
    query = {"id": QUERY_ID, "status": "succeeded"}
    if exceeded is not None:
        query["isRecordCountLimitExceeded"] = exceeded
    if approx is not None:
        query["approximateReturnedRecordCount"] = approx
    respx.get(QUERY_URL).mock(return_value=httpx.Response(200, json=query))
    respx.get(RECORDS_URL).mock(return_value=httpx.Response(200, json={"value": []}))
    out = server.audit_log_search_result(QUERY_ID)
    assert out["query"]["record_count_limit_exceeded"] is want_exceeded
    assert out["query"]["approximate_record_count"] == want_approx
