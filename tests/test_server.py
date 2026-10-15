"""Tests for the MCP tool layer: projections, degradation, and coverage flags.

FakeGraphClient is injected via ``monkeypatch.setitem(server._state, "client",
...)`` -- the same pattern the sibling gwsadm-mcp uses. Tools are called
directly as plain functions (``server.get_user(...)``), not through any MCP
transport wrapper; FastMCP's ``@mcp.tool()`` decorator leaves the underlying
function callable.
"""

import pytest

import entraadm_mcp.server as server
from entraadm_mcp.client import GraphError, GraphPermissionError

PERM_ERROR = GraphPermissionError(
    "insufficient privileges: this endpoint needs the Reports Reader directory role "
    "(delegated, azure-cli auth) or an application permission such as AuditLog.Read.All (app-only auth)"
)


class FakeGraphClient:
    """Test double for GraphClient.

    Each constructor argument that models a Graph response accepts either a
    canned value or an Exception instance to raise. Calls are recorded on
    ``self.calls`` as ``(method, path, params)`` tuples so tests can assert
    on the exact filter/select sent, without needing a live respx mock at
    this layer.
    """

    def __init__(
        self,
        get_responses=None,
        paged_responses=None,
        check_result=None,
        signin_probe_result=None,
        mode="azure-cli",
    ):
        # get_responses: dict[path] -> dict | Exception, or a single dict/Exception used for all paths
        self._get_responses = get_responses if get_responses is not None else {}
        # paged_responses: dict[path] -> (items, capped) | Exception
        self._paged_responses = paged_responses if paged_responses is not None else {}
        self._check_result = check_result if check_result is not None else {"auth": "ok", "detail": None}
        self._signin_probe_result = (
            signin_probe_result if signin_probe_result is not None else {"auth": "ok", "detail": None}
        )
        self.mode = mode
        self.calls = []

    def get(self, path, params=None, deadline=None):
        self.calls.append(("get", path, params))
        response = self._get_responses.get(path, self._get_responses.get("*"))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return {"value": []}
        return response

    def get_paged(self, path, params=None, max_pages=5, deadline=None):
        self.calls.append(("get_paged", path, params, max_pages))
        response = self._paged_responses.get(path, self._paged_responses.get("*"))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return [], False
        return response

    def check(self):
        return self._check_result

    def probe_signin_access(self):
        return self._signin_probe_result


class FakeArmClient:
    """Test double for ArmClient, keyed like FakeGraphClient.

    ``paged_responses`` maps a path (or ``"*"``) to ``(items, capped)`` or an
    Exception; a callable value is called with ``(path, params, max_pages)``
    for tests that need to see the request. ``check_result`` is what
    health_check's ``arm`` probe reports.
    """

    def __init__(self, paged_responses=None, check_result=None):
        self._paged_responses = paged_responses if paged_responses is not None else {}
        self._check_result = (
            check_result
            if check_result is not None
            else {"auth": "ok", "detail": None, "subscriptions": 0, "capped": False}
        )
        self.calls = []

    def get_paged(self, path, params=None, max_pages=5, deadline=None):
        self.calls.append(("get_paged", path, params, max_pages, deadline))
        response = self._paged_responses.get(path, self._paged_responses.get("*"))
        if callable(response):
            response = response(path, params, max_pages)
        if isinstance(response, Exception):
            raise response
        if response is None:
            return [], False
        return response

    def check(self, deadline=None):
        return self._check_result


@pytest.fixture
def inject(monkeypatch):
    # _license_cache is module-level state shared across get_user calls (by
    # design -- the tenant's SKU catalog rarely changes while the server
    # runs). Clear it per test so one test's resolved sku names don't leak
    # into another test's "resolution failed" fixture.
    monkeypatch.setattr(server, "_license_cache", {})
    # A developer shell may point at a real sites file; tests opt in explicitly.
    monkeypatch.delenv("ENTRAADM_SITES_INI", raising=False)

    # health_check also probes ARM; without a double here it would build a real
    # ArmClient (and AzureCliCredential would shell out to `az`).
    monkeypatch.setitem(server._state, "arm", FakeArmClient())

    def _inject(client):
        monkeypatch.setitem(server._state, "client", client)
        return client

    return _inject


@pytest.fixture
def inject_arm(monkeypatch):
    def _inject(arm):
        monkeypatch.setitem(server._state, "arm", arm)
        return arm

    return _inject


def _user_row(**overrides):
    row = {
        "id": "11111111-1111-1111-1111-111111111111",
        "displayName": "Test User",
        "userPrincipalName": "user@example.edu",
        "accountEnabled": True,
        "userType": "Member",
        "createdDateTime": "2020-01-01T00:00:00Z",
        "lastPasswordChangeDateTime": "2026-01-01T00:00:00Z",
        "onPremisesSyncEnabled": True,
        "onPremisesLastSyncDateTime": "2026-08-01T00:00:00Z",
        "assignedLicenses": [{"skuId": "sku-1"}],
    }
    row.update(overrides)
    return row


def _signin_row(**overrides):
    row = {
        "createdDateTime": "2026-08-21T09:00:00Z",
        "appDisplayName": "Office 365",
        "clientAppUsed": "Browser",
        "ipAddress": "203.0.113.5",
        "location": {"city": "Tokyo", "countryOrRegion": "JP"},
        "status": {"errorCode": 50126, "failureReason": "Error validating credentials"},
        "conditionalAccessStatus": "notApplied",
        "deviceDetail": {"operatingSystem": "Windows 11", "browser": "Edge"},
        "isInteractive": True,
        "userPrincipalName": "user@example.edu",
    }
    row.update(overrides)
    return row


def _audit_row(**overrides):
    row = {
        "activityDateTime": "2026-08-21T10:00:00Z",
        "activityDisplayName": "Update user",
        "category": "UserManagement",
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "admin@example.edu", "displayName": "Admin"}},
        "targetResources": [{"type": "User", "userPrincipalName": "user@example.edu", "displayName": "Test User"}],
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


def test_health_check_is_healthy_when_both_probes_ok(inject):
    inject(FakeGraphClient(mode="app-only"))
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["auth_mode"] == "app-only"
    assert result["graph"] == {"auth": "ok", "detail": None}
    assert result["signin_probe"] == {"auth": "ok", "detail": None}
    assert result["service"] == "entraadm-mcp"


def test_health_check_is_degraded_when_graph_ok_but_signin_probe_fails(inject):
    inject(
        FakeGraphClient(
            check_result={"auth": "ok", "detail": None},
            signin_probe_result={"auth": "error", "detail": "insufficient privileges: ..."},
        )
    )
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["graph"]["auth"] == "ok"
    assert result["signin_probe"]["auth"] == "error"


def test_health_check_is_degraded_when_graph_fails_but_signin_probe_succeeds(inject):
    # The bug this guards: health_check must not fabricate signin_probe's
    # result from graph's failure. If AuditLog.Read.All is granted before
    # the baseline User.Read.All (an unusual but real staged-permission
    # rollout), Graph is demonstrably reachable -- signin_probe proves it --
    # so this must not report "graph unreachable" for signin_probe, nor an
    # overall "error" status.
    inject(
        FakeGraphClient(
            check_result={"auth": "error", "detail": "insufficient privileges: ..."},
            signin_probe_result={"auth": "ok", "detail": None},
        )
    )
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["graph"]["auth"] == "error"
    assert result["signin_probe"] == {"auth": "ok", "detail": None}


def test_health_check_is_error_when_both_probes_fail(inject):
    inject(
        FakeGraphClient(
            check_result={"auth": "error", "detail": "network unreachable"},
            signin_probe_result={"auth": "error", "detail": "network unreachable"},
        )
    )
    result = server.health_check()
    assert result["status"] == "error"


def test_health_check_shape_is_identical_across_all_statuses(inject):
    healthy = server.health_check()
    inject(FakeGraphClient(signin_probe_result={"auth": "error", "detail": "x"}))
    degraded = server.health_check()
    inject(
        FakeGraphClient(
            check_result={"auth": "error", "detail": "y"},
            signin_probe_result={"auth": "error", "detail": "y"},
        )
    )
    errored = server.health_check()
    for result in (healthy, degraded, errored):
        assert set(result.keys()) == {
            "service",
            "version",
            "status",
            "auth_mode",
            "graph",
            "signin_probe",
            "arm",
            "sites",
        }
        assert set(result["sites"].keys()) == {"configured", "ranges", "error"}
        assert set(result["graph"].keys()) == {"auth", "detail"}
        assert set(result["signin_probe"].keys()) == {"auth", "detail"}
        assert set(result["arm"].keys()) == {"auth", "detail", "subscriptions", "capped"}


def test_health_check_gives_the_arm_probe_its_own_short_budget(inject, inject_arm, monkeypatch):
    import time

    inject(FakeGraphClient())
    seen = []

    class RecordingArm(FakeArmClient):
        def check(self, deadline=None):
            seen.append(deadline)
            return super().check(deadline)

    inject_arm(RecordingArm())
    monkeypatch.setenv("ENTRAADM_DEADLINE", "0")  # even with the tool budget disabled
    before = time.monotonic()
    server.health_check()
    assert len(seen) == 1 and seen[0] is not None
    assert 0 < seen[0] - before <= server._ARM_PROBE_SECONDS + 0.5


def test_health_check_arm_probe_is_informational(inject, inject_arm):
    # Azure RBAC is optional: a deployment used only for Entra triage must not
    # be degraded forever because ARM is unreachable or sees no subscription.
    inject(FakeGraphClient())
    probe = {"auth": "error", "detail": "no token", "subscriptions": None, "capped": None}
    inject_arm(FakeArmClient(check_result=probe))
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["arm"] == probe


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


def test_get_user_projects_lifecycle_fields(inject):
    inject(
        FakeGraphClient(
            get_responses={
                "/users": {"value": [_user_row()]},
                "/subscribedSkus": {"value": [{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK"}]},
            },
            paged_responses={"/subscribedSkus": ([{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK"}], False)},
        )
    )
    result = server.get_user("user@example.edu")
    assert result["account_enabled"] is True
    assert result["on_premises_sync_enabled"] is True
    assert result["licenses"] == ["ENTERPRISEPACK"]
    assert result["sign_in_activity"] is None  # not requested via $select in this fixture -> absent field


def test_get_user_degrades_sign_in_activity_without_reports_role(inject):
    client = FakeGraphClient()

    def get(path, params=None, deadline=None):
        client.calls.append(("get", path, params))
        select = (params or {}).get("$select", "")
        if select == "signInActivity":
            raise PERM_ERROR
        return {"value": [_user_row()]}

    client.get = get
    inject(client)

    result = server.get_user("user@example.edu")
    assert result["account_enabled"] is True  # rest of the entry still returns
    assert result["sign_in_activity"]["missing_permission"] == "AuditLog.Read.All"


def test_get_user_reports_not_found_without_an_error_key(inject):
    # A nonexistent account is a normal answer, not a tool failure -- the
    # smoke harness treats any top-level "error" key as an automatic FAIL,
    # so this path must not use one (see scripts/smoke_probes.py).
    inject(FakeGraphClient(get_responses={"/users": {"value": []}}))
    result = server.get_user("nobody@example.edu")
    assert result == {"found": False, "user_principal_name": "nobody@example.edu"}


def test_get_user_found_true_on_success(inject):
    inject(FakeGraphClient(get_responses={"/users": {"value": [_user_row()]}}))
    result = server.get_user("user@example.edu")
    assert result["found"] is True


def test_get_user_rejects_invalid_upn(inject):
    inject(FakeGraphClient())
    result = server.get_user("not-an-email")
    assert "error" in result


def test_get_user_falls_back_to_raw_sku_id_when_subscribedskus_fails(inject):
    client = FakeGraphClient()

    def get(path, params=None, deadline=None):
        client.calls.append(("get", path, params))
        return {"value": [_user_row()]}

    def get_paged(path, params=None, max_pages=5, deadline=None):
        raise GraphError("boom")

    client.get = get
    client.get_paged = get_paged
    inject(client)

    result = server.get_user("user@example.edu")
    assert result["licenses"] == ["sku-1"]  # best-effort fallback, not a crash


def test_get_user_license_lookup_honors_max_pages_default_env(inject, monkeypatch):
    monkeypatch.setenv("ENTRAADM_MAX_PAGES_DEFAULT", "17")
    client = inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={"/subscribedSkus": ([], False)},
        )
    )
    server.get_user("user@example.edu")
    paged_calls = [c for c in client.calls if c[0] == "get_paged"]
    assert paged_calls[0][3] == 17  # not the hardcoded 5 this used to bypass the env with


def test_get_user_flags_licenses_capped_when_scan_cut_short_before_own_sku(inject):
    # A low ENTRAADM_MAX_PAGES_DEFAULT (set to bound the cost of scanning
    # sign-in/audit logs) has nothing to do with the size of the tenant's
    # SKU catalog. If /subscribedSkus is capped before this user's own
    # license shows up, `licenses` silently falls back to a raw skuId --
    # that must be flagged, not presented as if it were a resolved name.
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row(assignedLicenses=[{"skuId": "sku-never-fetched"}])]}},
            paged_responses={"/subscribedSkus": ([{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK"}], True)},
        )
    )
    result = server.get_user("user@example.edu")
    assert result["licenses"] == ["sku-never-fetched"]
    assert result["licenses_capped"] is True


def test_get_user_does_not_flag_licenses_capped_when_scan_covered_everything_needed(inject):
    # The scan being capped is not itself the problem -- only a capped scan
    # that left one of *this user's* licenses unresolved is.
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row(assignedLicenses=[{"skuId": "sku-1"}])]}},
            paged_responses={"/subscribedSkus": ([{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK"}], True)},
        )
    )
    result = server.get_user("user@example.edu")
    assert result["licenses"] == ["ENTERPRISEPACK"]
    assert "licenses_capped" not in result


# ---------------------------------------------------------------------------
# signin_logs
# ---------------------------------------------------------------------------


def test_signin_logs_annotates_50126_as_wrong_password(inject):
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": {"value": [_signin_row()]}}))
    result = server.signin_logs("user@example.edu")
    assert result["events"][0]["error_code"] == 50126
    assert "wrong password" in result["events"][0]["error_code_meaning"]


def test_signin_logs_result_success_filters_out_failures(inject):
    inject(
        FakeGraphClient(
            get_responses={
                "/auditLogs/signIns": {
                    "value": [
                        _signin_row(status={"errorCode": 0}),
                        _signin_row(status={"errorCode": 50126, "failureReason": "bad password"}),
                    ]
                }
            }
        )
    )
    result = server.signin_logs("user@example.edu", result="success")
    assert result["count"] == 1
    assert result["events"][0]["error_code"] == 0


def test_signin_logs_result_all_keeps_everything(inject):
    inject(
        FakeGraphClient(
            get_responses={
                "/auditLogs/signIns": {
                    "value": [_signin_row(status={"errorCode": 0}), _signin_row(status={"errorCode": 50126})]
                }
            }
        )
    )
    result = server.signin_logs("user@example.edu", result="all")
    assert result["count"] == 2


def test_signin_logs_rejects_invalid_result_value(inject):
    inject(FakeGraphClient())
    result = server.signin_logs("user@example.edu", result="bogus")
    assert "error" in result


def test_signin_logs_rejects_odata_injection_in_user(inject):
    inject(FakeGraphClient())
    result = server.signin_logs("a/b@example.edu' or '1'='1")
    assert "error" in result


def test_signin_logs_surfaces_missing_permission(inject):
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": PERM_ERROR}))
    result = server.signin_logs("user@example.edu")
    assert result["missing_permission"] == "AuditLog.Read.All"


def test_signin_logs_stops_paging_once_top_is_reached(inject):
    page1 = {
        "value": [_signin_row() for _ in range(3)],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?skiptoken=x",
    }
    page2 = {"value": [_signin_row() for _ in range(3)]}
    responses = iter([page1, page2])
    client = FakeGraphClient()
    client.get = lambda path, params=None, deadline=None: (
        client.calls.append(("get", path, params)),
        next(responses),
    )[1]
    inject(client)

    result = server.signin_logs("user@example.edu", top=2, max_pages=5)
    assert result["count"] == 2
    assert len(client.calls) == 1  # stopped after page 1, never fetched page 2


def test_signin_logs_capped_true_when_page_budget_runs_out_with_more_data(inject):
    page1 = {
        "value": [_signin_row()],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?skiptoken=x",
    }
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": page1}))
    result = server.signin_logs("user@example.edu", top=100, max_pages=1)
    assert result["capped"] is True


def test_signin_logs_capped_false_when_window_fully_scanned(inject):
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": {"value": [_signin_row()]}}))
    result = server.signin_logs("user@example.edu", top=100, max_pages=5)
    assert result["capped"] is False


def test_signin_logs_capped_true_when_top_is_hit_mid_page_with_no_nextlink(inject):
    # A single page with no @odata.nextLink still needs capped=true if it
    # holds more matching rows than `top` -- Graph already handed over the
    # extra rows, but the loop stopped reading them once `top` was reached,
    # so "the whole window was scanned" would be a false claim.
    page = {"value": [_signin_row() for _ in range(5)]}  # no @odata.nextLink at all
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": page}))
    result = server.signin_logs("user@example.edu", top=3, max_pages=5)
    assert result["count"] == 3
    assert result["capped"] is True


def test_signin_logs_capped_false_when_trailing_rows_would_not_have_matched(inject):
    # Reaching `top` mid-page must not by itself force capped=true: if the
    # remaining, unread rows in that same page would never have matched the
    # result filter anyway (they're successes, and result="failure"), the
    # scan genuinely was complete. Over-reporting capped here would make a
    # correct, exhaustive answer look untrustworthy.
    page = {
        "value": [
            _signin_row(),  # failure, matches
            _signin_row(),  # failure, matches
            _signin_row(),  # failure, matches -- top=3 reached here
            _signin_row(status={"errorCode": 0}),  # success, would not match
        ]
    }
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": page}))
    result = server.signin_logs("user@example.edu", top=3, max_pages=5)
    assert result["count"] == 3
    assert result["capped"] is False


def test_signin_logs_hours_are_clamped(inject):
    inject(FakeGraphClient(get_responses={"/auditLogs/signIns": {"value": []}}))
    result = server.signin_logs("user@example.edu", hours=999999)
    assert result["window_hours"] == 720


# ---------------------------------------------------------------------------
# signin_by_ip
# ---------------------------------------------------------------------------


def test_signin_by_ip_summarises_each_account_and_lists_events_with_names(inject):
    rows = [
        _signin_row(
            userPrincipalName="a@example.edu",
            createdDateTime="2026-08-21T09:00:00Z",
            status={"errorCode": 0},
            clientAppUsed="Authenticated SMTP",
        ),
        _signin_row(
            userPrincipalName="a@example.edu",
            createdDateTime="2026-08-20T09:00:00Z",
            status={"errorCode": 0},
            clientAppUsed="Authenticated SMTP",
        ),
        _signin_row(userPrincipalName="b@example.edu", createdDateTime="2026-08-21T08:00:00Z"),
    ]
    fake = FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)})
    inject(fake)
    result = server.signin_by_ip("203.0.113.5", hours=48, top=2)
    assert "ipAddress eq '203.0.113.5'" in fake.calls[0][2]["$filter"]
    assert result["successes"] == 2 and result["failures"] == 1 and result["distinct_users"] == 2
    assert result["users"][0] == {
        "user_principal_name": "a@example.edu",
        "successes": 2,
        "failures": 0,
        "first_seen": "2026-08-20T09:00:00Z",
        "last_seen": "2026-08-21T09:00:00Z",
    }
    assert result["success_client_apps"] == [{"client_app": "Authenticated SMTP", "count": 2}]
    assert [e["user_principal_name"] for e in result["events"]] == ["a@example.edu", "a@example.edu"]
    assert result["events_truncated"] is True


def test_signin_by_ip_result_filter_keeps_only_successes(inject):
    rows = [
        _signin_row(userPrincipalName="a@example.edu", status={"errorCode": 0}),
        _signin_row(userPrincipalName="b@example.edu"),
    ]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_by_ip("203.0.113.5", result="success")
    assert result["count"] == 1 and result["events"][0]["user_principal_name"] == "a@example.edu"
    assert result["failures"] == 1  # the summary still counts the failure


def test_signin_by_ip_counts_rows_without_an_account_and_keeps_the_ip_spelling(inject):
    rows = [
        _signin_row(userPrincipalName=""),  # Graph logs some failures with no account name
        _signin_row(userPrincipalName="a@example.edu", status={"errorCode": 0}),
    ]
    fake = FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)})
    inject(fake)
    result = server.signin_by_ip(" 2001:0db8:0000:0000:0000:0000:0000:0001 ")
    assert "ipAddress eq '2001:0db8:0000:0000:0000:0000:0000:0001'" in fake.calls[0][2]["$filter"]
    assert result["ip_address"] == "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert result["successes"] == 1 and result["failures"] == 1
    assert result["distinct_users"] == 1


def test_signin_by_ip_rejects_a_non_address(inject):
    inject(FakeGraphClient())
    result = server.signin_by_ip("203.0.113.5 or 1 eq 1")
    assert "error" in result and "ip must be" in result["error"]


def test_signin_by_ip_row_without_error_code_is_not_a_failure(inject):
    rows = [_signin_row(userPrincipalName="a@example.edu", status={})]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_by_ip("203.0.113.5", result="failure")
    assert result["failures"] == 0 and result["count"] == 0
    assert result["users"][0]["failures"] == 0


def test_signin_by_ip_reports_missing_permission(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": GraphPermissionError("denied")}))
    result = server.signin_by_ip("2001:db8::1")
    assert result["missing_permission"] == "AuditLog.Read.All"


# ---------------------------------------------------------------------------
# signin_success_stats
# ---------------------------------------------------------------------------


def _success_row(**overrides):
    row = _signin_row(status={"errorCode": 0, "failureReason": "Other."})
    row.update(overrides)
    return row


def test_signin_success_stats_flags_an_ip_shared_by_several_accounts(inject):
    rows = [
        _success_row(
            userPrincipalName="a@example.edu",
            ipAddress="198.51.100.7",
            clientAppUsed="Authenticated SMTP",
            location={"countryOrRegion": "KR"},
            createdDateTime="2026-08-21T09:00:00Z",
        ),
        _success_row(
            userPrincipalName="b@example.edu",
            ipAddress="198.51.100.7",
            clientAppUsed="Authenticated SMTP",
            location={"countryOrRegion": "KR"},
            createdDateTime="2026-08-21T08:00:00Z",
        ),
        _success_row(
            userPrincipalName="a@example.edu",
            ipAddress="198.51.100.7",
            clientAppUsed="Browser",
            location={"countryOrRegion": "JP"},
            createdDateTime="2026-08-21T10:00:00Z",
        ),
        _success_row(userPrincipalName="c@example.edu", ipAddress="203.0.113.5", clientAppUsed="Browser"),
    ]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_success_stats()
    assert result["total_successes"] == 4
    assert result["distinct_users"] == 3
    assert len(result["shared_ips"]) == 1
    shared = result["shared_ips"][0]
    assert shared["ip_address"] == "198.51.100.7"
    assert shared["users"] == ["a@example.edu", "b@example.edu"]
    assert shared["legacy_auth"] is True
    assert shared["countries"] == ["JP", "KR"]
    assert shared["first_seen"] == "2026-08-21T08:00:00Z"
    assert shared["last_seen"] == "2026-08-21T10:00:00Z"
    assert shared["client_apps"][0] == {"client_app": "Authenticated SMTP", "count": 2}


def test_signin_success_stats_lists_legacy_auth_users_and_ignores_failures(inject):
    rows = [
        _success_row(userPrincipalName="a@example.edu", ipAddress="198.51.100.7", clientAppUsed="IMAP4"),
        _success_row(userPrincipalName="a@example.edu", ipAddress="198.51.100.8", clientAppUsed="IMAP4"),
        _success_row(userPrincipalName="b@example.edu", ipAddress="203.0.113.5", clientAppUsed="Browser"),
        _signin_row(userPrincipalName="z@example.edu", ipAddress="198.51.100.7", clientAppUsed="Authenticated SMTP"),
    ]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_success_stats()
    assert result["total_successes"] == 3
    assert result["legacy_auth_successes"] == 2
    assert result["legacy_auth_users"] == [
        {
            "user_principal_name": "a@example.edu",
            "successes": 2,
            "distinct_ips": 2,
            "countries": ["JP"],
            "last_seen": "2026-08-21T09:00:00Z",
        }
    ]
    # the failed SMTP attempt by z@ must not make 198.51.100.7 a shared IP
    assert result["shared_ips"] == []


def test_signin_success_stats_min_distinct_users_is_clamped_to_at_least_two(inject):
    rows = [_success_row(userPrincipalName="a@example.edu", ipAddress="203.0.113.5") for _ in range(3)]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_success_stats(min_distinct_users=1)
    assert result["shared_ips"] == []


def test_signin_success_stats_caps_shared_ips_most_shared_first(inject):
    rows = []
    for i in range(60):
        ip = f"198.51.100.{i}"
        n_users = 3 if i == 59 else 2
        rows.extend(_success_row(userPrincipalName=f"u{j}@example.edu", ipAddress=ip) for j in range(n_users))
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_success_stats()
    assert result["shared_ips_total"] == 60
    assert len(result["shared_ips"]) == 50
    assert result["shared_ips_capped"] is True
    assert result["shared_ips"][0]["ip_address"] == "198.51.100.59"


def test_signin_success_stats_reports_missing_permission(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": GraphPermissionError("denied")}))
    result = server.signin_success_stats()
    assert result["missing_permission"] == "AuditLog.Read.All"


# ---------------------------------------------------------------------------
# signin_failure_stats
# ---------------------------------------------------------------------------


def test_signin_failure_stats_distinct_failing_users_is_not_truncated_to_top_10(inject):
    # distinct_failing_users must reflect the full Counter, not len() of the
    # most_common(10)-truncated top_failing_users list -- otherwise a
    # 15-user incident silently reports "10 users affected".
    rows = [_signin_row(userPrincipalName=f"user{i}@example.edu") for i in range(15)]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    assert result["distinct_failing_users"] == 15
    assert len(result["top_failing_users"]) == 10


def test_signin_failure_stats_flags_a_spray_suspect(inject):
    rows = [_signin_row(userPrincipalName=f"user{i}@example.edu", ipAddress="203.0.113.9") for i in range(5)]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    assert result["spray_suspects"] == [{"ip_address": "203.0.113.9", "distinct_users": 5, "attempts": 5}]


def test_signin_failure_stats_does_not_flag_a_single_user_hammering_one_ip(inject):
    rows = [_signin_row(userPrincipalName="user@example.edu", ipAddress="203.0.113.9") for _ in range(20)]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    assert result["spray_suspects"] == []
    assert result["top_ips"][0]["distinct_users"] == 1


def test_signin_failure_stats_ignores_successful_signins(inject):
    rows = [_signin_row(status={"errorCode": 0})]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    assert result["total_failures"] == 0


def test_signin_failure_stats_surfaces_capped(inject):
    rows = [_signin_row()]
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, True)}))
    result = server.signin_failure_stats()
    assert result["capped"] is True


def test_signin_failure_stats_surfaces_missing_permission(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": PERM_ERROR}))
    result = server.signin_failure_stats()
    assert result["missing_permission"] == "AuditLog.Read.All"


def test_signin_failure_stats_error_codes_are_annotated(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": ([_signin_row()], False)}))
    result = server.signin_failure_stats()
    assert result["top_error_codes"][0]["meaning"] is not None


# ---------------------------------------------------------------------------
# directory_audits
# ---------------------------------------------------------------------------


def test_directory_audits_projects_actor_and_targets(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": ([_audit_row()], False)}))
    result = server.directory_audits()
    entry = result["events"][0]
    assert entry["initiated_by"]["user_principal_name"] == "admin@example.edu"
    assert entry["target_resources"][0]["user_principal_name"] == "user@example.edu"


def test_directory_audits_matches_user_as_target(inject):
    rows = [_audit_row(), _audit_row(targetResources=[{"type": "User", "userPrincipalName": "other@example.edu"}])]
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": (rows, False)}))
    result = server.directory_audits(user="user@example.edu")
    assert result["count"] == 1


def test_directory_audits_matches_user_as_initiator(inject):
    rows = [_audit_row(initiatedBy={"user": {"userPrincipalName": "user@example.edu"}}, targetResources=[])]
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": (rows, False)}))
    result = server.directory_audits(user="user@example.edu")
    assert result["count"] == 1


def test_directory_audits_app_initiator_is_labeled(inject):
    rows = [_audit_row(initiatedBy={"app": {"displayName": "Some Service Principal"}})]
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": (rows, False)}))
    result = server.directory_audits()
    assert result["events"][0]["initiated_by"] == {"type": "app", "display_name": "Some Service Principal"}


def test_directory_audits_surfaces_missing_permission(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": PERM_ERROR}))
    result = server.directory_audits()
    assert result["missing_permission"] == "AuditLog.Read.All"


def test_directory_audits_top_truncation_sets_capped(inject):
    rows = [_audit_row() for _ in range(3)]
    inject(FakeGraphClient(paged_responses={"/auditLogs/directoryAudits": (rows, False)}))
    result = server.directory_audits(top=2)
    assert result["count"] == 2
    assert result["capped"] is True


# ---------------------------------------------------------------------------
# get_user_auth_methods
# ---------------------------------------------------------------------------


def test_get_user_auth_methods_honors_max_pages_default_env(inject, monkeypatch):
    monkeypatch.setenv("ENTRAADM_MAX_PAGES_DEFAULT", "23")
    client = inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={"*": ([], False)},
        )
    )
    server.get_user_auth_methods("user@example.edu")
    paged_calls = [c for c in client.calls if c[0] == "get_paged"]
    assert paged_calls[0][3] == 23  # not get_paged's own hardcoded default of 5


def test_get_user_auth_methods_mfa_registered_true_with_non_password_method(inject):
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={
                "*": (
                    [
                        {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "1"},
                        {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", "id": "2"},
                    ],
                    False,
                )
            },
        )
    )
    result = server.get_user_auth_methods("user@example.edu")
    assert result["mfa_registered"] is True
    assert {m["type"] for m in result["methods"]} == {"password", "microsoftAuthenticator"}


def test_get_user_auth_methods_mfa_registered_false_with_only_password(inject):
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={
                "*": ([{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "1"}], False)
            },
        )
    )
    result = server.get_user_auth_methods("user@example.edu")
    assert result["mfa_registered"] is False


def test_get_user_auth_methods_surfaces_missing_permission(inject):
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={"*": PERM_ERROR},
        )
    )
    result = server.get_user_auth_methods("user@example.edu")
    assert result["missing_permission"] == "UserAuthenticationMethod.Read.All"


def test_get_user_auth_methods_reports_not_found_without_an_error_key(inject):
    inject(FakeGraphClient(get_responses={"/users": {"value": []}}))
    result = server.get_user_auth_methods("nobody@example.edu")
    assert result == {"found": False, "user_principal_name": "nobody@example.edu"}


def test_get_user_auth_methods_unknown_odata_type_passes_through(inject):
    inject(
        FakeGraphClient(
            get_responses={"/users": {"value": [_user_row()]}},
            paged_responses={"*": ([{"@odata.type": "#microsoft.graph.somethingNew", "id": "1"}], False)},
        )
    )
    result = server.get_user_auth_methods("user@example.edu")
    assert result["methods"][0]["type"] == "#microsoft.graph.somethingNew"


# ---------------------------------------------------------------------------
# daily_brief
# ---------------------------------------------------------------------------


def test_daily_brief_combines_sections(inject):
    inject(
        FakeGraphClient(
            paged_responses={
                "/auditLogs/signIns": ([_signin_row()], False),
                "/auditLogs/directoryAudits": ([_audit_row()], False),
            }
        )
    )
    result = server.daily_brief()
    assert result["summary"]["sign_in_failures"] == 1
    assert result["summary"]["admin_actions"] == 1
    assert "signin_failure_stats" in result
    assert "directory_audits" in result


def test_daily_brief_survives_permission_error_in_one_section(inject):
    inject(
        FakeGraphClient(
            paged_responses={
                "/auditLogs/signIns": PERM_ERROR,
                "/auditLogs/directoryAudits": ([_audit_row()], False),
            }
        )
    )
    result = server.daily_brief()
    assert "error" in result["signin_failure_stats"]
    assert result["summary"]["admin_actions"] == 1  # the other section still fully returns


def test_daily_brief_capped_is_the_or_of_both_sections(inject):
    inject(
        FakeGraphClient(
            paged_responses={
                "/auditLogs/signIns": ([_signin_row()], True),
                "/auditLogs/directoryAudits": ([_audit_row()], False),
            }
        )
    )
    result = server.daily_brief()
    assert result["summary"]["capped"] is True


# --- deadline and category -------------------------------------------------


def test_directory_audits_category_filter_goes_server_side(inject):
    client = FakeGraphClient()
    inject(client)
    server.directory_audits(hours=72, category="UserManagement")
    paged = [c for c in client.calls if c[0] == "get_paged"][0]
    assert "and category eq 'UserManagement'" in paged[2]["$filter"]


def test_directory_audits_rejects_odd_category(inject):
    inject(FakeGraphClient())
    result = server.directory_audits(category="x' or 1 eq 1 or category eq '")
    assert "error" in result


def test_daily_brief_shares_one_deadline_between_sections(inject, monkeypatch):
    seen = []
    client = FakeGraphClient()
    orig = client.get_paged

    def get_paged(path, params=None, max_pages=5, deadline=None):
        seen.append(deadline)
        return orig(path, params, max_pages)

    client.get_paged = get_paged
    inject(client)
    monkeypatch.setenv("ENTRAADM_DEADLINE", "30")
    server.daily_brief(hours=1)
    # service health (2 reads), audits, sign-ins: one budget for all four
    assert len(seen) == 4 and seen[0] is not None and len(set(seen)) == 1


def test_deadline_disabled_by_zero(inject, monkeypatch):
    seen = []
    client = FakeGraphClient()
    orig = client.get_paged

    def get_paged(path, params=None, max_pages=5, deadline=None):
        seen.append(deadline)
        return orig(path, params, max_pages)

    client.get_paged = get_paged
    inject(client)
    monkeypatch.setenv("ENTRAADM_DEADLINE", "0")
    server.signin_failure_stats(hours=1)
    assert seen == [None]


def test_get_user_and_auth_methods_share_one_deadline_per_call(inject, monkeypatch):
    seen = []
    client = FakeGraphClient(get_responses={"/users": {"value": [{"id": "11111111-1111-1111-1111-111111111111"}]}})
    orig_get, orig_paged = client.get, client.get_paged

    def get(path, params=None, deadline=None):
        seen.append(("get", deadline))
        return orig_get(path, params)

    def get_paged(path, params=None, max_pages=5, deadline=None):
        seen.append(("paged", deadline))
        return orig_paged(path, params, max_pages)

    client.get, client.get_paged = get, get_paged
    inject(client)
    monkeypatch.setenv("ENTRAADM_DEADLINE", "30")
    server.get_user_auth_methods("user@example.edu")
    deadlines = {d for _, d in seen}
    assert len(seen) >= 2 and None not in deadlines and len(deadlines) == 1


def test_daily_brief_runs_the_audit_scan_before_the_signin_scan(inject):
    order = []
    client = FakeGraphClient()
    orig = client.get_paged

    def get_paged(path, params=None, max_pages=5, deadline=None):
        order.append(path)
        return orig(path, params, max_pages)

    client.get_paged = get_paged
    inject(client)
    server.daily_brief(hours=1)
    assert order == [
        "/admin/serviceAnnouncement/healthOverviews",
        "/admin/serviceAnnouncement/issues",
        "/auditLogs/directoryAudits",
        "/auditLogs/signIns",
    ]


# ---------------------------------------------------------------------------
# ENTRAADM_SITES_INI: internal vs external spray suspects
# ---------------------------------------------------------------------------

_SITES_INI = """\
[HQ]
name = Head office
ipv4 = 192.0.2.0/24
ipv6 = 2001:db8:1::/48

[LAB]
ipv4 = 192.0.2.128/25
"""


def _spray_rows(ip, n=5):
    return [_signin_row(userPrincipalName=f"user{i}@example.edu", ipAddress=ip) for i in range(n)]


@pytest.fixture
def sites_ini(tmp_path, monkeypatch):
    path = tmp_path / "sites.ini"
    path.write_text(_SITES_INI, encoding="utf-8")
    monkeypatch.setenv("ENTRAADM_SITES_INI", str(path))
    return path


def test_signin_failure_stats_moves_internal_suspects_to_their_own_list(inject, sites_ini):
    rows = _spray_rows("192.0.2.10", 6) + _spray_rows("203.0.113.9")
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    assert result["spray_suspects"] == [{"ip_address": "203.0.113.9", "distinct_users": 5, "attempts": 5}]
    assert result["internal_spray_suspects"] == [
        {"ip_address": "192.0.2.10", "distinct_users": 6, "attempts": 6, "site": "HQ", "site_name": "Head office"}
    ]
    assert result["sites"] == {"configured": True, "ranges": 3, "error": None}


def test_signin_failure_stats_labels_top_ips_with_the_most_specific_site(inject, sites_ini):
    rows = _spray_rows("192.0.2.200", 1) + _spray_rows("2001:db8:1::5", 1)
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (rows, False)}))
    result = server.signin_failure_stats()
    by_ip = {e["ip_address"]: e for e in result["top_ips"]}
    assert by_ip["192.0.2.200"]["site"] == "LAB"  # /25 beats the wider /24
    assert "site_name" not in by_ip["192.0.2.200"]
    assert by_ip["2001:db8:1::5"]["site"] == "HQ"


def test_signin_failure_stats_without_sites_ini_keeps_every_suspect_external(inject):
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (_spray_rows("192.0.2.10"), False)}))
    result = server.signin_failure_stats()
    assert [s["ip_address"] for s in result["spray_suspects"]] == ["192.0.2.10"]
    assert result["internal_spray_suspects"] == []
    assert result["sites"] == {"configured": False, "ranges": 0, "error": None}


def test_signin_failure_stats_one_bad_cidr_does_not_make_the_good_ranges_external(inject, tmp_path, monkeypatch):
    path = tmp_path / "sites.ini"
    path.write_text("[HQ]\nipv4 = 192.0.2.0/24, 192.0.2.0/33\n", encoding="utf-8")
    monkeypatch.setenv("ENTRAADM_SITES_INI", str(path))
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (_spray_rows("192.0.2.10"), False)}))
    result = server.signin_failure_stats()
    assert result["spray_suspects"] == []
    assert [s["site"] for s in result["internal_spray_suspects"]] == ["HQ"]
    assert "192.0.2.0/33" in result["sites"]["error"]


def test_signin_failure_stats_with_a_broken_sites_ini_keeps_every_suspect_external(inject, tmp_path, monkeypatch):
    path = tmp_path / "sites.ini"
    path.write_text("[HQ]\nipv4 = 192.0.2.0/33\n", encoding="utf-8")
    monkeypatch.setenv("ENTRAADM_SITES_INI", str(path))
    inject(FakeGraphClient(paged_responses={"/auditLogs/signIns": (_spray_rows("192.0.2.10"), False)}))
    result = server.signin_failure_stats()
    assert [s["ip_address"] for s in result["spray_suspects"]] == ["192.0.2.10"]
    assert result["sites"]["error"] is not None


def test_health_check_is_degraded_when_sites_ini_is_missing(inject, tmp_path, monkeypatch):
    monkeypatch.setenv("ENTRAADM_SITES_INI", str(tmp_path / "missing.ini"))
    inject(FakeGraphClient())
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["sites"]["configured"] is True
    assert "cannot read" in result["sites"]["error"]


def test_health_check_reports_loaded_sites(inject, sites_ini):
    inject(FakeGraphClient())
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["sites"] == {"configured": True, "ranges": 3, "error": None}


def test_daily_brief_summary_counts_internal_suspects_and_surfaces_sites_error(inject, tmp_path, monkeypatch):
    path = tmp_path / "sites.ini"
    path.write_text("[HQ]\nname = x\n", encoding="utf-8")  # no ranges
    monkeypatch.setenv("ENTRAADM_SITES_INI", str(path))
    inject(
        FakeGraphClient(
            paged_responses={
                "/auditLogs/signIns": (_spray_rows("192.0.2.10"), False),
                "/auditLogs/directoryAudits": ([_audit_row()], False),
            }
        )
    )
    result = server.daily_brief()
    assert result["summary"]["internal_spray_suspects"] == []
    assert "no ipv4/ipv6 ranges" in result["summary"]["sites_error"]


def test_daily_brief_summary_counts_internal_suspects(inject, sites_ini):
    inject(
        FakeGraphClient(
            paged_responses={
                "/auditLogs/signIns": (_spray_rows("192.0.2.10"), False),
                "/auditLogs/directoryAudits": ([_audit_row()], False),
            }
        )
    )
    result = server.daily_brief()
    assert result["summary"]["spray_suspects"] == []
    assert [s["ip_address"] for s in result["summary"]["internal_spray_suspects"]] == ["192.0.2.10"]
    assert "sites_error" not in result["summary"]


# ---------------------------------------------------------------------------
# ARM: list_subscriptions / vm_backup_status / vm_backup_policies
# ---------------------------------------------------------------------------

SUB_A = "aaaaaaaa-1111-1111-1111-111111111111"
SUB_B = "22222222-2222-2222-2222-222222222222"
ARM_PERM_ERROR = server.ApiPermissionError("ARM denied the request (x); this credential needs the Reader role")


def _subs(*pairs):
    return [{"subscriptionId": sid, "displayName": name, "state": "Enabled"} for sid, name in pairs]


def _vm(sub, name, rg="rg1"):
    # ARM's Compute responses use this casing; RecoveryServices lower-cases parts of it.
    return {
        "id": f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}",
        "name": name,
        "location": "japaneast",
    }


def _vault(sub, name="vault1", rg="rg1"):
    return {
        "id": f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{name}",
        "name": name,
        "location": "japaneast",
    }


def _item(sub, vm, state="Protected", last_status="Completed", recovery_point="2026-10-15T20:00:00Z", rg="rg1", **more):
    props = {
        "friendlyName": vm,
        "virtualMachineId": (
            f"/subscriptions/{sub}/resourcegroups/{rg}/providers/microsoft.compute/virtualmachines/{vm}"
        ),
        "protectionState": state,
        "protectionStatus": "Healthy",
        "healthStatus": "Passed",
        "lastBackupStatus": last_status,
        "lastBackupTime": "2026-10-15T20:00:00Z",
        "lastRecoveryPoint": recovery_point,
        "policyName": "DailyPolicy",
    }
    props.update(more)
    return {
        "id": f"{_vault(sub)['id']}/backupFabrics/Azure/protectionContainers/c/protectedItems/{vm}",
        "properties": props,
    }


def _vms_path(sub):
    return f"/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines"


def _vaults_path(sub):
    return f"/subscriptions/{sub}/providers/Microsoft.RecoveryServices/vaults"


def _items_path(sub, name="vault1", rg="rg1"):
    return f"{_vault(sub, name, rg)['id']}/backupProtectedItems"


def _policies_path(sub, name="vault1", rg="rg1"):
    return f"{_vault(sub, name, rg)['id']}/backupPolicies"


@pytest.fixture
def frozen_now(monkeypatch):
    import datetime as dt

    fixed = dt.datetime(2026, 10, 16, 8, 0, tzinfo=dt.timezone.utc)

    class FrozenDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz is None else fixed.astimezone(tz)

    monkeypatch.setattr(server.datetime, "datetime", FrozenDateTime)
    return fixed


def test_list_subscriptions_projects_and_lowercases_ids(inject, inject_arm):
    inject(FakeGraphClient())
    arm = inject_arm(FakeArmClient({"/subscriptions": (_subs((SUB_A.upper(), "alpha")), True)}))
    result = server.list_subscriptions(max_pages=2)
    assert result == {
        "count": 1,
        "capped": True,
        "subscriptions": [{"subscription_id": SUB_A, "name": "alpha", "state": "Enabled"}],
    }
    assert arm.calls[0][2] == {"api-version": server.ARM_API_VERSIONS["subscriptions"]}
    assert arm.calls[0][3] == 2 and arm.calls[0][4] is not None


def test_list_subscriptions_rejects_a_malformed_id_before_it_can_reach_a_path(inject, inject_arm):
    inject(FakeGraphClient())
    inject_arm(FakeArmClient({"/subscriptions": ([{"subscriptionId": "../evil", "displayName": "x"}], False)}))
    result = server.list_subscriptions()
    assert "error" in result and "subscription id shape" in result["error"]


def test_list_subscriptions_surfaces_the_rbac_hint(inject, inject_arm):
    inject(FakeGraphClient())
    inject_arm(FakeArmClient({"/subscriptions": ARM_PERM_ERROR}))
    result = server.list_subscriptions()
    assert result["missing_permission"] == server.ARM_ROLE_HINT


@pytest.mark.parametrize("wanted", [SUB_A, SUB_A.upper(), "alpha", " alpha "])
def test_subscription_resolves_by_id_or_display_name(inject, inject_arm, wanted):
    inject(FakeGraphClient())
    arm = inject_arm(FakeArmClient({"/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False)}))
    result = server.vm_backup_status(subscription=wanted)
    assert [e["subscription_id"] for e in result["subscriptions"]] == [SUB_A]
    # only ARM's own id reaches a path, never the argument
    assert all(SUB_A.upper() not in c[1] for c in arm.calls)


def test_subscription_not_found_ambiguous_and_listing_capped(inject, inject_arm):
    inject(FakeGraphClient())
    inject_arm(FakeArmClient({"/subscriptions": (_subs((SUB_A, "dup"), (SUB_B, "dup")), True)}))
    assert server.vm_backup_status(subscription="nope") == {
        "found": False,
        "subscription": "nope",
        "listing_capped": True,
    }
    result = server.vm_backup_policies(subscription="dup")
    assert result["found"] is False and result["ambiguous"] == [SUB_A, SUB_B]


def test_vm_backup_status_classifies_every_state(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    items = [
        _item(SUB_A, "ok"),
        _item(SUB_A, "stopped", state="ProtectionStopped"),
        _item(SUB_A, "pending", state="IRPending", last_status="", recovery_point=None),
        _item(SUB_A, "failed", last_status="Failed", recovery_point="2026-10-10T20:00:00Z"),
        _item(SUB_A, "weird", state="SomethingNew", last_status=None, recovery_point="garbage"),
        _item(SUB_A, "gone"),  # the VM no longer exists
    ]
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): (
                    [_vm(SUB_A, n) for n in ("ok", "stopped", "pending", "failed", "weird", "none")],
                    False,
                ),
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _items_path(SUB_A): (items, False),
            }
        )
    )
    result = server.vm_backup_status(stale_hours=36)
    rows = {r["name"]: r for r in result["subscriptions"][0]["vms"]}
    assert rows["ok"]["protected"] is True and rows["ok"]["backup_ok"] is True and rows["ok"]["stale"] is False
    assert rows["ok"]["vault"] == "vault1" and rows["ok"]["policy_name"] == "DailyPolicy"
    assert rows["ok"]["resource_group"] == "rg1"
    assert rows["stopped"]["protected"] is False and rows["stopped"]["protection_state"] == "ProtectionStopped"
    assert rows["pending"]["protected"] is True and rows["pending"]["stale"] is None
    assert rows["pending"]["backup_ok"] is None and rows["pending"]["note"] == "initial backup pending"
    assert (
        rows["failed"]["protected"] is True and rows["failed"]["backup_ok"] is False and rows["failed"]["stale"] is True
    )
    assert rows["weird"]["protected"] is False and rows["weird"]["stale"] is None
    assert rows["none"]["protected"] is False and rows["none"]["vault"] is None and "note" not in rows["none"]
    counts = result["subscriptions"][0]
    assert (counts["vm_count"], counts["protected"], counts["unprotected"], counts["unknown"]) == (6, 3, 3, 0)
    assert (counts["stale"], counts["failed"]) == (1, 1)
    assert result["summary"] == {
        "subscriptions": 1,
        "failed_subscriptions": 0,
        "vm_count": 6,
        "protected": 3,
        "unprotected": 3,
        "unknown": 0,
        "stale": 1,
        "failed": 1,
        "orphans": 1,
        "capped": False,
    }
    assert result["orphans"][0]["name"] == "gone" and result["orphans"][0]["vault"] == "vault1"
    assert result["capped"] is False and result["skipped"] == []
    assert result["coverage"].startswith("every visible subscription")


def test_vm_backup_status_incomplete_item_scan_yields_unknown_not_unprotected(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok"), _vm(SUB_A, "unmatched")], False),
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _items_path(SUB_A): ([_item(SUB_A, "ok")], True),  # page budget ran out
            }
        )
    )
    result = server.vm_backup_status()
    rows = {r["name"]: r for r in result["subscriptions"][0]["vms"]}
    assert rows["ok"]["protected"] is True
    assert rows["unmatched"]["protected"] is None and "incomplete" in rows["unmatched"]["note"]
    entry = result["subscriptions"][0]
    assert entry["unknown"] == 1 and entry["unprotected"] == 0 and entry["capped"] is True
    assert entry["vaults"][0]["capped"] is True
    assert result["capped"] is True and result["summary"]["capped"] is True


def test_vm_backup_status_orphans_need_a_complete_vm_listing(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], True),  # VM listing capped
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _items_path(SUB_A): ([_item(SUB_A, "ok"), _item(SUB_A, "maybe-gone")], False),
            }
        )
    )
    result = server.vm_backup_status()
    assert result["orphans"] == [] and result["unjoined_items"] == 1
    assert result["subscriptions"][0]["vms_capped"] is True and result["capped"] is True


@pytest.mark.parametrize(
    "bad_id",
    [
        f"/subscriptions/{SUB_A}/resourceGroups/../providers/Microsoft.RecoveryServices/vaults/v1",
        f"/subscriptions/{SUB_A}/resourceGroups/./providers/Microsoft.RecoveryServices/vaults/v1",
        f"/subscriptions/{SUB_A}/resourceGroups/rg./providers/Microsoft.RecoveryServices/vaults/v1",
        f"/subscriptions/{SUB_A}/resourceGroups/rg 1/providers/Microsoft.RecoveryServices/vaults/v1",
        f"/subscriptions/{SUB_A}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/v1?x=1",
        f"/subscriptions/{SUB_A}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/v1#frag",
        f"/subscriptions/{SUB_A}/resourceGroups/rg%2F1/providers/Microsoft.RecoveryServices/vaults/v1",
        f"/subscriptions/{SUB_A}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/v1/extra",
        f"/subscriptions/{SUB_B}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/v1",
        "",
    ],
)
def test_vm_backup_status_never_requests_a_vault_id_that_fails_validation(inject, inject_arm, frozen_now, bad_id):
    inject(FakeGraphClient())
    arm = inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([{"id": bad_id, "name": "v1"}], False),
            }
        )
    )
    result = server.vm_backup_status()
    entry = result["subscriptions"][0]
    assert entry["vaults"] == [] and len(entry["skipped_vaults"]) == 1
    assert entry["skipped_vaults"][0]["reason"] == "id did not match the vault id pattern"
    assert all("backupProtectedItems" not in c[1] for c in arm.calls)
    assert entry["vms"][0]["protected"] is None  # the scan was incomplete, so not "unprotected"
    assert entry["items_complete"] is False and result["capped"] is True


@pytest.mark.parametrize("rg", ["My.RG_(1)", "rg..prod", ".prod", "東京-rg", "a"])
def test_vm_backup_status_accepts_arm_casing_differences_and_valid_group_names(inject, inject_arm, frozen_now, rg):
    inject(FakeGraphClient())
    odd = f"/SUBSCRIPTIONS/{SUB_A.upper()}/resourcegroups/{rg}/providers/microsoft.recoveryservices/vaults/My-Vault"
    arm = inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok", rg=rg)], False),
                _vaults_path(SUB_A): ([{"id": odd, "name": "My-Vault"}], False),
                f"{odd}/backupProtectedItems": ([_item(SUB_A, "ok", rg=rg.lower())], False),
            }
        )
    )
    result = server.vm_backup_status()
    entry = result["subscriptions"][0]
    assert entry["vaults"][0]["name"] == "My-Vault" and entry["vaults"][0]["resource_group"] == rg
    assert entry["vms"][0]["protected"] is True
    assert any(c[1] == f"{odd}/backupProtectedItems" for c in arm.calls)


def test_vm_backup_status_one_subscription_error_degrades_only_that_entry(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False),
                _vms_path(SUB_A): ARM_PERM_ERROR,
                _vms_path(SUB_B): ([_vm(SUB_B, "ok")], False),
                _vaults_path(SUB_B): ([_vault(SUB_B)], False),
                _items_path(SUB_B): ([_item(SUB_B, "ok")], False),
            }
        )
    )
    result = server.vm_backup_status()
    a, b = result["subscriptions"]
    assert a["subscription_id"] == SUB_A and a["missing_permission"] == server.ARM_ROLE_HINT and "vms" not in a
    assert b["vms"][0]["protected"] is True
    assert result["summary"]["subscriptions"] == 2 and result["summary"]["vm_count"] == 1
    # part of the inventory is missing, so the result is capped and an unmatched VM would be unknown
    assert result["summary"]["failed_subscriptions"] == 1 and result["capped"] is True
    only_b = server.vm_backup_status(subscription="beta")
    assert only_b["capped"] is False and only_b["summary"]["failed_subscriptions"] == 0


def test_vm_backup_status_global_join_needs_every_vault_scan_complete(inject, inject_arm, frozen_now):
    # The VM is in A (complete scan); B's vault scan was capped. Globally the VM
    # may be protected by a vault in B that was not read, so it is unknown.
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([], False),
                _vms_path(SUB_B): ([], False),
                _vaults_path(SUB_B): ([_vault(SUB_B)], False),
                _items_path(SUB_B): ([], True),
            }
        )
    )
    result = server.vm_backup_status()
    assert result["subscriptions"][0]["vms"][0]["protected"] is None
    assert result["summary"]["unknown"] == 1 and result["capped"] is True
    # Named alone, A's own (complete) scan is the authority.
    assert server.vm_backup_status(subscription="alpha")["subscriptions"][0]["vms"][0]["protected"] is False
    # Every subscription denied: nothing is known, and the summary says so.
    inject_arm(
        FakeArmClient({"/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False), "*": ARM_PERM_ERROR})
    )
    result = server.vm_backup_status()
    assert result["summary"]["failed_subscriptions"] == 2 and result["capped"] is True
    policies = server.vm_backup_policies()
    assert policies["summary"]["failed_subscriptions"] == 2 and policies["capped"] is True


def test_vm_backup_status_unreadable_vault_is_skipped_with_its_reason(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([_vault(SUB_A), _vault(SUB_A, "vault2")], False),
                _items_path(SUB_A): ARM_PERM_ERROR,
                _items_path(SUB_A, "vault2"): ([_item(SUB_A, "ok")], False),
            }
        )
    )
    result = server.vm_backup_status()
    entry = result["subscriptions"][0]
    assert [v["name"] for v in entry["vaults"]] == ["vault2"]
    assert (
        entry["skipped_vaults"][0]["id"].endswith("/vaults/vault1") and "Reader" in entry["skipped_vaults"][0]["reason"]
    )
    assert entry["vms"][0]["protected"] is True and entry["items_complete"] is False


def test_vm_backup_status_stops_at_the_deadline_and_lists_the_rest_as_skipped(
    inject, inject_arm, frozen_now, monkeypatch
):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _items_path(SUB_A): ([_item(SUB_A, "ok")], False),
            }
        )
    )
    budget = iter([True, True, False])  # subscription A, its vault, then the budget is gone
    monkeypatch.setattr(server, "_budget_left", lambda: next(budget))
    result = server.vm_backup_status()
    assert [e["subscription_id"] for e in result["subscriptions"]] == [SUB_A]
    assert result["skipped"] == [{"subscription_id": SUB_B, "name": "beta", "reason": "deadline"}]
    assert result["capped"] is True


def test_vm_backup_status_deadline_runs_out_between_vaults(inject, inject_arm, frozen_now, monkeypatch):
    inject(FakeGraphClient())
    arm = inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([_vault(SUB_A), _vault(SUB_A, "vault2")], False),
                _items_path(SUB_A): ([_item(SUB_A, "ok")], False),
            }
        )
    )
    budget = iter([True, True, False])
    monkeypatch.setattr(server, "_budget_left", lambda: next(budget))
    result = server.vm_backup_status()
    entry = result["subscriptions"][0]
    assert entry["skipped_vaults"] == [{"id": _vault(SUB_A, "vault2")["id"].lower(), "reason": "deadline"}]
    assert all("vault2/backupProtectedItems" not in c[1] for c in arm.calls)
    assert entry["vms"][0]["protected"] is True and result["capped"] is True


def test_vm_backup_status_cross_subscription_vault(inject, inject_arm, frozen_now):
    # The VM lives in A, its vault in B.
    inject(FakeGraphClient())
    responses = {
        "/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False),
        _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
        _vaults_path(SUB_A): ([], False),
        _vms_path(SUB_B): ([], False),
        _vaults_path(SUB_B): ([_vault(SUB_B)], False),
        _items_path(SUB_B): ([_item(SUB_A, "ok")], False),
    }
    inject_arm(FakeArmClient(responses))
    globally = server.vm_backup_status()
    assert globally["subscriptions"][0]["vms"][0]["protected"] is True
    assert globally["orphans"] == [] and globally["unjoined_items"] == 0
    only_a = server.vm_backup_status(subscription="alpha")
    assert only_a["subscriptions"][0]["vms"][0]["protected"] is False
    assert "another subscription" in only_a["coverage"]


def test_vm_backup_status_passes_one_deadline_to_every_arm_call(inject, inject_arm, frozen_now, monkeypatch):
    inject(FakeGraphClient())
    arm = inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok")], False),
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _items_path(SUB_A): ([_item(SUB_A, "ok")], False),
            }
        )
    )
    monkeypatch.setenv("ENTRAADM_DEADLINE", "30")
    server.vm_backup_status()
    deadlines = {c[4] for c in arm.calls}
    assert len(arm.calls) == 4 and len(deadlines) == 1 and None not in deadlines


def test_vm_backup_status_tolerates_null_and_wrong_typed_fields(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    broken_item = {
        "id": "x",
        "properties": {
            "virtualMachineId": _vm(SUB_A, "ok")["id"],
            "protectionState": None,
            "lastBackupStatus": 7,
            "lastRecoveryPoint": "2026-13-45T99:99:99Z",
            "policyName": ["list"],
        },
    }
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vms_path(SUB_A): ([_vm(SUB_A, "ok"), {"id": None, "name": 5}, "not a dict"], False),
                _vaults_path(SUB_A): ([_vault(SUB_A), "junk", {"id": 3}], False),
                _items_path(SUB_A): ([broken_item, {"properties": None}, "junk"], False),
            }
        )
    )
    result = server.vm_backup_status()
    entry = result["subscriptions"][0]
    rows = {r["id"]: r for r in entry["vms"]}
    ok = rows[_vm(SUB_A, "ok")["id"].lower()]
    assert ok["protected"] is False and ok["policy_name"] is None and ok["last_backup_status"] is None
    assert rows[""]["name"] is None and rows[""]["protected"] is None  # no id: cannot join; scan was incomplete
    assert len(entry["skipped_vaults"]) == 2


def test_parse_iso_handles_fractions_offsets_and_garbage():
    import datetime as dt

    assert server._parse_iso("2026-10-15T08:29:28.08Z") == dt.datetime(
        2026, 10, 15, 8, 29, 28, 80000, tzinfo=dt.timezone.utc
    )
    assert server._parse_iso("2026-10-15T08:29:28.1234567Z").microsecond == 123456
    assert server._parse_iso("2026-10-15T08:29:28+09:00").utcoffset() == dt.timedelta(hours=9)
    assert server._parse_iso("2026-10-15T08:29:28").tzinfo == dt.timezone.utc
    for bad in (None, 5, "", "yesterday", "2026-13-45T99:99:99Z", "2026-10-15"):
        assert server._parse_iso(bad) is None


def test_stale_hours_is_clamped(inject, inject_arm, frozen_now):
    inject(FakeGraphClient())
    inject_arm(FakeArmClient({"/subscriptions": ([], False)}))
    assert server.vm_backup_status(stale_hours=0)["stale_hours"] == 1
    assert server.vm_backup_status(stale_hours=10**9)["stale_hours"] == 24 * 400


def _policy(name, props):
    return {"id": f"policy/{name}", "name": name, "properties": props}


V1_POLICY = _policy(
    "DailyV1",
    {
        "backupManagementType": "AzureIaasVM",
        "policyType": "V1",
        "instantRpRetentionRangeInDays": 2,
        "timeZone": "Tokyo Standard Time",
        "protectedItemsCount": 7,
        "schedulePolicy": {
            "schedulePolicyType": "SimpleSchedulePolicy",
            "scheduleRunFrequency": "Daily",
            "scheduleRunTimes": ["2026-01-01T20:00:00Z"],
            "scheduleWeeklyFrequency": 0,
        },
        "retentionPolicy": {
            "retentionPolicyType": "LongTermRetentionPolicy",
            "dailySchedule": {
                "retentionTimes": ["2026-01-01T20:00:00Z"],
                "retentionDuration": {"count": 6, "durationType": "Days"},
            },
            "weeklySchedule": {
                "daysOfTheWeek": ["Sunday"],
                "retentionDuration": {"count": 3, "durationType": "Weeks"},
            },
            "monthlySchedule": {
                "retentionScheduleFormatType": "Daily",
                "retentionScheduleDaily": {"daysOfTheMonth": [{"date": 1, "isLast": False}]},
                "retentionDuration": {"count": 12, "durationType": "Months"},
            },
            "yearlySchedule": {
                "retentionScheduleFormatType": "Weekly",
                "monthsOfYear": ["January"],
                "retentionScheduleWeekly": {"daysOfTheWeek": ["Sunday"], "weeksOfTheMonth": ["First"]},
                "retentionDuration": {"count": 1, "durationType": "Years"},
            },
        },
    },
)


def _v2(frequency, **schedule):
    return _policy(
        f"{frequency}V2",
        {
            "policyType": "V2",
            "schedulePolicy": {
                "schedulePolicyType": "SimpleSchedulePolicyV2",
                "scheduleRunFrequency": frequency,
                **schedule,
            },
            "retentionPolicy": {
                "retentionPolicyType": "SimpleRetentionPolicy",
                "retentionDuration": {"count": 30, "durationType": "Days"},
            },
        },
    )


def test_vm_backup_policies_parses_v1_and_every_v2_frequency(inject, inject_arm):
    inject(FakeGraphClient())
    policies = [
        V1_POLICY,
        _v2(
            "Hourly",
            hourlySchedule={
                "interval": 4,
                "scheduleWindowStartTime": "2026-01-01T08:00:00Z",
                "scheduleWindowDuration": 12,
            },
        ),
        _v2("Daily", dailySchedule={"scheduleRunTimes": ["2026-01-01T20:00:00Z"]}),
        _v2(
            "Weekly",
            weeklySchedule={"scheduleRunDays": ["Monday", "Thursday"], "scheduleRunTimes": ["2026-01-01T20:00:00Z"]},
        ),
        _v2("Monthly"),  # a frequency this server does not know
        _policy(
            "Unknown",
            {
                "schedulePolicy": {"schedulePolicyType": "LogSchedulePolicy"},
                "retentionPolicy": {"retentionPolicyType": "NewRetention"},
            },
        ),
        _policy("Empty", {"schedulePolicy": None, "retentionPolicy": "junk"}),
    ]
    arm = inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha")), False),
                _vaults_path(SUB_A): ([_vault(SUB_A)], False),
                _policies_path(SUB_A): (policies, False),
            }
        )
    )
    result = server.vm_backup_policies(subscription="alpha")
    by_name = {p["name"]: p for p in result["subscriptions"][0]["policies"]}
    v1 = by_name["DailyV1"]
    assert v1["policy_type"] == "V1" and v1["vault"] == "vault1" and v1["protected_item_count"] == 7
    assert v1["instant_rp_days"] == 2 and v1["timezone"] == "Tokyo Standard Time"
    assert v1["schedule"] == {
        "type": "SimpleSchedulePolicy",
        "frequency": "Daily",
        "run_times": ["2026-01-01T20:00:00Z"],
        "weekdays": [],
    }
    assert v1["retention"]["daily"] == {"retention": {"count": 6, "unit": "Days"}}
    assert v1["retention"]["weekly"] == {"weekdays": ["Sunday"], "retention": {"count": 3, "unit": "Weeks"}}
    assert v1["retention"]["monthly"] == {
        "format": "Daily",
        "days_of_month": [{"day": 1, "is_last": False}],
        "retention": {"count": 12, "unit": "Months"},
    }
    assert v1["retention"]["yearly"] == {
        "format": "Weekly",
        "weekdays": ["Sunday"],
        "weeks_of_month": ["First"],
        "months": ["January"],
        "retention": {"count": 1, "unit": "Years"},
    }
    assert by_name["HourlyV2"]["schedule"] == {
        "type": "SimpleSchedulePolicyV2",
        "frequency": "Hourly",
        "interval_hours": 4,
        "window_start": "2026-01-01T08:00:00Z",
        "window_hours": 12,
    }
    assert by_name["DailyV2"]["schedule"]["run_times"] == ["2026-01-01T20:00:00Z"]
    assert by_name["WeeklyV2"]["schedule"]["weekdays"] == ["Monday", "Thursday"]
    assert by_name["DailyV2"]["retention"] == {
        "type": "SimpleRetentionPolicy",
        "retention": {"count": 30, "unit": "Days"},
    }
    assert by_name["MonthlyV2"]["schedule"] == {
        "type": "SimpleSchedulePolicyV2",
        "frequency": "Monthly",
        "unparsed": True,
    }
    assert by_name["Unknown"]["schedule"] == {"type": "LogSchedulePolicy", "unparsed": True}
    assert by_name["Unknown"]["retention"] == {"type": "NewRetention", "unparsed": True}
    assert by_name["Empty"]["schedule"] == {"type": None, "unparsed": True}
    assert by_name["Empty"]["protected_item_count"] is None
    assert result["summary"] == {"subscriptions": 1, "failed_subscriptions": 0, "policies": 7, "capped": False}
    # the policy listing uses the workload filter and the backup api-version; no second item scan
    policy_calls = [c for c in arm.calls if c[1].endswith("/backupPolicies")]
    assert policy_calls[0][2] == {"api-version": server.ARM_API_VERSIONS["backup"], "$filter": server._IAAS_VM_FILTER}
    assert not any(c[1].endswith("/backupProtectedItems") for c in arm.calls)


def test_vm_backup_policies_degrades_per_subscription_and_flags_capping(inject, inject_arm, monkeypatch):
    inject(FakeGraphClient())
    inject_arm(
        FakeArmClient(
            {
                "/subscriptions": (_subs((SUB_A, "alpha"), (SUB_B, "beta")), False),
                _vaults_path(SUB_A): ARM_PERM_ERROR,
                _vaults_path(SUB_B): ([_vault(SUB_B)], True),
                _policies_path(SUB_B): ([V1_POLICY], False),
            }
        )
    )
    result = server.vm_backup_policies()
    a, b = result["subscriptions"]
    assert a["missing_permission"] == server.ARM_ROLE_HINT
    assert b["capped"] is True and len(b["policies"]) == 1
    assert result["capped"] is True and result["summary"]["policies"] == 1
    budget = iter([False])
    monkeypatch.setattr(server, "_budget_left", lambda: next(budget, False))
    result = server.vm_backup_policies()
    assert result["subscriptions"] == [] and len(result["skipped"]) == 2 and result["capped"] is True


# ---------------------------------------------------------------------------
# m365_service_health and its daily_brief section
# ---------------------------------------------------------------------------

OVERVIEWS = "/admin/serviceAnnouncement/healthOverviews"
ISSUES = "/admin/serviceAnnouncement/issues"


def _issue(iid, classification="incident", **more):
    row = {
        "id": iid,
        "title": "Users may not receive notifications",
        "service": "Microsoft Teams",
        "feature": "Notifications",
        "classification": classification,
        "status": "serviceDegradation",
        "startDateTime": "2026-10-15T08:29:28.08Z",
        "lastModifiedDateTime": "2026-10-15T09:10:26.557Z",
        "impactDescription": "Some users may not receive meeting-started notifications.",
        "isResolved": False,
        "posts": [{"description": {"content": "long"}}],
    }
    row.update(more)
    return row


def test_m365_service_health_summarises_services_and_open_issues(inject):
    client = inject(
        FakeGraphClient(
            paged_responses={
                OVERVIEWS: (
                    [
                        {"id": "a", "service": "Exchange Online", "status": "serviceDegradation"},
                        {"id": "b", "service": "SharePoint Online", "status": "serviceOperational"},
                        "junk",
                    ],
                    False,
                ),
                ISSUES: ([_issue("TM1"), _issue("EX2", "advisory"), _issue("X3", None), "junk"], True),
            }
        )
    )
    result = server.m365_service_health(max_pages=3)
    assert result["summary"] == {
        "capped": True,
        "degraded_services": ["Exchange Online"],
        "services_without_status": 1,
        "open_incidents": 1,
        "open_advisories": 1,
    }
    assert result["services"][0] == {"service": "Exchange Online", "status": "serviceDegradation"}
    assert result["issues"][0] == {
        "id": "TM1",
        "title": "Users may not receive notifications",
        "service": "Microsoft Teams",
        "feature": "Notifications",
        "classification": "incident",
        "status": "serviceDegradation",
        "start": "2026-10-15T08:29:28.08Z",
        "last_modified": "2026-10-15T09:10:26.557Z",
        "impact": "Some users may not receive meeting-started notifications.",
    }
    assert "posts" not in result["issues"][0] and result["capped"] is True
    issues_call = next(c for c in client.calls if c[1] == ISSUES)
    assert issues_call[2] == {"$filter": "isResolved eq false", "$orderby": "startDateTime desc"}
    assert issues_call[3] == 3


def test_m365_service_health_permission_hint_only_for_permission_failures(inject):
    outage = GraphError("Graph request failed (503): try later")
    inject(FakeGraphClient(paged_responses={OVERVIEWS: outage, ISSUES: PERM_ERROR}))
    result = server.m365_service_health()
    assert result["services"] == {"error": str(outage)}
    assert result["issues"]["missing_permission"] == "ServiceHealth.Read.All"


def test_m365_service_health_degrades_each_section_on_its_own(inject):
    inject(FakeGraphClient(paged_responses={OVERVIEWS: PERM_ERROR, ISSUES: ([_issue("TM1")], False)}))
    result = server.m365_service_health()
    assert result["services"] == {"error": str(PERM_ERROR), "missing_permission": "ServiceHealth.Read.All"}
    assert result["summary"]["degraded_services"] == result["services"]
    assert result["summary"]["open_incidents"] == 1 and len(result["issues"]) == 1
    inject(FakeGraphClient(paged_responses={OVERVIEWS: ([], False), ISSUES: PERM_ERROR}))
    result = server.m365_service_health()
    assert result["issues"]["missing_permission"] == "ServiceHealth.Read.All"
    assert result["summary"]["open_incidents"] == result["issues"] and result["summary"]["degraded_services"] == []


def test_daily_brief_carries_a_service_health_section(inject):
    inject(
        FakeGraphClient(
            paged_responses={
                OVERVIEWS: ([{"service": "Microsoft Entra", "status": "serviceDegradation"}], False),
                ISSUES: ([_issue("AA1"), _issue("AA2", "advisory")], True),
                "/auditLogs/directoryAudits": ([], False),
                "/auditLogs/signIns": ([], False),
            }
        )
    )
    result = server.daily_brief(hours=1)
    assert result["summary"]["service_health"] == {
        "degraded_services": ["Microsoft Entra"],
        "open_incidents": 1,
        "capped": True,
    }
    assert result["m365_service_health"]["summary"]["open_advisories"] == 1
    # the service-health cap is reported in its own section, not folded into the sign-in cap
    assert result["summary"]["capped"] is False


def test_daily_brief_service_health_config_error_degrades_only_that_section(inject, monkeypatch):
    inject(FakeGraphClient(paged_responses={OVERVIEWS: PERM_ERROR, ISSUES: PERM_ERROR}))
    result = server.daily_brief(hours=1)
    health = result["summary"]["service_health"]
    assert health["degraded_services"]["missing_permission"] == "ServiceHealth.Read.All"
    assert result["summary"]["sign_in_failures"] == 0 and result["summary"]["admin_actions"] == 0
