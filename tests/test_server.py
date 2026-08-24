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

    def get(self, path, params=None):
        self.calls.append(("get", path, params))
        response = self._get_responses.get(path, self._get_responses.get("*"))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return {"value": []}
        return response

    def get_paged(self, path, params=None, max_pages=5):
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


@pytest.fixture
def inject(monkeypatch):
    # _license_cache is module-level state shared across get_user calls (by
    # design -- the tenant's SKU catalog rarely changes while the server
    # runs). Clear it per test so one test's resolved sku names don't leak
    # into another test's "resolution failed" fixture.
    monkeypatch.setattr(server, "_license_cache", {})

    def _inject(client):
        monkeypatch.setitem(server._state, "client", client)
        return client

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
        assert set(result.keys()) == {"service", "version", "status", "auth_mode", "graph", "signin_probe"}
        assert set(result["graph"].keys()) == {"auth", "detail"}
        assert set(result["signin_probe"].keys()) == {"auth", "detail"}


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

    def get(path, params=None):
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

    def get(path, params=None):
        client.calls.append(("get", path, params))
        return {"value": [_user_row()]}

    def get_paged(path, params=None, max_pages=5):
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
    client.get = lambda path, params=None: (client.calls.append(("get", path, params)), next(responses))[1]
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
