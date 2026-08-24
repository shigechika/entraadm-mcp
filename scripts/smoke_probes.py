"""Probe specs for this server's tools — the Entra-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

Two constraints shape everything below.

**Read-only.** Every tool here reads a sign-in log, an audit log, or a
directory snapshot; nothing in the tenant is changed.

**No tenant-specific values in this file.** This repository is public, so a
probe may not name a real account, tenant id, or app registration.
``signin_logs``/``get_user``/``get_user_auth_methods`` need a
userPrincipalName; this server has no directory-listing tool to discover a
real one from (unlike the sibling gwsadm-mcp, which can pull an address from
``suspended_accounts``/``login_audit``), so those probes build a
guaranteed-nonexistent one instead, in an RFC 2606 reserved domain that is
never delegated and never real. ``validate_upn`` only checks shape, not
tenant membership, so this exercises the full request path (auth, the
$filter query, the not-found projection) without naming, or reading the
state of, anybody's actual account. A "found: true" result would be the
surprise.
"""

import secrets
from typing import Any

from smoke_harness import Caller, Probe

#: Window and page bounds for the log-scanning tools. Small on purpose: one
#: page over one day proves the fetch, the projection, and the capping logic
#: all run.
WINDOW_HOURS = 24
MAX_PAGES = 1


def _reserved_domain() -> str:
    """An RFC 2606 reserved domain (never delegated, never real), assembled
    at call time so no address-shaped literal appears in this file's source.
    """
    return ".".join(["example", "invalid"])


def _fake_local_part() -> str:
    return f"smoke-test-{secrets.token_hex(8)}"


async def _fake_user_arg(call: Caller) -> dict[str, Any]:
    """A guaranteed-nonexistent account, under the ``user`` parameter name (signin_logs)."""
    del call  # no discovery needed -- see module docstring
    return {"user": f"{_fake_local_part()}@{_reserved_domain()}"}


async def _fake_upn_arg(call: Caller) -> dict[str, Any]:
    """Same as ``_fake_user_arg``, under the ``upn`` parameter name (get_user*)."""
    del call
    return {"upn": f"{_fake_local_part()}@{_reserved_domain()}"}


PROBES: dict[str, Probe] = {
    "health_check": Probe(
        require_keys=("service", "version", "status", "auth_mode", "graph", "signin_probe"),
        allow_empty=True,
    ),
    "get_user": Probe(
        args_factory=_fake_upn_arg,
        require_keys=("found",),
        must_match=(r'"found":\s*false',),
        allow_empty=True,
    ),
    "get_user_auth_methods": Probe(
        args_factory=_fake_upn_arg,
        require_keys=("found",),
        must_match=(r'"found":\s*false',),
        allow_empty=True,
    ),
    "signin_logs": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "top": 5, "result": "all"},
        args_factory=_fake_user_arg,
        require_keys=("window_hours", "result_filter", "count", "capped", "events"),
        rows_key="events",
        allow_empty=True,
    ),
    "signin_failure_stats": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES},
        require_keys=("window_hours", "capped", "total_failures", "top_error_codes", "spray_suspects"),
        allow_empty=True,
    ),
    "directory_audits": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "top": 5},
        require_keys=("window_hours", "capped", "count", "events"),
        rows_key="events",
        allow_empty=True,
    ),
    "daily_brief": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "samples": 5},
        require_keys=("window_hours", "summary", "signin_failure_stats", "directory_audits"),
        allow_empty=True,
        timeout=180,
    ),
}
