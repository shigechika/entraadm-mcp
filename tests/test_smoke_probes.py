"""Every registered tool must carry a smoke-test probe spec.

This is the CI half of the smoke test: the live run (scripts/smoke_test.py)
needs a reachable Entra ID tenant, but the *coverage* question -- did someone
add a tool without deciding how we would know it works? -- is answerable
offline, so it is enforced here on every push.
"""

import asyncio
import re
import sys
from pathlib import Path

from entraadm_mcp.server import mcp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import smoke_probes  # noqa: E402 - needs the sys.path line above
from smoke_harness import Probe  # noqa: E402

#: Literal shapes that would tie this public repository to one tenant.
#: Named by shape rather than by value: spelling out a real domain in order
#: to forbid it would put that domain here, which is what this check
#: prevents.
#:
#: The IPv6 pattern covers both the fully written form and the compressed
#: one. A compressed match requires a hex group to the left of "::" so that
#: a clock time (12:34:56) and a Python slice (a[::2]) do not read as
#: addresses, and loopback/unspecified forms (::1, ::) are not matched at
#: all -- they identify no site.
ADDRESS_SHAPES = {
    "email address": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "URL": r"https?://",
    # {1,} not {2,}: a bare two-label domain (example.com) is the common case.
    "hostname": r"\b(?:[a-z0-9-]+\.){1,}(?:jp|com|org|net|edu|ac|co|io|dev)\b",
    "IPv4 address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "IPv6 address": (
        r"(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}\b"
        r"|\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    ),
}

#: Tool parameters whose value names something in the tenant: an account.
#: Every one of these comes from an args_factory or is left unset -- see
#: scripts/smoke_probes.py's module docstring for why this server has no
#: "discover a real one" path the way gwsadm-mcp does.
IDENTIFIER_ARGS = {"user", "upn"}

#: Parameters that bound how much work a tool does. A scheduled probe must
#: pass each one it is offered rather than inheriting a default sized for a
#: human asking once -- these tools page the sign-in/audit log.
BOUNDING_ARGS = {"hours", "max_pages", "top", "samples"}

#: Tools that change anything in the tenant. The smoke test must never call
#: these. Empty: every tool in this server reads.
STATE_CHANGING: set[str] = set()


def _registered_tool_names() -> set[str]:
    """Tool names from the live registry (no Graph connection needed).

    ``asyncio.run`` rather than an async test: this suite has no async
    plugin, and the registry read is the only awaitable involved.
    """

    async def _names() -> set[str]:
        return {tool.name for tool in await mcp.list_tools()}

    return asyncio.run(_names())


def _server_source() -> str:
    # encoding pinned: the default is the locale's, which is cp1252 on the
    # Windows CI runner and cannot decode this source.
    return (Path(__file__).resolve().parent.parent / "entraadm_mcp" / "server.py").read_text(encoding="utf-8")


def test_every_registered_tool_has_a_probe():
    registered = _registered_tool_names()
    missing = sorted(registered - set(smoke_probes.PROBES))
    assert not missing, (
        f"Tool(s) registered with no smoke-test probe: {missing}. "
        "Add an entry to scripts/smoke_probes.py -- arguments plus what a working "
        "answer looks like, or an explicit skip= reason."
    )


def test_no_probe_targets_a_removed_tool():
    registered = _registered_tool_names()
    stale = sorted(set(smoke_probes.PROBES) - registered)
    assert not stale, f"Probe spec(s) for tools that are no longer registered: {stale}"


def test_state_changing_tools_are_skipped():
    """A smoke test that changes what it is measuring is worse than none."""
    registered = _registered_tool_names()
    for name in sorted(STATE_CHANGING & registered):
        probe = smoke_probes.PROBES[name]
        assert probe.skip, f"{name} changes state and must be skipped, not exercised"


def test_probes_are_probe_instances():
    for name, probe in smoke_probes.PROBES.items():
        assert isinstance(probe, Probe), f"{name} is not a Probe"


def test_expensive_tools_are_probed_within_explicit_bounds():
    """A scheduled probe must not inherit a tool's interactive defaults.

    These tools page the sign-in/audit log; their own defaults (e.g. 5 pages)
    are a reasonable answer for a human asking once and far too much work to
    repeat every day. Every bounding parameter a tool offers must therefore
    be passed explicitly -- found here from the source, so a new one cannot
    be added without the same decision.
    """
    source = _server_source()
    for chunk in source.split("@mcp.tool()")[1:]:
        match = re.search(r"^def ([a-z_0-9]+)\(", chunk, re.MULTILINE)
        if not match:
            continue
        name = match.group(1)
        signature = chunk.split(") -> dict", 1)[0]
        declared = {arg for arg in BOUNDING_ARGS if re.search(rf"\b{arg}\s*:", signature)}
        if not declared:
            continue
        probe = smoke_probes.PROBES.get(name)
        assert probe is not None, f"{name} takes bounding arguments and has no probe spec"
        if probe.skip:
            continue
        unbounded = sorted(arg for arg in declared if not isinstance(probe.args.get(arg), int))
        assert not unbounded, (
            f"{name} accepts {unbounded} but its probe leaves them at the tool's "
            "own default. Proving the tool works needs a sample, not the whole "
            "tenant."
        )


def test_every_exercised_probe_asserts_something():
    """A probe that asserts nothing reports a broken tool as OK."""
    offenders = [
        name
        for name, probe in smoke_probes.PROBES.items()
        if not probe.skip
        and not probe.must_match
        and not probe.min_chars
        and not probe.require_keys
        and not probe.min_values
    ]
    assert not offenders, (
        f"probes with nothing to assert: {offenders}. These tools answer with a "
        "dict, so name the envelope keys a working answer always carries "
        "(require_keys)."
    )


def test_fake_user_arg_and_upn_arg_are_address_shaped_but_never_real():
    """The discovery factories build a syntactically valid, guaranteed-fake account.

    Not a source-literal check (that is test_no_tenant_specific_literals_in_specs
    below) -- this confirms the *runtime* value the factories actually hand to a
    tool looks like an account (so validate_upn accepts it and the probe
    exercises the real request path) without asserting anything about a real
    tenant.
    """

    async def call(tool, args):
        raise AssertionError("factories must not call the server")

    user_args = asyncio.run(smoke_probes._fake_user_arg(call))
    upn_args = asyncio.run(smoke_probes._fake_upn_arg(call))
    assert re.match(r"^smoke-test-[0-9a-f]{16}@example\.invalid$", user_args["user"])
    assert re.match(r"^smoke-test-[0-9a-f]{16}@example\.invalid$", upn_args["upn"])
    # Two calls must not coincide -- a fixed address would defeat the point
    # of "guaranteed nonexistent" the moment it collided with a real one.
    assert asyncio.run(smoke_probes._fake_user_arg(call))["user"] != user_args["user"]


def test_address_shapes_catch_what_they_claim_to():
    """The guard below is only as good as these patterns, so pin them.

    IPv6 in particular is easy to get wrong in both directions: miss the
    compressed form, or swallow anything with two colons in it.
    """
    leaks = [
        "user@example.org",
        "https://api.example.ac.jp",
        "files.example.ac.jp",
        "example.com",  # a bare two-label domain is the common shape
        "example.io",
        "192.0.2.10",
        "2001:db8::1",
        "fe80::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ]
    for value in leaks:
        assert any(re.search(p, value) for p in ADDRESS_SHAPES.values()), f"missed: {value}"

    innocuous = [
        "12:34:56",  # a clock time
        "values[::2]",  # a Python slice
        "::1",  # loopback identifies no site
        '"max_pages": 1',  # a probe bound
        "get_user_auth_methods",
    ]
    for value in innocuous:
        matched = [label for label, p in ADDRESS_SHAPES.items() if re.search(p, value)]
        assert not matched, f"false positive on {value!r}: {matched}"


def test_no_account_identifying_arguments_are_hardcoded():
    """Arguments that name part of the tenant must be discovered, not written down."""
    source = _server_source()
    stale = sorted(k for k in IDENTIFIER_ARGS if not re.search(rf"\b{k}\s*:", source))
    assert not stale, (
        f"IDENTIFIER_ARGS names parameters no tool takes any more: {stale}. "
        "A renamed parameter silently empties this guard, so keep the set in "
        "step with the tool signatures."
    )

    offenders = [
        (name, key) for name, probe in smoke_probes.PROBES.items() for key in probe.args if key in IDENTIFIER_ARGS
    ]
    assert not offenders, (
        f"tenant-identifying arguments hardcoded in smoke_probes.py: {offenders}. "
        "Leave them unset, or discover them at run time (args_factory); this "
        "repository is public."
    )

    # The check above reads the specs as data, which an args_factory
    # sidesteps: a factory returning {"upn": "someone@..."} would satisfy it
    # while committing the very literal it exists to prevent. So read the
    # file as text too and refuse one of these keys paired with a string
    # literal anywhere in it -- a discovered value is an expression, never a
    # quote.
    spec_source = (Path(__file__).resolve().parent.parent / "scripts" / "smoke_probes.py").read_text(encoding="utf-8")
    literals = sorted(key for key in IDENTIFIER_ARGS if re.search(rf'["\']{key}["\']\s*:\s*["\']', spec_source))
    assert not literals, (
        f"tenant-identifying arguments written as literals in smoke_probes.py: {literals}. "
        "Return them from a discovery call instead of writing the value down."
    )


def test_no_tenant_specific_literals_in_specs():
    """This repository is public: probes must not name the tenant."""
    source = (Path(__file__).resolve().parent.parent / "scripts" / "smoke_probes.py").read_text(encoding="utf-8")
    hits = [label for label, pattern in ADDRESS_SHAPES.items() if re.search(pattern, source)]
    assert not hits, (
        f"address-like literals in smoke_probes.py: {hits}. Discover such arguments "
        "at run time (args_factory) rather than hardcoding them."
    )
