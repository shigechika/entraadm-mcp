#!/usr/bin/env python3
"""Exercise every registered tool against the live Microsoft Graph and report what is broken.

Unit tests verify logic against fixtures; this verifies that the tools users
actually call still answer with real data. A tool that exists but silently
returns nothing is worse than no tool, and no fixture-based test can tell you
that it happened.

Read-only by construction: every tool here reads an audit log or a directory
snapshot, and the report prints only tool names, statuses and row counts —
never payloads, which would otherwise carry account names and IP addresses into
logs.

Usage:
    # In-process: imports the server, uses its configured service accounts.
    ENTRAADM_TENANT_ID=... ENTRAADM_CLIENT_ID=... ENTRAADM_CLIENT_SECRET=... uv run python scripts/smoke_test.py

    # Iterate on one spec while writing it.
    uv run python scripts/smoke_test.py --only signin --traceback

    # Machine-readable output.
    uv run python scripts/smoke_test.py --output json

Exit code:
    0  every tool answered acceptably (OK / SKIP)
    1  at least one tool FAILED, or is registered with no probe spec
"""

import argparse
import asyncio
import importlib
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from smoke_harness import (  # noqa: E402 - needs the sys.path line above
    FAILING,
    JST,
    Caller,
    previous_weekday,
    render_json,
    render_markdown,
    run_probes,
)


def _decode(result: Any) -> Any:
    """Normalise an MCP tool result into plain Python data.

    ``mcp.server.fastmcp`` hands back ``(content_blocks, structured_result)``
    when it converts a result, and bare content blocks otherwise; the
    standalone FastMCP client used by --stdio hands back a ``CallToolResult``.
    Everything downstream expects a str/dict/list, so unwrap all three here
    rather than teaching the engine about SDK shapes.
    """
    # --stdio: the standalone client returns a CallToolResult object rather
    # than either of the SDK shapes below. Unwrapped first, and to the same
    # str/dict/list the in-process path yields, so a probe written against one
    # transport holds for the other. Structured content before .data: the
    # latter is the client's own coercion of it.
    if hasattr(result, "content") and hasattr(result, "is_error"):
        if result.is_error:
            # The client raises on error by default, so this is belt and
            # braces — but a tool failure decoded as ordinary data could
            # satisfy a loose text probe and report a broken tool as OK, which
            # is the one outcome this whole exercise exists to prevent.
            raise RuntimeError("the server reported the tool call as failed")
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict) and set(structured) == {"result"}:
            inner = structured["result"]
            if isinstance(inner, str):
                return inner
        if isinstance(structured, (dict, list)):
            return structured
        data = getattr(result, "data", None)
        if isinstance(data, (str, dict, list)):
            return data
        result = result.content

    # (content, structured): prefer the structured half when the tool declares
    # one — except for the {"result": "..."} wrapper the SDK puts around a tool
    # annotated `-> str`. Probes assert what the tool renders, and inside that
    # wrapper the rendered text is no longer at the start of the payload, so a
    # ``^header`` pattern would never match.
    if isinstance(result, tuple) and len(result) == 2:
        content, structured = result
        if isinstance(structured, dict) and set(structured) == {"result"}:
            inner = structured["result"]
            if isinstance(inner, str):
                return inner
        if isinstance(structured, (dict, list)):
            return structured
        result = content

    if _is_content_sequence(result):
        text = getattr(result[0], "text", None)
        if text is None:
            return result
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return result


def _is_content_sequence(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and bool(value) and hasattr(value[0], "type")


async def _in_process_caller() -> tuple[Caller, list[str]]:
    from entraadm_mcp.server import mcp

    async def call(name: str, args: dict[str, Any]) -> Any:
        return _decode(await mcp.call_tool(name, args))

    names = [tool.name for tool in await mcp.list_tools()]
    return call, names


async def _stdio_caller(command: str) -> tuple[Caller, list[str], Any]:
    """Speak MCP over stdio to a server launched as a subprocess."""
    import shlex

    try:
        from fastmcp import Client
        from fastmcp.client.transports import StdioTransport
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on the env
        # Deliberately not a dependency: this server is built on the official
        # SDK, and the in-process mode above needs nothing extra. --stdio is
        # the opt-in way to exercise the real protocol path.
        raise SystemExit("--stdio needs the standalone client library: pip install fastmcp") from exc

    parts = shlex.split(command)
    if not parts:
        raise ValueError("--stdio needs a command to launch the server")
    client = Client(StdioTransport(command=parts[0], args=parts[1:]))
    await client.__aenter__()
    try:
        names = [tool.name for tool in await client.list_tools()]
    except BaseException:
        # Otherwise the launched subprocess is stranded with its pipes open.
        await client.__aexit__(None, None, None)
        raise

    async def call(name: str, args: dict[str, Any]) -> Any:
        return _decode(await client.call_tool(name, args))

    return call, names, client


async def main_async(args: argparse.Namespace) -> int:
    probes_module = importlib.import_module(args.probes)
    probes = probes_module.PROBES

    client = None
    if args.stdio:
        call, names, client = await _stdio_caller(args.stdio)
        mode = f"stdio {args.stdio.split()[0]}"
    else:
        call, names = await _in_process_caller()
        mode = "in-process"

    try:
        today = datetime.now(JST).date()
        # No exchange calendar here; date tokens resolve against plain weekdays.
        reference = date.fromisoformat(args.date) if args.date else previous_weekday(today)

        selected = [n for n in names if args.only in n] if args.only else names
        if args.only and not selected:
            print(f"no registered tool matches --only {args.only!r}", file=sys.stderr)
            return 1

        results = await run_probes(
            selected,
            probes,
            call,
            reference,
            today,
            concurrency=args.concurrency,
            show_traceback=args.traceback,
            # Personal data must not reach the report: these tools deal in
            # account addresses and sign-in/audit details throughout, and an error
            # routinely quotes the one it was asked about. --traceback still
            # shows the full text on the operator's own terminal.
            redact_details=True,
        )
    finally:
        if client is not None:
            await client.__aexit__(None, None, None)

    stale = sorted(set(probes) - set(names))
    if stale and not args.only:
        # stderr: stdout carries the report, and --output json must stay valid.
        print(
            f"::warning::probe specs for tools that are no longer registered: {stale}",
            file=sys.stderr,
        )

    if args.output == "json":
        print(render_json(results, reference, mode))
    else:
        print(render_markdown(results, reference, mode))

    return 1 if any(r.status in FAILING for r in results) else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--stdio",
        default="",
        help="launch the server over stdio instead of importing it (needs `pip install fastmcp`)",
    )
    parser.add_argument("--probes", default="smoke_probes", help="module holding the probe specs")
    parser.add_argument("--only", default="", help="run only tools whose name contains this")
    parser.add_argument("--date", default="", help="override the reference date")
    parser.add_argument("--output", choices=("md", "json"), default="md")
    # Serial by default: Microsoft Graph is quota-limited per tenant and
    # these tools already fan out internally — a burst of them is a worse
    # neighbour than a slow smoke test.
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--traceback", action="store_true", help="print full stacks for failing tools")
    args = parser.parse_args()

    if args.date:
        try:
            date.fromisoformat(args.date)
        except ValueError:
            parser.error("--date must be YYYY-MM-DD")

    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
