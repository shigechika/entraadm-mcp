"""Entry point: ``entraadm-mcp`` (stdio server) / ``--check`` / ``--version`` / ``archive-signins``."""

import asyncio
import os
import sys

from entraadm_mcp import __version__


def _check() -> int:
    """Config + auth + Graph smoke test per tenant (plus an informational ARM line). Exit 0 = every Graph reachable."""
    import time

    from entraadm_mcp.client import ArmClient, GraphClient
    from entraadm_mcp.config import ConfigError, load_tenants

    try:
        tenants = load_tenants()
    except ConfigError as e:
        print(f"Error: {e}")
        return 2
    rc = 0
    default_client = None
    for tenant in tenants.tenants:
        label = f"[{tenant.name}{', default' if tenant.default else ''}] " if tenants.from_file else ""
        print(f"OK: {label}auth mode = {tenant.auth.mode}")
        client = GraphClient(tenant.auth)
        if tenant.default:
            default_client = client
        graph = client.check()
        if graph.get("auth") != "ok":
            print(f"Error: {label}Graph unreachable — {graph.get('detail')}")
            rc = 1
            continue
        print(f"OK: {label}Graph reachable")
        signin = client.probe_signin_access()
        if signin.get("auth") == "ok":
            print(f"OK: {label}sign-in log access confirmed")
        else:
            print(f"Degraded: {label}sign-in log access unavailable — {signin.get('detail')}")
    # Informational, like health_check's ``arm`` probe: Azure RBAC is optional. Default tenant only.
    arm = ArmClient(tenants.default.auth, credential=default_client.credential).check(deadline=time.monotonic() + 10.0)
    if arm.get("auth") == "ok":
        print(f"Info: ARM reachable, {arm.get('subscriptions')} subscription(s) visible")
    else:
        print(f"Info: ARM not usable — {arm.get('detail')}")
    return rc


def _archive_signins(argv: list[str]) -> int:
    """``archive-signins``: write each tenant's ended sign-in slots under --dir (see entraadm_mcp.archive)."""
    import argparse
    import datetime
    import json
    from pathlib import Path

    from entraadm_mcp.archive import MAX_DAYS, SLOT_HOURS_CHOICES, archive_tenant
    from entraadm_mcp.client import GraphClient
    from entraadm_mcp.config import ConfigError, load_tenants

    ap = argparse.ArgumentParser(
        prog="entraadm-mcp archive-signins",
        description="Archive the interactive sign-in log in UTC slots, one gzip JSON-lines file per slot.",
    )
    ap.add_argument("--dir", required=True, type=Path, help="archive root; each tenant gets <dir>/<tenant name>/")
    ap.add_argument("--tenant", action="append", help="tenant section name (repeatable; default: every tenant)")
    ap.add_argument(
        "--days", type=int, default=MAX_DAYS, help=f"how far back to fill (1-{MAX_DAYS}, default {MAX_DAYS})"
    )
    ap.add_argument("--refetch-hours", type=int, default=48, help="re-read slots that ended this recently (default 48)")
    ap.add_argument("--slot-hours", type=int, default=3, choices=SLOT_HOURS_CHOICES, help="slot length (default 3)")
    ap.add_argument("--keep-days", type=int, default=0, help="delete slots older than this many days (0: keep all)")
    args = ap.parse_args(argv)
    try:
        tenants = load_tenants()
    except ConfigError as e:
        print(f"entraadm-mcp: {e}", file=sys.stderr)
        return 2
    chosen = [t for t in tenants.tenants if not args.tenant or t.name in args.tenant]
    unknown = sorted(set(args.tenant or ()) - {t.name for t in tenants.tenants})
    if unknown:
        print(f"entraadm-mcp: unknown tenant(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    now = datetime.datetime.now(datetime.timezone.utc)
    summary = {}
    if not 1 <= args.days <= MAX_DAYS:
        print(f"entraadm-mcp: --days must be 1-{MAX_DAYS}", file=sys.stderr)
        return 2
    if args.refetch_hours < 0:
        print("entraadm-mcp: --refetch-hours must not be negative", file=sys.stderr)
        return 2
    if args.keep_days and args.keep_days <= args.days:
        print(f"entraadm-mcp: --keep-days must be 0 or more than --days ({args.days})", file=sys.stderr)
        return 2
    rc = 0
    for tenant in chosen:

        def log(msg: str, name: str = tenant.name) -> None:
            print(f"archive-signins: {name}: {msg}", file=sys.stderr, flush=True)

        try:
            summary[tenant.name] = archive_tenant(
                GraphClient(tenant.auth),
                args.dir / tenant.name,
                now,
                days=args.days,
                refetch_hours=args.refetch_hours,
                slot_hours=args.slot_hours,
                keep_days=args.keep_days,
                log=log,
            )
        except (ValueError, OSError) as e:
            # One tenant's archive cannot be used; the others still run and the summary still prints.
            print(f"entraadm-mcp: {tenant.name}: {e}", file=sys.stderr)
            summary[tenant.name] = {"written": 0, "skipped": 0, "rows": 0, "failed": [], "pruned": 0, "error": str(e)}
            rc = 2
    print(json.dumps({"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "tenants": summary}))
    if rc:
        return rc
    return 1 if any(s["failed"] or s["error"] for s in summary.values()) else 0


def main() -> None:
    argv = sys.argv[1:]
    if argv[:1] == ["archive-signins"]:
        sys.exit(_archive_signins(argv[1:]))
    if "--version" in argv:
        print(f"entraadm-mcp {__version__}")
        return
    if "--check" in argv:
        sys.exit(_check())
    if os.environ.get("ENTRAADM_CONFIG", "").strip():
        # A tenant file is validated before serving: a duplicate domain or a missing
        # default would otherwise surface only as an error on every tool call.
        from entraadm_mcp.config import ConfigError, load_tenants

        try:
            load_tenants()
        except ConfigError as e:
            print(f"entraadm-mcp: {e}", file=sys.stderr)
            sys.exit(2)
    try:
        # Import lazily so --version / --check work without the MCP runtime.
        # The import sits inside the try so a ^C during the (slow) import chain
        # also exits cleanly, not just one delivered while the server runs.
        from entraadm_mcp.server import mcp

        mcp.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        # anyio's teardown on SIGINT dumps a 20-80 line traceback. What it
        # raises out of mcp.run() is Python-version-dependent: a bare
        # KeyboardInterrupt on 3.12/3.13, but asyncio.CancelledError on 3.10
        # (asyncio.Runner.run() re-raises CancelledError instead of letting
        # KeyboardInterrupt propagate). Catch both and exit clean, same
        # convention as the sibling fleet MCP servers.
        os._exit(0)


if __name__ == "__main__":
    main()
