"""Entry point: ``entraadm-mcp`` (stdio server) / ``entraadm-mcp --check`` / ``--version``."""

import asyncio
import os
import sys

from entraadm_mcp import __version__


def _check() -> int:
    """Config + auth + Graph smoke test (plus an informational ARM line). Exit 0 = Graph reachable."""
    from entraadm_mcp.client import GraphClient
    from entraadm_mcp.config import AuthConfig, ConfigError

    try:
        config = AuthConfig.from_env()
    except ConfigError as e:
        print(f"Error: {e}")
        return 2
    print(f"OK: auth mode = {config.mode}")
    client = GraphClient(config)
    graph = client.check()
    if graph.get("auth") != "ok":
        print(f"Error: Graph unreachable — {graph.get('detail')}")
        return 1
    print("OK: Graph reachable")
    signin = client.probe_signin_access()
    if signin.get("auth") == "ok":
        print("OK: sign-in log access confirmed")
    else:
        print(f"Degraded: sign-in log access unavailable — {signin.get('detail')}")
    # Informational, like health_check's ``arm`` probe: Azure RBAC is optional.
    import time

    from entraadm_mcp.client import ArmClient

    arm = ArmClient(config, credential=client.credential).check(deadline=time.monotonic() + 10.0)
    if arm.get("auth") == "ok":
        print(f"Info: ARM reachable, {arm.get('subscriptions')} subscription(s) visible")
    else:
        print(f"Info: ARM not usable — {arm.get('detail')}")
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if "--version" in argv:
        print(f"entraadm-mcp {__version__}")
        return
    if "--check" in argv:
        sys.exit(_check())
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
