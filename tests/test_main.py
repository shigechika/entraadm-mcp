"""Entry-point behavior: interactive ^C must exit cleanly (no traceback)."""

import os
import signal
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT semantics differ on Windows")
def test_sigint_exits_cleanly():
    p = subprocess.Popen(
        [sys.executable, "-m", "entraadm_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2.0)  # let the stdio server start
    p.send_signal(signal.SIGINT)
    out, err = p.communicate(timeout=10)
    assert p.returncode == 0
    assert b"Traceback" not in err


def test_a_bad_tenant_file_stops_the_server_at_startup(tmp_path):
    bad = tmp_path / "tenants.ini"
    bad.write_text("[tenant.a]\ntenant_id = 00000000-0000-0000-0000-000000000001\n", encoding="utf-8")
    p = subprocess.run(
        [sys.executable, "-m", "entraadm_mcp"],
        env={**os.environ, "ENTRAADM_CONFIG": str(bad)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )
    assert p.returncode == 2
    assert b"domains is required" in p.stderr
