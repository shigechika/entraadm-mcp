"""Entry-point behavior: interactive ^C must exit cleanly (no traceback)."""

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
