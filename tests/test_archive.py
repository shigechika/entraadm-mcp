"""archive-signins: slot selection, refetch window, atomic writes, failures and pruning."""

import datetime
import gzip
import json
import os
import stat
import subprocess
import sys

import pytest

from entraadm_mcp.archive import archive_tenant, slot_starts
from entraadm_mcp.client import ApiError

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 8, 21, 7, 30, tzinfo=UTC)


class FakeClient:
    """get_paged answers per slot filter: a list of rows, (rows, capped), or an exception."""

    def __init__(self, answers=None, default=()):
        self.answers = answers or {}
        self.default = default if isinstance(default, Exception) else list(default)
        self.calls = []

    def get_paged(self, path, params=None, max_pages=5, deadline=None):
        assert path == "/auditLogs/signIns" and deadline is None
        self.calls.append(params["$filter"])
        start = params["$filter"].split(" ge ")[1].split(" and ")[0]
        answer = self.answers.get(start, self.default)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, tuple):
            return answer
        return list(answer), False


def _read(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def _run(tmp_path, client, **kw):
    kw.setdefault("sleep", lambda _s: None)
    return archive_tenant(client, tmp_path / "staff", NOW, **kw)


def test_slots_cover_only_ended_slots_aligned_to_utc():
    starts = slot_starts(NOW, 1, 3)
    # aligned up: 06:00-09:00 on the 20th straddles the 24-hour edge and is left out
    assert starts[0] == datetime.datetime(2026, 8, 20, 9, tzinfo=UTC)
    assert starts[-1] == datetime.datetime(2026, 8, 21, 3, tzinfo=UTC)  # 06:00-09:00 has not ended
    assert len(starts) == 7


def test_each_slot_is_written_deduplicated_and_sorted(tmp_path):
    rows = [
        {"id": "b", "createdDateTime": "2026-08-21T04:00:00Z"},
        {"id": "a", "createdDateTime": "2026-08-21T03:30:00Z"},
        {"id": "b", "createdDateTime": "2026-08-21T04:00:00Z"},
    ]
    client = FakeClient({"2026-08-21T03:00:00Z": rows})
    out = _run(tmp_path, client, days=1)
    assert out["written"] == 7 and out["failed"] == [] and out["rows"] == 2
    assert [r["id"] for r in _read(tmp_path / "staff" / "2026-08-21T03.jsonl.gz")] == ["a", "b"]
    assert _read(tmp_path / "staff" / "2026-08-20T09.jsonl.gz") == []  # read and empty, still written
    assert "createdDateTime lt 2026-08-21T06:00:00Z" in client.calls[-1]


def test_old_slots_with_a_file_are_skipped_and_recent_ones_refetched(tmp_path):
    _run(tmp_path, FakeClient(), days=3)
    client = FakeClient()
    out = _run(tmp_path, client, days=3, refetch_hours=6)
    # slots ending at or before 01:30 are kept; 00:00-03:00 and 03:00-06:00 end after it
    assert out["written"] == 2 and out["skipped"] == len(slot_starts(NOW, 3, 3)) - 2
    assert len(client.calls) == 2


def test_a_failed_or_capped_slot_keeps_the_previous_file(tmp_path):
    first = FakeClient({"2026-08-21T03:00:00Z": [{"id": "old"}]})
    _run(tmp_path, first, days=1)
    client = FakeClient(
        {"2026-08-21T03:00:00Z": ApiError("boom"), "2026-08-21T00:00:00Z": ([{"id": "x"}], True)},
    )
    out = _run(tmp_path, client, days=1)
    assert out["failed"] == ["2026-08-21T00.jsonl.gz", "2026-08-21T03.jsonl.gz"]
    assert _read(tmp_path / "staff" / "2026-08-21T03.jsonl.gz") == [{"id": "old"}]
    assert not [f for f in os.listdir(tmp_path / "staff") if f.startswith(".tmp-")]


def test_a_transient_error_is_retried(tmp_path):
    class Flaky(FakeClient):
        def get_paged(self, path, params=None, max_pages=5, deadline=None):
            self.calls.append(params["$filter"])
            if len(self.calls) == 1:
                raise ApiError("429")
            return [{"id": "ok"}], False

    waits = []
    out = archive_tenant(Flaky(), tmp_path / "s", NOW, days=2, slot_hours=24, sleep=waits.append)
    assert out["failed"] == [] and out["written"] == 1 and waits == [30]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_files_and_directories_are_private(tmp_path):
    d = tmp_path / "staff"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    _run(tmp_path, FakeClient(default=[{"id": "a"}]), days=2, slot_hours=24)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    (f,) = d.glob("*.jsonl.gz")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE((d / "SLOT_HOURS").stat().st_mode) == 0o600


def test_keep_days_prunes_older_slots(tmp_path):
    d = tmp_path / "staff"
    d.mkdir()
    for name in ("2026-07-01T00.jsonl.gz", "2026-08-19T00.jsonl.gz"):
        (d / name).write_bytes(gzip.compress(b""))
    out = _run(tmp_path, FakeClient(), days=1, slot_hours=24, keep_days=30)
    assert out["pruned"] == 1
    assert not (d / "2026-07-01T00.jsonl.gz").exists() and (d / "2026-08-19T00.jsonl.gz").exists()


def test_another_slot_length_is_refused_for_an_existing_archive(tmp_path):
    _run(tmp_path, FakeClient(), days=1, slot_hours=3)
    assert (tmp_path / "staff" / "SLOT_HOURS").read_text() == "3\n"
    with pytest.raises(ValueError, match="3-hour slots"):
        _run(tmp_path, FakeClient(), days=1, slot_hours=24)


def test_keep_days_must_exceed_the_fetch_window(tmp_path):
    with pytest.raises(ValueError, match="keep_days"):
        _run(tmp_path, FakeClient(), days=30, keep_days=30)


def test_a_slot_length_that_does_not_tile_a_day_is_refused(tmp_path):
    with pytest.raises(ValueError):
        _run(tmp_path, FakeClient(), slot_hours=5)


def test_cli_rejects_an_unknown_tenant(tmp_path):
    ini = tmp_path / "tenants.ini"
    ini.write_text(
        "[tenant.staff]\ntenant_id = 00000000-0000-0000-0000-000000000001\ndomains = example.edu\ndefault = true\n",
        encoding="utf-8",
    )
    p = subprocess.run(
        [sys.executable, "-m", "entraadm_mcp", "archive-signins", "--dir", str(tmp_path), "--tenant", "nope"],
        env={**os.environ, "ENTRAADM_CONFIG": str(ini)},
        capture_output=True,
        timeout=30,
    )
    assert p.returncode == 2 and b"unknown tenant(s): nope" in p.stderr


def test_an_auth_or_permission_error_stops_the_tenant(tmp_path):
    from entraadm_mcp.client import ApiPermissionError

    client = FakeClient(default=ApiPermissionError("403: AuditLog.Read.All is missing"))
    waits = []
    out = archive_tenant(client, tmp_path / "staff", NOW, days=3, sleep=waits.append)
    assert len(client.calls) == 1 and waits == []
    assert out["error"].startswith("403") and len(out["failed"]) == 1 and out["written"] == 0


def test_a_failed_reread_marks_the_slot_stale_until_a_read_succeeds(tmp_path):
    _run(tmp_path, FakeClient(default=[{"id": "early"}]), days=1)
    d = tmp_path / "staff"
    slot = "2026-08-21T03.jsonl.gz"
    _run(tmp_path, FakeClient({"2026-08-21T03:00:00Z": ApiError("boom")}), days=1)
    assert (d / (slot + ".stale")).exists()
    later = NOW + datetime.timedelta(days=5)  # far past the refetch window
    client = FakeClient({"2026-08-21T03:00:00Z": [{"id": "full"}]})
    archive_tenant(client, d, later, days=6, sleep=lambda _s: None)
    assert any("2026-08-21T03:00:00Z" in c for c in client.calls)
    assert _read(d / slot) == [{"id": "full"}] and not (d / (slot + ".stale")).exists()


def test_pruning_leaves_temporary_files_alone(tmp_path):
    d = tmp_path / "staff"
    d.mkdir()
    (d / "SLOT_HOURS").write_text("24\n")
    tmp = d / ".tmp-abc.jsonl.gz"
    tmp.write_bytes(b"")
    _run(tmp_path, FakeClient(), days=1, slot_hours=24, keep_days=30)
    assert tmp.exists()


@pytest.mark.parametrize("kw", [{"days": 0}, {"days": 31}, {"refetch_hours": -1}])
def test_out_of_range_arguments_are_refused(tmp_path, kw):
    with pytest.raises(ValueError):
        _run(tmp_path, FakeClient(), **kw)
