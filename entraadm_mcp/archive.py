"""Keep the interactive sign-in log beyond Entra's retention: ``entraadm-mcp archive-signins``.

Entra ID keeps sign-ins for 30 days (7 without a P1/P2 licence). This walks
``/auditLogs/signIns`` in fixed UTC slots and writes each slot, raw Graph
objects as JSON lines, to ``<dir>/<tenant>/<YYYY-MM-DDTHH>.jsonl.gz``:

- Only slots that have ended are written. A slot whose end is within
  ``refetch_hours`` of now is fetched again on every run (Graph delivers some
  sign-ins late); an older slot that already has a file is left alone.
- A slot is written to a temporary file and renamed into place, so a file
  that exists is a complete walk of its slot. A slot with no sign-ins gets an
  empty file: it was read, not skipped.
- A walk that runs out of pages, or fails, leaves the slot's previous file
  (if any) untouched and is reported in ``failed``.
- Rows are de-duplicated by ``id`` and sorted by ``createdDateTime``.
- Directories are created 0700 and files 0600: the rows name people and
  their addresses.
- The slot length is recorded in ``<dir>/<tenant>/SLOT_HOURS`` on the first
  run; a later run with another length is refused, since file names carry
  only the slot start.
- The oldest slot starts at or after ``days`` before now (aligned up): a slot
  straddling the retention edge would be read only partly and then kept.
- A failed re-read leaves ``<slot>.stale`` next to the slot's earlier file; a
  stale slot is re-read on every run, whatever its age, until a read succeeds.
- An authentication or permission error stops the tenant at once (every slot
  would fail the same way), with ``error`` set in the result.
"""

from __future__ import annotations

import datetime
import gzip
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from entraadm_mcp.client import ApiAuthError, ApiError, ApiPermissionError

#: Slot lengths that tile a UTC day. 1 and 3 also tile any whole-hour UTC offset's day in
#: steps of 3 hours or less, so a consumer can rebuild a local day from whole slots.
SLOT_HOURS_CHOICES = (1, 2, 3, 4, 6, 8, 12, 24)
#: Graph keeps interactive sign-ins for 30 days with P1/P2; asking further back returns nothing.
MAX_DAYS = 30
#: A slot is one filtered walk; the page budget is a backstop, not a sampling limit.
MAX_PAGES = 100_000
ATTEMPTS = 3
RETRY_WAIT_SECONDS = 30


def slot_starts(now: datetime.datetime, days: int, slot_hours: int) -> list[datetime.datetime]:
    """Starts of the slots that have ended, from ``days`` before ``now`` (aligned up) to the last full one."""
    step = datetime.timedelta(hours=slot_hours)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    first = now - datetime.timedelta(days=days)
    start = epoch + -((epoch - first) // step) * step
    out = []
    while start + step <= now:
        out.append(start)
        start += step
    return out


def _iso(t: datetime.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _slot_name(start: datetime.datetime) -> str:
    return start.strftime("%Y-%m-%dT%H") + ".jsonl.gz"


def _write(path: Path, rows: list[dict]) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".jsonl.gz")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            for row in rows:
                gz.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _fetch(client, start: datetime.datetime, end: datetime.datetime, sleep: Callable[[float], None]) -> list[dict]:
    """One complete walk of the slot; raises ApiError when it cannot be had in ATTEMPTS tries."""
    params = {"$filter": f"createdDateTime ge {_iso(start)} and createdDateTime lt {_iso(end)}", "$top": "1000"}
    for attempt in range(1, ATTEMPTS + 1):
        try:
            items, capped = client.get_paged("/auditLogs/signIns", params=params, max_pages=MAX_PAGES)
            if capped:
                raise ApiError(f"page budget of {MAX_PAGES} ran out")
            return items
        except (ApiAuthError, ApiPermissionError):
            raise
        except ApiError:
            if attempt == ATTEMPTS:
                raise
            sleep(RETRY_WAIT_SECONDS * attempt)
    raise AssertionError("unreachable")


def archive_tenant(
    client,
    out_dir: Path,
    now: datetime.datetime,
    *,
    days: int = MAX_DAYS,
    refetch_hours: int = 48,
    slot_hours: int = 3,
    keep_days: int = 0,
    log: Callable[[str], None] = lambda _m: None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Archive one tenant's slots into ``out_dir``; returns counts and the failed slot names."""
    if slot_hours not in SLOT_HOURS_CHOICES:
        raise ValueError(f"slot_hours must be one of {SLOT_HOURS_CHOICES}")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"days must be 1-{MAX_DAYS}")
    if refetch_hours < 0:
        raise ValueError("refetch_hours must not be negative")
    if keep_days and keep_days <= days:
        raise ValueError(f"keep_days ({keep_days}) must be 0 or more than days ({days})")
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    out_dir.chmod(0o700)
    marker = out_dir / "SLOT_HOURS"
    if marker.exists():
        recorded = marker.read_text(encoding="ascii").strip()
        if recorded != str(slot_hours):
            raise ValueError(f"{out_dir} holds {recorded}-hour slots; refusing to mix in {slot_hours}-hour slots")
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(f"{slot_hours}\n")
    step = datetime.timedelta(hours=slot_hours)
    fresh_after = now - datetime.timedelta(hours=refetch_hours)
    result = {"written": 0, "skipped": 0, "rows": 0, "failed": [], "pruned": 0, "error": None}
    for start in slot_starts(now, days, slot_hours):
        end = start + step
        path = out_dir / _slot_name(start)
        stale = path.with_name(path.name + ".stale")
        if path.exists() and end <= fresh_after and not stale.exists():
            result["skipped"] += 1
            continue
        try:
            items = _fetch(client, start, end, sleep)
        except (ApiAuthError, ApiPermissionError) as e:
            log(f"{path.name}: {e}; stopping this tenant")
            result["error"] = str(e)
            result["failed"].append(path.name)
            break
        except ApiError as e:
            log(f"{path.name}: failed: {e}")
            result["failed"].append(path.name)
            if path.exists():
                stale.touch(mode=0o600)
            continue
        unique = {}
        for row in items:
            unique[row.get("id") or json.dumps(row, sort_keys=True)] = row
        rows = sorted(unique.values(), key=lambda r: r.get("createdDateTime") or "")
        _write(path, rows)
        stale.unlink(missing_ok=True)
        result["written"] += 1
        result["rows"] += len(rows)
        log(f"{path.name}: {len(rows)} rows")
    if keep_days > 0:
        cutoff = _slot_name(now - datetime.timedelta(days=keep_days))
        for f in out_dir.glob("*.jsonl.gz"):
            if not f.name.startswith(".") and f.name < cutoff and f.name not in result["failed"]:
                f.unlink()
                f.with_name(f.name + ".stale").unlink(missing_ok=True)
                result["pruned"] += 1
    return result
