"""Classify source IPs into the tenant's own sites using an INI file.

The file is named by ``ENTRAADM_SITES_INI``. It uses the same format as the
sibling keycloak-mcp's ``KEYCLOAK_SITES_INI``, so one file can serve both::

    [HQ]
    name = Head office
    ipv4 = 192.0.2.0/24, 198.51.100.0/25
    ipv6 = 2001:db8:1::/48

Each section is a site: the section name is its short code, ``name`` an
optional display name, and ``ipv4`` / ``ipv6`` comma-separated CIDR ranges.
Lookups are longest-prefix: a narrower range carved out of a wider one wins,
whatever order the sections are written in. An IPv4-mapped IPv6 address
(``::ffff:192.0.2.1``) is looked up as IPv4.

An invalid CIDR is reported as an error, but the valid ranges are still used,
so one typo does not turn every internal range into "external". The file is
re-read when it changes (size, mtime, ctime or inode), and a failed read is not
cached, so an updated or repaired file takes effect without a restart.
"""

from __future__ import annotations

import configparser
import ipaddress
import os
import threading
from dataclasses import dataclass, field

ENV_VAR = "ENTRAADM_SITES_INI"

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Site:
    """One matched site: short code (section name) and optional display name."""

    code: str
    name: str | None


@dataclass
class SiteTable:
    """Loaded ranges, plus enough state to report the configuration in health_check."""

    path: str | None
    networks: list[tuple[_Network, Site]] = field(default_factory=list)
    error: str | None = None

    @property
    def configured(self) -> bool:
        """True when ENTRAADM_SITES_INI is set, whether or not it loaded."""
        return bool(self.path)

    def classify(self, ip: str | None) -> Site | None:
        """Return the site whose range most specifically contains ``ip``, or None."""
        if not ip or not self.networks:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        # networks is sorted longest prefix first, so the first match is the most specific.
        for net, site in self.networks:
            if addr.version == net.version and addr in net:
                return site
        return None

    def status(self) -> dict:
        """Fixed-shape summary for health_check and tool output."""
        return {"configured": self.configured, "ranges": len(self.networks), "error": self.error}


def _parse(path: str) -> SiteTable:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as f:
            parser.read_file(f)
    except (OSError, UnicodeDecodeError, configparser.Error) as e:
        return SiteTable(path=path, error=f"cannot read {ENV_VAR}: {type(e).__name__}: {e}")

    networks: list[tuple[_Network, Site]] = []
    bad: list[str] = []
    for section in parser.sections():
        site = Site(code=section, name=parser.get(section, "name", fallback=None) or None)
        for key in ("ipv4", "ipv6"):
            for cidr in parser.get(section, key, fallback="").split(","):
                cidr = cidr.strip()
                if not cidr:
                    continue
                try:
                    networks.append((ipaddress.ip_network(cidr, strict=False), site))
                except ValueError:
                    bad.append(f"[{section}] {cidr}")

    networks.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
    error = None
    if bad:
        more = f" (+{len(bad) - 5} more)" if len(bad) > 5 else ""
        error = f"invalid CIDR in {ENV_VAR}, skipped: {', '.join(bad[:5])}{more}"
    elif not networks:
        error = f"{ENV_VAR} has no ipv4/ipv6 ranges"
    return SiteTable(path=path, networks=networks, error=error)


_lock = threading.Lock()
_cache: dict[str, object] = {"key": None, "table": SiteTable(path=None)}


def load(env: dict | None = None) -> SiteTable:
    """Return the site table for the current environment, re-reading the file only when it changes."""
    e = os.environ if env is None else env
    path = e.get(ENV_VAR) or None
    if path is None:
        return SiteTable(path=None)
    try:
        st = os.stat(path)
    except OSError as err:
        return SiteTable(path=path, error=f"cannot read {ENV_VAR}: {type(err).__name__}: {err}")

    # ctime catches a chmod/chown repair; size and inode catch a rewrite within one mtime tick.
    key = (path, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
    with _lock:
        if _cache["key"] == key:
            return _cache["table"]  # type: ignore[return-value]
        table = _parse(path)
        if table.networks or not table.error:
            _cache["key"], _cache["table"] = key, table
        else:
            # Nothing loaded: try again on the next call instead of caching the failure.
            _cache["key"] = None
        return table
