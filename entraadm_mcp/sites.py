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
whatever order the sections are written in.

The file is re-read when its modification time changes, so an updated file
takes effect without restarting the server.
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

    @property
    def usable(self) -> bool:
        """True when at least one range loaded and no error occurred."""
        return self.error is None and bool(self.networks)

    def classify(self, ip: str | None) -> Site | None:
        """Return the site whose range most specifically contains ``ip``, or None."""
        if not ip or not self.networks:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: tuple[_Network, Site] | None = None
        for net, site in self.networks:
            if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, site)
        return best[1] if best else None

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

    if bad:
        # A typo must not quietly turn an internal range into "external".
        return SiteTable(path=path, error=f"invalid CIDR in {ENV_VAR}: {', '.join(bad[:5])}")
    if not networks:
        return SiteTable(path=path, error=f"{ENV_VAR} has no ipv4/ipv6 ranges")
    return SiteTable(path=path, networks=networks)


_lock = threading.Lock()
_cache: dict[str, object] = {"key": None, "table": SiteTable(path=None)}


def load(env: dict | None = None) -> SiteTable:
    """Return the site table for the current environment, re-reading the file only when it changes."""
    e = os.environ if env is None else env
    path = e.get(ENV_VAR) or None
    if path is None:
        return SiteTable(path=None)
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError as err:
        return SiteTable(path=path, error=f"cannot read {ENV_VAR}: {type(err).__name__}: {err}")

    key = (path, mtime)
    with _lock:
        if _cache["key"] != key:
            _cache["table"] = _parse(path)
            _cache["key"] = key
        return _cache["table"]  # type: ignore[return-value]
