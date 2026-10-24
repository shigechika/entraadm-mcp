"""Configuration for entraadm-mcp: environment variables, plus an optional tenant file.

Three env vars describe one app registration in one Entra ID tenant, and that
is still the whole configuration for a single-tenant deployment. A deployment
that serves several tenants (the way the sibling gwsadm-mcp serves several
Workspace domains with ``[domain.*]`` sections) points ``ENTRAADM_CONFIG`` at an
INI file with one ``[tenant.<name>]`` section per tenant::

    [tenant.staff]
    tenant_id = 00000000-0000-0000-0000-000000000001
    domains = example.edu
    default = true

    [tenant.students]
    tenant_id = 00000000-0000-0000-0000-000000000002
    domains = students.example.edu
    ; optional: an app of its own (the secret comes from the named env var)
    ; client_id = 00000000-0000-0000-0000-000000000003
    ; client_secret_env = ENTRAADM_STUDENTS_CLIENT_SECRET

A section without ``client_id`` reuses the env app (``ENTRAADM_CLIENT_ID`` /
``ENTRAADM_CLIENT_SECRET``: a multi-tenant app registration consented in each
tenant, the token requested from that tenant's authority), or ``az login`` when
no env app is set. No secret is ever written in the file.
"""

from __future__ import annotations

import configparser
import math
import os
import re
from dataclasses import dataclass, field

#: Env vars that together select app-only auth. All three or none -- see AuthConfig.from_env.
_APP_ONLY_VARS = ("ENTRAADM_TENANT_ID", "ENTRAADM_CLIENT_ID", "ENTRAADM_CLIENT_SECRET")

DEFAULT_MAX_PAGES = 50
DEFAULT_DEADLINE_SECONDS = 45.0
MIN_MAX_PAGES = 1
MAX_MAX_PAGES = 50


class ConfigError(Exception):
    """Raised when the environment cannot be turned into a usable AuthConfig."""


@dataclass(frozen=True)
class AuthConfig:
    """Resolved auth configuration: which credential to build and with what."""

    mode: str  # "app-only" | "azure-cli"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None

    @classmethod
    def from_env(cls, env: dict | None = None) -> AuthConfig:
        """Resolve auth mode from the environment.

        All three ENTRAADM_TENANT_ID/CLIENT_ID/CLIENT_SECRET set -> app-only
        (ClientSecretCredential), used for a headless deployment. None set ->
        azure-cli (AzureCliCredential), used for local development against an
        `az login` session. Any other combination (one or two of the three)
        is a misconfiguration and fails fast rather than silently falling
        back to a different auth mode than intended.
        """
        e = os.environ if env is None else env
        values = {name: e.get(name) for name in _APP_ONLY_VARS}
        present = [name for name, v in values.items() if v]

        if len(present) == 3:
            return cls(
                mode="app-only",
                tenant_id=values["ENTRAADM_TENANT_ID"],
                client_id=values["ENTRAADM_CLIENT_ID"],
                client_secret=values["ENTRAADM_CLIENT_SECRET"],
            )
        if len(present) == 0:
            return cls(mode="azure-cli")

        missing = [name for name in _APP_ONLY_VARS if name not in present]
        raise ConfigError(
            "incomplete app-only credentials: set all of "
            f"{', '.join(_APP_ONLY_VARS)}, or none of them to fall back to "
            f"azure-cli auth (missing: {', '.join(missing)})"
        )


def max_pages_default(env: dict | None = None) -> int:
    """Resolve the default page cap from ENTRAADM_MAX_PAGES_DEFAULT.

    Clamped to [1, 50]; a missing or non-integer value falls back to
    DEFAULT_MAX_PAGES rather than raising, so a typo in the env degrades to a
    safe default instead of crashing the whole server at startup.
    """
    e = os.environ if env is None else env
    raw = e.get("ENTRAADM_MAX_PAGES_DEFAULT")
    if raw is None:
        return DEFAULT_MAX_PAGES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_PAGES
    return max(MIN_MAX_PAGES, min(MAX_MAX_PAGES, value))


def deadline_seconds(env: dict | None = None) -> float | None:
    """Per-call wall-clock budget from ENTRAADM_DEADLINE (default 45 s).

    A hosted MCP client cuts a tool call off at about 60 s, so a paged scan stops
    at this budget and returns what it has (``capped=true``). ``0`` or a negative
    value disables the budget (page count only); a non-numeric value falls back to
    the default.
    """
    e = os.environ if env is None else env
    raw = e.get("ENTRAADM_DEADLINE")
    if raw is None or raw == "":
        return DEFAULT_DEADLINE_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_DEADLINE_SECONDS
    if not math.isfinite(value):
        return DEFAULT_DEADLINE_SECONDS  # nan / inf must not silently disable the budget
    return value if value > 0 else None


#: Opt-in switch for ``revoke_sign_in_sessions``, the only state-changing tool.
REVOKE_SESSIONS_ENV = "ENTRAADM_ENABLE_REVOKE_SESSIONS"


def revoke_sessions_enabled(env: dict | None = None) -> bool:
    """Whether ``revoke_sign_in_sessions`` is enabled (``ENTRAADM_ENABLE_REVOKE_SESSIONS`` is exactly "1").

    Off by default, and any other value ("true", "yes", " 1") is off, so a
    deployment that never set it -- a shared gateway, for instance -- cannot
    expose the tool by accident.
    """
    e = os.environ if env is None else env
    return e.get(REVOKE_SESSIONS_ENV) == "1"


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

#: Env var naming the optional tenant file. Unset or empty: one tenant from the env vars.
CONFIG_ENV = "ENTRAADM_CONFIG"
#: Name of the one tenant of an env-only (no file) deployment.
ENV_TENANT_NAME = "default"

_TENANT_KEYS = {"tenant_id", "domains", "client_id", "client_secret_env", "default"}
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
#: Authority aliases that name no single tenant; never a ``tenant_id``.
_AUTHORITY_ALIASES = {"common", "organizations", "consumers"}


def _valid_tenant_id(value: str) -> bool:
    """A GUID, or a domain name (with a dot) such as a verified domain or <name>.onmicrosoft.com."""
    if _GUID_RE.match(value):
        return True
    return value.lower() not in _AUTHORITY_ALIASES and bool(_DOMAIN_RE.match(value.lower()))


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


@dataclass(frozen=True)
class TenantConfig:
    """One Entra tenant: its credential and the UPN domains routed to it."""

    name: str
    auth: AuthConfig
    domains: tuple[str, ...] = ()
    default: bool = False


@dataclass(frozen=True)
class Tenants:
    """Every configured tenant, the default one, and how to pick one.

    ``from_file`` is False for an env-only deployment: one tenant named
    ``default`` that every UPN routes to, whatever its domain (the behaviour
    before tenant files existed).
    """

    tenants: tuple[TenantConfig, ...]
    from_file: bool = False
    _by_domain: dict = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self):
        by_domain = {d: t for t in self.tenants for d in t.domains}
        object.__setattr__(self, "_by_domain", by_domain)

    @property
    def default(self) -> TenantConfig:
        return next(t for t in self.tenants if t.default)

    @property
    def names(self) -> list[str]:
        return [t.name for t in self.tenants]

    @property
    def domains(self) -> list[str]:
        return sorted(self._by_domain)

    def get(self, name: str) -> TenantConfig:
        return next(t for t in self.tenants if t.name == name)

    def for_upn(self, upn: str) -> TenantConfig | None:
        """The tenant whose ``domains`` holds the UPN's domain (exact match), or None.

        Env-only: always the one tenant.
        """
        if not self.from_file:
            return self.default
        _, _, domain = upn.rpartition("@")
        return self._by_domain.get(domain.strip().lower())

    def resolve(self, ref: str | None) -> TenantConfig | None:
        """A tenant by section name, one of its domains or its tenant id (any case); None picks the default.

        Env-only, the one tenant answers to ``default`` and to its tenant id. An
        unknown reference is None, never the default.
        """
        if ref is None or ref.strip() == "":
            return self.default
        key = ref.strip().lower()
        for t in self.tenants:
            if t.name == key or (t.auth.tenant_id or "").lower() == key:
                return t
        return self._by_domain.get(key)


def _env_app(env) -> tuple[str, str] | None:
    """The env app's (client id, secret), None when neither is set; half of it is a ConfigError."""
    client_id, secret = env.get("ENTRAADM_CLIENT_ID"), env.get("ENTRAADM_CLIENT_SECRET")
    if client_id and secret:
        return client_id, secret
    if client_id or secret:
        raise ConfigError(
            "incomplete env app: set both ENTRAADM_CLIENT_ID and ENTRAADM_CLIENT_SECRET (the app the "
            f"{CONFIG_ENV} sections without client_id reuse), or neither to use az login"
        )
    return None


def _tenant_from_section(name: str, sec, env) -> TenantConfig:
    unknown = sorted(set(sec.keys()) - _TENANT_KEYS)
    if unknown:
        raise ConfigError(f"[tenant.{name}]: unknown key(s) {unknown}")
    tenant_id = (sec.get("tenant_id") or "").strip()
    if not tenant_id:
        raise ConfigError(f"[tenant.{name}]: tenant_id is required")
    if not _valid_tenant_id(tenant_id):
        raise ConfigError(
            f"[tenant.{name}]: tenant_id must be a GUID or the tenant's domain name with a dot "
            f"(got {tenant_id!r}; common/organizations/consumers name no single tenant)"
        )
    domains = []
    for raw in (sec.get("domains") or "").split(","):
        d = raw.strip().lower()
        if not d:
            continue
        if not _DOMAIN_RE.match(d):
            raise ConfigError(f"[tenant.{name}]: {d!r} is not a domain name")
        if d not in domains:
            domains.append(d)
    if not domains:
        raise ConfigError(f"[tenant.{name}]: domains is required (comma-separated UPN domains)")
    try:
        is_default = sec.getboolean("default", fallback=False)
    except ValueError:
        raise ConfigError(f"[tenant.{name}]: default must be true or false") from None

    client_id = (sec.get("client_id") or "").strip()
    secret_env = (sec.get("client_secret_env") or "").strip()
    if bool(client_id) != bool(secret_env):
        raise ConfigError(f"[tenant.{name}]: set both client_id and client_secret_env, or neither")
    if client_id:
        if not _ENV_NAME_RE.match(secret_env):
            raise ConfigError(f"[tenant.{name}]: client_secret_env must name an environment variable")
        secret = env.get(secret_env)
        if not secret:
            raise ConfigError(f"[tenant.{name}]: environment variable {secret_env} (client_secret_env) is unset")
        auth = AuthConfig(mode="app-only", tenant_id=tenant_id, client_id=client_id, client_secret=secret)
    else:
        app = _env_app(env)
        if app is None:
            auth = AuthConfig(mode="azure-cli", tenant_id=tenant_id)
        else:
            auth = AuthConfig(mode="app-only", tenant_id=tenant_id, client_id=app[0], client_secret=app[1])
    return TenantConfig(name=name, auth=auth, domains=tuple(domains), default=is_default)


def load_tenants(env: dict | None = None) -> Tenants:
    """Every tenant this process serves.

    ``ENTRAADM_CONFIG`` unset or empty: one tenant from the env vars
    (``AuthConfig.from_env``), unchanged single-tenant behaviour. Set: the INI
    file's ``[tenant.<name>]`` sections. Raises ConfigError for an unreadable
    file, a section that is not ``[tenant.*]``, an unknown key, a missing
    ``tenant_id`` / ``domains``, a domain claimed by two tenants, more than one
    ``default = true``, or none when there are several tenants (a single
    section is the default without saying so).
    """
    e = os.environ if env is None else env
    path = (e.get(CONFIG_ENV) or "").strip()
    if not path:
        auth = AuthConfig.from_env(e)
        return Tenants((TenantConfig(name=ENV_TENANT_NAME, auth=auth, default=True),), from_file=False)

    parser = configparser.ConfigParser(interpolation=None, default_section="__none__")
    try:
        with open(path, encoding="utf-8") as f:
            parser.read_file(f)
    except (OSError, UnicodeDecodeError, configparser.Error) as exc:
        # The file holds no secret by design, so the parser's own detail (line, section, option) is safe.
        raise ConfigError(f"{CONFIG_ENV}: cannot read {path} ({type(exc).__name__}: {exc})") from None
    if parser.defaults():
        # configparser hides its default section from sections() and copies its keys into every
        # section, which would let a stray [__none__] fill in a tenant's required keys.
        raise ConfigError(f"{CONFIG_ENV}: unknown section [{parser.default_section}] (only [tenant.<name>])")

    tenants: list[TenantConfig] = []
    seen_names: set[str] = set()
    for section in parser.sections():
        if not section.startswith("tenant."):
            raise ConfigError(f"{CONFIG_ENV}: unknown section [{section}] (only [tenant.<name>])")
        name = section[len("tenant.") :].strip().lower()
        if not _NAME_RE.match(name):
            raise ConfigError(f"[{section}]: tenant name must be lower-case letters, digits, '-' or '_'")
        if name in seen_names:
            raise ConfigError(f"[{section}]: tenant {name!r} is defined twice")
        seen_names.add(name)
        tenants.append(_tenant_from_section(name, parser[section], e))
    if not tenants:
        raise ConfigError(f"{CONFIG_ENV}: {path} has no [tenant.<name>] section")

    owner: dict[str, str] = {}
    for t in tenants:
        for d in t.domains:
            if d in owner:
                raise ConfigError(f"domain {d!r} is claimed by both [tenant.{owner[d]}] and [tenant.{t.name}]")
            owner[d] = t.name

    defaults = [t.name for t in tenants if t.default]
    if len(defaults) > 1:
        raise ConfigError(f"more than one default tenant: {defaults}")
    if not defaults:
        if len(tenants) > 1:
            raise ConfigError("no default tenant: set default = true on one [tenant.<name>] section")
        only = tenants[0]
        tenants[0] = TenantConfig(name=only.name, auth=only.auth, domains=only.domains, default=True)
    return Tenants(tuple(tenants), from_file=True)


#: Env var with the ISO 3166-1 alpha-2 codes of the countries the tenant's users sign in from.
HOME_COUNTRIES_ENV = "ENTRAADM_HOME_COUNTRIES"


def home_countries(env: dict | None = None) -> tuple[frozenset[str] | None, str | None]:
    """The home countries from ``ENTRAADM_HOME_COUNTRIES`` (e.g. "JP" or "JP, US"), and an error.

    Unset or empty: ``(None, None)`` -- the caller skips anything that needs
    them rather than guessing. A value with any code that is not an assigned
    ISO 3166-1 alpha-2 code (``JPN``, ``ZZ``): ``(None, message)``, so a typo
    never makes every country look foreign. Codes are upper-cased.
    """
    e = os.environ if env is None else env
    raw = (e.get(HOME_COUNTRIES_ENV) or "").strip()
    if not raw:
        return None, None
    from entraadm_mcp.iso3166 import ISO_3166_ALPHA2

    codes = [c.strip().upper() for c in raw.split(",") if c.strip()]
    bad = [c for c in codes if c not in ISO_3166_ALPHA2]
    if bad or not codes:
        return None, f"{HOME_COUNTRIES_ENV} must be assigned ISO 3166-1 alpha-2 codes such as 'JP' (not {bad or raw!r})"
    return frozenset(codes), None
