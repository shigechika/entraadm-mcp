"""Environment-variable configuration for entraadm-mcp.

Unlike the sibling gwsadm-mcp (multi-domain, service-account-file-per-domain),
this server talks to exactly one Entra ID tenant, so a config *file* would add
a layer of indirection for no benefit. Three env vars are enough to describe
one app registration; everything else has a safe default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

#: Env vars that together select app-only auth. All three or none -- see AuthConfig.from_env.
_APP_ONLY_VARS = ("ENTRAADM_TENANT_ID", "ENTRAADM_CLIENT_ID", "ENTRAADM_CLIENT_SECRET")

DEFAULT_MAX_PAGES = 5
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
