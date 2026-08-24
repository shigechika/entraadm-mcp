"""Tests for environment-driven auth configuration."""

import pytest

from entraadm_mcp.config import (
    DEFAULT_MAX_PAGES,
    AuthConfig,
    ConfigError,
    max_pages_default,
)

FULL_APP_ONLY = {
    "ENTRAADM_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "ENTRAADM_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "ENTRAADM_CLIENT_SECRET": "super-secret-value",
}


def test_all_three_vars_selects_app_only():
    config = AuthConfig.from_env(FULL_APP_ONLY)
    assert config.mode == "app-only"
    assert config.tenant_id == FULL_APP_ONLY["ENTRAADM_TENANT_ID"]
    assert config.client_id == FULL_APP_ONLY["ENTRAADM_CLIENT_ID"]
    assert config.client_secret == FULL_APP_ONLY["ENTRAADM_CLIENT_SECRET"]


def test_no_vars_selects_azure_cli():
    config = AuthConfig.from_env({})
    assert config.mode == "azure-cli"
    assert config.tenant_id is None
    assert config.client_id is None
    assert config.client_secret is None


@pytest.mark.parametrize(
    "present_keys",
    [
        ["ENTRAADM_TENANT_ID"],
        ["ENTRAADM_CLIENT_ID"],
        ["ENTRAADM_CLIENT_SECRET"],
        ["ENTRAADM_TENANT_ID", "ENTRAADM_CLIENT_ID"],
        ["ENTRAADM_TENANT_ID", "ENTRAADM_CLIENT_SECRET"],
        ["ENTRAADM_CLIENT_ID", "ENTRAADM_CLIENT_SECRET"],
    ],
)
def test_partial_app_only_vars_raises_configerror(present_keys):
    env = {k: FULL_APP_ONLY[k] for k in present_keys}
    with pytest.raises(ConfigError, match="incomplete app-only credentials"):
        AuthConfig.from_env(env)


def test_empty_string_values_do_not_count_as_present():
    env = {**FULL_APP_ONLY, "ENTRAADM_CLIENT_SECRET": ""}
    with pytest.raises(ConfigError):
        AuthConfig.from_env(env)


def test_max_pages_default_falls_back_when_unset():
    assert max_pages_default({}) == DEFAULT_MAX_PAGES


def test_max_pages_default_reads_env():
    assert max_pages_default({"ENTRAADM_MAX_PAGES_DEFAULT": "17"}) == 17


def test_max_pages_default_clamps_high():
    assert max_pages_default({"ENTRAADM_MAX_PAGES_DEFAULT": "9999"}) == 50


def test_max_pages_default_clamps_low():
    assert max_pages_default({"ENTRAADM_MAX_PAGES_DEFAULT": "0"}) == 1


def test_max_pages_default_falls_back_on_non_integer():
    # A typo in the env degrades to the safe default instead of crashing the
    # whole server at startup.
    assert max_pages_default({"ENTRAADM_MAX_PAGES_DEFAULT": "not-a-number"}) == DEFAULT_MAX_PAGES
