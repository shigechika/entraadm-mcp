"""Tests for environment-driven auth configuration."""

import re

import pytest

from entraadm_mcp.config import (
    DEFAULT_MAX_PAGES,
    AuthConfig,
    ConfigError,
    load_tenants,
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


def test_deadline_seconds_default_and_overrides():
    from entraadm_mcp.config import DEFAULT_DEADLINE_SECONDS, deadline_seconds

    assert deadline_seconds({}) == DEFAULT_DEADLINE_SECONDS == 45.0
    assert deadline_seconds({"ENTRAADM_DEADLINE": "20"}) == 20.0
    assert deadline_seconds({"ENTRAADM_DEADLINE": "0"}) is None
    assert deadline_seconds({"ENTRAADM_DEADLINE": "-1"}) is None
    assert deadline_seconds({"ENTRAADM_DEADLINE": "abc"}) == DEFAULT_DEADLINE_SECONDS
    assert deadline_seconds({"ENTRAADM_DEADLINE": ""}) == DEFAULT_DEADLINE_SECONDS
    assert deadline_seconds({"ENTRAADM_DEADLINE": "nan"}) == DEFAULT_DEADLINE_SECONDS
    assert deadline_seconds({"ENTRAADM_DEADLINE": "inf"}) == DEFAULT_DEADLINE_SECONDS
    assert deadline_seconds({"ENTRAADM_DEADLINE": "-inf"}) == DEFAULT_DEADLINE_SECONDS


# ---------------------------------------------------------------------------
# Tenants (ENTRAADM_CONFIG)
# ---------------------------------------------------------------------------

STAFF_ID = "00000000-0000-0000-0000-000000000001"
STUDENTS_ID = "00000000-0000-0000-0000-000000000002"
ENV_APP = {"ENTRAADM_CLIENT_ID": "app-id", "ENTRAADM_CLIENT_SECRET": "app-secret"}


def _ini(tmp_path, text):
    path = tmp_path / "tenants.ini"
    path.write_text(text, encoding="utf-8")
    return {"ENTRAADM_CONFIG": str(path)}


TWO_TENANTS = f"""
[tenant.staff]
tenant_id = {STAFF_ID}
domains = example.edu
default = true

[tenant.students]
tenant_id = {STUDENTS_ID}
domains = students.example.edu, Alumni.Example.edu
"""


def test_env_only_is_one_default_tenant_routing_every_domain():
    tenants = load_tenants(FULL_APP_ONLY)
    assert tenants.from_file is False and tenants.names == ["default"]
    assert tenants.default.auth == AuthConfig.from_env(FULL_APP_ONLY)
    assert tenants.for_upn("anyone@anywhere.example").name == "default"


def test_empty_config_var_is_env_only():
    assert load_tenants({"ENTRAADM_CONFIG": "  "}).from_file is False


def test_two_tenants_share_the_env_app(tmp_path):
    tenants = load_tenants({**_ini(tmp_path, TWO_TENANTS), **ENV_APP})
    assert tenants.from_file and tenants.names == ["staff", "students"]
    assert tenants.default.name == "staff"
    staff, students = tenants.get("staff"), tenants.get("students")
    assert staff.auth == AuthConfig("app-only", STAFF_ID, "app-id", "app-secret")
    assert students.auth == AuthConfig("app-only", STUDENTS_ID, "app-id", "app-secret")
    assert students.domains == ("students.example.edu", "alumni.example.edu")


def test_a_tenant_without_an_env_app_uses_az_login_in_that_tenant(tmp_path):
    tenants = load_tenants(_ini(tmp_path, TWO_TENANTS))
    assert tenants.get("students").auth == AuthConfig(mode="azure-cli", tenant_id=STUDENTS_ID)


def test_a_tenant_can_bring_its_own_app(tmp_path):
    text = TWO_TENANTS + "client_id = own-app\nclient_secret_env = STUDENTS_SECRET\n"
    tenants = load_tenants({**_ini(tmp_path, text), **ENV_APP, "STUDENTS_SECRET": "s2"})
    assert tenants.get("students").auth == AuthConfig("app-only", STUDENTS_ID, "own-app", "s2")
    assert tenants.get("staff").auth.client_id == "app-id"


def test_routing_is_by_exact_domain(tmp_path):
    tenants = load_tenants(_ini(tmp_path, TWO_TENANTS))
    assert tenants.for_upn("a@example.edu").name == "staff"
    assert tenants.for_upn("b@STUDENTS.example.edu").name == "students"
    assert tenants.for_upn("c@alumni.example.edu").name == "students"
    assert tenants.for_upn("d@sub.example.edu") is None
    assert tenants.domains == ["alumni.example.edu", "example.edu", "students.example.edu"]


def test_resolve_by_name_or_domain(tmp_path):
    tenants = load_tenants(_ini(tmp_path, TWO_TENANTS))
    assert tenants.resolve(None).name == "staff"
    assert tenants.resolve("").name == "staff"
    assert tenants.resolve("Students").name == "students"
    assert tenants.resolve("students.example.edu").name == "students"
    assert tenants.resolve("nobody") is None


def test_a_single_section_is_the_default(tmp_path):
    text = f"[tenant.only]\ntenant_id = {STAFF_ID}\ndomains = example.edu\n"
    assert load_tenants(_ini(tmp_path, text)).default.name == "only"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            TWO_TENANTS.replace("Alumni.Example.edu", "Example.EDU"),
            "claimed by both",
        ),
        (
            TWO_TENANTS.replace("domains = students.example.edu", "default = true\ndomains = students.example.edu"),
            "more than one default",
        ),
        (TWO_TENANTS.replace("default = true\n", ""), "no default tenant"),
        (TWO_TENANTS.replace("domains = example.edu\n", ""), "domains is required"),
        (TWO_TENANTS.replace(f"tenant_id = {STUDENTS_ID}\n", ""), "tenant_id is required"),
        (TWO_TENANTS + "client_secret = oops\n", "unknown key"),
        (TWO_TENANTS + "[other]\nx = 1\n", "unknown section"),
        (TWO_TENANTS + "client_id = own-app\n", "set both client_id and client_secret_env"),
        (TWO_TENANTS + "client_id = own-app\nclient_secret_env = UNSET_SECRET\n", "is unset"),
        (TWO_TENANTS.replace("domains = example.edu", "domains = not a domain"), "is not a domain name"),
        (TWO_TENANTS.replace("default = true", "default = maybe"), "default must be true or false"),
        ("", "has no [tenant.<name>] section"),
    ],
)
def test_bad_tenant_files_are_config_errors(tmp_path, text, message):
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_tenants({**_ini(tmp_path, text), **ENV_APP})


def test_half_an_env_app_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="incomplete env app"):
        load_tenants({**_ini(tmp_path, TWO_TENANTS), "ENTRAADM_CLIENT_ID": "app-id"})


def test_an_unreadable_tenant_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_tenants({"ENTRAADM_CONFIG": str(tmp_path / "missing.ini")})


def test_the_secret_is_never_in_the_file(tmp_path):
    text = TWO_TENANTS + "client_id = own-app\nclient_secret_env = STUDENTS_SECRET\n"
    tenants = load_tenants({**_ini(tmp_path, text), "STUDENTS_SECRET": "s2"})
    assert "s2" not in (tmp_path / "tenants.ini").read_text(encoding="utf-8")
    assert tenants.get("students").auth.client_secret == "s2"


@pytest.mark.parametrize("bad", ["staff", "common", "organizations", "consumers", "-", "..."])
def test_tenant_id_must_be_a_guid_or_a_dotted_domain(tmp_path, bad):
    text = f"[tenant.only]\ntenant_id = {bad}\ndomains = example.edu\n"
    with pytest.raises(ConfigError, match="tenant_id must be a GUID"):
        load_tenants(_ini(tmp_path, text))


@pytest.mark.parametrize("good", [STAFF_ID, STAFF_ID.upper(), "contoso.onmicrosoft.com", "Example.EDU"])
def test_tenant_id_accepts_a_guid_or_a_domain(tmp_path, good):
    text = f"[tenant.only]\ntenant_id = {good}\ndomains = example.edu\n"
    assert load_tenants(_ini(tmp_path, text)).default.auth.tenant_id == good


def test_a_parse_error_names_the_line(tmp_path):
    text = TWO_TENANTS + "domains = again.example.edu\n"
    with pytest.raises(ConfigError, match=r"DuplicateOptionError: .*line +[0-9]+.*'domains'"):
        load_tenants(_ini(tmp_path, text))


def test_a_default_section_cannot_fill_in_a_tenant(tmp_path):
    text = f"[__none__]\ntenant_id = {STAFF_ID}\ndomains = example.edu\n\n[tenant.staff]\n"
    with pytest.raises(ConfigError, match=r"unknown section \[__none__\]"):
        load_tenants(_ini(tmp_path, text))


def test_resolve_by_tenant_id(tmp_path):
    tenants = load_tenants(_ini(tmp_path, TWO_TENANTS))
    assert tenants.resolve(STUDENTS_ID).name == "students"


def test_env_only_resolves_default_and_its_tenant_id_only():
    tenants = load_tenants(FULL_APP_ONLY)
    assert tenants.resolve("default").name == "default"
    assert tenants.resolve(FULL_APP_ONLY["ENTRAADM_TENANT_ID"]).name == "default"
    assert tenants.resolve("example.edu") is None
