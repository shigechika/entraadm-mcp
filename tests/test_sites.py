"""Tests for the ENTRAADM_SITES_INI loader and longest-prefix classifier."""

import os

from entraadm_mcp import sites


def _write(tmp_path, text):
    path = tmp_path / "sites.ini"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_unset_env_is_not_configured():
    table = sites.load(env={})
    assert table.status() == {"configured": False, "ranges": 0, "error": None}
    assert table.classify("192.0.2.1") is None


def test_longest_prefix_wins_regardless_of_section_order(tmp_path):
    path = _write(
        tmp_path,
        "[NARROW]\nipv4 = 192.0.2.128/25\n\n[WIDE]\nname = Wide\nipv4 = 192.0.2.0/24\n",
    )
    table = sites.load(env={sites.ENV_VAR: path})
    assert table.classify("192.0.2.200") == sites.Site(code="NARROW", name=None)
    assert table.classify("192.0.2.5") == sites.Site(code="WIDE", name="Wide")
    assert table.classify("198.51.100.1") is None


def test_ipv6_and_bad_input(tmp_path):
    path = _write(tmp_path, "[HQ]\nipv6 = 2001:db8::/32\n")
    table = sites.load(env={sites.ENV_VAR: path})
    assert table.classify("2001:db8:0:1::5").code == "HQ"
    assert table.classify("192.0.2.1") is None
    assert table.classify("not-an-ip") is None
    assert table.classify(None) is None


def test_invalid_cidr_is_an_error_not_a_silent_skip(tmp_path):
    path = _write(tmp_path, "[HQ]\nipv4 = 192.0.2.0/24, 300.0.0.0/8\n")
    table = sites.load(env={sites.ENV_VAR: path})
    assert table.error is not None and "300.0.0.0/8" in table.error
    assert table.classify("192.0.2.1") is None


def test_missing_file_is_an_error(tmp_path):
    table = sites.load(env={sites.ENV_VAR: str(tmp_path / "nope.ini")})
    assert table.configured and table.error is not None


def test_percent_signs_do_not_trip_interpolation(tmp_path):
    path = _write(tmp_path, "[HQ]\nname = 100% office\nipv4 = 192.0.2.0/24\n")
    table = sites.load(env={sites.ENV_VAR: path})
    assert table.classify("192.0.2.1").name == "100% office"


def test_file_is_reread_when_it_changes(tmp_path):
    path = _write(tmp_path, "[A]\nipv4 = 192.0.2.0/24\n")
    env = {sites.ENV_VAR: path}
    assert sites.load(env=env).classify("192.0.2.1").code == "A"
    with open(path, "w", encoding="utf-8") as f:
        f.write("[B]\nipv4 = 192.0.2.0/24\n")
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert sites.load(env=env).classify("192.0.2.1").code == "B"
