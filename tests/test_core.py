import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquota as nq  # noqa: E402


def test_parse_quota_units():
    assert nq.parse_quota("500 MB") == 500_000_000
    assert nq.parse_quota("2 gb") == 2_000_000_000
    assert nq.parse_quota("750 MiB") == 750 * 1024**2
    assert nq.parse_quota("1.5GiB") == int(1.5 * 1024**3)
    assert nq.parse_quota("300") == 300_000_000  # bare number means MB


@pytest.mark.parametrize("bad", ["0", "-5 GB", "abc", ""])
def test_parse_quota_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        nq.parse_quota(bad)


def test_fmt_bytes():
    assert nq.fmt_bytes(0) == "0 B"
    assert nq.fmt_bytes(1536) == "1.5 KB"
    assert nq.fmt_bytes(5 * 1024**2) == "5.0 MB"


def test_frozen_tk_environment_uses_bundled_libraries(tmp_path):
    tcl_dir = tmp_path / "_tcl_data"
    tk_dir = tmp_path / "_tk_data"
    tcl_dir.mkdir()
    tk_dir.mkdir()
    environment = {
        "TCL_LIBRARY": r"C:\OtherPython\tcl",
        "TK_LIBRARY": r"C:\OtherPython\tk",
        "TCLLIBPATH": r"C:\OtherPython\lib",
        "PYTHONHOME": r"C:\OtherPython",
        "PYTHONPATH": r"C:\OtherPython\modules",
    }

    nq.configure_tk_environment(environment, frozen=True, bundle_root=str(tmp_path))

    assert environment["TCL_LIBRARY"] == str(tcl_dir)
    assert environment["TK_LIBRARY"] == str(tk_dir)
    assert "TCLLIBPATH" not in environment
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment


def test_frozen_tk_environment_discards_unbundled_library_paths():
    environment = {
        "TCL_LIBRARY": r"C:\OtherPython\tcl",
        "TK_LIBRARY": r"C:\OtherPython\tk",
    }

    nq.configure_tk_environment(environment, frozen=True, bundle_root=None)

    assert "TCL_LIBRARY" not in environment
    assert "TK_LIBRARY" not in environment


def test_rule_names_are_stable_and_distinct():
    a, b = nq.rule_names(r"C:\a\app.exe"), nq.rule_names(r"C:\b\app.exe")
    assert a == nq.rule_names(r"C:\a\app.exe")
    assert a != b
    assert a[0].endswith("-OUT") and a[1].endswith("-IN")


def test_loopback_detection():
    assert nq.is_lo("127.0.0.1") and nq.is_lo("::1")
    assert not nq.is_lo("192.168.1.5")


def test_vt_status_thresholds():
    assert nq.vt_status(0, 0, 70) == "clean"
    assert nq.vt_status(2, 0, 70) == "suspicious"
    assert nq.vt_status(0, 1, 70) == "suspicious"
    assert nq.vt_status(3, 0, 70) == "malicious"
    assert nq.vt_status(0, 0, 0) == "unknown"


def test_parse_vt_report():
    js = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 0, "undetected": 60},
        "last_analysis_results": {"EngA": {"category": "malicious", "result": "Trojan.X"},
                                  "EngB": {"category": "undetected", "result": None}},
        "popular_threat_classification": {"suggested_threat_label": "trojan.x"}}}}
    r = nq.parse_vt_report(js)
    assert r["status"] == "malicious" and r["malicious"] == 5
    assert "EngA: Trojan.X" in r["detail"] and "EngB" not in r["detail"]


def test_sha256_and_multipart(tmp_path):
    p = tmp_path / "t.exe"
    p.write_bytes(b"HELLO")
    assert nq.sha256_file(str(p)) == "3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5"
    body, ctype = nq.vt_multipart(str(p))
    assert b'filename="t.exe"' in body and b"HELLO" in body
    assert ctype.startswith("multipart/form-data; boundary=")
