"""Edge-case and error-path tests added during hardening."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rugradar.core import scan_source, scan_abi, scan_text, summarize  # noqa: E402
from rugradar.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# scan_source edge cases
# ---------------------------------------------------------------------------

def test_scan_source_empty_string_returns_safe():
    """Empty source must return a valid report with SAFE verdict, not crash."""
    report = scan_source("")
    assert report["verdict"] == "SAFE"
    assert report["risk_score"] == 0
    assert report["findings"] == []


def test_scan_source_whitespace_only_returns_safe():
    report = scan_source("   \n\t  ")
    assert report["verdict"] == "SAFE"


def test_scan_source_wrong_type_raises():
    with pytest.raises(TypeError, match="string"):
        scan_source(None)  # type: ignore[arg-type]


def test_scan_source_bytes_raises():
    with pytest.raises(TypeError):
        scan_source(b"contract C {}")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# scan_abi edge cases
# ---------------------------------------------------------------------------

def test_scan_abi_empty_list_returns_safe():
    report = scan_abi([])
    assert report["input_kind"] == "abi"
    assert report["verdict"] == "SAFE"
    assert report["findings"] == []


def test_scan_abi_empty_json_array_string():
    report = scan_abi("[]")
    assert report["input_kind"] == "abi"
    assert report["findings"] == []


def test_scan_abi_malformed_json_raises_value_error():
    with pytest.raises(ValueError, match="not valid JSON"):
        scan_abi("{not json}")


def test_scan_abi_empty_string_raises_value_error():
    with pytest.raises(ValueError, match="empty"):
        scan_abi("")


def test_scan_abi_wrong_root_type_raises():
    # A plain string (not a list or {abi:[...]}) after JSON parsing.
    with pytest.raises(TypeError, match="JSON array"):
        scan_abi('"just a string"')


def test_scan_abi_skips_non_dict_entries():
    """ABI entries that are not dicts must be silently skipped."""
    abi = [
        None,
        42,
        "bad entry",
        {"type": "function", "name": "mint", "stateMutability": "nonpayable", "inputs": []},
    ]
    report = scan_abi(abi)
    ids = {f["id"] for f in report["findings"]}
    assert "MINT_FUNCTION" in ids  # real entry still detected


# ---------------------------------------------------------------------------
# scan_text edge cases
# ---------------------------------------------------------------------------

def test_scan_text_wrong_type_raises():
    with pytest.raises(TypeError):
        scan_text(123)  # type: ignore[arg-type]


def test_scan_text_empty_string_returns_safe():
    report = scan_text("")
    assert report["verdict"] == "SAFE"


# ---------------------------------------------------------------------------
# summarize edge cases
# ---------------------------------------------------------------------------

def test_summarize_wrong_type_raises():
    with pytest.raises(TypeError):
        summarize("not a dict")  # type: ignore[arg-type]


def test_summarize_missing_keys_uses_defaults():
    """summarize() must not crash on a report with missing optional keys."""
    minimal = {}
    result = summarize(minimal)
    assert "verdict=UNKNOWN" in result
    assert "score=0" in result


def test_summarize_partial_counts():
    partial = {"verdict": "SAFE", "risk_score": 0, "counts": {"critical": 0}}
    result = summarize(partial)
    assert "verdict=SAFE" in result


# ---------------------------------------------------------------------------
# CLI edge cases
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_one(capsys):
    """Non-existent path must print to stderr and return exit code 1."""
    rc = main(["scan", "/nonexistent/path/to/contract.sol"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_empty_file_returns_one(capsys, tmp_path):
    """Empty file must print an error and return exit code 1."""
    empty = tmp_path / "empty.sol"
    empty.write_text("")
    rc = main(["scan", str(empty)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "empty" in err.lower()


def test_cli_malformed_abi_returns_one(capsys, tmp_path):
    """Malformed JSON passed as --kind abi must exit 1 with an error message."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json}")
    rc = main(["scan", str(bad), "--kind", "abi"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_kind_abi_empty_array_exits_zero(capsys, tmp_path):
    """An empty ABI [] is valid — should produce a SAFE report and exit 0."""
    f = tmp_path / "empty.abi.json"
    f.write_text("[]")
    rc = main(["scan", str(f), "--kind", "abi", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SAFE" in out


def test_cli_no_subcommand_returns_one(capsys):
    """Running with no subcommand must print help and return 1."""
    rc = main([])
    capsys.readouterr()
    assert rc == 1
