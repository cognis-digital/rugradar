"""Smoke tests for RUGRADAR. No network access."""

import json
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rugradar import scan_source, scan_abi, scan_text, summarize, TOOL_NAME, TOOL_VERSION  # noqa: E402
from rugradar.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic",
                    "HoneypotToken.sol")


def _read_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return fh.read()


def test_metadata():
    assert TOOL_NAME == "rugradar"
    assert TOOL_VERSION.count(".") == 2


def test_demo_is_critical():
    report = scan_source(_read_demo())
    assert report["verdict"] == "CRITICAL"
    assert report["risk_score"] >= 85
    ids = {f["id"] for f in report["findings"]}
    # The demo bundles all of these specific mechanisms.
    assert "MINT_FUNCTION" in ids
    assert "HIDDEN_OWNER" in ids
    assert "BLACKLIST" in ids
    assert "TRADING_SWITCH" in ids
    assert "MUTABLE_FEE" in ids


def test_unrestricted_mint_is_critical():
    report = scan_source(_read_demo())
    mint = [f for f in report["findings"] if f["id"] == "MINT_FUNCTION"][0]
    # mint() in the demo has no onlyOwner -> critical, not high.
    assert mint["severity"] == "critical"
    assert mint["lines"]  # a real line number was captured


def test_clean_contract_is_safe():
    clean = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    contract Plain {
        mapping(address => uint256) public balanceOf;
        function transfer(address to, uint256 amount) public returns (bool) {
            require(balanceOf[msg.sender] >= amount);
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            return true;
        }
    }
    """
    report = scan_source(clean)
    assert report["verdict"] in ("SAFE", "CAUTION")
    assert report["counts"]["critical"] == 0


def test_comments_are_ignored():
    # A scary keyword only inside a comment must NOT produce a finding.
    src = """
    pragma solidity ^0.8.0;
    contract C {
        // this contract has no mint and no blacklist, promise
        function transfer(address to, uint256 a) public returns (bool) {
            return true;
        }
    }
    """
    report = scan_source(src)
    ids = {f["id"] for f in report["findings"]}
    assert "MINT_FUNCTION" not in ids
    assert "BLACKLIST" not in ids


def test_abi_scan_detects_mint_and_blacklist():
    abi = [
        {"type": "function", "name": "mint", "stateMutability": "nonpayable",
         "inputs": [{"type": "address"}, {"type": "uint256"}]},
        {"type": "function", "name": "setBlacklist", "stateMutability": "nonpayable",
         "inputs": [{"type": "address"}, {"type": "bool"}]},
        {"type": "function", "name": "balanceOf", "stateMutability": "view",
         "inputs": [{"type": "address"}]},
    ]
    report = scan_abi(json.dumps(abi))
    ids = {f["id"] for f in report["findings"]}
    assert "MINT_FUNCTION" in ids
    assert "BLACKLIST" in ids
    assert report["input_kind"] == "abi"


def test_scan_text_autodetects_abi():
    abi = '[{"type":"function","name":"setFee","stateMutability":"nonpayable","inputs":[]}]'
    report = scan_text(abi)
    assert report["input_kind"] == "abi"


def test_scan_text_autodetects_solidity():
    report = scan_text(_read_demo())
    assert report["input_kind"] == "solidity"


def test_summarize_is_string():
    report = scan_source(_read_demo())
    s = summarize(report)
    assert "verdict=CRITICAL" in s


def test_cli_table_exit_code(capsys):
    rc = main(["scan", DEMO])
    out = capsys.readouterr().out
    assert "VERDICT : CRITICAL" in out
    assert rc == 2  # default --fail-on high_risk gate trips


def test_cli_json_output(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "CRITICAL"
    assert data["tool"] == "rugradar"
    assert rc == 2


def test_cli_fail_on_never_exits_zero(capsys):
    rc = main(["scan", DEMO, "--fail-on", "never"])
    capsys.readouterr()
    assert rc == 0


def test_cli_no_command_returns_one(capsys):
    rc = main([])
    capsys.readouterr()
    assert rc == 1
