"""RUGRADAR command-line interface.

Examples:
  # Scan a Solidity source file as a table
  rugradar scan demos/01-basic/HoneypotToken.sol

  # Scan an ABI JSON and emit machine-readable JSON for CI
  rugradar scan Token.abi.json --format json

  # Read from stdin (auto-detects Solidity vs ABI)
  cat Token.sol | rugradar scan -

  # Fail CI only when risk is HIGH_RISK or worse
  rugradar scan Token.sol --fail-on high_risk

Exit codes:
  0  scan succeeded and risk verdict is below the --fail-on threshold
  2  scan succeeded but verdict met/exceeded the --fail-on threshold (CI gate)
  1  usage / IO error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    scan_abi,
    scan_source,
    scan_text,
    summarize,
)

_VERDICT_RANK = {"SAFE": 0, "CAUTION": 1, "HIGH_RISK": 2, "CRITICAL": 3}
_FAIL_ON_CHOICES = {
    "never": 99,
    "caution": 1,
    "high_risk": 2,
    "critical": 3,
    "any": 1,  # alias: any finding above SAFE
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _render_table(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("=" * 64)
    lines.append(" RUGRADAR  v%s   input=%s" % (report["version"], report["input_kind"]))
    lines.append("=" * 64)
    lines.append(" VERDICT : %s   (risk score %d/100)"
                 % (report["verdict"], report["risk_score"]))
    c = report["counts"]
    lines.append(" COUNTS  : critical=%d high=%d medium=%d low=%d info=%d"
                 % (c["critical"], c["high"], c["medium"], c["low"], c["info"]))
    lines.append("-" * 64)
    findings = sorted(report["findings"],
                      key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    if not findings:
        lines.append(" No risk patterns detected.")
    for f in findings:
        loc = (" @L" + ",".join(str(x) for x in f["lines"])) if f["lines"] else ""
        lines.append(" [%-8s] %s%s" % (f["severity"].upper(), f["title"], loc))
        lines.append("            %s" % f["detail"])
        for ev in f["evidence"]:
            lines.append("            > %s" % ev)
    lines.append("=" * 64)
    lines.append(" " + summarize(report))
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=("RUGRADAR - self-hostable token contract risk scanner. "
                     "Detects honeypots, hidden mint/blacklist, owner "
                     "backdoors and fee traps from Solidity source or ABI."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version",
                   version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    sub = p.add_subparsers(dest="command")

    sc = sub.add_parser(
        "scan",
        help="Scan a contract source/ABI file (use '-' for stdin).",
        description="Scan a Solidity source or ABI JSON file for rug-pull risk.",
    )
    sc.add_argument("path", help="Path to .sol / .json file, or '-' for stdin.")
    sc.add_argument("--format", choices=("table", "json"), default="table",
                    help="Output format (default: table).")
    sc.add_argument("--kind", choices=("auto", "solidity", "abi"),
                    default="auto",
                    help="Force input interpretation (default: auto-detect).")
    sc.add_argument("--fail-on", choices=tuple(_FAIL_ON_CHOICES),
                    default="high_risk",
                    help=("Exit non-zero (2) when verdict reaches this level. "
                          "Default: high_risk. Use 'never' to always exit 0."))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "command", None) != "scan":
        parser.print_help(sys.stderr)
        return 1

    try:
        text = _read_input(args.path)
    except OSError as exc:
        print("error: cannot read %r: %s" % (args.path, exc), file=sys.stderr)
        return 1

    if not text.strip():
        print("error: input is empty: %r" % args.path, file=sys.stderr)
        return 1

    try:
        if args.kind == "solidity":
            report = scan_source(text)
        elif args.kind == "abi":
            report = scan_abi(text)
        else:
            report = scan_text(text)
    except (ValueError, TypeError) as exc:
        print("error: failed to parse input: %s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print("error: unexpected failure while scanning: %s" % exc, file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(_render_table(report))

    threshold = _FAIL_ON_CHOICES[args.fail_on]
    verdict_rank = _VERDICT_RANK.get(report.get("verdict", "SAFE"), 0)
    if verdict_rank >= threshold:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
