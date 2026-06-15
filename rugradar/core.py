"""RUGRADAR core engine.

Real, dependency-free static analysis of token smart contracts.

Two entry points:
  * scan_source(text)  -> analyze raw Solidity source code
  * scan_abi(abi_obj)  -> analyze a parsed/serialized ABI (list or JSON str)

Both return a normalized report dict:
  {
    'tool': 'rugradar', 'version': '...',
    'input_kind': 'solidity' | 'abi',
    'findings': [ {id, title, severity, weight, evidence, lines}, ... ],
    'risk_score': int (0-100),
    'verdict': 'SAFE' | 'CAUTION' | 'HIGH_RISK' | 'CRITICAL',
    'counts': {critical, high, medium, low, info},
  }

The detection logic is heuristic but concrete: it tokenizes the source,
tracks function visibility/modifiers, and matches well-known rug patterns.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Union

TOOL_NAME = "rugradar"
TOOL_VERSION = "1.0.0"

# Severity -> numeric weight used for the aggregate risk score.
SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 0,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # critical|high|medium|low|info
    detail: str
    evidence: List[str] = field(default_factory=list)
    lines: List[int] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 0)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["weight"] = self.weight
        return d


# --------------------------------------------------------------------------
# Source pre-processing helpers
# --------------------------------------------------------------------------

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(src: str) -> str:
    """Remove comments so keyword matches reflect real code, not docs."""
    src = _BLOCK_COMMENT.sub("", src)
    src = _LINE_COMMENT.sub("", src)
    return src


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


_FUNC_RE = re.compile(
    r"function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)"
    r"(?P<attrs>[^{;]*)",
)

_VISIBILITY = ("public", "external", "internal", "private")


@dataclass
class FuncInfo:
    name: str
    visibility: str
    attrs: str
    line: int


def _parse_functions(src: str) -> List[FuncInfo]:
    funcs: List[FuncInfo] = []
    for m in _FUNC_RE.finditer(src):
        attrs = m.group("attrs") or ""
        vis = "public"  # solidity default for free functions is internal,
        # but for analysis we treat unmarked as public to stay conservative.
        for v in _VISIBILITY:
            if re.search(r"\b" + v + r"\b", attrs):
                vis = v
                break
        funcs.append(
            FuncInfo(
                name=m.group("name"),
                visibility=vis,
                attrs=attrs.strip(),
                line=_line_of(src, m.start()),
            )
        )
    return funcs


def _is_owner_guarded(attrs: str) -> bool:
    """True if the function is restricted to an admin/owner via a modifier."""
    patterns = (
        r"onlyOwner",
        r"onlyAdmin",
        r"onlyRole",
        r"only[A-Z]\w*",  # generic onlyXxx modifier
        r"authorized",
        r"requiresAuth",
    )
    return any(re.search(p, attrs) for p in patterns)


def _externally_callable(f: FuncInfo) -> bool:
    return f.visibility in ("public", "external")


# --------------------------------------------------------------------------
# Solidity source scanning
# --------------------------------------------------------------------------

def scan_source(source: str) -> Dict[str, Any]:
    """Analyze Solidity source text and return a risk report."""
    if not isinstance(source, str):
        raise TypeError("source must be a string of Solidity code")
    if not source.strip():
        return _build_report([], "solidity", source=source)

    raw = source
    src = _strip_comments(source)
    funcs = _parse_functions(src)
    findings: List[Finding] = []

    findings.extend(_detect_mint(src, funcs))
    findings.extend(_detect_blacklist(src, funcs))
    findings.extend(_detect_trading_switch(src, funcs))
    findings.extend(_detect_fee_manipulation(src, funcs))
    findings.extend(_detect_max_tx_limit(src, funcs))
    findings.extend(_detect_ownership(src, funcs))
    findings.extend(_detect_proxy_upgrade(src, funcs))
    findings.extend(_detect_balance_rewrite(src, funcs))
    findings.extend(_detect_self_destruct(src))
    findings.extend(_detect_hidden_owner(src))

    return _build_report(findings, "solidity", source=raw)


def _kw_lines(src: str, pattern: str, limit: int = 4) -> List[int]:
    return [_line_of(src, m.start()) for m in re.finditer(pattern, src)][:limit]


def _detect_mint(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    mint_funcs = [
        f for f in funcs
        if re.search(r"^_?mint", f.name, re.I) and _externally_callable(f)
    ]
    # Also detect raw balance increment + totalSupply increment (manual mint).
    has_supply_bump = bool(
        re.search(r"_totalSupply\s*\+=", src)
        or re.search(r"totalSupply\s*\+=", src)
    )
    for f in mint_funcs:
        guarded = _is_owner_guarded(f.attrs)
        sev = "high" if guarded else "critical"
        out.append(Finding(
            id="MINT_FUNCTION",
            title="Externally callable mint function",
            severity=sev,
            detail=(
                "Function '%s' can create new tokens. "
                % f.name
                + ("Owner-restricted: supply can be inflated by the admin."
                   if guarded else
                   "NOT owner-restricted: anyone may mint unlimited tokens.")
            ),
            evidence=["function %s(...) %s" % (f.name, f.attrs)],
            lines=[f.line],
        ))
    if not mint_funcs and has_supply_bump:
        out.append(Finding(
            id="MANUAL_SUPPLY_INCREASE",
            title="Manual total-supply increment",
            severity="high",
            detail="Code increments totalSupply directly, a hidden mint path.",
            evidence=["_totalSupply += ..."],
            lines=_kw_lines(src, r"(_?totalSupply)\s*\+="),
        ))
    return out


def _detect_blacklist(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    bl_terms = r"(blacklist|blocklist|_isBlocked|isBot|_bots|banned|denylist|_excluded[A-Za-z]*Bot)"
    if re.search(bl_terms, src, re.I):
        lines = _kw_lines(src, bl_terms)
        # A blacklist that gates transfer = can freeze holders (honeypot).
        gates_transfer = bool(
            re.search(r"require\s*\(\s*!\s*\w*(blacklist|isBot|banned|blocked)",
                      src, re.I)
            or re.search(r"(blacklist|isBot|banned|blocked)\w*\[[^\]]+\]\s*==\s*false",
                         src, re.I)
        )
        out.append(Finding(
            id="BLACKLIST",
            title="Blacklist / address-freeze mechanism",
            severity="high" if gates_transfer else "medium",
            detail=("Contract can mark addresses as blocked"
                    + (" and a transfer guard enforces it, freezing victims "
                       "(classic honeypot)." if gates_transfer else
                       " (mapping present).")),
            evidence=["blacklist mapping / guard"],
            lines=lines,
        ))
    return out


def _detect_trading_switch(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    switch = r"(tradingEnabled|tradingActive|tradingOpen|canTrade|enableTrading|_tradingPaused|swapEnabled)"
    if re.search(switch, src, re.I):
        # If there is an enable but no obvious disable being public toggled both ways,
        # presence of a flag gating transfers is still a honeypot lever.
        gates = bool(re.search(r"require\s*\([^)]*" + switch, src, re.I))
        out.append(Finding(
            id="TRADING_SWITCH",
            title="Owner-controlled trading on/off switch",
            severity="high" if gates else "medium",
            detail=("A flag gates whether transfers/sells are allowed. "
                    "Owner can disable selling at will (honeypot lever)."),
            evidence=["trading flag gating transfers"],
            lines=_kw_lines(src, switch),
        ))
    return out


def _detect_fee_manipulation(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    setters = [
        f for f in funcs
        if _externally_callable(f)
        and re.search(r"(setFee|setTax|updateFee|setBuyTax|setSellTax|"
                      r"setTaxes|setFees)", f.name, re.I)
    ]
    for f in setters:
        out.append(Finding(
            id="MUTABLE_FEE",
            title="Mutable transfer fee/tax",
            severity="high",
            detail=("Function '%s' lets the owner change buy/sell tax after "
                    "launch. Fees can be raised to 100%% to block sells."
                    % f.name),
            evidence=["function %s(...) %s" % (f.name, f.attrs)],
            lines=[f.line],
        ))
    # Hard-coded extreme fee.
    for m in re.finditer(r"(fee|tax)\w*\s*=\s*(\d{2,3})\b", src, re.I):
        val = int(m.group(2))
        if val >= 25:
            out.append(Finding(
                id="HIGH_FEE",
                title="Very high hard-coded fee",
                severity="medium",
                detail="A fee/tax constant of %d%% drains trades." % val,
                evidence=[m.group(0)],
                lines=[_line_of(src, m.start())],
            ))
    return out


def _detect_max_tx_limit(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    setters = [
        f for f in funcs
        if _externally_callable(f)
        and re.search(r"(setMaxTx|setMaxWallet|setMaxSell|updateMaxTx)", f.name, re.I)
    ]
    if setters:
        out.append(Finding(
            id="MUTABLE_MAX_TX",
            title="Adjustable max-transaction / max-wallet limit",
            severity="medium",
            detail=("Owner can shrink the max transaction or wallet size, "
                    "which can be set near zero to halt sells."),
            evidence=["function %s(...)" % f.name for f in setters][:3],
            lines=[f.line for f in setters][:3],
        ))
    return out


def _detect_ownership(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    has_owner = bool(re.search(r"\bonlyOwner\b", src)) or bool(
        re.search(r"address\s+(public\s+)?(private\s+)?owner\b", src))
    renounces = bool(re.search(r"renounceOwnership", src))
    transfers = bool(re.search(r"transferOwnership", src))
    if has_owner and not renounces:
        out.append(Finding(
            id="OWNERSHIP_RETAINED",
            title="Privileged owner with no renounce path",
            severity="medium",
            detail=("Contract has onlyOwner powers but no renounceOwnership "
                    "function; admin control is permanent."),
            evidence=["onlyOwner present, renounceOwnership absent"],
            lines=_kw_lines(src, r"onlyOwner"),
        ))
    if transfers:
        out.append(Finding(
            id="OWNERSHIP_TRANSFERABLE",
            title="Ownership can be transferred",
            severity="info",
            detail="transferOwnership present (standard, but note custody risk).",
            evidence=["transferOwnership"],
            lines=_kw_lines(src, r"transferOwnership"),
        ))
    return out


def _detect_proxy_upgrade(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    if re.search(r"(delegatecall|_upgradeTo|upgradeToAndCall|setImplementation|"
                 r"_implementation\b)", src, re.I):
        out.append(Finding(
            id="UPGRADEABLE_PROXY",
            title="Upgradeable / delegatecall proxy logic",
            severity="high",
            detail=("Contract logic can be swapped via delegatecall/upgrade. "
                    "A benign implementation can be replaced by a malicious "
                    "one post-audit."),
            evidence=["delegatecall / upgradeTo"],
            lines=_kw_lines(src, r"(delegatecall|upgradeTo|setImplementation)"),
        ))
    return out


def _detect_balance_rewrite(src: str, funcs: List[FuncInfo]) -> List[Finding]:
    out: List[Finding] = []
    # Owner function that writes arbitrary balances = can drain or zero holders.
    for f in funcs:
        if not _externally_callable(f):
            continue
        if re.search(r"(setBalance|updateBalance|airdrop|distribute|burnFrom\b)",
                     f.name, re.I) and re.search(r"(burnFrom|setBalance|updateBalance)",
                                                  f.name, re.I):
            out.append(Finding(
                id="ARBITRARY_BALANCE",
                title="Owner can rewrite arbitrary balances",
                severity="critical",
                detail=("Function '%s' writes balances of arbitrary addresses, "
                        "allowing the owner to seize or zero holder funds."
                        % f.name),
                evidence=["function %s(...)" % f.name],
                lines=[f.line],
            ))
    return out


def _detect_self_destruct(src: str) -> List[Finding]:
    out: List[Finding] = []
    if re.search(r"\b(selfdestruct|suicide)\s*\(", src):
        out.append(Finding(
            id="SELFDESTRUCT",
            title="selfdestruct present",
            severity="high",
            detail="Contract can be destroyed, bricking the token.",
            evidence=["selfdestruct(...)"],
            lines=_kw_lines(src, r"(selfdestruct|suicide)\s*\("),
        ))
    return out


def _detect_hidden_owner(src: str) -> List[Finding]:
    out: List[Finding] = []
    # A second hard-coded admin address compared in require() = hidden owner.
    # Pattern 1: raw hex address directly in require(msg.sender == 0x...).
    direct = re.search(
        r"require\s*\([^)]*msg\.sender\s*==\s*0x[a-fA-F0-9]{40}", src)
    if direct:
        out.append(Finding(
            id="HIDDEN_OWNER",
            title="Hard-coded hidden admin address",
            severity="critical",
            detail=("A privileged check compares msg.sender against a "
                    "hard-coded address - a backdoor owner outside the "
                    "normal ownership model."),
            evidence=["require(msg.sender == 0x...)"],
            lines=_kw_lines(src,
                r"require\s*\([^)]*msg\.sender\s*==\s*0x[a-fA-F0-9]{40}"),
        ))
        return out
    # Pattern 2: named address constant (address constant/immutable FOO = 0x...)
    # used in require(msg.sender == FOO).  This is the same backdoor via an alias.
    named_consts = {
        name: addr
        for name, addr in re.findall(
            r"address\s+(?:(?:private|public|internal)\s+)?(?:constant|immutable)\s+"
            r"(\w+)\s*=\s*(0x[a-fA-F0-9]{40})",
            src,
        )
    }
    if named_consts:
        req_names = re.findall(r"require\s*\([^)]*msg\.sender\s*==\s*(\w+)", src)
        matched = [n for n in req_names if n in named_consts]
        if matched:
            out.append(Finding(
                id="HIDDEN_OWNER",
                title="Hard-coded hidden admin address (named constant)",
                severity="critical",
                detail=(
                    "A privileged check compares msg.sender against '%s', "
                    "a named constant holding a hard-coded address (%s). "
                    "This is a backdoor owner outside the normal ownership model."
                    % (matched[0], named_consts[matched[0]])
                ),
                evidence=["require(msg.sender == %s)" % matched[0]],
                lines=_kw_lines(
                    src,
                    r"require\s*\([^)]*msg\.sender\s*==\s*" + matched[0],
                ),
            ))
    return out


# --------------------------------------------------------------------------
# ABI scanning (no source available)
# --------------------------------------------------------------------------

_ABI_RISK_NAMES = {
    r"^_?mint$|^mintTo$": ("MINT_FUNCTION", "Mint function in ABI", "high",
        "A mint function is exposed; supply may be inflated by privileged callers."),
    r"blacklist|blocklist|setBot|banAddress|addBot": ("BLACKLIST",
        "Blacklist setter in ABI", "high",
        "ABI exposes an address-freeze setter (honeypot lever)."),
    r"enableTrading|setTradingEnabled|openTrading": ("TRADING_SWITCH",
        "Trading toggle in ABI", "high",
        "Owner can switch trading on/off."),
    r"setFee|setTax|updateFee|setBuyTax|setSellTax": ("MUTABLE_FEE",
        "Fee setter in ABI", "high",
        "Fees/taxes can be changed after launch (sell-blocking)."),
    r"setMaxTx|setMaxWallet|updateMaxTx": ("MUTABLE_MAX_TX",
        "Max-tx setter in ABI", "medium",
        "Transaction/wallet caps are adjustable by owner."),
    r"upgradeTo|setImplementation": ("UPGRADEABLE_PROXY",
        "Upgrade entrypoint in ABI", "high",
        "Implementation can be swapped (proxy)."),
    r"selfdestruct|destroy$|kill$": ("SELFDESTRUCT",
        "Destruct entrypoint in ABI", "high",
        "Contract can be destroyed."),
    r"setBalance|updateBalance|burnFrom": ("ARBITRARY_BALANCE",
        "Balance rewrite in ABI", "critical",
        "Owner can rewrite arbitrary balances."),
}


def scan_abi(abi: Union[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Analyze a contract ABI (JSON string or parsed list)."""
    if isinstance(abi, str):
        if not abi.strip():
            raise ValueError("ABI input is empty")
        try:
            abi = json.loads(abi)
        except json.JSONDecodeError as exc:
            raise ValueError("ABI is not valid JSON: %s" % exc) from exc
    if isinstance(abi, dict) and "abi" in abi:
        abi = abi["abi"]
    if not isinstance(abi, list):
        raise TypeError("ABI must be a JSON array of entries (or {abi:[...]})")
    if len(abi) == 0:
        return _build_report([], "abi")

    findings: List[Finding] = []
    func_names = [
        e.get("name", "") for e in abi
        if isinstance(e, dict) and e.get("type") == "function"
    ]
    mutating = [
        e for e in abi
        if isinstance(e, dict) and e.get("type") == "function"
        and e.get("stateMutability") not in ("view", "pure")
    ]

    for e in mutating:
        name = e.get("name", "") or ""
        for pat, (fid, title, sev, detail) in _ABI_RISK_NAMES.items():
            if re.search(pat, name, re.I):
                findings.append(Finding(
                    id=fid,
                    title=title + ": %s()" % name,
                    severity=sev,
                    detail=detail,
                    evidence=["%s(%s)" % (name, ",".join(
                        i.get("type", "") for i in e.get("inputs", [])))],
                ))
                break

    # Ownership / pause signals.
    if any(re.search(r"owner|onlyOwner|getOwner", n, re.I) for n in func_names):
        if not any(re.search(r"renounceOwnership", n) for n in func_names):
            findings.append(Finding(
                id="OWNERSHIP_RETAINED",
                title="Owner role exposed without renounce",
                severity="medium",
                detail="ABI exposes owner accessor but no renounceOwnership.",
                evidence=["owner()"],
            ))
    if any(re.search(r"^pause$|^unpause$", n) for n in func_names):
        findings.append(Finding(
            id="PAUSABLE",
            title="Pausable transfers",
            severity="medium",
            detail="Owner can pause all transfers (freeze).",
            evidence=["pause()"],
        ))

    return _build_report(findings, "abi")


def scan_text(text: str) -> Dict[str, Any]:
    """Convenience: detect whether input is ABI JSON or Solidity, then scan."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            return scan_abi(text)
        except (ValueError, TypeError):
            pass
    return scan_source(text)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def _build_report(findings: List[Finding], input_kind: str,
                  source: Optional[str] = None) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    raw = sum(f.weight for f in findings)
    risk_score = min(100, raw)
    # Any critical drives score to at least 85.
    if counts["critical"] > 0:
        risk_score = max(risk_score, 85)
    elif counts["high"] > 0:
        risk_score = max(risk_score, 50)

    if risk_score >= 85 or counts["critical"] > 0:
        verdict = "CRITICAL"
    elif risk_score >= 50:
        verdict = "HIGH_RISK"
    elif risk_score >= 20:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "input_kind": input_kind,
        "findings": [f.to_dict() for f in findings],
        "counts": counts,
        "risk_score": risk_score,
        "verdict": verdict,
    }


def summarize(report: Dict[str, Any]) -> str:
    """Human-readable one-paragraph summary of a report."""
    if not isinstance(report, dict):
        raise TypeError("report must be a dict")
    c = report.get("counts") or {}
    return ("%s verdict=%s score=%d/100  "
            "(critical=%d high=%d medium=%d low=%d info=%d)" % (
                report.get("tool", TOOL_NAME),
                report.get("verdict", "UNKNOWN"),
                report.get("risk_score", 0),
                c.get("critical", 0),
                c.get("high", 0),
                c.get("medium", 0),
                c.get("low", 0),
                c.get("info", 0),
            ))
