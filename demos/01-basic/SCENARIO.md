# Demo 01 - Basic honeypot scan

This demo runs RUGRADAR against `HoneypotToken.sol`, a deliberately
malicious ERC-20-style contract that bundles several classic rug-pull
mechanisms:

| Pattern in the source                         | Finding ID            | Severity |
|-----------------------------------------------|-----------------------|----------|
| Unrestricted `mint()` (no `onlyOwner`)        | `MINT_FUNCTION`       | critical |
| Hard-coded hidden admin in a `require`        | `HIDDEN_OWNER`        | critical |
| `blacklist` mapping gating transfers          | `BLACKLIST`           | high     |
| `enableTrading` flag gating transfers         | `TRADING_SWITCH`      | high     |
| `setSellTax()` mutable fee setter             | `MUTABLE_FEE`         | high     |
| Owner role with no `renounceOwnership`        | `OWNERSHIP_RETAINED`  | medium   |

## Run it

```bash
# Human-readable table
python -m rugradar scan demos/01-basic/HoneypotToken.sol

# JSON for CI / piping
python -m rugradar scan demos/01-basic/HoneypotToken.sol --format json
```

## Expected result

- `verdict` is **CRITICAL** (at least two critical findings are present).
- `risk_score` is `>= 85`.
- The process exits with code **2** (the default `--fail-on high_risk`
  gate is tripped), so a CI pipeline that scans untrusted contracts will
  block on this token.

A clean, standard OpenZeppelin-style token with no mutable fees,
blacklist, hidden owner, or unrestricted mint would instead report
`SAFE`/`CAUTION` and exit `0`.
