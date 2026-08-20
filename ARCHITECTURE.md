# RiskPass Architecture

## Philosophy

- RiskPass never treats absence of evidence as evidence of safety.
- RiskPass never claims more coverage than it actually obtained.
- RiskPass treats external data as untrusted, always.
- Critical evidence overrides uncertainty.
- Uncertainty overrides PASS.
- Every blockchain is analyzed according to its own native security model.
- The user interface stays simple even when the underlying security model is sophisticated.

## Layers

```
RiskPass Core
│
├── Input validation        (Layer 0 — per-chain address validators)
├── Data acquisition        (Layer 1 — adapters treat provider responses as hostile)
├── Evidence normalization  (Layer 2 — the CHECK model)
├── Verdict engine          (Layer 5 — provider- and chain-agnostic)
├── Confidence engine       (Layer 6 — coverage, critical-check tracking)
└── UI                      (Layer 7 — thin, DOM-only, knows nothing security-specific)
        │
        ├── EVM adapter     (Layer 3)
        └── Solana adapter  (Layer 3)
```

Layer 4 (cross-provider correlation) is not yet implemented — GoPlus remains
the sole provider per chain. The adapter interface is shaped so a second
provider can be added to `fetchChecks()` per adapter without changing the
verdict engine.

### Layer 0 — Input validation

Each adapter owns its own `validateAddress()`. EVM and Solana never share a
validator: `/^0x[a-fA-F0-9]{40}$/` vs base58 with excluded ambiguous
characters (`0`, `O`, `I`, `l`). No cross-chain guessing.

### Layer 1 — Data acquisition

Every HTTP response is checked for `res.ok`, then for the provider's own
success code, then for the presence of `result`, before any field is read.
Network failure and HTTP errors both throw and are surfaced as an explicit
error state — never as a verdict.

### Layer 2 — Evidence normalization

Every raw provider field becomes at most one `CHECK`:

```
CHECK
  id           string
  category     string   (control | supply | liquidity | economics | reputation | transparency)
  status       'PASS' | 'RISK' | 'UNKNOWN'
  critical     boolean  (can this check alone force a FAIL?)
  severityWeight number (contribution to the caution/fail score)
  label        string
  detail       string
  source       string   (which provider/adapter produced this)
```

A field that is simply absent from the response never becomes a CHECK at
all — its absence is accounted for via `checksExpected` vs `checksValid`,
never silently folded into "clear." A field that IS present but not in a
recognized shape (null, an array, an unexpected string) becomes a CHECK
with `status: 'UNKNOWN'`, not a guessed PASS.

The verdict engine (Layer 5) only ever reads this CHECK shape. It has no
knowledge of GoPlus, EVM, or Solana field names.

### Layer 3 — Chain adapters

`EvmAdapter` and `SolanaAdapter` each expose the same interface:
`{ id, name, capabilities, chains, validateAddress(addr), fetchChecks(addr, assetType, chainId, fetchImpl) }`.
Adding a chain means writing a new adapter against this interface — it does
not mean touching the verdict engine. Solana's checks are read from a
nested `{status}` object shape; EVM's are flat `"1"/"0"` fields. The
adapters absorb that difference; nothing above them needs to know it exists.

### Layer 5/6 — Verdict engine and confidence

Four states, in strict priority order:

1. **FAIL** — any `critical: true` check has `status: 'RISK'`. This fires
   regardless of how sparse the rest of the response is — a confirmed
   honeypot with only 1 of 12 fields returned is still FAIL, not
   "insufficient data." (This exact interaction was a real bug caught by
   the regression suite during development — see the test named
   `critical hit even with sparse data`.)
2. **INSUFFICIENT DATA** — fewer than 40% of expected checks returned
   usable (PASS/RISK) data. Never collapses into PASS.
3. **FAIL** (score-based) / **CAUTION** — accumulated severity score from
   non-critical RISK and UNKNOWN checks.
4. **PASS** — only when coverage is adequate and nothing scored.

Separately, a well-covered PASS or CAUTION result still checks whether any
`critical`-tier check specifically went unanswered (`criticalMissing`) and
appends an explicit note if so — a scan can have 79% overall coverage and
still be silently missing the single most decisive check (e.g. honeypot
detection). This is deliberately additive to the main classification, not
folded into the coverage threshold, because "most things checked out, but
we couldn't check the one that matters most" is a different, more targeted
kind of uncertainty than "most of the response was empty."

### Layer 7 — Presentation

The badge, the one-line verdict subtext, and a coverage line
(`N/M checks completed`) are the only things a casual user needs to read.
The full per-check list and raw API response are present but not
foregrounded.

## Capability declarations

Each adapter declares what it actually implements, not what the upstream
provider theoretically supports:

| Capability | EVM | Solana |
|---|---|---|
| Token security | yes | yes |
| Wallet screening | yes | no — not yet implemented in RiskPass |
| Transaction simulation | no | no |
| Liquidity analysis | no | no |
| Contract/source analysis | yes | n/a (different security model) |

The UI reads this table directly (`renderCapabilityNote()`) rather than
having a hardcoded list duplicated in markup, and the Solana wallet-scan
tab is disabled at the UI level and refused at the adapter level — a
capability gap can't silently produce a false result because the code
path to reach one doesn't exist.

## Permanent regression suite

`riskpass.regression.test.js` requires `core.js` directly and asserts the
resulting **verdict label** for each case, not merely that nothing threw.
It should be run after any change to `core.js`, and `core.js` is the
source of truth — the copy embedded in `riskpass.html`'s `<script>` tag
must be pasted from `core.js` verbatim after any edit. `verify_embedded.js`
exists to catch drift between the two if that discipline slips.

Current coverage: 27 assertions across malicious input, benign input,
empty/malformed/partial provider responses, contradictory indicators,
missing critical fields, malformed numeric values, a confirmed critical
finding under sparse data, Unicode/HTML payloads, unexpected JSON types,
unknown chain IDs, and per-chain address-validator isolation.

## Deliberately deferred

Sui, Aptos, and TRON adapters are not built yet. Per the same reasoning
that shaped this refactor: retrofitting five chains onto an unproven
architecture produces five times the risk of the same class of bug this
session found and fixed twice. The adapter interface is now shaped to make
each of those a scoped, testable addition — not a rewrite — but doing them
before Solana had a working, tested adapter would have been the wrong
order of operations.
