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
        ├── EVM adapter     (Layer 3) ──────────────► GoPlus EVM API
        │                                              (direct browser call, CORS-enabled)
        │
        └── Solana adapter  (Layer 3) ──► CORS proxy ──► GoPlus Solana API (Beta)
                                           (Cloudflare Worker,
                                            stateless relay — see below)
```

**All decision logic — validation, normalization, the verdict engine — runs
entirely client-side for every chain, no exception.** The one thing that
differs per chain is the *network path* to the data provider. EVM's GoPlus
endpoint sends proper CORS headers, so the browser calls it directly. As of
this writing, GoPlus's Solana endpoint does not send those headers — the
Solana adapter routes through a small proxy to work around that. Details
in "The Solana CORS proxy" below.


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

This layer is also where the EVM and Solana adapters diverge in practice.
`EvmAdapter.fetchChecks()` calls `api.gopluslabs.io` directly from the
browser. `SolanaAdapter.fetchChecks()` calls a Cloudflare Worker instead,
because GoPlus's Solana endpoint does not return an
`Access-Control-Allow-Origin` header — confirmed directly in the browser
console (`"...has been blocked by CORS policy: No 'Access-Control-Allow-Origin'
header is present..."`), not inferred. Every scan, regardless of chain,
still goes through the same fetch-timeout-catch handling in `runScan()` —
only the URL each adapter builds differs.

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

### The Solana CORS proxy

**What happened:** early Solana scans hung for roughly 80 seconds and then
failed with a generic "Failed to fetch." The first fix attempt (a 20-second
client-side timeout) treated this as a slow-provider problem — a reasonable
guess, since a hard CORS rejection normally fails in a second or two, not
80. It was wrong. A browser console check settled it directly:

```
Access to fetch at 'https://api.gopluslabs.io/api/v1/solana/token_security?...'
from origin 'https://stefantsezarov.github.io' has been blocked by CORS
policy: No 'Access-Control-Allow-Origin' header is present on the
requested resource.
```

That's a hard block — no client-side code change can fix a missing
response header, no matter how the timeout or retry logic is written. The
console also showed a `504 Gateway Timeout` from GoPlus's own backend
alongside the CORS error, meaning there were two separate problems stacked
on each other: the browser was never going to be allowed to read the
response, and GoPlus's Solana endpoint (documented by GoPlus as Beta) is
also, separately, sometimes slow to answer.

**The fix:** `riskpass-solana-proxy-worker.js`, deployed on Cloudflare
Workers. It receives the request in place of GoPlus, forwards it
server-to-server (CORS is a browser-enforced restriction — it does not
apply between two servers), and returns the response with an
`Access-Control-Allow-Origin` header the browser will accept.

**What the proxy does:**
- Accepts `GET ?contract_addresses=<address>`, nothing else.
- Re-validates the address against the same base58 pattern the client
  already checked, before forwarding anything — a public endpoint
  shouldn't blindly relay arbitrary input just because the browser-side
  check already ran once.
- Restricts `Access-Control-Allow-Origin` to the site's own origin, not `*`.
- Applies its own 15-second timeout against GoPlus, returning a clear `504`
  JSON error rather than hanging, so a slow upstream fails predictably on
  both sides of the proxy.

**What the proxy explicitly does not do:**
- Store, log, or cache any address or response beyond Cloudflare's own
  default platform-level request logs.
- Touch EVM traffic at all — that adapter's direct-to-GoPlus path is
  unchanged, because that endpoint's CORS support was never the problem.
- Add any authentication, custody, or state. It is a stateless relay with
  one job.

**The honest architectural consequence:** the claim "every check runs
entirely in the browser, no backend" is no longer 100% true — it's true
for EVM, and true for Solana's *decision logic*, but Solana's *network
path* now depends on one small, separately-hosted component. If GoPlus
adds proper CORS support to their Solana API — plausible, since it's
still labeled Beta — this proxy becomes removable and the Solana adapter
can call GoPlus directly, exactly like the EVM adapter already does.

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

Worth planning for now, given the Solana proxy above: if any future chain's
data provider has the same CORS gap Solana's did, that adapter will need
the same proxy pattern. It isn't yet clear whether that's a Solana-specific
quirk or a more general pattern with less mature/Beta security APIs — one
data point isn't enough to say. The next chain added will effectively be
the test of which it is.
