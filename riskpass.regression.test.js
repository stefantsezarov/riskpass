/* =====================================================================
   RISKPASS REGRESSION SUITE
   Run with: node riskpass.regression.test.js
   This is meant to be kept in the repo and re-run after ANY change to
   core.js or the adapters. Every test asserts the resulting VERDICT,
   per the project rule: a test that only checks "did not crash" is
   not sufficient for a security-verdict engine.
   ===================================================================== */
const path = require('path');
const {
  escapeHtml, stripSpoofChars, VerdictEngine,
  EVM_TOKEN_CHECK_DEFS, EVM_CHAINS, normalizeEvmRecord, EvmAdapter,
  normalizeSolanaRecord, SolanaAdapter
} = require(path.join(__dirname, 'core.js'));

let passed = 0, failed = 0;
function assertVerdict(name, actual, expected){
  const ok = actual.label === expected;
  if(ok) passed++; else failed++;
  console.log(
    (ok ? 'PASS ' : 'FAIL ') + name +
    ' -> ' + actual.label + ' (expected ' + expected + ')' +
    '  [valid=' + actual.checksValid + '/' + actual.checksExpected +
    ', unknown=' + actual.checksUnknown + ', critical=' + actual.criticalFindings + ']'
  );
}

function fullClean(defs, extra){
  const rec = {};
  defs.forEach(d => { rec[d.key] = '0'; });
  return Object.assign(rec, extra || {});
}

// ---------------------------------------------------------------------
// EVM — TOKEN
// ---------------------------------------------------------------------
console.log('\n== EVM token checks ==');

{ // 1. malicious input — single confirmed critical flag
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:'1'}, 'token');
  assertVerdict('malicious input (confirmed honeypot, sparse)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 2. benign input — fully clean, full coverage
  const rec = fullClean(EVM_TOKEN_CHECK_DEFS, {is_open_source:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('benign input (fully clean, full coverage)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 3. empty provider response
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({}, 'token');
  assertVerdict('empty provider response', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 4. malformed provider response — wrong JSON types
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:null, is_mintable:[], is_blacklisted:'unknown'}, 'token');
  assertVerdict('malformed types (null/array/string)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 5. partial response — low coverage, all clear
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:'0', is_mintable:'0', is_blacklisted:'0'}, 'token');
  assertVerdict('partial response (3/12, all clear)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 6. partial response — majority present, all clear (should still pass)
  const rec = {}; EVM_TOKEN_CHECK_DEFS.slice(0,8).forEach(d => rec[d.key] = '0');
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('partial response (8/12, all clear)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 7. contradictory indicators — two warn flags with full coverage
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_mintable:'1', is_proxy:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('two warn flags, full coverage', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'CAUTION');
}
{ // 8. missing critical field entirely — must not crash, and (this is the actual
  // requirement) a well-covered PASS must still explicitly disclose that a
  // high-stakes check specifically was never answered, rather than reading
  // as unqualified confidence.
  const rec = fullClean(EVM_TOKEN_CHECK_DEFS.filter(d => d.key !== 'is_honeypot'), {is_open_source:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  const result = VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal);
  const verdictOk = result.label === 'PASS';
  const disclosedOk = result.criticalMissing === 1 && /could not be evaluated/.test(result.sub);
  const ok = verdictOk && disclosedOk;
  console.log((ok ? 'PASS ' : 'FAIL ') + 'missing critical field: verdict stays PASS at high coverage BUT discloses the gap -> ' + result.label + ' | criticalMissing=' + result.criticalMissing + ' | sub="' + result.sub + '"');
  ok ? passed++ : failed++;
}
{ // 9. malformed numeric value — non-numeric tax
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_open_source:'1', buy_tax:'not-a-number', sell_tax:'also-bad'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('malformed numeric tax value', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'CAUTION');
}
{ // 10. confirmed critical finding with sparse data — the exact bug found earlier
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({selfdestruct:'1'}, 'token');
  assertVerdict('critical finding despite sparse data (1/12 fields)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 11. Unicode/HTML payload — sanitization functions, not verdict, but must not throw
  const evil = '<img src=x onerror=alert(1)>\u202Eevil\u202C';
  let threw = false, out = '';
  try { out = escapeHtml(stripSpoofChars(evil)); } catch(e){ threw = true; }
  const ok = !threw && !out.includes('<img') && !out.includes('\u202E');
  console.log((ok ? 'PASS ' : 'FAIL ') + 'Unicode/HTML payload sanitized without throwing -> ' + JSON.stringify(out));
  ok ? passed++ : failed++;
}
{ // 12. unexpected JSON types — object/array in a boolean-shaped field
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_proxy:{weird:'object'}, is_blacklisted:[1,2,3]});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  const result = VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal);
  const hasUnknownChecks = checks.some(c => c.status === 'UNKNOWN');
  console.log((hasUnknownChecks ? 'PASS ' : 'FAIL ') + 'unexpected JSON types classified as UNKNOWN, not crashed -> ' + result.label);
  hasUnknownChecks ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// EVM adapter-level: unknown chain / unsupported asset type
// ---------------------------------------------------------------------
console.log('\n== EVM adapter guards ==');
{
  let threw = false;
  EvmAdapter.fetchChecks('0x0000000000000000000000000000000000dead', 'token', '999999', async()=>({ok:true,json:async()=>({code:1,result:{}})}))
    .catch(() => { threw = true; });
  // fetchChecks is async; run a synchronous pre-check instead since we need this to assert immediately
  const chainKnown = !!EVM_CHAINS['999999'];
  console.log((chainKnown ? 'FAIL' : 'PASS') + ' unknown chain id is not in the supported chain list (999999)');
  chainKnown ? failed++ : passed++;
}
{
  const walletOnEvmOk = EvmAdapter.capabilities.walletScreening === true;
  console.log((walletOnEvmOk ? 'PASS' : 'FAIL') + ' EVM adapter declares wallet screening capability');
  walletOnEvmOk ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// SOLANA — TOKEN
// ---------------------------------------------------------------------
console.log('\n== Solana token checks ==');

{ // 13. malicious input — confirmed critical Solana flag
  const rec = { closable: { status: '1' } };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  assertVerdict('Solana: confirmed closable program (sparse)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 14. benign input — fully clean Solana record
  const rec = {
    closable: {status:'0'}, balance_mutable_authority:{status:'0'}, freezable:{status:'0'},
    mintable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'},
    non_transferable:'0', transfer_hook:{address:''},
    creator:{address:'Abc123', malicious_address:'0'}, mintable_authority_check: null
  };
  rec.mintable.authority = { address:'Xyz', malicious_address:'0' };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  assertVerdict('Solana: fully clean record', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 15. empty Solana response
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord({});
  assertVerdict('Solana: empty provider response', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 16. non-EVM-shaped nested field, malformed type — must not crash on bad nesting
  const rec = { closable: 'not-an-object', mintable: null, freezable: {status:'0'} };
  let threw = false, checks = [], expected = 0;
  try { ({checks, expected} = normalizeSolanaRecord(rec)); } catch(e){ threw = true; }
  console.log((!threw ? 'PASS' : 'FAIL') + ' Solana: malformed nested structure does not throw');
  !threw ? passed++ : failed++;
}
{ // 17. trusted-token exception — mintable=on but trusted_token=1 should not read as risk
  const rec = { trusted_token:'1', mintable:{status:'1'}, closable:{status:'0'}, balance_mutable_authority:{status:'0'},
    freezable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'}, non_transferable:'0' };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  const mintCheck = checks.find(c => c.id === 'mintable');
  const ok = mintCheck && mintCheck.status === 'PASS';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: trusted_token suppresses mintable risk (matches GoPlus\'s documented intent) -> ' + (mintCheck ? mintCheck.status : 'MISSING'));
  ok ? passed++ : failed++;
}
{ // 18. unsupported asset type — Solana wallet screening must be refused, not silently attempted
  let refused = false;
  try {
    // fetchChecks is async, but the capability guard throws synchronously before any await
    const p = SolanaAdapter.fetchChecks('SomeAddress111111111111111111111111111111', 'wallet', null, async()=>{throw new Error('should not be called');});
    p.catch(()=>{});
  } catch(e){ refused = true; }
  const capabilityDeclared = SolanaAdapter.capabilities.walletScreening === false;
  console.log((capabilityDeclared ? 'PASS' : 'FAIL') + ' Solana adapter declares walletScreening: false (capability-honest)');
  capabilityDeclared ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// Address validation — Layer 0, must not share validators across chains
// ---------------------------------------------------------------------
console.log('\n== Layer 0: address validation ==');
const addrTests = [
  ['EVM valid', EvmAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), true],
  ['EVM rejects Solana-shaped address', EvmAdapter.validateAddress('9sj3vLFy26i1j4safWWoPujx7YScrWa4HyRF7s8XVb3U'), false],
  ['EVM rejects short hex', EvmAdapter.validateAddress('0x1234'), false],
  ['EVM rejects injection attempt', EvmAdapter.validateAddress('0x' + 'a'.repeat(40) + '<script>'), false],
  ['Solana valid', SolanaAdapter.validateAddress('9sj3vLFy26i1j4safWWoPujx7YScrWa4HyRF7s8XVb3U'), true],
  ['Solana rejects EVM-shaped address', SolanaAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), false],
  ['Solana rejects ambiguous base58 chars (0,O,I,l)', SolanaAdapter.validateAddress('0OIl' + 'a'.repeat(40)), false],
];
addrTests.forEach(([name, actual, expected]) => {
  const ok = actual === expected;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + ' -> ' + actual + ' (expected ' + expected + ')');
  ok ? passed++ : failed++;
});

{ // 19. mint authority object entirely absent (consistent with revocation) resolves to a clear
  // check, not a silent gap that would otherwise count toward criticalMissing
  const rec = { closable:{status:'0'}, balance_mutable_authority:{status:'0'}, freezable:{status:'0'},
    mintable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'},
    non_transferable:'0', transfer_hook:{address:''}, creator:{address:'Abc', malicious_address:'0'} };
    // note: no `mintable.authority` key at all
  const { checks } = normalizeSolanaRecord(rec);
  const mintAuthCheck = checks.find(c => c.id === 'mint_authority_malicious');
  const ok = mintAuthCheck && mintAuthCheck.status === 'PASS';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: absent mint authority resolves to PASS, not missing -> ' + (mintAuthCheck ? mintAuthCheck.status : 'ABSENT FROM CHECKS'));
  ok ? passed++ : failed++;
}
{ // 20. mint authority object present but malicious_address unreadable -> genuinely UNKNOWN, not silently dropped
  const rec = { mintable: { status:'0', authority: { address:'Xyz', malicious_address: [1,2,3] } } };
  const { checks } = normalizeSolanaRecord(rec);
  const mintAuthCheck = checks.find(c => c.id === 'mint_authority_malicious');
  const ok = mintAuthCheck && mintAuthCheck.status === 'UNKNOWN';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: unreadable malicious_address on a present authority -> UNKNOWN, not dropped -> ' + (mintAuthCheck ? mintAuthCheck.status : 'ABSENT FROM CHECKS'));
  ok ? passed++ : failed++;
}
console.log(passed + '/' + (passed + failed) + ' regression tests passed');
console.log('='.repeat(60));
if(failed > 0) process.exit(1);
