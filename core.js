/* =====================================================================
   RISKPASS CORE
   Layers 0-6 from the architecture: input validation, data acquisition,
   evidence normalization, chain adapters, verdict engine, confidence.
   This block has NO DOM dependency except an optional escapeHtml path,
   so it can be eval()'d in Node for regression testing, unmodified,
   exactly as it ships in the browser.
   ===================================================================== */

// ---------- Sanitization ----------
function escapeHtml(str){
  if(typeof document !== 'undefined'){
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function stripSpoofChars(str){
  return String(str).replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g, '');
}

function getPath(obj, path){
  let cur = obj;
  for(const key of path){
    if(cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[key];
  }
  return cur;
}

// ---------- Layer 1/2: flag classification + evidence model ----------
// Every raw provider value is classified into exactly one bucket.
// 'missing' fields never become a CHECK object at all — they are simply
// absent, and absence is accounted for via checksExpected vs checksValid,
// never silently treated as clear.
function flagState(v){
  if(v === '1' || v === 1 || v === true) return 'on';
  if(v === '0' || v === 0 || v === false) return 'off';
  if(v === undefined || v === null) return 'missing';
  return 'unrecognized';
}

// CHECK = { id, category, status: 'PASS'|'RISK'|'UNKNOWN', critical, severityWeight, label, detail, source }
function buildCheck(def, rawValue, source){
  const state = flagState(rawValue);
  if(state === 'missing') return null;
  if(state === 'unrecognized'){
    return { id: def.key, category: def.category || 'general', status: 'UNKNOWN', critical: !!def.critical,
      severityWeight: 1, label: def.label, detail: def.detail + ' (provider returned an unrecognized value type for this field)', source };
  }
  const on = state === 'on';
  return { id: def.key, category: def.category || 'general', status: on ? 'RISK' : 'PASS',
    critical: !!def.critical, severityWeight: def.sev === 'bad' ? 3 : 1, label: def.label, detail: def.detail, source };
}

// ---------- Layer 5/6: Verdict engine — knows NOTHING about any provider or chain ----------
const VerdictEngine = {
  evaluate(checks, expectedChecks, source, criticalDefsTotal){
    const risks = checks.filter(c => c.status === 'RISK');
    const unknowns = checks.filter(c => c.status === 'UNKNOWN');
    const valid = checks.filter(c => c.status === 'PASS' || c.status === 'RISK').length;
    const criticalFindings = risks.filter(c => c.critical).length;
    const criticalHit = criticalFindings > 0;
    const criticalSeen = checks.filter(c => c.critical).length; // critical-tier checks we got ANY answer for, PASS/RISK/UNKNOWN alike
    const criticalMissing = typeof criticalDefsTotal === 'number' ? Math.max(0, criticalDefsTotal - criticalSeen) : 0;

    let score = 0;
    risks.forEach(c => { score += c.severityWeight; });
    score += unknowns.length; // each unreadable field nudges toward caution, doesn't force it alone

    const coverage = expectedChecks ? valid / expectedChecks : 0;
    const insufficientData = valid === 0 || coverage < 0.4;

    let verdict, label, sub;
    if(criticalHit){
      verdict = 'fail'; label = 'FAIL';
      sub = 'A confirmed high-severity indicator was detected';
    } else if(insufficientData){
      verdict = 'unknown'; label = 'INSUFFICIENT DATA';
      sub = `Only ${valid}/${expectedChecks} indicators returned usable data — too little to form a judgment. This is not a clean result.`;
    } else if(score >= 6){
      verdict = 'fail'; label = 'FAIL';
      sub = 'Significant risk indicators detected';
    } else if(score >= 2 || unknowns.length > 0){
      verdict = 'caution'; label = 'CAUTION';
      sub = (unknowns.length > 0 && score < 2)
        ? 'Some indicators returned unreadable data — treat as unverified, not clean'
        : 'Risk indicators detected — review before proceeding';
    } else {
      verdict = 'pass'; label = 'PASS';
      sub = `No major risk indicators across ${valid}/${expectedChecks} checks — not a safety guarantee`;
    }

    // Additive disclosure: even a well-covered, otherwise-clean scan should
    // say so plainly if one of the specific high-stakes checks (e.g.
    // honeypot detection) simply wasn't answered by the provider. This is
    // deliberately separate from the coverage-driven INSUFFICIENT DATA
    // state above — losing one decisive check is a different, more
    // targeted kind of uncertainty than losing most of the response.
    if(criticalMissing > 0 && (verdict === 'pass' || verdict === 'caution')){
      sub += ` Note: ${criticalMissing} high-severity check${criticalMissing===1?'':'s'} could not be evaluated (no data returned) — treat this result as incomplete on that point.`;
    }

    const confidence = insufficientData ? 'low' : (unknowns.length > 0 || criticalMissing > 0 ? 'medium' : 'high');

    return {
      verdict, label, sub, score,
      checksExpected: expectedChecks,
      checksReceived: checks.length,
      checksValid: valid,
      checksUnknown: unknowns.length,
      criticalFindings,
      criticalMissing,
      coverage,
      confidence,
      source,
      checks
    };
  }
};

// ---------- Layer 3: chain adapters ----------

// -- EVM adapter --
const EVM_TOKEN_CHECK_DEFS = [
  {key:'is_honeypot', category:'liquidity', label:'Honeypot pattern', detail:'Token can be bought but may not be sellable.', sev:'bad', critical:true},
  {key:'cannot_sell_all', category:'liquidity', label:'Cannot sell full balance', detail:'Contract may block selling 100% of holdings.', sev:'bad', critical:true},
  {key:'selfdestruct', category:'control', label:'Self-destruct function present', detail:'Contract could be destroyed, freezing funds.', sev:'bad', critical:true},
  {key:'owner_change_balance', category:'control', label:'Owner can edit balances', detail:'Contract owner can directly alter holder balances.', sev:'bad', critical:true},
  {key:'can_take_back_ownership', category:'control', label:'Ownership can be reclaimed', detail:'A renounced-looking contract may still be controllable.', sev:'bad', critical:true},
  {key:'hidden_owner', category:'control', label:'Hidden owner address', detail:'Contract owner is concealed from standard checks.', sev:'bad', critical:false},
  {key:'is_blacklisted', category:'control', label:'Blacklist function present', detail:'Owner can block specific addresses from trading.', sev:'warn', critical:false},
  {key:'is_mintable', category:'supply', label:'Owner can mint new supply', detail:'Total supply is not fixed.', sev:'warn', critical:false},
  {key:'transfer_pausable', category:'control', label:'Transfers can be paused', detail:'Owner can freeze all trading at will.', sev:'warn', critical:false},
  {key:'slippage_modifiable', category:'economics', label:'Tax/slippage can be changed', detail:'Buy/sell tax is not locked.', sev:'warn', critical:false},
  {key:'is_proxy', category:'control', label:'Upgradeable proxy contract', detail:'Logic can be swapped after deployment.', sev:'warn', critical:false},
  {key:'is_anti_whale_modifiable', category:'control', label:'Anti-whale limits are adjustable', detail:'Transaction size limits can be changed by the owner.', sev:'warn', critical:false},
];

const EVM_WALLET_CHECK_DEFS = [
  {key:'sanctioned', category:'reputation', label:'On a sanctions list', detail:'Address appears on a known sanctions record.', sev:'bad', critical:true},
  {key:'phishing_activities', category:'reputation', label:'Linked to phishing', detail:'Address has been associated with phishing activity.', sev:'bad', critical:true},
  {key:'stealing_attack', category:'reputation', label:'Linked to theft', detail:'Address has been associated with a stealing attack.', sev:'bad', critical:true},
  {key:'money_laundering', category:'reputation', label:'Linked to money laundering', detail:'Flagged in money-laundering-related activity.', sev:'bad', critical:true},
  {key:'darkweb_transactions', category:'reputation', label:'Dark web transaction history', detail:'Address has interacted with dark web markets.', sev:'bad', critical:true},
  {key:'cybercrime', category:'reputation', label:'Linked to cybercrime', detail:'Address has been associated with cybercrime.', sev:'bad', critical:true},
  {key:'blackmail_activities', category:'reputation', label:'Linked to blackmail/extortion', detail:'Flagged in blackmail-related activity.', sev:'bad', critical:true},
  {key:'mixer', category:'reputation', label:'Mixer / tumbler service', detail:'Address is associated with a coin-mixing service.', sev:'warn', critical:false},
  {key:'fake_kyc', category:'reputation', label:'Fake KYC association', detail:'Linked to fraudulent identity-verification activity.', sev:'warn', critical:false},
  {key:'blacklist_doubt', category:'reputation', label:'On a community blacklist (unconfirmed)', detail:'Reported but not fully confirmed.', sev:'warn', critical:false},
  {key:'gas_abuse', category:'reputation', label:'Gas abuse pattern', detail:'Associated with gas-griefing or abuse patterns.', sev:'warn', critical:false},
];

const EVM_CHAINS = {"1":"Ethereum","56":"BNB Chain","137":"Polygon","42161":"Arbitrum","10":"Optimism","8453":"Base","43114":"Avalanche","250":"Fantom"};

function normalizeEvmRecord(record, assetType){
  const defs = assetType === 'token' ? EVM_TOKEN_CHECK_DEFS : EVM_WALLET_CHECK_DEFS;
  const checks = [];
  let expected = defs.length;
  let criticalDefsTotal = defs.filter(d => d.critical).length;

  defs.forEach(def => {
    const c = buildCheck(def, record[def.key], 'GoPlus Security (EVM)');
    if(c) checks.push(c);
  });

  if(assetType === 'token'){
    expected += 2; // is_open_source + tax are extra checks beyond the base list
    if(record.is_open_source !== undefined){
      const openState = flagState(record.is_open_source);
      if(openState === 'on'){
        checks.push({id:'is_open_source', category:'transparency', status:'PASS', critical:false, severityWeight:0, label:'Source code verified', detail:'Contract code has been published/verified.', source:'GoPlus Security (EVM)'});
      } else if(openState === 'off'){
        checks.push({id:'is_open_source', category:'transparency', status:'RISK', critical:false, severityWeight:2, label:'Source code not verified', detail:'Contract code has not been published/verified.', source:'GoPlus Security (EVM)'});
      }
      // unrecognized type for is_open_source: leave unclassified rather than guess a boolean meaning
    }
    if(record.buy_tax !== undefined || record.sell_tax !== undefined){
      const buyNum = parseFloat(record.buy_tax);
      const sellNum = parseFloat(record.sell_tax);
      const buyOk = Number.isFinite(buyNum);
      const sellOk = Number.isFinite(sellNum);
      if(buyOk || sellOk){
        const buyPct = buyOk ? buyNum * 100 : null;
        const sellPct = sellOk ? sellNum * 100 : null;
        const high = (buyPct !== null && buyPct > 10) || (sellPct !== null && sellPct > 10);
        checks.push({id:'tax_rate', category:'economics', status: high ? 'RISK' : 'PASS', critical:false, severityWeight:2,
          label: high ? 'High buy/sell tax' : 'Buy/sell tax within normal range',
          detail: `Buy tax ${buyPct !== null ? buyPct.toFixed(1)+'%' : 'unknown'} · Sell tax ${sellPct !== null ? sellPct.toFixed(1)+'%' : 'unknown'}`,
          source:'GoPlus Security (EVM)'});
      } else {
        checks.push({id:'tax_rate', category:'economics', status:'UNKNOWN', critical:false, severityWeight:1,
          label:'Tax data unreadable', detail:'Buy/sell tax fields returned a non-numeric value.', source:'GoPlus Security (EVM)'});
      }
    }
  }

  return { checks, expected, criticalDefsTotal };
}

const EvmAdapter = {
  id: 'evm', name: 'EVM',
  capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:false, contractAnalysis:true },
  chains: EVM_CHAINS,
  validateAddress(addr){ return /^0x[a-fA-F0-9]{40}$/.test(String(addr).trim()); },
  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(!EVM_CHAINS[chainId]) throw new Error('Unsupported or unrecognized chain for the EVM adapter.');
    if(assetType === 'wallet' && !this.capabilities.walletScreening) throw new Error('Wallet screening is not supported by this adapter.');
    const endpoint = assetType === 'token'
      ? `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${addr}`
      : `https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=${chainId}`;
    const res = await fetchImpl(endpoint);
    if(!res.ok) throw new Error('Network response was not OK (' + res.status + ')');
    const data = await res.json();
    if(data.code !== 1 || !data.result) throw new Error(data.message || 'No security data returned for this address.');
    let record;
    if(assetType === 'token'){
      const keys = Object.keys(data.result);
      if(keys.length === 0) throw new Error('This address does not appear to be a recognized token contract on the selected chain.');
      record = data.result[keys[0]];
    } else {
      record = data.result;
    }
    const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(record, assetType);
    return { checks, expected, criticalDefsTotal, record, raw: data };
  }
};

// -- Solana adapter --
// Field names verified against GoPlus's published Solana Token Security
// response schema (nested {status} objects) — deliberately NOT the same
// shape as the EVM adapter's flat fields, per the architecture principle
// that each chain's native security model gets its own representation.
const SOLANA_CHECK_DEFS = [
  {key:'closable', path:['closable','status'], category:'control', label:'Program can be closed', detail:'Developer can close the token program, eliminating all associated assets.', sev:'bad', critical:true},
  {key:'balance_mutable', path:['balance_mutable_authority','status'], category:'control', label:'Balance can be altered', detail:'Developer retains authority to directly change user token balances.', sev:'bad', critical:true},
  {key:'freezable', path:['freezable','status'], category:'control', label:'Accounts can be frozen', detail:'Developer can freeze holder accounts, blocking trading.', sev:'bad', critical:false},
  {key:'mintable', path:['mintable','status'], category:'supply', label:'Supply can be minted', detail:'Total supply is not fixed; new tokens can be created.', sev:'warn', critical:false},
  {key:'metadata_mutable', path:['metadata_mutable','status'], category:'transparency', label:'Metadata can be changed', detail:'Name, symbol, or description can be altered after launch.', sev:'warn', critical:false},
  {key:'transfer_fee_upgradable', path:['transfer_fee_upgradable','status'], category:'economics', label:'Transfer fee can be changed', detail:'Fee equivalent to buy/sell tax is not locked.', sev:'warn', critical:false},
  {key:'default_account_state_upgradable', path:['default_account_state_upgradable','status'], category:'control', label:'Default account state is upgradable', detail:'The default frozen/initialized state for new accounts can be changed.', sev:'warn', critical:false},
  {key:'hook_upgradable', path:['transfer_hook_upgradable','status'], category:'control', label:'Transfer hook is upgradable', detail:'External hook logic attached to transfers can be changed later.', sev:'warn', critical:false},
];

function normalizeSolanaRecord(record){
  const checks = [];
  let expected = SOLANA_CHECK_DEFS.length + 4; // + non_transferable, transfer_hook presence, creator malicious, mint-authority malicious
  let criticalDefsTotal = SOLANA_CHECK_DEFS.filter(d => d.critical).length + 3; // non_transferable, creator_malicious, mint_authority_malicious are critical:true; transfer_hook_present is not
  const trusted = flagState(record.trusted_token) === 'on';

  SOLANA_CHECK_DEFS.forEach(def => {
    const raw = getPath(record, def.path);
    // GoPlus documents that trusted, well-known tokens (e.g. USDC) can
    // legitimately have functions like mint enabled without being a risk.
    // Only the mint check gets this exception, per GoPlus's own guidance.
    if(def.key === 'mintable' && trusted && flagState(raw) === 'on'){
      checks.push({id:'mintable', category:'supply', status:'PASS', critical:false, severityWeight:0,
        label:'Mint function present, but token is GoPlus-verified trusted', detail:'This token is on GoPlus\'s trusted-token list; mint authority is a known, accepted design choice for it.', source:'GoPlus Security (Solana)'});
      return;
    }
    const c = buildCheck(def, raw, 'GoPlus Security (Solana)');
    if(c) checks.push(c);
  });

  if(record.non_transferable !== undefined){
    const state = flagState(record.non_transferable);
    if(state === 'on'){
      checks.push({id:'non_transferable', category:'liquidity', status:'RISK', critical:true, severityWeight:3, label:'Token is non-transferable', detail:'Token cannot be transferred once acquired — functionally a honeypot.', source:'GoPlus Security (Solana)'});
    } else if(state === 'off'){
      checks.push({id:'non_transferable', category:'liquidity', status:'PASS', critical:false, severityWeight:0, label:'Token is transferable', detail:'No transfer restriction detected.', source:'GoPlus Security (Solana)'});
    }
  }

  const hookAddr = getPath(record, ['transfer_hook','address']);
  if(hookAddr !== undefined){
    const hasHook = typeof hookAddr === 'string' && hookAddr.length > 0;
    checks.push({id:'transfer_hook_present', category:'control', status: hasHook ? 'RISK' : 'PASS', critical:false, severityWeight:1,
      label: hasHook ? 'External transfer hook present' : 'No external transfer hook',
      detail: hasHook ? 'A hook contract can intervene in transfers and may block trading.' : 'No hook contract detected in the token program.',
      source:'GoPlus Security (Solana)'});
  }

  const creatorMalicious = getPath(record, ['creator','malicious_address']);
  if(creatorMalicious !== undefined){
    const state = flagState(creatorMalicious);
    if(state === 'on') checks.push({id:'creator_malicious', category:'reputation', status:'RISK', critical:true, severityWeight:3, label:'Creator address flagged malicious', detail:'The token creator address appears on a known malicious-address record.', source:'GoPlus Security (Solana)'});
    else if(state === 'off') checks.push({id:'creator_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0, label:'Creator address not flagged', detail:'Creator address does not appear on known malicious-address records.', source:'GoPlus Security (Solana)'});
  }

  const mintAuthority = getPath(record, ['mintable','authority']);
  if(mintAuthority === undefined || mintAuthority === null){
    // No authority object at all is consistent with mint authority having
    // been revoked (a positive signal) — but GoPlus's docs don't guarantee
    // that's the only reason it could be absent, so the wording below stays
    // deliberately hedged rather than asserting "revoked" as fact.
    checks.push({id:'mint_authority_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0,
      label:'No mint authority to check', detail:'No mint authority address was returned — consistent with mint authority having been revoked, though this cannot be confirmed from this field alone.', source:'GoPlus Security (Solana)'});
  } else {
    const state = flagState(mintAuthority.malicious_address);
    if(state === 'on') checks.push({id:'mint_authority_malicious', category:'reputation', status:'RISK', critical:true, severityWeight:3, label:'Mint authority flagged malicious', detail:'The address holding mint authority appears on a known malicious-address record.', source:'GoPlus Security (Solana)'});
    else if(state === 'off') checks.push({id:'mint_authority_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0, label:'Mint authority not flagged', detail:'Mint authority address does not appear on known malicious-address records.', source:'GoPlus Security (Solana)'});
    else if(state === 'unrecognized') checks.push({id:'mint_authority_malicious', category:'reputation', status:'UNKNOWN', critical:true, severityWeight:1, label:'Mint authority flagged malicious', detail:'A mint authority exists, but the malicious-address field for it returned an unreadable value.', source:'GoPlus Security (Solana)'});
    // state === 'missing' here (authority object present, malicious_address key absent within it) is a genuine
    // data gap and is deliberately left unpushed, so it still counts toward criticalMissing honestly.
  }

  return { checks, expected, criticalDefsTotal };
}

// SETUP: replace with your deployed Cloudflare Worker URL — see
// riskpass-solana-proxy-worker.js. GoPlus's Solana API does not send CORS
// headers, so direct browser requests are blocked; this proxy is required,
// not optional, for Solana scanning to work at all.
const SOLANA_PROXY_URL = 'https://cool-sound-6db2riskpass.stefan-tsezarov82.workers.dev';

const SolanaAdapter = {
  id: 'solana', name: 'Solana',
  capabilities: { tokenSecurity:true, walletScreening:false, txSimulation:false, liquidityAnalysis:false, contractAnalysis:false },
  chains: { 'solana': 'Solana Mainnet' },
  validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },
  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(assetType !== 'token') throw new Error('Wallet screening is not yet supported for Solana in RiskPass — token scans only.');
    if(SOLANA_PROXY_URL.includes('REPLACE-WITH-YOUR-WORKER-URL')){
      throw new Error('Solana scanning needs the CORS proxy deployed first — see setup instructions. GoPlus\'s Solana API blocks direct browser requests.');
    }
    const endpoint = `${SOLANA_PROXY_URL}?contract_addresses=${addr}`;
    const res = await fetchImpl(endpoint);
    if(!res.ok) throw new Error('Network response was not OK (' + res.status + ')');
    const data = await res.json();
    if(data.code !== 1 || !data.result) throw new Error(data.message || data.error || 'No security data returned for this address.');
    const keys = Object.keys(data.result);
    if(keys.length === 0) throw new Error('This address does not appear to be a recognized token on Solana.');
    const record = data.result[keys[0]];
    const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(record);
    return { checks, expected, criticalDefsTotal, record, raw: data };
  }
};

const Adapters = { evm: EvmAdapter, solana: SolanaAdapter };

// Guarded export: in a browser <script> tag, `module` doesn't exist, so this
// block is skipped and every const/function above simply lives in script
// scope, same as before. In Node (the regression suite), this makes the
// exact same source file directly require()-able with no duplication.
if(typeof module !== 'undefined' && module.exports){
  module.exports = {
    escapeHtml, stripSpoofChars, getPath, flagState, buildCheck, VerdictEngine,
    EVM_TOKEN_CHECK_DEFS, EVM_WALLET_CHECK_DEFS, EVM_CHAINS, normalizeEvmRecord, EvmAdapter,
    SOLANA_CHECK_DEFS, normalizeSolanaRecord, SolanaAdapter, Adapters
  };
}
