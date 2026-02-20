
// Configuration constants - More generous timeouts for robustness
const CONFIG = {
  TIMEOUTS: {
    FETCH_DEFAULT: 8000,      // Increased from 3000
    FETCH_HEADERS: 5000,      // Increased from 2500
    FETCH_TEXT: 6000,         // Increased from 2500
    FETCH_JSON: 8000,         // Increased from 3500
    FETCH_FAVICON: 4000,      // Increased from 2000
    DOH_RESOLVE: 5000,        // Increased from 2500
    SECURITY_TXT: 4000,       // Increased from 2000
    VT_REQUEST: 8000,         // Increased from 3000
    CVE_NVD: 10000,           // Increased from 4000
    SUBDOMAIN_PASSIVE: 8000,  // New
    IP_ENRICHMENT: 8000       // New
  },
  LIMITS: {
    MAX_IPS: 20,
    MAX_EXTERNAL_SCRIPTS: 12,
    MAX_INLINE_SCRIPTS: 16,
    MAX_SECRETS_RESULTS: 20,
    MAX_SUBDOMAINS: 200,
    MAX_SUBDOMAINS_LIVE: 80,
    MAX_SUBDOMAINS_QUEUE: 120,
    MAX_PARALLEL_WORKERS: 6,
    MAX_CPES_PER_IP: 5,
    MAX_CVE_RESULTS: 60,
    MAX_SOURCE_MAPS: 6,
    MAX_DKIM_SELECTORS: 6,
    MAX_DOM_PATHS: 200
  },
  RETRY: {
    MAX_ATTEMPTS: 3,
    INITIAL_DELAY: 500,
    MAX_DELAY: 4000
  },
  CACHE: {
    DOH_MS: 5 * 60 * 1000,
    SUBDOMAIN_MS: 10 * 60 * 1000,
    MAX_ENTRIES: 128
  }
};

function log(...a){ try{ console.log("[SnailSploit Recon]", ...a);}catch{} }
function logError(...a){ try{ console.error("[SnailSploit Recon ERROR]", ...a);}catch{} }
function merge(a, b) {
  const result = Object.assign({}, a || {});
  for (const [key, val] of Object.entries(b || {})) {
    if (val !== null && typeof val === 'object' && !Array.isArray(val) &&
        result[key] !== null && typeof result[key] === 'object' && !Array.isArray(result[key])) {
      result[key] = merge(result[key], val);
    } else {
      result[key] = val;
    }
  }
  return result;
}
const dohCache = new Map();
const subdomainCache = new Map();
const highlightTimers = new Map();
function setBoundedCache(map, key, value){
  map.set(key, value);
  if (map.size > CONFIG.CACHE.MAX_ENTRIES) {
    const first = map.keys().next().value;
    if (first !== undefined) map.delete(first);
  }
}

// Exponential backoff retry helper
async function retryWithBackoff(fn, maxAttempts = CONFIG.RETRY.MAX_ATTEMPTS, operation = "operation") {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === maxAttempts) {
        logError(`${operation} failed after ${maxAttempts} attempts:`, error);
        throw error;
      }
      const delay = Math.min(CONFIG.RETRY.INITIAL_DELAY * Math.pow(2, attempt - 1), CONFIG.RETRY.MAX_DELAY);
      log(`${operation} attempt ${attempt}/${maxAttempts} failed, retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

async function fetchWithTimeout(resource, options={}, ms=3000){
  const c = new AbortController(); const id = setTimeout(()=>c.abort(), ms);
  try { return await fetch(resource, { ...options, signal: c.signal, cache: "no-store" }); }
  finally { clearTimeout(id); }
}
async function jsonWithTimeout(url, opts={}, ms=3000){ const r=await fetchWithTimeout(url,opts,ms); if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

// headers
const headersByTab = new Map();
chrome.webRequest.onHeadersReceived.addListener((d)=>{
  if (d.type !== "main_frame") return;
  headersByTab.set(d.tabId, { url: d.url, responseHeaders: d.responseHeaders || [] });
}, { urls: ["<all_urls>"] }, ["responseHeaders","extraHeaders"]);

function pickSecurityHeaders(tabId){
  const rec = headersByTab.get(tabId); if (!rec) return null;
  const h = {}; const setCookies = [];
  for (const {name,value} of rec.responseHeaders||[]) {
    const lc = name.toLowerCase();
    if (lc === "set-cookie") { setCookies.push(value || ""); }
    else { h[lc] = value || ""; }
  }
  // Preserve all Set-Cookie headers as an array
  if (setCookies.length) h["set-cookie"] = setCookies;
  const get = k => h[k] || null;
  return { url: rec.url, headers: {
    "content-security-policy": get("content-security-policy"),
    "strict-transport-security": get("strict-transport-security"),
    "x-frame-options": get("x-frame-options"),
    "x-content-type-options": get("x-content-type-options"),
    "referrer-policy": get("referrer-policy"),
    "permissions-policy": get("permissions-policy"),
    "server": get("server"),
    "alt-svc": get("alt-svc"),
    "x-powered-by": get("x-powered-by"),
    "via": get("via"),
    "set-cookie": setCookies.length ? setCookies : null
  }};
}
async function fetchHeadersFallback(url){
  try{ const r=await fetchWithTimeout(url,{method:"HEAD"},2500); const o={}; for(const [k,v] of r.headers.entries()) o[k.toLowerCase()]=v; return o; }catch(e){ log(`HEAD fallback failed for ${url}:`, e.message); }
  try{ const r=await fetchWithTimeout(url,{method:"GET",headers:{"Range":"bytes=0-0"}},2500); const o={}; for(const [k,v] of r.headers.entries()) o[k.toLowerCase()]=v; return o; }catch(e){ log(`GET-Range fallback failed for ${url}:`, e.message); }
  return null;
}

// DNS resolution via DNS-over-HTTPS (DoH) - Uses Google and Cloudflare public resolvers
// Avoids chrome.dns API requirement, making extension work on Chrome Stable
async function dohResolve(name, type){
  const key = `${name}|${type}`;
  const now = Date.now();
  const cached = dohCache.get(key);
  if (cached && (now - cached.ts) < CONFIG.CACHE.DOH_MS) return cached.ans;
  const enc = encodeURIComponent(name);
  const urls = [
    `https://dns.google/resolve?name=${enc}&type=${type}`,
    `https://cloudflare-dns.com/dns-query?name=${enc}&type=${type}`
  ];
  for (const u of urls) {
    try {
      const r = await fetchWithTimeout(u, { headers:{accept:"application/dns-json"} }, 2500);
      if (!r.ok) continue;
      const j=await r.json();
      if (j.Answer && j.Answer.length) {
        setBoundedCache(dohCache, key, { ts: now, ans: j.Answer });
        return j.Answer;
      }
    } catch (e) { log(`DoH resolver failed (${u}):`, e.message); }
  }
  setBoundedCache(dohCache, key, { ts: now, ans: [] });
  return [];
}
async function dohTXT(name){ const ans=await dohResolve(name,"TXT"); const out=[]; for(const a of ans){ if(a.type!==16) continue; let d=a.data||""; d=d.replace(/^\"|\"$/g,"").replace(/\"\\s+\"?/g,""); out.push(d);} return out; }
async function dohMX(name){ const ans=await dohResolve(name,"MX"); return (ans||[]).filter(a=>a.type===15).map(a=>a.data); }
function isIPv4(ip){ return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip); }
function isIPv6(ip){ return ip.includes(":"); }
function ipv4ToPtr(ip){ return ip.split(".").reverse().join(".") + ".in-addr.arpa"; }
function expandIPv6Blocks(ip){ const [h,t]=ip.split("::"); const H=(h?h.split(":"):[]).filter(Boolean); const T=(t?t.split(":"):[]).filter(Boolean); const miss=Math.max(0,8-(H.length+T.length)); return [...H,...Array(miss).fill("0"),...T].map(x=>("0000"+x).slice(-4)); }
function ipv6ToPtr(ip){ try{ const parts=expandIPv6Blocks(ip).join(""); return parts.split("").reverse().join(".") + ".ip6.arpa"; }catch{ return null; } }
async function reverseDNS(ip){ let name=null; if(isIPv4(ip)) name=ipv4ToPtr(ip); else if(isIPv6(ip)) name=ipv6ToPtr(ip); if(!name) return null; const ans=await dohResolve(name,"PTR"); const a=(ans||[]).find(x=>x.type===12); return a ? (a.data||"").replace(/\.$/,"") : null; }
async function resolveIPs(hostname){
  const ips = new Set();
  const q = encodeURIComponent(hostname);
  const urls = [
    `https://dns.google/resolve?name=${q}&type=A`,
    `https://dns.google/resolve?name=${q}&type=AAAA`,
    `https://cloudflare-dns.com/dns-query?name=${q}&type=A`,
    `https://cloudflare-dns.com/dns-query?name=${q}&type=AAAA`
  ];
  const all = await Promise.all(urls.map(u => fetchWithTimeout(u, { headers:{accept:"application/dns-json"} }, CONFIG.TIMEOUTS.DOH_RESOLVE).then(r=>r.json()).catch(()=>({}))));
  for (const j of all) for (const a of (j.Answer||[])) if (a.type===1||a.type===28) ips.add(a.data);
  return [...ips].slice(0, CONFIG.LIMITS.MAX_IPS);
}

// Enrichers with robust error handling and retry logic
async function fetchJSON(url, opts = {}, timeout = CONFIG.TIMEOUTS.FETCH_JSON) {
  return retryWithBackoff(async () => {
    const r = await fetchWithTimeout(url, { ...opts }, timeout);
    if (r.status === 429) {
      const retryAfter = parseInt(r.headers.get('retry-after') || '5', 10);
      log(`Rate limited (429) on ${url}, waiting ${retryAfter}s`);
      await new Promise(res => setTimeout(res, retryAfter * 1000));
      throw new Error(`Rate limited (429) for ${url}`);
    }
    if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
    return r.json();
  }, 2, `fetchJSON(${url})`);
}

async function shodanInternetDB(ip) {
  try {
    return await fetchJSON(`https://internetdb.shodan.io/${ip}`, {}, CONFIG.TIMEOUTS.IP_ENRICHMENT);
  } catch (e) {
    logError(`Shodan InternetDB failed for ${ip}:`, e);
    return {};
  }
}

async function ipWhoIs(ip) {
  try {
    return await fetchJSON(`https://ipwho.is/${ip}`, {}, CONFIG.TIMEOUTS.IP_ENRICHMENT);
  } catch (e) {
    log(`ipwho.is failed for ${ip}, trying ipapi.co...`);
    try {
      return await fetchJSON(`https://ipapi.co/${ip}/json/`, {}, CONFIG.TIMEOUTS.IP_ENRICHMENT);
    } catch (e2) {
      logError(`Both IP whois services failed for ${ip}`);
      return {};
    }
  }
}

async function rdapDomain(domain) {
  try {
    return await fetchJSON(`https://rdap.org/domain/${domain}`, {}, CONFIG.TIMEOUTS.FETCH_JSON);
  } catch (e) {
    logError(`RDAP domain lookup failed for ${domain}:`, e);
    return null;
  }
}

async function rdapIP(ip) {
  try {
    return await fetchJSON(`https://rdap.org/ip/${ip}`, {}, CONFIG.TIMEOUTS.IP_ENRICHMENT);
  } catch (e) {
    logError(`RDAP IP lookup failed for ${ip}:`, e);
    return null;
  }
}

async function getSecurityTxt(origin) {
  try {
    const u1 = new URL("/.well-known/security.txt", origin).href;
    const r1 = await fetchWithTimeout(u1, {}, CONFIG.TIMEOUTS.SECURITY_TXT);
    if (r1.ok) return { url: u1 };
  } catch (e) {
    log(`security.txt not found at /.well-known/, trying root...`);
  }
  try {
    const u2 = new URL("/security.txt", origin).href;
    const r2 = await fetchWithTimeout(u2, {}, CONFIG.TIMEOUTS.SECURITY_TXT);
    if (r2.ok) return { url: u2 };
  } catch (e) {
    log(`security.txt not found at root either`);
  }
  return null;
}

async function getRobots(origin) {
  try {
    const u = new URL("/robots.txt", origin).href;
    const r = await fetchWithTimeout(u, {}, CONFIG.TIMEOUTS.SECURITY_TXT);
    if (r.ok) return { url: u };
  } catch (e) {
    log(`robots.txt not found for ${origin}`);
  }
  return null;
}
async function checkDMARC(d){ try{ const recs=await dohTXT(`_dmarc.${d}`); const m=recs.find(r=>String(r).toUpperCase().includes("V=DMARC1")); return {present:!!m, record:m||null}; }catch{ return {present:false, record:null}; } }
async function checkSPF(d){ try{ const recs=await dohTXT(d); const m=recs.find(r=>String(r).toLowerCase().startsWith("v=spf1")); return {present:!!m, record:m||null}; }catch{ return {present:false, record:null}; } }
const COMMON_DKIM=["default","google","mail","mandrill","dkim","selector","selector1","selector2","s1","s2","k1","mx","smtp"];
async function checkDKIM(d){ const found=[]; for(const sel of COMMON_DKIM){ try{ const txts=await dohTXT(`${sel}._domainkey.${d}`); const rec=(txts||[]).find(r=>String(r).toLowerCase().includes("v=dkim1")); if(rec) found.push({selector:sel,record:rec}); if(found.length>=6) break; }catch{} } return {selectors:found}; }

// Subdomain enumeration - OPTIMIZED: Parallel API calls to all sources
// Combines passive sources (crt.sh, BufferOver, Anubis) concurrently
async function subdomainsPassive(domain){
  const set = new Set(); const q = domain.replace(/^\*\./, "");
  const cached = subdomainCache.get(q);
  if (cached && (Date.now() - cached.ts) < CONFIG.CACHE.SUBDOMAIN_MS) {
    log(`Using cached subdomains for ${q}`);
    return cached.data.slice(0, CONFIG.LIMITS.MAX_SUBDOMAINS);
  }

  // Fetch from all sources in parallel for maximum speed
  const sources = await Promise.allSettled([
    // crt.sh - certificate transparency logs (uses shared cache)
    (async () => {
      try {
        log(`Fetching subdomains from crt.sh for ${q}...`);
        const arr = await fetchCrtshData(q);
        const results = [];
        for (const row of arr) {
          const names = String(row.name_value || "").split(/\n+/);
          for (const n of names) {
            if (n && n.endsWith(q)) results.push(n.replace(/^\*\./, ""));
          }
        }
        log(`crt.sh found ${results.length} subdomains`);
        return results;
      } catch (e) {
        logError(`crt.sh lookup failed for ${q}:`, e);
      }
      return [];
    })(),

    // BufferOver - DNS aggregator
    (async () => {
      try {
        log(`Fetching subdomains from BufferOver for ${q}...`);
        const r = await fetchWithTimeout(`https://dns.bufferover.run/dns?q=.${encodeURIComponent(q)}`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
        if (r.ok) {
          const j = await r.json();
          const results = [];
          for (const line of (j.FDNS_A || [])) {
            const d = (line.split(",")[1] || "").trim();
            if (d && d.endsWith(q)) results.push(d);
          }
          for (const line of (j.FDNS_AAAA || [])) {
            const d = (line.split(",")[1] || "").trim();
            if (d && d.endsWith(q)) results.push(d);
          }
          log(`BufferOver found ${results.length} subdomains`);
          return results;
        }
      } catch (e) {
        logError(`BufferOver lookup failed for ${q}:`, e);
      }
      return [];
    })(),

    // Anubis - subdomain aggregator
    (async () => {
      try {
        log(`Fetching subdomains from Anubis for ${q}...`);
        const r = await fetchWithTimeout(`https://jldc.me/anubis/subdomains/${encodeURIComponent(q)}`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
        if (r.ok) {
          const arr = await r.json();
          const results = [];
          for (const d of arr) {
            if (typeof d === "string" && d.endsWith(q)) results.push(d);
          }
          log(`Anubis found ${results.length} subdomains`);
          return results;
        }
      } catch (e) {
        logError(`Anubis lookup failed for ${q}:`, e);
      }
      return [];
    })(),

    // AlienVault OTX - passive DNS aggregator (4th source)
    (async () => {
      try {
        log(`Fetching subdomains from AlienVault OTX for ${q}...`);
        const r = await fetchWithTimeout(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(q)}/passive_dns`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
        if (r.ok) {
          const j = await r.json();
          const results = [];
          for (const entry of (j.passive_dns || [])) {
            const h = (entry.hostname || "").trim();
            if (h && h.endsWith(q) && h !== q) results.push(h);
          }
          log(`AlienVault OTX found ${results.length} subdomains`);
          return results;
        }
      } catch (e) {
        logError(`AlienVault OTX lookup failed for ${q}:`, e);
      }
      return [];
    })()
  ]);

  // Merge all results
  for (const result of sources) {
    if (result.status === 'fulfilled' && Array.isArray(result.value)) {
      result.value.forEach(sub => set.add(sub));
    }
  }

  log(`Total ${set.size} unique subdomains found for ${q} (parallel fetch)`);
  const list = [...set].slice(0, CONFIG.LIMITS.MAX_SUBDOMAINS);
  setBoundedCache(subdomainCache, q, { ts: Date.now(), data: list });
  return list;
}

async function subdomainsLive(domain){
  const passive=await subdomainsPassive(domain); const out=[]; const queue=passive.slice(0,CONFIG.LIMITS.MAX_SUBDOMAINS_QUEUE); const limit=CONFIG.LIMITS.MAX_PARALLEL_WORKERS;
  async function worker(){ while(queue.length){ const s=queue.shift(); try{ const a4=(await dohResolve(s,"A")).filter(x=>x.type===1).map(x=>x.data); const a6=(await dohResolve(s,"AAAA")).filter(x=>x.type===28).map(x=>x.data); const cnames=(await dohResolve(s,"A")).filter(x=>x.type===5).map(x=>x.data?.replace(/\.$/,"")); if(a4.length||a6.length) out.push({subdomain:s,a:a4,aaaa:a6,cnames}); }catch(e){ log(`DNS resolve failed for ${s}:`, e.message); } } }
  await Promise.all(Array.from({length:limit},worker)); return out.slice(0,CONFIG.LIMITS.MAX_SUBDOMAINS_LIVE);
}

// Favicon hash - Computes MurmurHash3 (32-bit) of favicon for fingerprinting
// Used by Shodan and other tools to identify web technologies by favicon signature
function mmh3_32_from_b64(b64){
  function rotl32(x,r){ return (x<<r)|(x>>> (32-r)); }
  const bin=atob(b64); const arr=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  let h1=0x811c9dc5; const c1=0xcc9e2d51, c2=0x1b873593; const view=new DataView(arr.buffer,arr.byteOffset,arr.byteLength);
  const nblocks=Math.floor(arr.byteLength/4);
  // Process 4-byte blocks
  for(let i=0;i<nblocks;i++){ let k1=view.getUint32(i*4,true); k1=Math.imul(k1,c1); k1=rotl32(k1,15); k1=Math.imul(k1,c2); h1^=k1; h1=rotl32(h1,13); h1=(Math.imul(h1,5)+0xe6546b64)|0; }
  // Process remaining bytes
  let k1=0; const tail=arr.byteLength & 3; const p=nblocks*4;
  if(tail===3) k1^=arr[p+2]<<16; if(tail>=2) k1^=arr[p+1]<<8; if(tail>=1){ k1^=arr[p]; k1=Math.imul(k1,c1); k1=rotl32(k1,15); k1=Math.imul(k1,c2); h1^=k1; }
  // Finalization
  h1^=arr.byteLength; h1^=h1>>>16; h1=Math.imul(h1,0x85ebca6b); h1^=h1>>>13; h1=Math.imul(h1,0xc2b2ae35); h1^=h1>>>16; return (h1|0);
}
// Fetches favicon and computes its mmh3 hash for fingerprinting
async function faviconHash(url){ try{ const r=await fetchWithTimeout(url,{},CONFIG.TIMEOUTS.FETCH_FAVICON); if(!r.ok) return null; const buf=await r.arrayBuffer(); const b64=btoa(String.fromCharCode(...new Uint8Array(buf))); return mmh3_32_from_b64(b64);}catch{ return null; }}

// Shared crt.sh data cache to avoid duplicate API calls
const crtshCache = new Map();

async function fetchCrtshData(hostname) {
  const q = hostname.replace(/^\*\./, "");
  if (crtshCache.has(q)) return crtshCache.get(q);

  try {
    log(`Fetching crt.sh data for ${q}...`);
    const r = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
    if (!r.ok) { crtshCache.set(q, []); return []; }

    const t = await r.text();
    let arr = [];
    try {
      arr = JSON.parse(t);
    } catch {
      arr = t.trim().split("\n").map(x => {
        try { return JSON.parse(x); } catch { return null; }
      }).filter(Boolean);
    }
    crtshCache.set(q, arr);
    return arr;
  } catch (e) {
    logError(`crt.sh fetch failed for ${q}:`, e);
    crtshCache.set(q, []);
    return [];
  }
}

// TLS/SSL Certificate Analysis - Extract certificate details from shared crt.sh data
async function getTLSInfo(hostname) {
  try {
    log(`Extracting TLS certificate info for ${hostname}...`);
    const certs = await fetchCrtshData(hostname);
    if (!Array.isArray(certs) || certs.length === 0) return null;

    // Get the most recent cert for the exact hostname (not wildcard subdomains)
    const relevant = certs.filter(c => {
      const names = String(c.name_value || "").split(/\n+/);
      return names.some(n => n.trim() === hostname || n.trim() === `*.${hostname}`);
    });
    const pool = relevant.length ? relevant : certs;
    const latest = pool.sort((a, b) => new Date(b.entry_timestamp) - new Date(a.entry_timestamp))[0];

    // Parse SANs (Subject Alternative Names) for subdomain intel
    const sans = new Set();
    if (latest.name_value) {
      latest.name_value.split('\n').forEach(n => {
        const clean = n.trim().replace(/^\*\./, '');
        if (clean && clean.includes('.')) sans.add(clean);
      });
    }

    return {
      issuer: latest.issuer_name || 'Unknown',
      notBefore: latest.not_before,
      notAfter: latest.not_after,
      serialNumber: latest.serial_number,
      sans: Array.from(sans).slice(0, 100),
      commonName: latest.common_name
    };
  } catch (e) {
    logError(`TLS info extraction failed for ${hostname}:`, e);
    return null;
  }
}

// Wayback Machine URL Discovery - Finds historical URLs for the target domain
// Reveals old endpoints, forgotten admin panels, API routes, and URL parameters
async function waybackUrls(domain) {
  try {
    log(`Fetching Wayback Machine URLs for ${domain}...`);
    const r = await fetchWithTimeout(
      `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=200`,
      {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE
    );
    if (!r.ok) return [];
    const rows = await r.json();
    // First row is header ["original"], skip it
    const urls = new Set();
    for (let i = 1; i < rows.length; i++) {
      const u = rows[i]?.[0];
      if (u && typeof u === "string") urls.add(u);
    }
    // Deduplicate by path (strip query string for grouping, but keep full URL)
    const unique = [...urls].slice(0, 150);
    log(`Wayback Machine found ${unique.length} unique URLs for ${domain}`);
    // Extract interesting patterns: admin, api, config, backup, login, upload
    const interesting = unique.filter(u =>
      /\b(admin|api|login|upload|config|backup|dashboard|debug|internal|console|panel|phpinfo|wp-admin|.env|graphql|swagger)\b/i.test(u)
    );
    return { all: unique, interesting: interesting.slice(0, 50) };
  } catch (e) {
    logError(`Wayback Machine lookup failed for ${domain}:`, e);
    return { all: [], interesting: [] };
  }
}

// CORS Misconfiguration Detection - Test for overly permissive CORS policies
async function checkCORS(url) {
  try {
    log(`Checking CORS policy for ${url}...`);
    const testOrigins = [
      'https://evil.com',
      'null',
      url.replace(/^https?:\/\//, 'https://attacker.')
    ];

    const findings = [];
    for (const origin of testOrigins) {
      try {
        const r = await fetchWithTimeout(url, {
          method: 'GET',
          headers: { 'Origin': origin }
        }, 3000);

        const acao = r.headers.get('access-control-allow-origin');
        const acac = r.headers.get('access-control-allow-credentials');

        if (acao === '*') {
          findings.push({ type: 'wildcard', detail: 'ACAO: * (allows any origin)' });
        } else if (acao === origin) {
          findings.push({ type: 'reflected', detail: `ACAO reflects: ${origin}`, credentials: acac === 'true' });
        } else if (acao === 'null') {
          findings.push({ type: 'null_origin', detail: 'ACAO: null (sandbox bypass risk)' });
        }
      } catch (e) { log(`CORS probe failed for origin ${origin}:`, e.message); }
    }

    return findings.length > 0 ? findings : null;
  } catch (e) {
    logError(`CORS check failed for ${url}:`, e);
    return null;
  }
}

// HTTP Methods Enumeration - Discover allowed HTTP methods
async function probeHTTPMethods(url) {
  try {
    log(`Probing HTTP methods for ${url}...`);
    const r = await fetchWithTimeout(url, { method: 'OPTIONS' }, 3000);

    const allow = r.headers.get('allow');
    const acao = r.headers.get('access-control-allow-methods');

    const methods = new Set();
    if (allow) allow.split(',').forEach(m => methods.add(m.trim().toUpperCase()));
    if (acao) acao.split(',').forEach(m => methods.add(m.trim().toUpperCase()));

    const dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'].filter(m => methods.has(m));

    return {
      all: Array.from(methods),
      dangerous: dangerous,
      risky: dangerous.length > 0
    };
  } catch (e) {
    logError(`HTTP methods probe failed for ${url}:`, e);
    return null;
  }
}

// Sensitive File/Directory Probing - Check for exposed sensitive files
// Uses content-type validation and soft-404 detection to reduce false positives
async function probeSensitiveFiles(origin) {
  const sensitiveFiles = [
    { path: '/.git/config', expectedType: /text|octet-stream/, marker: '[core]' },
    { path: '/.git/HEAD', expectedType: /text|octet-stream/, marker: 'ref:' },
    { path: '/.env', expectedType: /text|octet-stream/, marker: '=' },
    { path: '/.env.local', expectedType: /text|octet-stream/, marker: '=' },
    { path: '/.env.production', expectedType: /text|octet-stream/, marker: '=' },
    { path: '/package.json', expectedType: /json/, marker: '"name"' },
    { path: '/composer.json', expectedType: /json/, marker: '"require"' },
    { path: '/web.config', expectedType: /xml|text/, marker: '<configuration' },
    { path: '/.htaccess', expectedType: /text|octet-stream/, marker: null },
    { path: '/phpinfo.php', expectedType: /html/, marker: 'phpinfo' },
    { path: '/server-status', expectedType: /html|text/, marker: 'Apache' },
    { path: '/backup.zip', expectedType: /zip|octet-stream/, marker: null },
    { path: '/database.sql', expectedType: /sql|text|octet-stream/, marker: null },
    { path: '/.DS_Store', expectedType: /octet-stream/, marker: null },
    { path: '/Dockerfile', expectedType: /text|octet-stream/, marker: 'FROM' },
    { path: '/docker-compose.yml', expectedType: /yaml|text|octet-stream/, marker: 'services' },
    { path: '/swagger.json', expectedType: /json/, marker: '"swagger"' },
    { path: '/graphql', expectedType: /json|html/, marker: null },
    { path: '/.svn/entries', expectedType: /text|xml|octet-stream/, marker: null }
  ];

  const found = [];
  // Rate-limited: batch in groups of 5 with small delay to avoid WAF triggers
  for (let i = 0; i < sensitiveFiles.length; i += 5) {
    const batch = sensitiveFiles.slice(i, i + 5);
    const checks = batch.map(async ({ path, expectedType, marker }) => {
      try {
        const url = new URL(path, origin).href;
        // Use GET with small range to validate content, not just HEAD (which can lie)
        const r = await fetchWithTimeout(url, { method: 'GET' }, 2500);

        if (!r.ok) return;

        const ct = r.headers.get('content-type') || '';
        const size = r.headers.get('content-length');

        // Skip if content-type is HTML for non-HTML expected files (likely a custom 404 page)
        if (expectedType && !expectedType.test(ct) && /text\/html/i.test(ct)) return;

        // Read a small sample for marker validation
        const body = await r.text();
        const sample = body.slice(0, 2000);

        // Soft-404 detection: skip if response looks like a generic error page
        if (/text\/html/i.test(ct) && /(?:404|not found|page not found|error|does not exist)/i.test(sample) && !marker) return;

        // If a marker is specified, verify it exists in the response
        if (marker && !sample.includes(marker)) return;

        found.push({
          path: path,
          status: r.status,
          size: size ? parseInt(size) : body.length,
          contentType: ct
        });
        log(`Confirmed exposed file: ${path} (${r.status}, ct: ${ct})`);
      } catch (e) { log(`Probe ${path} failed:`, e.message); }
    });
    await Promise.all(checks);
    // Small delay between batches to avoid aggressive scanning detection
    if (i + 5 < sensitiveFiles.length) await new Promise(r => setTimeout(r, 200));
  }
  return found.length > 0 ? found : null;
}

// Extract emails, phone numbers, and other intel from page content
function extractIntelFromText(html) {
  const intel = {
    emails: new Set(),
    phones: new Set(),
    socialLinks: new Set(),
    comments: []
  };

  // Email extraction
  const emailRx = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emails = html.match(emailRx);
  if (emails) emails.forEach(e => intel.emails.add(e.toLowerCase()));

  // Phone number extraction (international formats: US, UK, EU, intl prefix)
  const phoneRx = /(?:\+\d{1,3}[-.\s]?)?\(?([0-9]{2,4})\)?[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})/g;
  const phones = html.match(phoneRx);
  if (phones) phones.filter(p => p.replace(/\D/g, '').length >= 7).forEach(p => intel.phones.add(p));

  // Social media links (updated: includes x.com, tiktok, mastodon, threads)
  const socialRx = /https?:\/\/(?:www\.)?(?:twitter\.com|x\.com|linkedin\.com|facebook\.com|github\.com|instagram\.com|youtube\.com|tiktok\.com|mastodon\.social|threads\.net)\/[@A-Za-z0-9_\-\.\/]+/gi;
  const social = html.match(socialRx);
  if (social) social.forEach(s => intel.socialLinks.add(s));

  // HTML comments (often contain sensitive info)
  const commentRx = /<!--([\s\S]*?)-->/g;
  let match;
  while ((match = commentRx.exec(html)) !== null) {
    const comment = match[1].trim();
    if (comment.length > 5 && comment.length < 500) {
      intel.comments.push(comment);
    }
  }

  return {
    emails: Array.from(intel.emails).slice(0, 50),
    phones: Array.from(intel.phones).slice(0, 20),
    socialLinks: Array.from(intel.socialLinks).slice(0, 30),
    comments: intel.comments.slice(0, 20)
  };
}

// Subdomain Takeover Detection - Check if subdomains point to unclaimed services
async function checkSubdomainTakeover(subdomain, cnames) {
  const vulnerableServices = [
    { pattern: /\.herokuapp\.com$/i, service: 'Heroku', message: 'No such app' },
    { pattern: /\.github\.io$/i, service: 'GitHub Pages', message: "There isn't a GitHub Pages site here" },
    { pattern: /\.azurewebsites\.net$/i, service: 'Azure', message: 'Error 404' },
    { pattern: /\.s3\.amazonaws\.com$/i, service: 'AWS S3', message: 'NoSuchBucket' },
    { pattern: /\.cloudfront\.net$/i, service: 'AWS CloudFront', message: 'The request could not be satisfied' },
    { pattern: /\.wordpress\.com$/i, service: 'WordPress.com', message: "Do you want to register" },
    { pattern: /\.pantheonsite\.io$/i, service: 'Pantheon', message: '404 error unknown site' },
    { pattern: /\.zendesk\.com$/i, service: 'Zendesk', message: 'Help Center Closed' },
    { pattern: /\.fastly\.net$/i, service: 'Fastly', message: 'Fastly error: unknown domain' },
    { pattern: /\.ghost\.io$/i, service: 'Ghost', message: 'The thing you were looking for is no longer here' }
  ];

  if (!Array.isArray(cnames) || cnames.length === 0) return null;

  for (const cname of cnames) {
    for (const vuln of vulnerableServices) {
      if (vuln.pattern.test(cname)) {
        // Found potential takeover - try to verify
        try {
          const r = await fetchWithTimeout(`https://${subdomain}`, {}, 3000);
          const text = await r.text();

          if (text.includes(vuln.message) || r.status === 404) {
            return {
              subdomain: subdomain,
              cname: cname,
              service: vuln.service,
              vulnerable: true,
              confidence: 'high'
            };
          }
        } catch {}
      }
    }
  }

  return null;
}

// ============ LEAD GENERATION ENGINE ============
// Extracts actionable intelligence that tells pentesters WHERE to look

// Extract API endpoints, routes, and interesting URLs from JavaScript source
function extractJSEndpoints(jsText) {
  const endpoints = new Set();
  const apiPatterns = [
    // Fetch/XHR calls: fetch("/api/users"), axios.get("/v1/data")
    /(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax|\.open)\s*\(\s*["'`](\/[^"'`\s]{3,})/gi,
    // Route definitions: router.get("/users/:id"), app.post("/api")
    /(?:router|app|server)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*["'`](\/[^"'`\s]{3,})/gi,
    // String assignments that look like API paths
    /(?:url|endpoint|path|route|api|href|action|src)\s*[:=]\s*["'`](\/(?:api|v\d|graphql|auth|admin|user|account|dashboard|internal|ws|socket)[^"'`\s]*)/gi,
    // Full URL patterns pointing to APIs
    /["'`](https?:\/\/[^"'`\s]*\/(?:api|v\d|graphql|auth|admin|internal|ws)[^"'`\s]*)/gi,
    // GraphQL operations
    /(?:query|mutation|subscription)\s+(\w+)\s*[\({]/g,
    // Webpack/build config API base URLs
    /(?:BASE_URL|API_URL|BACKEND|SERVER_URL|API_HOST|API_BASE)\s*[:=]\s*["'`]([^"'`\s]+)/gi,
  ];
  for (const rx of apiPatterns) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(jsText)) !== null) {
      const ep = m[1];
      if (ep && ep.length > 2 && ep.length < 200) endpoints.add(ep);
    }
  }
  return [...endpoints];
}

// Extract URL parameters for injection testing
function extractParameters(urls) {
  const params = new Map(); // param name → Set of example values
  for (const url of urls) {
    try {
      const u = new URL(url, "https://placeholder.test");
      for (const [k, v] of u.searchParams) {
        if (!params.has(k)) params.set(k, new Set());
        if (v && v.length < 100) params.get(k).add(v);
      }
    } catch {}
  }
  // Convert to array sorted by frequency (most-seen params first)
  return [...params.entries()]
    .map(([name, values]) => ({ name, examples: [...values].slice(0, 3), count: values.size }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 40);
}

// Detect login/auth surfaces from forms, URLs, and page content
function detectAuthSurfaces(forms, urls, html) {
  const surfaces = [];

  // Check forms for auth patterns
  if (forms) {
    for (const form of forms) {
      if (form.hasPassword) {
        surfaces.push({
          type: "login_form",
          detail: `${form.method} ${form.action || "(self)"}`,
          risk: "high",
          why: "Password field found - test default creds, brute force, SQLi in login"
        });
      }
    }
  }

  // Check URLs for auth-related paths
  const authPaths = /\b(login|signin|sign-in|auth|oauth|sso|saml|jwt|register|signup|sign-up|forgot|reset-password|2fa|mfa|token|session|api[-_]?key)\b/i;
  const seen = new Set();
  for (const url of (urls || [])) {
    if (authPaths.test(url)) {
      const path = url.replace(/https?:\/\/[^\/]+/, "").split("?")[0];
      if (!seen.has(path)) {
        seen.add(path);
        surfaces.push({
          type: "auth_endpoint",
          detail: url.length > 120 ? url.slice(0, 120) + "…" : url,
          risk: "medium",
          why: "Auth-related endpoint - test for bypasses, token leaks, rate limits"
        });
      }
    }
  }

  // Check HTML for OAuth/SSO integrations
  if (html) {
    if (/accounts\.google\.com|googleapis\.com\/auth/i.test(html)) surfaces.push({ type: "oauth", detail: "Google OAuth", risk: "medium", why: "Test OAuth misconfiguration, redirect_uri manipulation" });
    if (/graph\.facebook\.com|facebook\.com\/v\d+/i.test(html)) surfaces.push({ type: "oauth", detail: "Facebook Login", risk: "medium", why: "Test OAuth state parameter, CSRF in OAuth flow" });
    if (/github\.com\/login\/oauth/i.test(html)) surfaces.push({ type: "oauth", detail: "GitHub OAuth", risk: "medium", why: "Test scope escalation, token leakage" });
    if (/cognito|auth0|okta|keycloak/i.test(html)) surfaces.push({ type: "sso", detail: html.match(/cognito|auth0|okta|keycloak/i)[0], risk: "medium", why: "Centralised auth provider - check for misconfig, token reuse" });
  }

  return surfaces.slice(0, 15);
}

// Extract hardcoded configs, debug flags, and interesting JS globals
function extractJSConfigs(jsText) {
  const configs = [];
  const patterns = [
    { rx: /(?:debug|DEBUG|verbose|VERBOSE)\s*[:=]\s*(true|1|"true")/g, type: "debug_flag", why: "Debug mode enabled - may expose stack traces, verbose errors" },
    { rx: /(?:NODE_ENV|ENVIRONMENT|ENV)\s*[:=]\s*["'`](development|staging|test|dev)["'`]/gi, type: "non_prod_env", why: "Non-production environment flag - likely less hardened" },
    { rx: /(?:admin|ADMIN)[-_]?(?:URL|PATH|ROUTE|PANEL)\s*[:=]\s*["'`]([^"'`]+)/gi, type: "admin_path", why: "Admin panel path discovered" },
    { rx: /(?:firebase|supabase|amplify)Config\s*[:=]\s*\{/gi, type: "backend_config", why: "Backend-as-a-Service config exposed - check for public write access" },
    { rx: /(?:STRIPE|PAYPAL|SQUARE)[-_]?(?:KEY|TOKEN|SECRET)\s*[:=]\s*["'`]([^"'`]+)/gi, type: "payment_config", why: "Payment processor config - check for live vs test keys" },
    { rx: /(?:ws|wss):\/\/[^"'`\s]+/g, type: "websocket", why: "WebSocket endpoint - test for auth bypass, injection" },
    { rx: /(?:bucket|BUCKET)[-_]?(?:NAME|URL|PATH)\s*[:=]\s*["'`]([^"'`]+)/gi, type: "storage_bucket", why: "Cloud storage bucket reference - check for public access" },
    { rx: /(?:SENTRY|DATADOG|NEWRELIC)[-_]?(?:DSN|KEY|TOKEN)\s*[:=]\s*["'`]([^"'`]+)/gi, type: "monitoring", why: "Monitoring service config - may leak internal infra details" },
  ];
  for (const { rx, type, why } of patterns) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(jsText)) !== null) {
      configs.push({ type, match: m[0].slice(0, 150), why });
      if (configs.length >= 20) return configs;
    }
  }
  return configs;
}

// MASTER LEAD GENERATOR - Correlates all findings into prioritised attack leads
function generateLeads(state) {
  const leads = [];

  // Lead 1: Exposed sensitive files → direct exploitation
  if (state.sensitiveFiles?.length) {
    for (const f of state.sensitiveFiles) {
      if (f.path.includes('.git')) {
        leads.push({ priority: 1, category: "Source Code Leak", title: "Git repository exposed", detail: `${f.path} is accessible. Use git-dumper to extract full source code, then search for secrets, hardcoded creds, and business logic flaws.`, action: `git-dumper ${state.url}/.git/ ./dumped-repo` });
      } else if (f.path.includes('.env')) {
        leads.push({ priority: 1, category: "Credential Leak", title: "Environment file exposed", detail: `${f.path} accessible. Likely contains DB creds, API keys, and secrets. Fetch and extract immediately.`, action: `curl -s ${new URL(f.path, state.url).href}` });
      } else if (f.path.includes('swagger') || f.path.includes('graphql')) {
        leads.push({ priority: 2, category: "API Documentation", title: `API docs at ${f.path}`, detail: "API documentation is publicly accessible. Map all endpoints, test auth requirements, look for IDOR and mass assignment.", action: `Browse: ${new URL(f.path, state.url).href}` });
      }
    }
  }

  // Lead 2: CORS + credentials = account takeover
  if (state.corsFindings?.length) {
    const credsCors = state.corsFindings.find(f => f.credentials);
    if (credsCors) {
      leads.push({ priority: 1, category: "Account Takeover", title: "CORS allows credentials with reflected origin", detail: "Any origin can make credentialed requests. Build a PoC page that steals user data via cross-origin fetch with credentials:include.", action: "Create attacker page with: fetch(target, {credentials:'include'}).then(r=>r.json()).then(exfil)" });
    }
  }

  // Lead 3: Subdomain takeovers = immediate win
  if (state.subdomainTakeovers?.length) {
    for (const t of state.subdomainTakeovers) {
      leads.push({ priority: 1, category: "Subdomain Takeover", title: `Claim ${t.subdomain} on ${t.service}`, detail: `CNAME points to ${t.cname} but service is unclaimed. Register on ${t.service} to take control. Can be used for phishing, cookie theft, or CSP bypass.`, action: `Register ${t.cname} on ${t.service}` });
    }
  }

  // Lead 4: Auth surfaces found
  if (state.authSurfaces?.length) {
    for (const auth of state.authSurfaces.slice(0, 3)) {
      leads.push({ priority: auth.risk === "high" ? 2 : 3, category: "Auth Testing", title: auth.type.replace(/_/g, " "), detail: `${auth.detail} — ${auth.why}`, action: auth.detail });
    }
  }

  // Lead 5: JS endpoints = hidden attack surface
  if (state.jsEndpoints?.length) {
    const adminEps = state.jsEndpoints.filter(e => /admin|internal|debug|config/i.test(e));
    const apiEps = state.jsEndpoints.filter(e => /api|v\d|graphql/i.test(e));
    if (adminEps.length) {
      leads.push({ priority: 2, category: "Hidden Endpoints", title: `${adminEps.length} admin/internal endpoints in JS`, detail: `Found: ${adminEps.slice(0, 5).join(", ")}${adminEps.length > 5 ? "…" : ""}. Test for auth bypass, IDOR, privilege escalation.`, action: adminEps.slice(0, 3).join("\n") });
    }
    if (apiEps.length) {
      leads.push({ priority: 3, category: "API Surface", title: `${apiEps.length} API endpoints discovered in JS`, detail: `Found: ${apiEps.slice(0, 5).join(", ")}${apiEps.length > 5 ? "…" : ""}. Fuzz parameters, test auth, check for IDOR.`, action: apiEps.slice(0, 5).join("\n") });
    }
  }

  // Lead 6: Parameters for injection
  if (state.discoveredParams?.length) {
    const injectable = state.discoveredParams.filter(p =>
      /id|user|name|query|search|q|url|redirect|file|path|page|callback|token|ref|sort|order|filter|lang|type/i.test(p.name)
    );
    if (injectable.length) {
      leads.push({ priority: 2, category: "Injection Points", title: `${injectable.length} potentially injectable parameters`, detail: `High-interest params: ${injectable.slice(0, 8).map(p => p.name).join(", ")}. Test for SQLi, XSS, SSRF, path traversal, and IDOR.`, action: injectable.slice(0, 5).map(p => `${p.name}=${p.examples[0] || "FUZZ"}`).join("&") });
    }
  }

  // Lead 7: JS configs (debug, non-prod, admin paths)
  if (state.jsConfigs?.length) {
    for (const cfg of state.jsConfigs.slice(0, 3)) {
      leads.push({ priority: cfg.type === "debug_flag" || cfg.type === "non_prod_env" ? 2 : 3, category: "JS Config Leak", title: cfg.type.replace(/_/g, " "), detail: `${cfg.match} — ${cfg.why}`, action: cfg.match });
    }
  }

  // Lead 8: High-severity CVEs with known exploits
  const allCves = [];
  for (const [ip, data] of Object.entries(state.perIp || {})) {
    for (const cve of (data.cve_enrich || [])) {
      if (Number(cve.score) >= 8) allCves.push({ ...cve, ip });
    }
  }
  if (allCves.length) {
    leads.push({ priority: 2, category: "Known Vulnerabilities", title: `${allCves.length} high-severity CVEs (CVSS ≥ 8)`, detail: allCves.slice(0, 5).map(c => `${c.id} (${c.score}) on ${c.ip}`).join(", "), action: `searchsploit ${allCves[0].id}` });
  }

  // Lead 9: Dangerous HTTP methods
  if (state.httpMethods?.risky) {
    leads.push({ priority: 3, category: "HTTP Methods", title: `Dangerous methods: ${state.httpMethods.dangerous.join(", ")}`, detail: "PUT/DELETE may allow file upload or resource modification. Test with curl.", action: `curl -X PUT ${state.url}/test.txt -d "pwned"` });
  }

  // Lead 10: Missing security headers → XSS potential
  const headers = state.headers || {};
  if (!headers["content-security-policy"] && !headers["x-frame-options"]) {
    leads.push({ priority: 3, category: "XSS/Clickjacking", title: "No CSP or X-Frame-Options", detail: "Page can be framed and has no CSP. Test for reflected/stored XSS and clickjacking.", action: `<iframe src="${state.url}"></iframe>` });
  }

  // Lead 11: Insecure cookies
  if (state.cookieSecurity?.some(c => c.issues.length > 0 && !c.httpOnly)) {
    const vulnCookies = state.cookieSecurity.filter(c => !c.httpOnly);
    if (vulnCookies.length) {
      leads.push({ priority: 3, category: "Session Hijacking", title: `${vulnCookies.length} cookies accessible via JavaScript`, detail: `Cookies without HttpOnly: ${vulnCookies.map(c => c.name).join(", ")}. If XSS exists, these can be stolen.`, action: "document.cookie" });
    }
  }

  // Sort by priority (1=critical, 2=high, 3=medium)
  leads.sort((a, b) => a.priority - b.priority);
  return leads.slice(0, 15);
}

// Form Analysis - Identify input fields and sensitive forms
function analyzeForms(html) {
  const forms = [];
  const formRx = /<form[\s\S]*?<\/form>/gi;
  const inputRx = /<input[^>]*>/gi;

  let formMatch;
  while ((formMatch = formRx.exec(html)) !== null) {
    const formHTML = formMatch[0];
    const action = (formHTML.match(/action=["']([^"']+)["']/i) || [])[1];
    const method = (formHTML.match(/method=["']([^"']+)["']/i) || [])[1] || 'GET';

    const inputs = [];
    let inputMatch;
    while ((inputMatch = inputRx.exec(formHTML)) !== null) {
      const inputHTML = inputMatch[0];
      const type = (inputHTML.match(/type=["']([^"']+)["']/i) || [])[1] || 'text';
      const name = (inputHTML.match(/name=["']([^"']+)["']/i) || [])[1];

      inputs.push({ type, name });
    }

    const hasPassword = inputs.some(i => i.type === 'password');
    const hasHidden = inputs.some(i => i.type === 'hidden');

    forms.push({
      action,
      method: method.toUpperCase(),
      inputs: inputs.length,
      hasPassword,
      hasHidden,
      sensitive: hasPassword || (method.toUpperCase() === 'GET' && hasHidden)
    });
  }

  return forms.length > 0 ? forms.slice(0, 20) : null;
}

// Enhanced WAF Detection - More comprehensive fingerprinting
function detectWAF(headers, html) {
  const wafSignatures = [
    { name: 'Cloudflare', headers: ['cf-ray', 'cf-cache-status'], html: /cdn-cgi\//, cookie: '__cfduid' },
    { name: 'AWS WAF', headers: ['x-amzn-requestid', 'x-amz-cf-id'] },
    { name: 'Akamai', headers: ['x-akamai-transformed'], html: /akamai/i },
    { name: 'Imperva/Incapsula', headers: ['x-iinfo'], cookie: 'incap_ses|visid_incap' },
    { name: 'Sucuri', headers: ['x-sucuri-id', 'x-sucuri-cache'] },
    { name: 'ModSecurity', html: /mod_security|NOYB/i },
    { name: 'Wordfence', html: /wordfence/i },
    { name: 'StackPath', headers: ['x-stackpath-shield'] },
    { name: 'Barracuda', html: /barra_counter_session|BNI__BARRACUDA_LB_COOKIE/i },
    { name: 'F5 BIG-IP', headers: ['x-wa-info'], cookie: 'TS[a-z0-9]{6}' },
    { name: 'Fortinet FortiWeb', cookie: 'FORTIWAFSID' },
    { name: 'Citrix NetScaler', cookie: 'ns_af|citrix_ns_id|NSC_' }
  ];

  const detected = [];
  const headerStr = JSON.stringify(headers).toLowerCase();
  const htmlStr = (html || '').toLowerCase();

  for (const waf of wafSignatures) {
    let match = false;

    if (waf.headers) {
      match = waf.headers.some(h => headerStr.includes(h.toLowerCase()));
    }

    if (!match && waf.html && html) {
      match = waf.html.test(htmlStr);
    }

    if (!match && waf.cookie) {
      const cookieHeader = headers['set-cookie'] || headers['cookie'] || '';
      match = new RegExp(waf.cookie, 'i').test(cookieHeader);
    }

    if (match) {
      detected.push(waf.name);
    }
  }

  return detected.length > 0 ? detected : null;
}

// Cookie Security Analysis - Check HttpOnly, Secure, SameSite flags
function analyzeCookies(headers) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return null;

  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const analysis = [];

  for (const cookie of cookies) {
    const name = (cookie.split('=')[0] || '').trim();
    const hasHttpOnly = /httponly/i.test(cookie);
    const hasSecure = /secure/i.test(cookie);
    const sameSite = (cookie.match(/samesite=([^;]+)/i) || [])[1];

    const issues = [];
    if (!hasHttpOnly) issues.push('Missing HttpOnly');
    if (!hasSecure) issues.push('Missing Secure');
    if (!sameSite) issues.push('Missing SameSite');

    analysis.push({
      name,
      httpOnly: hasHttpOnly,
      secure: hasSecure,
      sameSite: sameSite || null,
      issues
    });
  }

  return analysis;
}

// JavaScript Library Detection - scans script URLs and HTML for library references
// Note: `scripts` is an array of script URLs (not content), so patterns match URL paths
function detectJSLibraries(html, scriptUrls) {
  const libraries = [];
  const seen = new Set();
  // Combine script URLs and HTML meta/link references for matching
  const urlsStr = (scriptUrls || []).join(' ');

  // Patterns tuned for URL path matching (e.g., "/jquery-3.6.0.min.js")
  const libPatterns = [
    { name: 'jQuery', urlRx: /jquery[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: /jquery[\/\-\.](?:v?(\d+\.\d+\.\d+))/i },
    { name: 'Angular', urlRx: /angular(?:js)?[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: /ng-app|ng-controller/i },
    { name: 'React', urlRx: /react(?:-dom)?[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: /data-reactroot|data-reactid|__NEXT_DATA__/i },
    { name: 'Vue', urlRx: /vue[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: /data-v-[a-f0-9]|__vue__/i },
    { name: 'Bootstrap', urlRx: /bootstrap[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null },
    { name: 'Lodash', urlRx: /lodash[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null },
    { name: 'Moment.js', urlRx: /moment[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null },
    { name: 'D3', urlRx: /d3[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null },
    { name: 'Axios', urlRx: /axios[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null },
    { name: 'Three.js', urlRx: /three[\/\-\.](?:v?(\d+\.\d+\.\d+))/i, htmlRx: null }
  ];

  for (const lib of libPatterns) {
    if (seen.has(lib.name)) continue;
    // Check URLs first (more reliable for version extraction)
    const urlMatch = urlsStr.match(lib.urlRx);
    if (urlMatch) {
      seen.add(lib.name);
      libraries.push({ name: lib.name, version: urlMatch[1] || 'detected' });
      continue;
    }
    // Fallback: check HTML for DOM markers (no version available)
    if (lib.htmlRx) {
      const htmlMatch = html.match(lib.htmlRx);
      if (htmlMatch) {
        seen.add(lib.name);
        libraries.push({ name: lib.name, version: 'detected' });
      }
    }
  }

  return libraries.length > 0 ? libraries : null;
}

// Secrets scanner - Comprehensive patterns for exposed credentials, API keys, and sensitive data
// Over 40 patterns covering major cloud providers, SaaS platforms, and crypto
const SECRET_PATTERNS=[
  // AWS
  {id:"aws_access_key", rx:/AKIA[0-9A-Z]{16}/g},
  {id:"aws_secret_key", rx:/(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\s:=]+[A-Za-z0-9\/\+=]{40}/g},
  {id:"aws_session_token", rx:/(?:aws_session_token|AWS_SESSION_TOKEN)[\s:=]+[A-Za-z0-9\/\+=]{100,}/g},
  // Google Cloud & Firebase
  {id:"google_api_key", rx:/AIza[0-9A-Za-z\-_]{35}/g},
  {id:"google_oauth", rx:/ya29\.[0-9A-Za-z\-_]+/g},
  {id:"gcp_sa", rx:/[a-z0-9\-]{6,}\@[a-z0-9\-]+\.iam\.gserviceaccount\.com/g},
  {id:"firebase_db", rx:/https:\/\/[a-z0-9\-]+\.firebaseio\.com/gi},
  // GitHub
  {id:"github_pat", rx:/(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}/g},
  {id:"github_fine_grained", rx:/github_pat_[A-Za-z0-9_]{22,}/g},
  {id:"github_oauth", rx:/gho_[0-9A-Za-z]{36}/g},
  // GitLab
  {id:"gitlab_pat", rx:/glpat-[0-9A-Za-z\-_]{20,}/g},
  // Slack
  {id:"slack_token", rx:/xox[baprs]-[A-Za-z0-9\-]{10,48}/g},
  {id:"slack_webhook", rx:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g},
  // Discord
  {id:"discord_token", rx:/[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g},
  {id:"discord_webhook", rx:/https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,19}\/[A-Za-z0-9_\-]{68}/g},
  // Telegram (require "bot" context to reduce false positives)
  {id:"telegram_bot", rx:/(?:bot|telegram|tg)[\s:=]*\d{8,10}:[A-Za-z0-9_\-]{35}/gi},
  // Payment Processors
  {id:"stripe_key", rx:/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,99}/g},
  {id:"paypal_braintree", rx:/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g},
  {id:"square_token", rx:/sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}/g},
  // Email & SMS
  {id:"sendgrid_key", rx:/SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{10,}/g},
  {id:"mailgun_key", rx:/key-[0-9a-zA-Z]{32}/g},
  {id:"twilio_sid", rx:/AC[a-f0-9]{32}/gi},
  {id:"twilio_token", rx:/SK[a-f0-9]{32}/gi},
  // Cloud Storage
  {id:"s3_url", rx:/https?:\/\/[a-z0-9\.\-]{3,}\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com\/[^\s"'<>()]+/gi},
  {id:"azure_sas", rx:/(?:sig=)[A-Za-z0-9%]{20,}&(?:se=|\bsv=)/g},
  {id:"gcs_bucket", rx:/https?:\/\/storage\.googleapis\.com\/[a-z0-9\-_.]+/gi},
  // Heroku & PaaS
  {id:"heroku_key", rx:/[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi},
  {id:"doppler_token", rx:/dp\.pt\.[a-zA-Z0-9]{43}/g},
  // Databases
  {id:"mongodb_uri", rx:/mongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi},
  {id:"postgres_uri", rx:/postgres(?:ql)?:\/\/[^\s"'<>]+/gi},
  {id:"redis_uri", rx:/redis:\/\/[^\s"'<>]+/gi},
  {id:"mysql_uri", rx:/mysql:\/\/[^\s"'<>]+/gi},
  // Auth & JWT
  {id:"jwt", rx:/eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g},
  {id:"bearer_token", rx:/[Bb]earer\s+[A-Za-z0-9\-_=]{20,}/g},
  {id:"basic_auth", rx:/[Bb]asic\s+[A-Za-z0-9+\/=]{20,}/g},
  // Private Keys
  {id:"private_key", rx:/-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) (?:PRIVATE )?KEY-----/g},
  {id:"ssh_key", rx:/ssh-rsa\s+AAAA[0-9A-Za-z+\/]+[=]{0,3}/g},
  // Crypto & Blockchain (tightened to reduce false positives)
  {id:"ethereum_private_key", rx:/(?:private[-_]?key|PRIVATE[-_]?KEY|eth[-_]?key)[\s:=]+["']?0x[a-fA-F0-9]{64}["']?/gi},
  // Network & Infrastructure (only flag internal IPs when embedded in config-like contexts)
  {id:"internal_ip", rx:/(?:["'=:]\s*)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?=["'\s;,\]}])/g},
  // API Endpoints & Routes (only match routes with sensitive path segments, NOT all URLs)
  {id:"api_route", rx:/(?:^|[^a-z])\/(?:api|v\d+|graphql|admin|internal|wp-json)\/[A-Za-z0-9_\-\/\.]+/gi},
  {id:"api_key_assign", rx:/(?:api[_-]?key|apikey|token|secret|password|passwd|bearer|auth)[\s]*[:=][\s]*["'][^"']{8,}["']/gi},
  // Additional Secrets
  {id:"npm_token", rx:/npm_[A-Za-z0-9]{36}/g},
  {id:"pypi_token", rx:/pypi-[A-Za-z0-9\-_]{32,}/g},
  {id:"docker_hub_token", rx:/dckr_pat_[A-Za-z0-9_-]{32,}/g},
  {id:"datadog_api_key", rx:/(?:DATADOG|DD)[-_]?(?:API[-_]?KEY|APP[-_]?KEY)[\s:=]+["']?[a-f0-9]{32}["']?/gi}
];
function scanText(t){ const out=[]; for(const {id,rx} of SECRET_PATTERNS){ try{ rx.lastIndex=0; const m=t.match(rx); if(m&&m.length) out.push({id, samples: Array.from(new Set(m)).slice(0,5)});}catch{}} return out; }
async function fetchText(url){ try{ const r=await fetchWithTimeout(url,{},2500); if(!r.ok) return ""; const ct=r.headers.get("content-type")||""; if(!/javascript|json|text|xml|html/.test(ct)) return ""; const t=await Promise.race([r.text(), new Promise((_,rej)=>setTimeout(()=>rej(new Error("body read timeout")),5000))]); return t.slice(0, 300*1024);}catch(e){ log(`fetchText(${url}) failed:`, e.message); return ""; } }
const scannedByTab=new Map();
async function probeSourceMaps(urls){
  const out=[];
  for(const u of urls.slice(0,6)){ try{ const m=u.endsWith(".map")?u:(u+".map"); const r=await fetchWithTimeout(m,{},2000); if(!r.ok) continue; const t=await r.text(); if(t && /"sources"|\bversion\b/i.test(t)){ const f=scanText(t.slice(0,500*1024)); if(f.length) out.push({source:m, findings:f}); } }catch{} }
  return out;
}
async function runSecretsScan(tabId, state, resources, origin){
  const scanned = scannedByTab.get(tabId) || new Set(); scannedByTab.set(tabId, scanned);
  const results = state.secrets ? [...state.secrets] : [];
  const inline = Array.isArray(resources?.inlineScripts)? resources.inlineScripts : [];
  const external = Array.isArray(resources?.externalScripts)? resources.externalScripts.slice(0,12) : [];
  // Inline scripts (fast, no I/O)
  for(const chunk of inline){ const f=scanText(chunk); if(f.length) results.push({source:"inline_script", findings:f}); if(results.length>=20) break; }
  // External scripts - fetch in parallel batches of 4 for speed
  const toFetch = external.filter(url => !scanned.has(url));
  toFetch.forEach(url => scanned.add(url));
  for (let i = 0; i < toFetch.length && results.length < 20; i += 4) {
    const batch = toFetch.slice(i, i + 4);
    const texts = await Promise.all(batch.map(url => fetchText(url)));
    for (let j = 0; j < batch.length; j++) {
      if (!texts[j]) continue;
      const f = scanText(texts[j]);
      if (f.length) results.push({ source: batch[j], findings: f });
      if (results.length >= 20) break;
    }
  }
  // HTML document scan
  if(!scanned.has("__HTML__") && origin){ scanned.add("__HTML__"); try{ const r=await fetchWithTimeout(origin,{},2500); if(r.ok){ const ct=r.headers.get("content-type")||""; if(/text\/html/i.test(ct)){ const html=(await r.text()).slice(0,200*1024); const f=scanText(html); if(f.length) results.push({source:"document_html", findings:f}); } } }catch(e){ log(`HTML secrets scan failed:`, e.message); } }
  let favHash = state.faviconHash || null; const fav = resources?.favicon || (origin? new URL("/favicon.ico",origin).href:null); if(!favHash && fav) favHash = await faviconHash(fav);
  const patch = { secrets: results, faviconHash: favHash };
  const next = merge(state, patch); await setTabData(tabId, next); return next;
}

// VT domain enrichment
async function vtDomain(domain, apiKey){
  const r = await fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": apiKey, accept:"application/json" } }, 3000);
  if(!r.ok) throw new Error(`VirusTotal HTTP ${r.status}`); const j=await r.json(); const a=j?.data?.attributes||{}; return { reputation:a.reputation??0, last_analysis_stats:a.last_analysis_stats||null, categories:a.categories||null };
}

// OpenAI API integration for intelligent host filtering and correlation
async function callOpenAI(apiKey, messages, model = "gpt-4o-mini") {
  try {
    const r = await fetchWithTimeout("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: model,
        messages: messages,
        temperature: 0.3,
        max_tokens: 2000
      })
    }, 15000);

    if (!r.ok) {
      const err = await r.text();
      throw new Error(`OpenAI API error ${r.status}: ${err}`);
    }

    const j = await r.json();
    return j.choices?.[0]?.message?.content || null;
  } catch (e) {
    logError(`OpenAI API call failed:`, e);
    return null;
  }
}

// AI-powered host filtering - uses OpenAI to identify relevant hosts
async function filterHostsWithAI(apiKey, hosts, targetDomain) {
  if (!apiKey || !hosts || hosts.length === 0) return hosts;

  try {
    log(`Using AI to filter ${hosts.length} hosts for ${targetDomain}...`);

    const prompt = `You are a cybersecurity reconnaissance expert. Given the target domain "${targetDomain}", analyze this list of subdomains and identify which ones are RELEVANT for security reconnaissance.

Subdomains found (${hosts.length} total):
${hosts.slice(0, 200).join('\n')}

Filter OUT:
- CDN/caching subdomains (cdn, cache, static, assets)
- Wildcard/test subdomains (test, dev, staging - UNLESS they look production-exposed)
- Third-party/unrelated services
- Obvious spam/parked domains

Keep RELEVANT subdomains for:
- Production services (api, admin, portal, app, www)
- Authentication/IAM (auth, login, sso, oauth)
- Internal/staging if production-exposed (vpn, internal, intranet)
- Interesting infrastructure (mail, mx, smtp, git, jenkins, grafana)
- Database/backend services (db, sql, mongo, redis)

Respond with ONLY a JSON array of relevant hostnames, no explanation:
["host1.example.com", "host2.example.com"]

If all should be kept, return all. If none are relevant, return [].`;

    const response = await callOpenAI(apiKey, [
      { role: "system", content: "You are a cybersecurity expert assistant specializing in reconnaissance and infrastructure analysis. Respond only with valid JSON." },
      { role: "user", content: prompt }
    ]);

    if (!response) {
      log(`AI filtering failed, returning all hosts`);
      return hosts;
    }

    // Parse AI response safely
    let filtered;
    try {
      filtered = JSON.parse(response.trim());
    } catch (parseErr) {
      logError(`AI response was not valid JSON, returning all hosts:`, parseErr.message);
      return hosts;
    }
    if (Array.isArray(filtered)) {
      log(`AI filtered ${hosts.length} hosts down to ${filtered.length} relevant ones`);
      return filtered;
    } else {
      logError(`AI response was not an array, returning all hosts`);
      return hosts;
    }
  } catch (e) {
    logError(`AI host filtering failed:`, e);
    return hosts; // Fallback to all hosts
  }
}

// AI-powered correlation - finds connections between different data sources
async function correlateFindings(apiKey, state) {
  if (!apiKey || !state) return null;

  try {
    log(`Using AI to correlate findings for ${state.domain}...`);

    const summary = {
      domain: state.domain,
      ips: state.ips || [],
      subdomains: (state.quickSubs || []).map(s => s.subdomain).slice(0, 50),
      technologies: (state.tech?.tags || []),
      secretsCount: (state.secrets || []).length,
      cveCount: Object.values(state.perIp || {}).reduce((acc, ip) => acc + (ip.cve_enrich?.length || 0), 0),
      headers: Object.keys(state.headers || {}),
      hasSecurityTxt: !!state.securityTxt,
      hasRobots: !!state.robots,
      dmarcPresent: state.dmarc?.present || false,
      spfPresent: state.spf?.present || false
    };

    const prompt = `You are a cybersecurity reconnaissance expert. Analyze these findings for ${state.domain} and provide key insights and correlations:

FINDINGS:
${JSON.stringify(summary, null, 2)}

Provide a concise analysis covering:
1. **Security Posture**: Overall security assessment (headers, email security, exposed services)
2. **Attack Surface**: Interesting entry points, exposed services, potential vulnerabilities
3. **Infrastructure**: Hosting/CDN, technology stack insights, interesting patterns
4. **Recommendations**: Top 2-3 areas to investigate further

Respond in markdown format, be concise (max 300 words), focus on actionable intel for red team operators.`;

    const response = await callOpenAI(apiKey, [
      { role: "system", content: "You are a cybersecurity expert providing reconnaissance analysis for authorized penetration testing." },
      { role: "user", content: prompt }
    ]);

    if (response) {
      log(`AI correlation generated ${response.length} chars of analysis`);
      return response;
    }

    return null;
  } catch (e) {
    logError(`AI correlation failed:`, e);
    return null;
  }
}

// Enhanced crt.sh background processing with AI filtering
async function enhancedSubdomainRecon(domain, openaiApiKey) {
  try {
    log(`Starting enhanced subdomain recon for ${domain} with AI filtering...`);

    // Get all subdomains from crt.sh (more extensive than normal)
    const allSubs = await subdomainsPassive(domain);
    log(`Found ${allSubs.length} total subdomains from passive sources`);

    if (allSubs.length === 0) return [];

    // Use AI to filter relevant hosts
    const relevantHosts = await filterHostsWithAI(openaiApiKey, allSubs, domain);
    log(`AI filtered to ${relevantHosts.length} relevant hosts`);

    // Resolve filtered hosts to IPs
    const resolvedHosts = [];
    const queue = relevantHosts.slice(0, 100); // Limit to top 100 AI-filtered
    const limit = CONFIG.LIMITS.MAX_PARALLEL_WORKERS;

    async function worker() {
      while (queue.length) {
        const host = queue.shift();
        try {
          const a4 = (await dohResolve(host, "A")).filter(x => x.type === 1).map(x => x.data);
          const a6 = (await dohResolve(host, "AAAA")).filter(x => x.type === 28).map(x => x.data);

          if (a4.length || a6.length) {
            resolvedHosts.push({
              subdomain: host,
              a: a4,
              aaaa: a6,
              aiFiltered: true
            });
          }
        } catch (e) {
          logError(`Failed to resolve ${host}:`, e);
        }
      }
    }

    await Promise.all(Array.from({ length: limit }, worker));
    log(`Resolved ${resolvedHosts.length} AI-filtered hosts to IPs`);

    return resolvedHosts;
  } catch (e) {
    logError(`Enhanced subdomain recon failed:`, e);
    return [];
  }
}

// CVE enrichment - Converts CPEs (Common Platform Enumeration) from Shodan to CVE IDs with severity scores
// Uses CIRCL.lu API (primary) with NVD (fallback) for CVE lookups
const cveCache = new Map();

function normCVE(items) {
  const out = [];
  for (const it of items || []) {
    if (!it) continue;
    let id = it.id || it.cve?.id || it.cve?.CVE_data_meta?.ID || it.cveId || it.cve?.cveId;
    if (!id) continue;

    let score = null, severity = null, published = null, lastModified = null;
    if ("cvss" in it) score = Number(it.cvss) || null;
    if (typeof it.severity === "string") severity = it.severity;
    if ("Published" in it) published = it.Published;
    if ("Modified" in it) lastModified = it.Modified;

    const nvd = it.cve || it;
    try {
      const m = nvd.metrics || {};
      const v31 = m.cvssMetricV31?.[0]?.cvssData;
      const v30 = m.cvssMetricV30?.[0]?.cvssData;
      const v2 = m.cvssMetricV2?.[0]?.cvssData;
      const pick = v31 || v30 || v2;
      if (pick && pick.baseScore != null) {
        score = Number(pick.baseScore);
        severity = pick.baseSeverity || severity;
      }
      published = nvd.published || nvd.publishedDate || published;
      lastModified = nvd.lastModified || nvd.lastModifiedDate || lastModified;
    } catch (e) {
      logError(`Error parsing CVE metrics for ${id}:`, e);
    }
    out.push({ id, score, severity, published, lastModified });
  }
  return out;
}

async function cveFromCIRCL(cpe) {
  try {
    log(`Fetching CVEs from CIRCL for CPE: ${cpe}`);
    const j = await fetchJSON(`https://cve.circl.lu/api/search/cpe/${encodeURIComponent(cpe)}`, {}, CONFIG.TIMEOUTS.FETCH_JSON);
    const cves = normCVE(j).map(x => ({ ...x, source: "circl" }));
    log(`CIRCL returned ${cves.length} CVEs for ${cpe}`);
    return cves;
  } catch (e) {
    logError(`CIRCL CVE lookup failed for ${cpe}:`, e);
    return [];
  }
}

async function cveFromNVD(cpe) {
  try {
    log(`Fetching CVEs from NVD for CPE: ${cpe}`);
    const j = await fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=50`, {}, CONFIG.TIMEOUTS.CVE_NVD);
    const arr = (j.vulnerabilities || []).map(v => v.cve);
    const cves = normCVE(arr).map(x => ({ ...x, source: "nvd" }));
    log(`NVD returned ${cves.length} CVEs for ${cpe}`);
    return cves;
  } catch (e) {
    logError(`NVD CVE lookup failed for ${cpe}:`, e);
    return [];
  }
}

async function enrichCVEsForCPE(cpe) {
  if (!cpe) return [];
  if (cveCache.has(cpe)) {
    log(`Using cached CVEs for ${cpe}`);
    return cveCache.get(cpe);
  }

  let items = await cveFromCIRCL(cpe);
  if (!items.length) {
    log(`CIRCL had no results, falling back to NVD for ${cpe}`);
    items = await cveFromNVD(cpe);
  }

  items.sort((a, b) => (Number(b.score || 0) - Number(a.score || 0)));
  const top = items.slice(0, CONFIG.LIMITS.MAX_CVE_RESULTS / 2);
  setBoundedCache(cveCache, cpe, top);
  log(`Cached ${top.length} CVEs for ${cpe}`);
  return top;
}

// state
async function setTabData(tabId, data) {
  try {
    await chrome.storage.session.set({ [`tab:${tabId}`]: data });
  } catch (e) {
    if (String(e).includes('QUOTA') || String(e).includes('quota')) {
      logError(`Storage quota exceeded for tab ${tabId}, pruning old data`);
      // Trim large fields to fit within quota
      if (data.secrets?.length > 10) data.secrets = data.secrets.slice(0, 10);
      if (data.quickSubs?.length > 40) data.quickSubs = data.quickSubs.slice(0, 40);
      if (data.aiEnhancedSubs?.length > 30) data.aiEnhancedSubs = data.aiEnhancedSubs.slice(0, 30);
      try { await chrome.storage.session.set({ [`tab:${tabId}`]: data }); } catch (e2) { logError(`Storage set still failed after pruning:`, e2); }
    } else {
      logError(`Failed to set tab data for ${tabId}:`, e);
    }
  }
}
const getTabData = async (tabId) => (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`];
// Proper mutex: each key has a chain of promises; new callers always
// append to the tail, guaranteeing serialised execution without TOCTOU gaps.
const patchQueues = new Map();
async function patchState(tabId, patch){
  const key = `tab:${tabId}`;
  const prev = patchQueues.get(key) || Promise.resolve();
  let releaseLock;
  const gate = new Promise(r => { releaseLock = r; });
  // Atomically replace the tail with our gate *before* awaiting
  patchQueues.set(key, gate);
  try {
    await prev; // wait for preceding patch to finish
    const cur = await getTabData(tabId) || {};
    const next = merge(cur, patch);
    await setTabData(tabId, next);
    return next;
  } finally {
    // If this was the last in the chain, clean up the key
    if (patchQueues.get(key) === gate) patchQueues.delete(key);
    releaseLock();
  }
}

// Technology detection - Comprehensive fingerprinting from headers, meta tags, and DOM hints
function detectTech({headers={}, meta={}, domHints={}, faviconHash}){
  const tags=new Set(); const notes=[];
  const H = (k)=>headers[k] || headers[k?.toLowerCase?.()] || null;
  const server=H("server")||""; const via=H("via")||""; const powered=H("x-powered-by")||"";
  const gen=(meta?.generator||"").toLowerCase(); const paths=(domHints?.paths||[]).join(" ");
  const hStr = JSON.stringify(headers).toLowerCase();

  // CDN & Edge
  if(/cloudflare/i.test(server) || H("cf-ray")) tags.add("Cloudflare");
  if(/fastly|varnish/i.test(server)) tags.add("Fastly");
  if(/akamai/i.test(server) || /akamai/i.test(via)) tags.add("Akamai");
  if(/cloudfront|x-amz-cf-id/i.test(hStr)) tags.add("AWS CloudFront");
  if(/bunnycdn/i.test(hStr)) tags.add("BunnyCDN");
  if(/stackpath|netdna/i.test(server)) tags.add("StackPath");

  // Hosting Platforms
  if(/vercel/i.test(server) || /x-vercel-id/i.test(hStr)) tags.add("Vercel");
  if(/github-pages|GitHub\.com/i.test(server)) tags.add("GitHub Pages");
  if(/Netlify|x-nf-request-id/i.test(hStr)) tags.add("Netlify");
  if(/WP Engine/i.test(hStr)) tags.add("WP Engine");
  if(/x-kinsta/i.test(hStr)) tags.add("Kinsta");

  // CMS & Frameworks
  if(/wordpress/i.test(gen) || /wp-content|wp-includes|wp-json/i.test(paths)) tags.add("WordPress");
  if(/drupal/i.test(gen) || /drupal/i.test(paths)) tags.add("Drupal");
  if(/joomla/i.test(gen) || /joomla/i.test(paths)) tags.add("Joomla");
  if(/wix\.com/i.test(hStr)) tags.add("Wix");
  if(/squarespace/i.test(hStr)) tags.add("Squarespace");
  if(/shopify/i.test(hStr)) tags.add("Shopify");
  if(/magento/i.test(powered) || /mage/i.test(paths)) tags.add("Magento");
  if(/prestashop/i.test(gen)) tags.add("PrestaShop");
  if(/webflow/i.test(hStr)) tags.add("Webflow");

  // JavaScript Frameworks
  if(/next\.js/i.test(powered) || /_next\//i.test(paths)) tags.add("Next.js");
  if(/_nuxt\//i.test(paths) || /nuxt/i.test(powered)) tags.add("Nuxt.js");
  if(/gatsby/i.test(gen) || /gatsby/i.test(paths)) tags.add("Gatsby");
  if(/angular/i.test(paths) || /ng-/i.test(hStr)) tags.add("Angular");
  if(/react/i.test(paths)) tags.add("React");
  if(/vue\.js/i.test(paths) || /vuejs/i.test(hStr)) tags.add("Vue.js");
  if(/svelte/i.test(paths)) tags.add("Svelte");
  if(/ember/i.test(paths)) tags.add("Ember.js");

  // Backend/Server
  if(/express/i.test(powered)) tags.add("Express.js");
  if(/nginx/i.test(server)) tags.add("Nginx");
  if(/apache/i.test(server)) tags.add("Apache");
  if(/iis|microsoft/i.test(server)) tags.add("IIS");
  if(/kestrel/i.test(server)) tags.add("Kestrel");
  if(/litespeed/i.test(server)) tags.add("LiteSpeed");
  if(/tomcat/i.test(server)) tags.add("Apache Tomcat");
  if(/jetty/i.test(server)) tags.add("Jetty");
  if(/gunicorn/i.test(server)) tags.add("Gunicorn");
  if(/uwsgi/i.test(server)) tags.add("uWSGI");
  if(/passenger/i.test(server)) tags.add("Phusion Passenger");

  // Languages & Runtimes
  if(/php/i.test(powered) || /\.php\b/i.test(paths) || /x-php/i.test(hStr)) tags.add("PHP");
  if(/asp\.net|microsoft/i.test(powered) || /x-aspnet/i.test(hStr)) tags.add("ASP.NET");
  if(/rails/i.test(powered) || /_rails_session/i.test(hStr)) tags.add("Ruby on Rails");
  if(/django/i.test(powered) || /csrftoken|django/i.test(hStr)) tags.add("Django");
  if(/flask/i.test(powered)) tags.add("Flask");
  if(/laravel/i.test(powered) || /laravel/i.test(paths)) tags.add("Laravel");
  if(/symfony/i.test(powered) || /symfony/i.test(paths)) tags.add("Symfony");
  if(/spring/i.test(powered) || /jsessionid/i.test(hStr)) tags.add("Spring");
  if(/\.jsp\b/i.test(paths)) tags.add("JSP/Java");
  if(/\.aspx\b/i.test(paths)) tags.add("ASP.NET");
  if(/\.cfm\b/i.test(paths)) tags.add("ColdFusion");

  // WAF & Security
  if(/x-sucuri/i.test(hStr)) tags.add("Sucuri WAF");
  if(/wordfence/i.test(hStr)) tags.add("Wordfence");
  if(/x-powered-by-plesk/i.test(hStr)) tags.add("Plesk");
  if(/cpanel/i.test(hStr)) tags.add("cPanel");

  // Analytics & Tracking
  if(/google-site-verification/i.test(hStr)) notes.push("Google Site Verification");
  if(/google-analytics|gtag|ga\.js/i.test(paths)) notes.push("Google Analytics");
  if(/facebook\.net|fbevents/i.test(paths)) notes.push("Facebook Pixel");

  // Additional Info
  if(typeof faviconHash==="number") notes.push(`favicon mmh3: ${faviconHash}`);
  if(H("x-cache")) notes.push(`Cache: ${H("x-cache")}`);
  if(H("x-runtime")) notes.push(`Runtime: ${H("x-runtime")}`);

  return { tags: Array.from(tags).slice(0,25), notes };
}

function deriveHighlights(state){
  if(!state) return null;
  const items = [];
  const headers = state.headers || {};
  const perIp = state.perIp || {};
  const secrets = state.secrets || [];

  // Security Headers
  const missingHeaders = ["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy"].filter(h=>!headers[h]);
  if(missingHeaders.length) items.push({ severity:"high", title:"Missing security headers", detail: missingHeaders.join(", ") });

  // Cookie Security
  if(state.cookieSecurity && state.cookieSecurity.length > 0) {
    const insecureCookies = state.cookieSecurity.filter(c => c.issues && c.issues.length > 0);
    if(insecureCookies.length) items.push({ severity:"medium", title:"Insecure cookies detected", detail:`${insecureCookies.length} cookies missing security flags` });
  }

  // CORS Misconfigurations
  if(state.corsFindings && state.corsFindings.length > 0) {
    const critical = state.corsFindings.find(f => f.credentials);
    if(critical) items.push({ severity:"critical", title:"CORS allows credentials + reflected origin", detail:"Possible credential theft via CORS" });
    else items.push({ severity:"high", title:"CORS misconfiguration detected", detail:`${state.corsFindings.length} issues found` });
  }

  // Sensitive Files
  if(state.sensitiveFiles && state.sensitiveFiles.length > 0) {
    const criticalFiles = state.sensitiveFiles.filter(f => f.path.includes('.git') || f.path.includes('.env'));
    if(criticalFiles.length) items.push({ severity:"critical", title:"Exposed sensitive files", detail:criticalFiles.map(f=>f.path).slice(0,3).join(", ") });
    else items.push({ severity:"high", title:"Sensitive files accessible", detail:`${state.sensitiveFiles.length} files found` });
  }

  // Dangerous HTTP Methods
  if(state.httpMethods?.risky) {
    items.push({ severity:"high", title:"Dangerous HTTP methods allowed", detail:state.httpMethods.dangerous.join(", ") });
  }

  // WAF Detection
  if(state.waf && state.waf.length > 0) {
    items.push({ severity:"low", title:`WAF detected: ${state.waf.join(", ")}`, detail:"Evasion techniques may be required" });
  }

  // Email Posture
  const dmarc = state.dmarc; const spf = state.spf;
  if(dmarc && !dmarc.present) items.push({ severity:"medium", title:"DMARC not found", detail:"Email spoofing resilience unknown" });
  if(spf && !spf.present) items.push({ severity:"low", title:"SPF missing", detail:"Sender validation record not found" });

  // Network Intelligence
  const openPorts = new Set(); const riskyPorts = new Set();
  const highCves = [];
  for(const [ip,data] of Object.entries(perIp)){
    const ports = Array.isArray(data?.internetdb?.ports) ? data.internetdb.ports : [];
    ports.forEach(p=>{ openPorts.add(p); if(![80,443,8080,8443].includes(Number(p))) riskyPorts.add(p); });
    const cves = Array.isArray(data?.cve_enrich) ? data.cve_enrich : [];
    cves.filter(c=>Number(c.score||0) >= 7).slice(0,5).forEach(c=>highCves.push(c.id));
  }
  if(riskyPorts.size) items.push({ severity:"high", title:"Non-standard exposed ports", detail:[...riskyPorts].slice(0,10).map(p=>`:${p}`).join(" ") });
  else if(openPorts.size) items.push({ severity:"medium", title:"Open ports observed", detail:[...openPorts].slice(0,10).map(p=>`:${p}`).join(" ") });
  if(highCves.length) items.push({ severity:"critical", title:"High-severity CVEs from CPEs", detail: [...new Set(highCves)].slice(0,8).join(", ") });

  // Secrets
  if(secrets.length) items.push({ severity:"high", title:"Potential secrets/endpoints", detail:`${secrets.length} sources flagged` });

  // Subdomain Takeover
  if(state.subdomainTakeovers && state.subdomainTakeovers.length > 0) {
    items.push({ severity:"critical", title:"Subdomain takeover possible", detail: state.subdomainTakeovers.map(t => `${t.subdomain} → ${t.service}`).join(", ") });
  }

  // Wayback URLs
  if(state.waybackUrls && state.waybackUrls.length > 0) {
    items.push({ severity:"low", title:`${state.waybackUrls.length} historical URLs from Wayback Machine`, detail: "May reveal old endpoints, parameters, or forgotten pages" });
  }

  // Intel Extraction
  if(state.intel) {
    if(state.intel.emails && state.intel.emails.length > 0) {
      items.push({ severity:"low", title:`${state.intel.emails.length} email addresses found`, detail:state.intel.emails.slice(0,3).join(", ") });
    }
    if(state.intel.comments && state.intel.comments.length > 0) {
      items.push({ severity:"medium", title:"HTML comments found", detail:`${state.intel.comments.length} comments (may leak info)` });
    }
  }

  // Forms
  if(state.forms) {
    const sensitiveForms = state.forms.filter(f => f.sensitive);
    if(sensitiveForms.length) items.push({ severity:"medium", title:"Sensitive forms detected", detail:`${sensitiveForms.length} forms with passwords or GET methods` });
  }

  // TLS Certificate
  if(state.tlsInfo) {
    const expiry = new Date(state.tlsInfo.notAfter);
    const daysLeft = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
    if(daysLeft < 30 && daysLeft > 0) items.push({ severity:"low", title:"Certificate expiring soon", detail:`${daysLeft} days remaining` });
    if(daysLeft < 0) items.push({ severity:"high", title:"Certificate expired", detail:`Expired ${Math.abs(daysLeft)} days ago` });
  }

  // AI Findings
  const aiHosts = Array.isArray(state.aiEnhancedSubs) ? state.aiEnhancedSubs.length : 0;
  if(aiHosts) items.push({ severity:"medium", title:"AI-relevant hosts", detail:`${aiHosts} prioritized subdomains` });

  const quickSubs = Array.isArray(state.quickSubs) ? state.quickSubs.length : 0;
  if(quickSubs > 20) items.push({ severity:"low", title:"Broad attack surface", detail:`${quickSubs} live subdomains resolved` });

  if(!state.securityTxt) items.push({ severity:"low", title:"security.txt not found", detail:"No disclosure policy located" });

  return { items: items.slice(0, 12) };
}

// Regenerate leads when new data arrives (called alongside highlights)
async function refreshLeads(tabId) {
  try {
    const state = await getTabData(tabId);
    if (!state) return;
    const leads = generateLeads(state);
    if (leads.length) await patchState(tabId, { leads });
  } catch (e) { logError("Lead refresh failed:", e); }
}

function scheduleHighlights(tabId){
  if(highlightTimers.has(tabId)) return;
  const timer = setTimeout(async()=>{
    highlightTimers.delete(tabId);
    try{
      const state = await getTabData(tabId);
      const highlights = deriveHighlights(state);
      if(highlights) await patchState(tabId, { highlights });
      // Also refresh leads with latest data
      await refreshLeads(tabId);
    }catch(e){ logError("Highlight generation failed", e); }
  }, 400);
  highlightTimers.set(tabId, timer);
}

// content bridge
const resourcesByTab = new Map();
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "pageResources" && sender.tab?.id != null) {
        resourcesByTab.set(sender.tab.id, msg);
        const base = await getTabData(sender.tab.id);
        if (base) {
          try {
            const fav = base.faviconHash;
            const tech = detectTech({ headers: base.headers || {}, meta: msg.meta || {}, domHints: msg.domHints || {}, faviconHash: fav });
            await patchState(sender.tab.id, { tech });
            scheduleHighlights(sender.tab.id);
          } catch {}

          // Enhanced content analysis with new intel extraction
          if (msg.htmlSample) {
            try {
              const intel = extractIntelFromText(msg.htmlSample);
              const forms = analyzeForms(msg.htmlSample);
              const waf = detectWAF(base.headers || {}, msg.htmlSample);
              const jsLibs = detectJSLibraries(msg.htmlSample, msg.externalScripts || []);

              await patchState(sender.tab.id, {
                intel,
                forms,
                waf,
                jsLibraries: jsLibs
              });
              scheduleHighlights(sender.tab.id);
            } catch (e) {
              logError('Intel extraction failed:', e);
            }
          }

          await runSecretsScan(sender.tab.id, base, msg, new URL(base.url).origin);
          scheduleHighlights(sender.tab.id);
          const mapFinds = await probeSourceMaps(Array.isArray(msg.externalScripts)?msg.externalScripts:[]);
          if (mapFinds.length) {
            const fresh = await getTabData(sender.tab.id);
            const merged = (fresh.secrets || []).concat(mapFinds);
            await patchState(sender.tab.id, { secrets: merged });
            scheduleHighlights(sender.tab.id);
          }

          // JS deep analysis: endpoints, configs, auth surfaces, parameters
          (async () => {
            try {
              const allJS = (msg.inlineScripts || []).join("\n");
              // Also fetch external scripts for endpoint extraction
              const extTexts = await Promise.all(
                (msg.externalScripts || []).slice(0, 8).map(u => fetchText(u))
              );
              const combinedJS = allJS + "\n" + extTexts.join("\n");
              const combinedHTML = msg.htmlSample || "";

              const jsEndpoints = extractJSEndpoints(combinedJS);
              const jsConfigs = extractJSConfigs(combinedJS);
              const currentState = await getTabData(sender.tab.id);
              const authSurfaces = detectAuthSurfaces(
                currentState?.forms,
                [...jsEndpoints, ...(currentState?.waybackUrls || [])],
                combinedHTML + combinedJS
              );

              // Extract params from wayback URLs + JS endpoints
              const allUrls = [
                ...(currentState?.waybackAll || []),
                ...jsEndpoints.filter(e => e.includes("?"))
              ];
              const discoveredParams = extractParameters(allUrls);

              await patchState(sender.tab.id, {
                jsEndpoints,
                jsConfigs,
                authSurfaces,
                discoveredParams
              });

              // Generate leads from all collected data
              const latestState = await getTabData(sender.tab.id);
              const leads = generateLeads(latestState);
              await patchState(sender.tab.id, { leads });
              scheduleHighlights(sender.tab.id);
              log(`Lead generation complete: ${leads.length} leads, ${jsEndpoints.length} endpoints, ${discoveredParams.length} params`);
            } catch (e) {
              logError("JS deep analysis failed:", e);
            }
          })();
        }
        sendResponse({ ok: true });
      } else if (msg?.type === "getState") {
        sendResponse(await getTabData(msg.tabId));
      } else if (msg?.type === "vtSubdomain") {
        const { sub } = msg;
        const state = await getTabData(msg.tabId);
        const { vtApiKey: saved } = await chrome.storage.local.get(["vtApiKey"]);
        let apiKey = saved;
        if (!apiKey) {
          try { const cfg = await (await fetch(chrome.runtime.getURL("config.json"))).json(); apiKey = cfg.vtApiKey || ""; } catch {}
        }
        if (!apiKey) { sendResponse({ ok:false, error:"no_api_key" }); return; }
        try {
          const rep = await vtDomain(sub, apiKey);
          await patchState(msg.tabId, { vt: merge((state&&state.vt)||{}, { [sub]: rep }) });
          scheduleHighlights(msg.tabId);
          sendResponse({ ok: true, data: rep });
        } catch (e) {
          sendResponse({ ok: false, error: String(e) });
        }
      }
    } catch (e) {
      try { sendResponse({ ok:false, error: String(e) }); } catch {}
    }
  })();
  return true;
});

// analyzer
async function analyze(tabId, url){
  try{
    const u=new URL(url); if(!/^https?:$/.test(u.protocol)) return;
    const domain=u.hostname;

    let hdrSnap = pickSecurityHeaders(tabId);
    if(!hdrSnap){ try{ const h=await fetchHeadersFallback(url); if(h) hdrSnap={url, headers:h}; }catch{} }

    await setTabData(tabId, { url, domain, headers: hdrSnap?hdrSnap.headers:{}, ts: Date.now() });
    scheduleHighlights(tabId);

    // IPs - Resolve and enrich with all available data
    (async () => {
      try {
        log(`Starting IP resolution for ${domain}...`);
        const ips = await resolveIPs(domain);
        if (!ips || ips.length === 0) {
          log(`No IPs resolved for ${domain}`);
          await patchState(tabId, { ips: [], perIp: {} });
          return;
        }
        log(`Resolved ${ips.length} IPs for ${domain}: ${ips.join(', ')}`);

        const perIp = {};
        await Promise.all(ips.map(async (ip) => {
          try {
            log(`Enriching IP: ${ip}...`);
            const [internetdb, ipwhois, iprdap, ptr] = await Promise.allSettled([
              shodanInternetDB(ip),
              ipWhoIs(ip),
              rdapIP(ip),
              reverseDNS(ip)
            ]);

            perIp[ip] = {
              internetdb: internetdb.status === 'fulfilled' ? (internetdb.value || {}) : {},
              ipwhois: ipwhois.status === 'fulfilled' ? (ipwhois.value || {}) : {},
              rdap: iprdap.status === 'fulfilled' ? iprdap.value : null,
              rdns: ptr.status === 'fulfilled' ? ptr.value : null,
              cve_enrich: null
            };
            log(`IP ${ip} enrichment complete`);
          } catch (e) {
            logError(`Failed to enrich IP ${ip}:`, e);
            perIp[ip] = { internetdb: {}, ipwhois: {}, rdap: null, rdns: null, cve_enrich: null };
          }
        }));

        await patchState(tabId, { ips, perIp });
        scheduleHighlights(tabId);
        log(`IP enrichment complete for ${domain}`);

        // CVE enrichment - Background task for CPE → CVE lookup
        (async () => {
          try {
            log(`Starting CVE enrichment for ${domain}...`);
            const current = await getTabData(tabId);
            if (!current?.perIp) {
              log(`No perIp data found, skipping CVE enrichment`);
              return;
            }

            for (const ip of Object.keys(current.perIp)) {
              try {
                const ipData = current.perIp[ip];
                if (!ipData?.internetdb) continue;

                const s = ipData.internetdb || {};
                const cpes = Array.isArray(s.cpes) ? s.cpes.slice(0, CONFIG.LIMITS.MAX_CPES_PER_IP) : [];

                if (cpes.length === 0) {
                  log(`No CPEs found for IP ${ip}`);
                  continue;
                }

                log(`Found ${cpes.length} CPEs for IP ${ip}, enriching...`);
                let agg = [];
                for (const c of cpes) {
                  const list = await enrichCVEsForCPE(c);
                  agg = agg.concat(list);
                  if (agg.length >= CONFIG.LIMITS.MAX_CVE_RESULTS) break;
                }

                // Deduplicate CVEs
                const seen = new Set();
                const dedup = [];
                for (const it of agg) {
                  if (it && it.id && !seen.has(it.id)) {
                    seen.add(it.id);
                    dedup.push(it);
                  }
                }

                const upd = await getTabData(tabId);
                if (!upd?.perIp?.[ip]) continue;
                upd.perIp[ip].cve_enrich = dedup.slice(0, CONFIG.LIMITS.MAX_CVE_RESULTS);
                await setTabData(tabId, upd);
                scheduleHighlights(tabId);
                log(`CVE enrichment complete for IP ${ip}: ${dedup.length} CVEs`);
              } catch (e) {
                logError(`CVE enrichment failed for IP ${ip}:`, e);
              }
            }
            log(`CVE enrichment complete for all IPs`);
          } catch (e) {
            logError(`CVE enrichment process failed:`, e);
          }
        })();
      } catch (e) {
        logError(`IP resolution/enrichment failed for ${domain}:`, e);
        await patchState(tabId, { ips: [], perIp: {}, error: `IP resolution failed: ${e.message}` });
      }
    })();

    // Domain posture and security checks (now includes TLS cert, CORS, HTTP methods, cookies)
    (async () => {
      const [domainRDAP, robots, secTxt, dmarc, spf, dkim, mx, tlsInfo, corsCheck, httpMethods, sensitiveFiles, cookieAnalysis] = await Promise.allSettled([
        rdapDomain(domain),
        getRobots(u.origin),
        getSecurityTxt(u.origin),
        checkDMARC(domain),
        checkSPF(domain),
        checkDKIM(domain),
        dohMX(domain),
        getTLSInfo(domain),
        checkCORS(url),
        probeHTTPMethods(url),
        probeSensitiveFiles(u.origin),
        analyzeCookies(hdrSnap?.headers || {})
      ]);

      await patchState(tabId, {
        domainRDAP: domainRDAP.value || null,
        robots: robots.value || null,
        securityTxt: secTxt.value || null,
        dmarc: dmarc.value || null,
        spf: spf.value || null,
        dkim: dkim.value || null,
        mx: mx.value || null,
        tlsInfo: tlsInfo.value || null,
        corsFindings: corsCheck.value || null,
        httpMethods: httpMethods.value || null,
        sensitiveFiles: sensitiveFiles.value || null,
        cookieSecurity: cookieAnalysis.value || null
      });
      scheduleHighlights(tabId);
    })();

    // Wayback Machine URL discovery (background)
    (async () => {
      try {
        const wb = await waybackUrls(domain);
        if (wb.all.length) {
          await patchState(tabId, { waybackUrls: wb.interesting, waybackAll: wb.all });
          scheduleHighlights(tabId);
        }
      } catch (e) { logError(`Wayback Machine recon failed:`, e); }
    })();

    // Subdomains + takeover detection
    (async () => {
      const liveSubs = await subdomainsLive(domain);
      await patchState(tabId, { quickSubs: liveSubs });
      scheduleHighlights(tabId);

      // Check for subdomain takeover on subs with CNAMEs (background)
      const subsWithCnames = liveSubs.filter(s => s.cnames && s.cnames.length > 0);
      if (subsWithCnames.length) {
        const takeovers = [];
        for (const sub of subsWithCnames.slice(0, 20)) {
          try {
            const result = await checkSubdomainTakeover(sub.subdomain, sub.cnames);
            if (result) takeovers.push(result);
          } catch (e) { log(`Takeover check failed for ${sub.subdomain}:`, e.message); }
        }
        if (takeovers.length) {
          await patchState(tabId, { subdomainTakeovers: takeovers });
          scheduleHighlights(tabId);
        }
      }
    })();

    // AI-Enhanced Subdomain Recon (background task)
    (async () => {
      try {
        const { openaiApiKey: saved } = await chrome.storage.local.get(["openaiApiKey"]);
        let apiKey = saved;
        if (!apiKey) {
          try {
            const cfg = await (await fetch(chrome.runtime.getURL("config.json"))).json();
            apiKey = cfg.openaiApiKey || "";
          } catch {}
        }

        if (apiKey) {
          log(`OpenAI API key found, starting AI-enhanced subdomain recon...`);
          const enhancedSubs = await enhancedSubdomainRecon(domain, apiKey);
          await patchState(tabId, { aiEnhancedSubs: enhancedSubs });
          scheduleHighlights(tabId);
          log(`AI-enhanced subdomain recon complete: ${enhancedSubs.length} relevant hosts`);
        } else {
          log(`No OpenAI API key configured, skipping AI-enhanced recon`);
        }
      } catch (e) {
        logError(`AI-enhanced subdomain recon failed:`, e);
      }
    })();

    // Secrets if resources already here
    const res = resourcesByTab.get(tabId);
    if (res) {
      const base = await getTabData(tabId);
      await runSecretsScan(tabId, base, res, u.origin);
      // compute tech once we have resources + fav
      const fav = (await getTabData(tabId))?.faviconHash || null;
      const tech = detectTech({ headers: (await getTabData(tabId))?.headers || {}, meta: res.meta||{}, domHints: res.domHints||{}, faviconHash: fav });
      await patchState(tabId, { tech });
      scheduleHighlights(tabId);
    }

    // AI Correlation (background task - runs after all data collected)
    (async () => {
      try {
        // Wait a bit for other recon to complete
        await new Promise(resolve => setTimeout(resolve, 5000));

        const { openaiApiKey: saved } = await chrome.storage.local.get(["openaiApiKey"]);
        let apiKey = saved;
        if (!apiKey) {
          try {
            const cfg = await (await fetch(chrome.runtime.getURL("config.json"))).json();
            apiKey = cfg.openaiApiKey || "";
          } catch {}
        }

        if (apiKey) {
          const currentState = await getTabData(tabId);
          if (currentState) {
            log(`Starting AI correlation for ${domain}...`);
            const correlation = await correlateFindings(apiKey, currentState);
            if (correlation) {
              await patchState(tabId, { aiCorrelation: correlation });
              scheduleHighlights(tabId);
              log(`AI correlation complete for ${domain}`);
            }
          }
        }
      } catch (e) {
        logError(`AI correlation failed:`, e);
      }
    })();

  }catch(e){ await setTabData(tabId, { url, error: String(e) }); }
}
chrome.tabs.onUpdated.addListener((tabId, info, tab)=>{ if(info.status==="complete" && tab?.url) analyze(tabId, tab.url); });

// Clean up per-tab data when tabs are closed to prevent memory leaks
chrome.tabs.onRemoved.addListener((tabId) => {
  headersByTab.delete(tabId);
  resourcesByTab.delete(tabId);
  scannedByTab.delete(tabId);
  patchQueues.delete(`tab:${tabId}`);
  if (highlightTimers.has(tabId)) {
    clearTimeout(highlightTimers.get(tabId));
    highlightTimers.delete(tabId);
  }
  chrome.storage.session.remove(`tab:${tabId}`).catch(e => logError(`Failed to clean session for tab ${tabId}:`, e));
  log(`Cleaned up data for closed tab ${tabId}`);
});
