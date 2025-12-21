
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
const merge = (a,b)=>Object.assign({},a||{},b||{});
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
  const h = {}; for (const {name,value} of rec.responseHeaders||[]) h[name.toLowerCase()] = value || "";
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
    "via": get("via")
  }};
}
async function fetchHeadersFallback(url){
  try{ const r=await fetchWithTimeout(url,{method:"HEAD"},2500); const o={}; for(const [k,v] of r.headers.entries()) o[k.toLowerCase()]=v; return o; }catch{}
  try{ const r=await fetchWithTimeout(url,{method:"GET",headers:{"Range":"bytes=0-0"}},2500); const o={}; for(const [k,v] of r.headers.entries()) o[k.toLowerCase()]=v; return o; }catch{}
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
    } catch {}
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

// Subdomain enumeration - Combines passive sources (crt.sh, BufferOver, Anubis)
// Then performs active DNS resolution to verify live subdomains
async function subdomainsPassive(domain){
  const set = new Set(); const q = domain.replace(/^\*\./, "");
  const cached = subdomainCache.get(q);
  if (cached && (Date.now() - cached.ts) < CONFIG.CACHE.SUBDOMAIN_MS) {
    log(`Using cached subdomains for ${q}`);
    return cached.data.slice(0, CONFIG.LIMITS.MAX_SUBDOMAINS);
  }

  // crt.sh - certificate transparency logs
  try {
    log(`Fetching subdomains from crt.sh for ${q}...`);
    const r = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
    if (r.ok) {
      const t = await r.text();
      let arr = [];
      try {
        arr = JSON.parse(t);
      } catch {
        // Handle NDJSON format
        arr = t.trim().split("\n").map(x => {
          try { return JSON.parse(x); } catch { return null; }
        }).filter(Boolean);
      }
      for (const row of arr) {
        const names = String(row.name_value || "").split(/\n+/);
        for (const n of names) {
          if (n && n.endsWith(q)) set.add(n.replace(/^\*\./, ""));
        }
      }
      log(`crt.sh found ${set.size} subdomains`);
    }
  } catch (e) {
    logError(`crt.sh lookup failed for ${q}:`, e);
  }

  // BufferOver - DNS aggregator
  try {
    log(`Fetching subdomains from BufferOver for ${q}...`);
    const r = await fetchWithTimeout(`https://dns.bufferover.run/dns?q=.${encodeURIComponent(q)}`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
    if (r.ok) {
      const j = await r.json();
      const initialSize = set.size;
      for (const line of (j.FDNS_A || [])) {
        const d = (line.split(",")[1] || "").trim();
        if (d && d.endsWith(q)) set.add(d);
      }
      for (const line of (j.FDNS_AAAA || [])) {
        const d = (line.split(",")[1] || "").trim();
        if (d && d.endsWith(q)) set.add(d);
      }
      log(`BufferOver added ${set.size - initialSize} new subdomains`);
    }
  } catch (e) {
    logError(`BufferOver lookup failed for ${q}:`, e);
  }

  // Anubis - subdomain aggregator
  try {
    log(`Fetching subdomains from Anubis for ${q}...`);
    const r = await fetchWithTimeout(`https://jldc.me/anubis/subdomains/${encodeURIComponent(q)}`, {}, CONFIG.TIMEOUTS.SUBDOMAIN_PASSIVE);
    if (r.ok) {
      const arr = await r.json();
      const initialSize = set.size;
      for (const d of arr) {
        if (typeof d === "string" && d.endsWith(q)) set.add(d);
      }
      log(`Anubis added ${set.size - initialSize} new subdomains`);
    }
  } catch (e) {
    logError(`Anubis lookup failed for ${q}:`, e);
  }

  log(`Total ${set.size} unique subdomains found for ${q}`);
  const list = [...set].slice(0, CONFIG.LIMITS.MAX_SUBDOMAINS);
  setBoundedCache(subdomainCache, q, { ts: Date.now(), data: list });
  return list;
}
async function subdomainsLive(domain){
  const passive=await subdomainsPassive(domain); const out=[]; const queue=passive.slice(0,CONFIG.LIMITS.MAX_SUBDOMAINS_QUEUE); const limit=CONFIG.LIMITS.MAX_PARALLEL_WORKERS;
  async function worker(){ while(queue.length){ const s=queue.shift(); try{ const a4=(await dohResolve(s,"A")).filter(x=>x.type===1).map(x=>x.data); const a6=(await dohResolve(s,"AAAA")).filter(x=>x.type===28).map(x=>x.data); if(a4.length||a6.length) out.push({subdomain:s,a:a4,aaaa:a6}); }catch{} } }
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
  // Telegram
  {id:"telegram_bot", rx:/\b\d{8,10}:[A-Za-z0-9_\-]{35}\b/g},
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
  // Crypto & Blockchain
  {id:"ethereum_key", rx:/0x[a-fA-F0-9]{64}/g},
  {id:"bitcoin_address", rx:/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g},
  // Network & Infrastructure
  {id:"internal_ip", rx:/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g},
  {id:"ipv6_address", rx:/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g},
  // API Endpoints & Routes
  {id:"endpoint_url", rx:/https?:\/\/[a-z0-9\.\-]+(?::\d{2,5})?(?:\/[A-Za-z0-9_\-\.~%\/\?\=\&#]+)?/gi},
  {id:"api_route", rx:/(?:^|[^a-z])\/(?:api|v\d+|graphql|admin|internal|wp-json)\/[A-Za-z0-9_\-\/\.]+/gi},
  {id:"api_key_assign", rx:/(?:api[_-]?key|apikey|token|secret|password|passwd|bearer|auth)[\s]*[:=][\s]*["'][^"']{8,}["']/gi},
  // Additional Secrets
  {id:"npm_token", rx:/npm_[A-Za-z0-9]{36}/g},
  {id:"pypi_token", rx:/pypi-[A-Za-z0-9\-_]{32,}/g},
  {id:"docker_hub_token", rx:/dckr_pat_[A-Za-z0-9_-]{32,}/g},
  {id:"datadog_key", rx:/[a-f0-9]{32}(?:-[a-f0-9]{8})?/g}
];
function scanText(t){ const out=[]; for(const {id,rx} of SECRET_PATTERNS){ try{ rx.lastIndex=0; const m=t.match(rx); if(m&&m.length) out.push({id, samples: Array.from(new Set(m)).slice(0,5)});}catch{}} return out; }
async function fetchText(url){ try{ const r=await fetchWithTimeout(url,{},2500); if(!r.ok) return ""; const ct=r.headers.get("content-type")||""; if(!/javascript|json|text|xml|html/.test(ct)) return ""; const t=await r.text(); return t.slice(0, 300*1024);}catch{ return ""; } }
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
  for(const chunk of inline){ const f=scanText(chunk); if(f.length) results.push({source:"inline_script", findings:f}); if(results.length>=20) break; }
  for(const url of external){ if(scanned.has(url)) continue; scanned.add(url); const text=await fetchText(url); if(!text) continue; const f=scanText(text); if(f.length) results.push({source:url, findings:f}); if(results.length>=20) break; }
  if(!scanned.has("__HTML__") && origin){ scanned.add("__HTML__"); try{ const r=await fetchWithTimeout(origin,{},2500); if(r.ok){ const ct=r.headers.get("content-type")||""; if(/text\/html/i.test(ct)){ const html=(await r.text()).slice(0,200*1024); const f=scanText(html); if(f.length) results.push({source:"document_html", findings:f}); } } }catch{} }
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

    // Parse AI response
    const filtered = JSON.parse(response.trim());
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
  cveCache.set(cpe, top);
  log(`Cached ${top.length} CVEs for ${cpe}`);
  return top;
}

// state
const setTabData = async (tabId, data) => chrome.storage.session.set({ [`tab:${tabId}`]: data });
const getTabData = async (tabId) => (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`];
async function patchState(tabId, patch){ const cur=await getTabData(tabId)||{}; const next=merge(cur,patch); await setTabData(tabId,next); return next; }

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

  const missingHeaders = ["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy"].filter(h=>!headers[h]);
  if(missingHeaders.length) items.push({ severity:"high", title:"Missing security headers", detail: missingHeaders.join(", ") });

  const dmarc = state.dmarc; const spf = state.spf;
  if(dmarc && !dmarc.present) items.push({ severity:"medium", title:"DMARC not found", detail:"Email spoofing resilience unknown" });
  if(spf && !spf.present) items.push({ severity:"low", title:"SPF missing", detail:"Sender validation record not found" });

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

  if(secrets.length) items.push({ severity:"high", title:"Potential secrets/endpoints", detail:`${secrets.length} sources flagged` });

  const aiHosts = Array.isArray(state.aiEnhancedSubs) ? state.aiEnhancedSubs.length : 0;
  if(aiHosts) items.push({ severity:"medium", title:"AI-relevant hosts", detail:`${aiHosts} prioritized subdomains` });

  const quickSubs = Array.isArray(state.quickSubs) ? state.quickSubs.length : 0;
  if(quickSubs > 20) items.push({ severity:"low", title:"Broad attack surface", detail:`${quickSubs} live subdomains resolved` });

  if(!state.securityTxt) items.push({ severity:"low", title:"security.txt not found", detail:"No disclosure policy located" });

  return { items: items.slice(0, 8) };
}

function scheduleHighlights(tabId){
  if(highlightTimers.has(tabId)) return;
  const timer = setTimeout(async()=>{
    highlightTimers.delete(tabId);
    try{
      const state = await getTabData(tabId);
      const highlights = deriveHighlights(state);
      if(highlights) await patchState(tabId, { highlights });
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
          await runSecretsScan(sender.tab.id, base, msg, new URL(base.url).origin);
          scheduleHighlights(sender.tab.id);
          const mapFinds = await probeSourceMaps(Array.isArray(msg.externalScripts)?msg.externalScripts:[]);
          if (mapFinds.length) {
            const fresh = await getTabData(sender.tab.id);
            const merged = (fresh.secrets || []).concat(mapFinds);
            await patchState(sender.tab.id, { secrets: merged });
            scheduleHighlights(sender.tab.id);
          }
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

    // Domain posture
    (async () => {
      const [domainRDAP, robots, secTxt, dmarc, spf, dkim, mx] = await Promise.allSettled([ rdapDomain(domain), getRobots(u.origin), getSecurityTxt(u.origin), checkDMARC(domain), checkSPF(domain), checkDKIM(domain), dohMX(domain) ]);
      await patchState(tabId, { domainRDAP: domainRDAP.value||null, robots: robots.value||null, securityTxt: secTxt.value||null, dmarc: dmarc.value||null, spf: spf.value||null, dkim: dkim.value||null, mx: mx.value||null });
      scheduleHighlights(tabId);
    })();

    // Subdomains
    (async () => {
      const liveSubs = await subdomainsLive(domain);
      await patchState(tabId, { quickSubs: liveSubs });
      scheduleHighlights(tabId);
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
