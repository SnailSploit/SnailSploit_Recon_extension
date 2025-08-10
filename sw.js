
function log(...a){ try{ console.log("[ReconRadar]", ...a);}catch{} }
const merge = (a,b)=>Object.assign({},a||{},b||{});

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

// DNS (DoH only)
async function dohResolve(name, type){
  const enc = encodeURIComponent(name);
  const urls = [
    `https://dns.google/resolve?name=${enc}&type=${type}`,
    `https://cloudflare-dns.com/dns-query?name=${enc}&type=${type}`
  ];
  for (const u of urls) {
    try { const r = await fetchWithTimeout(u, { headers:{accept:"application/dns-json"} }, 2500); if (!r.ok) continue; const j=await r.json(); if (j.Answer && j.Answer.length) return j.Answer; } catch {}
  }
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
  const all = await Promise.all(urls.map(u => fetchWithTimeout(u, { headers:{accept:"application/dns-json"} }, 2500).then(r=>r.json()).catch(()=>({}))));
  for (const j of all) for (const a of (j.Answer||[])) if (a.type===1||a.type===28) ips.add(a.data);
  return [...ips].slice(0, 20);
}

// enrichers
async function fetchJSON(url,opts={}){ try{ const r=await fetchWithTimeout(url,{...opts},3500); if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }catch(e){ const r=await fetchWithTimeout(url,{...opts},4000); if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); } }
async function shodanInternetDB(ip){ try{ return await fetchJSON(`https://internetdb.shodan.io/${ip}`);}catch{return{}} }
async function ipWhoIs(ip){ try{ return await fetchJSON(`https://ipwho.is/${ip}`);}catch{} try{ return await fetchJSON(`https://ipapi.co/${ip}/json/`);}catch{} return {}; }
async function rdapDomain(domain){ try{ return await fetchJSON(`https://rdap.org/domain/${domain}`);}catch{return null} }
async function rdapIP(ip){ try{ return await fetchJSON(`https://rdap.org/ip/${ip}`);}catch{return null} }
async function getSecurityTxt(origin){ try{ const u1=new URL("/.well-known/security.txt",origin).href; const r1=await fetchWithTimeout(u1,{},2000); if(r1.ok) return {url:u1}; }catch{} try{ const u2=new URL("/security.txt",origin).href; const r2=await fetchWithTimeout(u2,{},2000); if(r2.ok) return {url:u2}; }catch{} return null; }
async function getRobots(origin){ try{ const u=new URL("/robots.txt",origin).href; const r=await fetchWithTimeout(u,{},2000); if(r.ok) return {url:u}; }catch{} return null; }
async function checkDMARC(d){ try{ const recs=await dohTXT(`_dmarc.${d}`); const m=recs.find(r=>String(r).toUpperCase().includes("V=DMARC1")); return {present:!!m, record:m||null}; }catch{ return {present:false, record:null}; } }
async function checkSPF(d){ try{ const recs=await dohTXT(d); const m=recs.find(r=>String(r).toLowerCase().startsWith("v=spf1")); return {present:!!m, record:m||null}; }catch{ return {present:false, record:null}; } }
const COMMON_DKIM=["default","google","mail","mandrill","dkim","selector","selector1","selector2","s1","s2","k1","mx","smtp"];
async function checkDKIM(d){ const found=[]; for(const sel of COMMON_DKIM){ try{ const txts=await dohTXT(`${sel}._domainkey.${d}`); const rec=(txts||[]).find(r=>String(r).toLowerCase().includes("v=dkim1")); if(rec) found.push({selector:sel,record:rec}); if(found.length>=6) break; }catch{} } return {selectors:found}; }

// subdomains
async function subdomainsPassive(domain){
  const set = new Set(); const q=domain.replace(/^\*\./,"");
  try{ const r=await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json`,{},2500); if(r.ok){ const t=await r.text(); let arr=[]; try{arr=JSON.parse(t);}catch{arr=t.trim().split("\n").map(x=>{try{return JSON.parse(x)}catch{return null}}).filter(Boolean);} for(const row of arr){ for(const n of String(row.name_value||"").split(/\n+/)) if(n && n.endsWith(q)) set.add(n.replace(/^\*\./,"")); } } }catch{}
  try{ const r=await fetchWithTimeout(`https://dns.bufferover.run/dns?q=.${encodeURIComponent(q)}`,{},2500); if(r.ok){ const j=await r.json(); for(const line of (j.FDNS_A||[])){ const d=(line.split(",")[1]||"").trim(); if(d.endsWith(q)) set.add(d);} for(const line of (j.FDNS_AAAA||[])){ const d=(line.split(",")[1]||"").trim(); if(d.endsWith(q)) set.add(d);} } }catch{}
  try{ const r=await fetchWithTimeout(`https://jldc.me/anubis/subdomains/${encodeURIComponent(q)}`,{},2500); if(r.ok){ const arr=await r.json(); for(const d of arr) if(typeof d==="string"&&d.endsWith(q)) set.add(d); } }catch{}
  return [...set].slice(0,200);
}
async function subdomainsLive(domain){
  const passive=await subdomainsPassive(domain); const out=[]; const queue=passive.slice(0,120); const limit=6;
  async function worker(){ while(queue.length){ const s=queue.shift(); try{ const a4=(await dohResolve(s,"A")).filter(x=>x.type===1).map(x=>x.data); const a6=(await dohResolve(s,"AAAA")).filter(x=>x.type===28).map(x=>x.data); if(a4.length||a6.length) out.push({subdomain:s,a:a4,aaaa:a6}); }catch{} } }
  await Promise.all(Array.from({length:limit},worker)); return out.slice(0,80);
}

// favicon hash
function mmh3_32_from_b64(b64){
  function rotl32(x,r){ return (x<<r)|(x>>> (32-r)); }
  const bin=atob(b64); const arr=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  let h1=0x811c9dc5; const c1=0xcc9e2d51, c2=0x1b873593; const view=new DataView(arr.buffer,arr.byteOffset,arr.byteLength);
  const nblocks=Math.floor(arr.byteLength/4);
  for(let i=0;i<nblocks;i++){ let k1=view.getUint32(i*4,true); k1=Math.imul(k1,c1); k1=rotl32(k1,15); k1=Math.imul(k1,c2); h1^=k1; h1=rotl32(h1,13); h1=(Math.imul(h1,5)+0xe6546b64)|0; }
  let k1=0; const tail=arr.byteLength & 3; const p=nblocks*4;
  if(tail===3) k1^=arr[p+2]<<16; if(tail>=2) k1^=arr[p+1]<<8; if(tail>=1){ k1^=arr[p]; k1=Math.imul(k1,c1); k1=rotl32(k1,15); k1=Math.imul(k1,c2); h1^=k1; }
  h1^=arr.byteLength; h1^=h1>>>16; h1=Math.imul(h1,0x85ebca6b); h1^=h1>>>13; h1=Math.imul(h1,0xc2b2ae35); h1^=h1>>>16; return (h1|0);
}
async function faviconHash(url){ try{ const r=await fetchWithTimeout(url,{},2000); if(!r.ok) return null; const buf=await r.arrayBuffer(); const b64=btoa(String.fromCharCode(...new Uint8Array(buf))); return mmh3_32_from_b64(b64);}catch{ return null; }}

// secrets
const SECRET_PATTERNS=[
  {id:"aws_access_key", rx:/AKIA[0-9A-Z]{16}/g},
  {id:"google_api_key", rx:/AIza[0-9A-Za-z\-_]{35}/g},
  {id:"github_pat", rx:/(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}/g},
  {id:"github_fine_grained", rx:/github_pat_[A-Za-z0-9_]{22,}/g},
  {id:"slack_token", rx:/xox[baprs]-[A-Za-z0-9\-]{10,48}/g},
  {id:"stripe_key", rx:/(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}/g},
  {id:"sendgrid_key", rx:/SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{10,}/g},
  {id:"twilio_sid", rx:/AC[a-f0-9]{32}/gi},
  {id:"jwt", rx:/eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g},
  {id:"private_key", rx:/-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g},
  {id:"gcp_sa", rx:/[a-z0-9\-]{6,}\@[a-z0-9\-]+\.iam\.gserviceaccount\.com/g},
  {id:"s3_url", rx:/https?:\/\/[a-z0-9\.\-]{3,}\.s3\.amazonaws\.com\/[^\s"'<>()]+/gi},
  {id:"azure_sas", rx:/(?:sig=)[A-Za-z0-9%]{20,}&(?:se=|\bsv=)/g},
  {id:"internal_ip", rx:/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g},
  {id:"endpoint_url", rx:/https?:\/\/[a-z0-9\.\-]+(?::\d{2,5})?(?:\/[A-Za-z0-9_\-\.~%\/\?\=\&#]+)?/gi},
  {id:"api_route", rx:/(?:^|[^a-z])\/(?:api|v1|v2|graphql|admin|internal)\/[A-Za-z0-9_\-\/\.]+/gi},
  {id:"api_key_assign", rx:/(?:api[_-]?key|token|secret|bearer)\s*[:=]\s*["'][^"']{12,}["']/gi}
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

// CVE enrichment
const cveCache=new Map();
function normCVE(items){ const out=[]; for(const it of items||[]){ if(!it) continue; let id = it.id || it.cve?.id || it.cve?.CVE_data_meta?.ID || it.cveId || it.cve?.cveId; if(!id) continue; let score=null, severity=null, published=null, lastModified=null; if("cvss" in it) score=Number(it.cvss)||null; if(typeof it.severity==="string") severity=it.severity; if("Published" in it) published=it.Published; if("Modified" in it) lastModified=it.Modified; const nvd = it.cve || it; try{ const m=nvd.metrics||{}; const v31=m.cvssMetricV31?.[0]?.cvssData; const v30=m.cvssMetricV30?.[0]?.cvssData; const v2=m.cvssMetricV2?.[0]?.cvssData; const pick=v31||v30||v2; if(pick && pick.baseScore!=null){ score=Number(pick.baseScore); severity=pick.baseSeverity||severity; } published=nvd.published||nvd.publishedDate||published; lastModified=nvd.lastModified||nvd.lastModifiedDate||lastModified; }catch{} out.push({id,score,severity,published,lastModified}); } return out; }
async function cveFromCIRCL(cpe){ try{ const j=await fetchJSON(`https://cve.circl.lu/api/search/cpe/${encodeURIComponent(cpe)}`); return normCVE(j).map(x=>({...x,source:"circl"})); }catch{ return []; } }
async function cveFromNVD(cpe){ try{ const j=await jsonWithTimeout(`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=50`,{},4000); const arr=(j.vulnerabilities||[]).map(v=>v.cve); return normCVE(arr).map(x=>({...x,source:"nvd"})); }catch{ return []; } }
async function enrichCVEsForCPE(cpe){ if(cveCache.has(cpe)) return cveCache.get(cpe); let items=await cveFromCIRCL(cpe); if(!items.length) items=await cveFromNVD(cpe); items.sort((a,b)=>(Number(b.score||0)-Number(a.score||0))); const top=items.slice(0,30); cveCache.set(cpe,top); return top; }

// state
const setTabData = async (tabId, data) => chrome.storage.session.set({ [`tab:${tabId}`]: data });
const getTabData = async (tabId) => (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`];
async function patchState(tabId, patch){ const cur=await getTabData(tabId)||{}; const next=merge(cur,patch); await setTabData(tabId,next); return next; }

// tech heuristics
function detectTech({headers={}, meta={}, domHints={}, faviconHash}){
  const tags=new Set(); const notes=[];
  const H = (k)=>headers[k] || headers[k?.toLowerCase?.()] || null;
  const server=H("server")||""; const via=H("via")||""; const powered=H("x-powered-by")||""; const gen=(meta?.generator||"").toLowerCase(); const paths=(domHints?.paths||[]).join(" ");
  if(/cloudflare/i.test(server) || headers["cf-ray"]) tags.add("Cloudflare");
  if(/fastly|varnish/i.test(server)) tags.add("Fastly");
  if(/akamai/i.test(server) || /akamai/i.test(via)) tags.add("Akamai");
  if(/vercel/i.test(server) || /x-vercel-id/i.test(JSON.stringify(headers))) tags.add("Vercel");
  if(/github-pages|GitHub\.com/i.test(server)) tags.add("GitHub Pages");
  if(/Netlify|x-nf-request-id/i.test(JSON.stringify(headers))) tags.add("Netlify");
  if(/wordpress/i.test(gen) || /wp-content|wp-includes/i.test(paths)) tags.add("WordPress");
  if(/drupal/i.test(gen) || /drupal/i.test(paths)) tags.add("Drupal");
  if(/next\.js/i.test(powered) || /_next\//i.test(paths)) tags.add("Next.js");
  if(/_nuxt\//i.test(paths)) tags.add("Nuxt");
  if(/express/i.test(powered)) tags.add("Express");
  if(/php/i.test(powered) || /\.php\b/i.test(paths)) tags.add("PHP");
  if(/asp\.net|microsoft/i.test(powered) || /x-aspnet/i.test(JSON.stringify(headers))) tags.add("ASP.NET");
  if(/rails/i.test(powered) || /_rails_session/i.test(JSON.stringify(headers))) tags.add("Rails");
  if(typeof faviconHash==="number") notes.push(`favicon mmh3: ${faviconHash}`);
  return { tags: Array.from(tags).slice(0,12), notes };
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
          } catch {}
          await runSecretsScan(sender.tab.id, base, msg, new URL(base.url).origin);
          const mapFinds = await probeSourceMaps(Array.isArray(msg.externalScripts)?msg.externalScripts:[]);
          if (mapFinds.length) {
            const fresh = await getTabData(sender.tab.id);
            const merged = (fresh.secrets || []).concat(mapFinds);
            await patchState(sender.tab.id, { secrets: merged });
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

    // IPs
    (async () => {
      const ips = await resolveIPs(domain);
      const perIp = {};
      await Promise.all(ips.map(async (ip) => {
        const [internetdb, ipwhois, iprdap, ptr] = await Promise.allSettled([ shodanInternetDB(ip), ipWhoIs(ip), rdapIP(ip), reverseDNS(ip) ]);
        perIp[ip] = { internetdb: internetdb.value||{}, ipwhois: ipwhois.value||{}, rdap: iprdap.value||null, rdns: ptr.value||null, cve_enrich: null };
      }));
      await patchState(tabId, { ips, perIp });

      // CVE enrichment
      (async () => {
        const current = await getTabData(tabId); if(!current?.perIp) return;
        for (const ip of Object.keys(current.perIp)) {
          try {
            const s = current.perIp[ip]?.internetdb || {}; const cpes = Array.isArray(s.cpes) ? s.cpes.slice(0,5) : [];
            let agg = [];
            for (const c of cpes){ const list = await enrichCVEsForCPE(c); agg = agg.concat(list); if (agg.length>=60) break; }
            const seen=new Set(); const dedup=[]; for(const it of agg){ if(!seen.has(it.id)){ seen.add(it.id); dedup.push(it);} }
            const upd = await getTabData(tabId); if(!upd?.perIp?.[ip]) continue; upd.perIp[ip].cve_enrich = dedup.slice(0,60); await setTabData(tabId, upd);
          } catch {}
        }
      })();
    })();

    // Domain posture
    (async () => {
      const [domainRDAP, robots, secTxt, dmarc, spf, dkim, mx] = await Promise.allSettled([ rdapDomain(domain), getRobots(u.origin), getSecurityTxt(u.origin), checkDMARC(domain), checkSPF(domain), checkDKIM(domain), dohMX(domain) ]);
      await patchState(tabId, { domainRDAP: domainRDAP.value||null, robots: robots.value||null, securityTxt: secTxt.value||null, dmarc: dmarc.value||null, spf: spf.value||null, dkim: dkim.value||null, mx: mx.value||null });
    })();

    // Subdomains
    (async () => {
      const liveSubs = await subdomainsLive(domain);
      await patchState(tabId, { quickSubs: liveSubs });
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
    }

  }catch(e){ await setTabData(tabId, { url, error: String(e) }); }
}
chrome.tabs.onUpdated.addListener((tabId, info, tab)=>{ if(info.status==="complete" && tab?.url) analyze(tabId, tab.url); });
