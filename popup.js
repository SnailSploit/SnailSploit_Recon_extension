
let TAB_ID = null;
async function getTabId(){ const [t]=await chrome.tabs.query({active:true,currentWindow:true}); return t?.id; }
function el(html){ const t=document.createElement("template"); t.innerHTML=html.trim(); return t.content.firstChild; }
function esc(s){ return (s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

function headerCard(s){
  const fav = (typeof s.faviconHash==="number") ? `<span class="small">favicon mmh3: <code>${s.faviconHash}</code></span>` : "";

  // Domain accumulation stats
  const ds = s._domainStats;
  let statsHtml = "";
  if (ds) {
    const elapsed = ds.firstSeen ? timeSince(ds.firstSeen) : "";
    statsHtml = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">
      <span class="chip" style="background:#e3f2fd;border-color:#1976d2;color:#0d47a1" title="Pages browsed on this domain">${ds.totalPages} pages</span>
      <span class="chip" style="background:#e8f5e9;border-color:#4caf50;color:#2e7d32" title="JS endpoints extracted">${ds.totalEndpoints} endpoints</span>
      <span class="chip" style="background:#fff3e0;border-color:#fb8c00;color:#e65100" title="Secrets flagged">${ds.totalSecrets} secrets</span>
      ${ds.totalEmails ? `<span class="chip">${ds.totalEmails} emails</span>` : ""}
      ${elapsed ? `<span class="chip small" title="Tracking since first visit">${elapsed}</span>` : ""}
    </div>`;
  }

  return el(`<div class="card"><div><b>${esc(s.domain||"")}</b><div class="small">${esc(s.url||"")}</div>${fav}${statsHtml}</div></div>`);
}

function timeSince(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function severityStyle(level){
  const map={
    critical:"background:#ffebee;border-color:#ef5350;color:#b71c1c",
    high:"background:#fff3e0;border-color:#fb8c00;color:#e65100",
    medium:"background:#fff8e1;border-color:#fdd835;color:#f9a825",
    low:"background:#f5f5f5;border-color:#bdbdbd;color:#424242"
  };
  return map[level] || map.low;
}
function highlightsCard(s){
  const card=el(`<div class="card"><h3>🔎 Pentester Highlights</h3></div>`);
  const items = s.highlights?.items || [];
  if(!items.length){ card.appendChild(el('<div class="small">Collecting signals…</div>')); return card; }
  for(const it of items){
    const sev=it.severity||"low";
    const row=el(`<div class="row" style="margin:6px 0;display:flex;gap:8px;align-items:center">
      <span class="chip" style="${severityStyle(sev)};font-weight:bold;text-transform:uppercase">${esc(sev)}</span>
      <div><div><b>${esc(it.title||"")}</b></div>${it.detail?`<div class="small">${esc(it.detail)}</div>`:""}</div>
    </div>`);
    card.appendChild(row);
  }
  return card;
}
function headersCard(h){
  const map={"Content-Security-Policy":h?.["content-security-policy"],"Strict-Transport-Security":h?.["strict-transport-security"],"X-Frame-Options":h?.["x-frame-options"],"X-Content-Type-Options":h?.["x-content-type-options"],"Referrer-Policy":h?.["referrer-policy"],"Permissions-Policy":h?.["permissions-policy"],"Server":h?.["server"],"Alt-Svc":h?.["alt-svc"]};
  const card=el(`<div class="card"><h3>Security Headers</h3><div class="grid" id="hdr"></div></div>`); const box=card.querySelector("#hdr");
  Object.entries(map).forEach(([k,v])=>box.appendChild(el(`<div><span class="chip">${esc(k)}</span> ${v?`<code>${esc(String(v).slice(0,160))}${String(v).length>160?'…':''}</code>`:'<span class="small">missing/loading</span>'}</div>`)));
  return card;
}
function ipsCard(s){
  const card=el(`<div class="card"><h3>IPs</h3></div>`);
  const ips=s.ips||[]; if(!ips.length){ card.appendChild(el('<div class="small">loading…</div>')); return card; }
  card.querySelector("h3").appendChild(copyBtn(ips.join("\n"), "Copy IPs"));
  for(const ip of ips){
    const per=s.perIp?.[ip]||{}; const sh=per.internetdb||{}; const geo=per.ipwhois||{};
    const row = el(`<div class="row">
      <div><span class="chip"><b>${esc(ip)}</b></span> ${Array.isArray(sh.ports)&&sh.ports.length?sh.ports.map(p=>`<span class="chip">:${p}</span>`).join(" "):'<span class="small">no ports</span>'} <span class="chip">Shodan</span></div>
      ${sh.vulns?.length ? `<details class="small"><summary>CVEs (Shodan ${sh.vulns.length})</summary><div>${sh.vulns.map(v=>`<code>${esc(v)}</code>`).join(" ")}</div></details>` : ""}
      ${per.cve_enrich?.length ? `<details class="small"><summary>CVEs (CPE→CVE ${per.cve_enrich.length})</summary><div>${per.cve_enrich.slice(0,30).map(v=>`<div class="small"><code>${esc(v.id)}</code>${v.score?` · <b>${esc(v.score)}</b>`:''}${v.source?` · <span class="small">${esc(v.source)}</span>`:''}</div>`).join("")}</div></details>` : (!sh.vulns?.length?'<div class="small">CVE enrichment: loading…</div>':'')}
      <div class="small">ISP/ASN: ${esc(geo.isp||geo.org||"n/a")} ${geo.asn?("· AS"+esc(geo.asn)):""} ${geo.country?("· "+esc(geo.country)):""}</div>
      ${per.rdns?`<div class="small">rDNS: ${esc(per.rdns)}</div>`:""}
    </div>`);
    card.appendChild(row);
  }
  return card;
}
function domainCard(s){
  const dr=s.domainRDAP||{}; const ns=(dr?.nameservers||[]).map(n=>n.ldhName||n.unicodeName).filter(Boolean);
  const card=el(`<div class="card"><h3>Domain</h3></div>`);
  card.appendChild(el(`<div class="row">NS: ${ns.length?ns.map(n=>`<span class="chip">${esc(n)}</span>`).join(" "):'<span class="small">loading/none</span>'}</div>`));
  if(Array.isArray(s.mx)) card.appendChild(el(`<div class="row">MX: ${s.mx.length?s.mx.map(m=>`<span class="chip">${esc(m)}</span>`).join(" "):'<span class="small">none</span>'}</div>`));
  return card;
}
function mailCard(s){
  const card=el(`<div class="card"><h3>Email Posture</h3></div>`);
  card.appendChild(el(`<div class="row"><b>DMARC</b>: ${s.dmarc?(s.dmarc.present?`<code>${esc(s.dmarc.record)}</code>`:'<span class="small">missing</span>'):'<span class="small">loading…</span>'}</div>`));
  card.appendChild(el(`<div class="row"><b>SPF</b>: ${s.spf?(s.spf.present?`<code>${esc(s.spf.record)}</code>`:'<span class="small">missing</span>'):'<span class="small">loading…</span>'}</div>`));
  card.appendChild(el(`<div class="row"><b>DKIM</b>: ${s.dkim?(s.dkim.selectors?.length ? s.dkim.selectors.map(x=>`<span class="chip">${esc(x.selector)}</span>`).join(" "):'<span class="small">no common selectors</span>'):'<span class="small">loading…</span>'}</div>`));
  return card;
}
function textsCard(s){
  const card=el(`<div class="card grid">`);
  card.appendChild(el(`<div><h3>security.txt</h3>${s.securityTxt?`<a href="${esc(s.securityTxt.url)}" target="_blank">open</a>`:'<span class="small">not found / loading</span>'}</div>`));
  card.appendChild(el(`<div><h3>robots.txt</h3>${s.robots?`<a href="${esc(s.robots.url)}" target="_blank">open</a>`:'<span class="small">not found / loading</span>'}</div>`));
  return card;
}
function secretsCard(s){
  const card=el(`<div class="card"><h3>Secrets & Endpoints</h3></div>`);
  if(!s.secrets){ card.appendChild(el('<div class="small">scanning…</div>')); return card; }
  if(!s.secrets.length){ card.appendChild(el('<div class="small">no obvious secrets (regex)</div>')); return card; }
  for(const item of s.secrets){
    const src=item.source||"inline"; const blk=el(`<details class="row"><summary class="mono">${esc(src.length>80?src.slice(0,80)+'…':src)}</summary></details>`);
    for(const f of item.findings){ blk.appendChild(el(`<div class="small"><b>${esc(f.id)}</b>: ${(f.samples||[]).map(x=>`<code>${esc(String(x).slice(0,120))}${String(x).length>120?'…':''}</code>`).join(" ")}</div>`)); }
    card.appendChild(blk);
  }
  return card;
}
function subsCard(s){
  const card=el(`<div class="card"><h3>Live Subdomains</h3><div id="subs"></div></div>`); const box=card.querySelector("#subs");
  const subs=s.quickSubs||[]; if(!subs.length){ box.appendChild(el('<div class="small">resolving…</div>')); return card; }
  card.querySelector("h3").appendChild(copyBtn(subs.map(x=>x.subdomain).join("\n"), "Copy All"));
  for(const it of subs){
    const vt = s.vt?.[it.subdomain];
    const vtHTML = vt ? `<div class="small">VT rep: <b>${esc(vt.reputation??0)}</b> · <code>${esc(JSON.stringify(vt.last_analysis_stats||{}))}</code></div>` : `<button class="btn vt" data-sub="${esc(it.subdomain)}">Enrich with VirusTotal</button>`;
    const ips = (it.a||[]).concat(it.aaaa||[]).map(ip=>`<span class="chip">${esc(ip)}</span>`).join(" ");
    const row = el(`<div class="sub"><div class="mono">${esc(it.subdomain)}</div><div>${ips||'<span class="small">no IPs?</span>'}</div><div>${vtHTML}</div></div>`);
    box.appendChild(row);
  }
  box.querySelectorAll("button.vt").forEach(b=>{
    b.addEventListener("click", async()=>{ b.disabled=true; b.textContent="Enriching…"; const res=await chrome.runtime.sendMessage({type:"vtSubdomain", tabId:TAB_ID, sub:b.dataset.sub}); if(!res?.ok){ b.textContent=res?.error||"VT error"; return;} render(); });
  });
  return card;
}
function techCard(s){
  const t=s.tech||{}; const tags=t.tags||[]; const notes=t.notes||[]; const card=el(`<div class="card"><h3>Tech Fingerprints</h3></div>`);
  if(!tags.length && !notes.length){ card.appendChild(el('<div class="small">none</div>')); return card; }
  if(tags.length) card.appendChild(el(`<div>${tags.map(x=>`<span class="chip">${esc(x)}</span>`).join(" ")}</div>`));
  if(notes.length) card.appendChild(el(`<div class="small">${notes.map(esc).join(" · ")}</div>`));

  // Add WAF detection if present
  if(s.waf && s.waf.length > 0) {
    card.appendChild(el(`<div class="row" style="margin-top:8px"><b>WAF Detected:</b> ${s.waf.map(w=>`<span class="chip" style="background:#ffebee;border-color:#ef5350;color:#b71c1c">${esc(w)}</span>`).join(" ")}</div>`));
  }

  // Add JS libraries if detected
  if(s.jsLibraries && s.jsLibraries.length > 0) {
    card.appendChild(el(`<div class="row" style="margin-top:8px"><b>JS Libraries:</b> ${s.jsLibraries.map(lib=>`<span class="chip">${esc(lib.name)}${lib.version !== 'unknown' ? ` v${esc(lib.version)}` : ''}</span>`).join(" ")}</div>`));
  }

  return card;
}

function tlsCard(s){
  const card=el(`<div class="card"><h3>TLS Certificate</h3></div>`);
  const tls=s.tlsInfo;
  if(!tls){ card.appendChild(el('<div class="small">loading…</div>')); return card; }

  const expiry = new Date(tls.notAfter);
  const daysLeft = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
  const expiryColor = daysLeft < 0 ? 'color:#ef5350' : daysLeft < 30 ? 'color:#fb8c00' : 'color:#4caf50';

  card.appendChild(el(`<div class="row"><b>Issuer:</b> <span class="small">${esc(tls.issuer)}</span></div>`));
  card.appendChild(el(`<div class="row"><b>Common Name:</b> <code>${esc(tls.commonName||'N/A')}</code></div>`));
  card.appendChild(el(`<div class="row"><b>Expiry:</b> <span style="${expiryColor}">${daysLeft < 0 ? 'Expired' : `${daysLeft} days left`}</span> · <span class="small">${esc(tls.notAfter)}</span></div>`));
  if(tls.sans && tls.sans.length > 0){
    card.appendChild(el(`<details class="small"><summary>SANs (${tls.sans.length} domains)</summary><div>${tls.sans.slice(0,20).map(s=>`<div class="mono">${esc(s)}</div>`).join("")}</div></details>`));
  }
  return card;
}

function securityChecksCard(s){
  const card=el(`<div class="card"><h3>Security Checks</h3></div>`);

  // CORS
  if(s.corsFindings && s.corsFindings.length > 0){
    const corsHTML = s.corsFindings.map(c => {
      const severity = c.credentials ? 'critical' : 'high';
      return `<div class="row" style="margin:4px 0"><span class="chip" style="${severityStyle(severity)}">${c.type.toUpperCase()}</span> <span class="small">${esc(c.detail)}</span></div>`;
    }).join('');
    card.appendChild(el(`<div><b>CORS Issues:</b>${corsHTML}</div>`));
  }

  // HTTP Methods
  if(s.httpMethods){
    const methods = s.httpMethods;
    const methodsHTML = methods.risky ?
      `<div class="row"><b>HTTP Methods:</b> ${methods.all.map(m=>`<span class="chip" style="${methods.dangerous.includes(m)?'background:#ffebee;border-color:#ef5350;color:#b71c1c':''}">${esc(m)}</span>`).join(" ")}</div>` :
      `<div class="row"><b>HTTP Methods:</b> <span class="small">${methods.all.join(", ")}</span></div>`;
    card.appendChild(el(methodsHTML));
  }

  // Cookies
  if(s.cookieSecurity && s.cookieSecurity.length > 0){
    const insecure = s.cookieSecurity.filter(c => c.issues.length > 0);
    if(insecure.length > 0){
      card.appendChild(el(`<details class="row"><summary><b>Cookie Issues (${insecure.length})</b></summary><div>${insecure.map(c=>`<div class="small"><code>${esc(c.name)}</code>: ${c.issues.join(", ")}</div>`).join("")}</div></details>`));
    } else {
      card.appendChild(el(`<div class="row"><b>Cookies:</b> <span class="small" style="color:#4caf50">All secure (${s.cookieSecurity.length} cookies)</span></div>`));
    }
  }

  // Sensitive Files
  if(s.sensitiveFiles && s.sensitiveFiles.length > 0){
    card.appendChild(el(`<details class="row"><summary><b style="color:#ef5350">Exposed Files (${s.sensitiveFiles.length})</b></summary><div>${s.sensitiveFiles.map(f=>`<div class="small"><code>${esc(f.path)}</code> · ${f.status} · ${f.size ? `${f.size} bytes` : 'N/A'}</div>`).join("")}</div></details>`));
  }

  if(!s.corsFindings && !s.httpMethods && !s.cookieSecurity && !s.sensitiveFiles){
    card.appendChild(el('<div class="small">running checks…</div>'));
  }

  return card;
}

function intelCard(s){
  const card=el(`<div class="card"><h3>Intelligence Gathered</h3></div>`);
  const intel=s.intel;

  if(!intel){ card.appendChild(el('<div class="small">analyzing page…</div>')); return card; }

  if(intel.emails && intel.emails.length > 0){
    const emailRow = el(`<details class="row"><summary><b>Email Addresses (${intel.emails.length})</b></summary><div>${intel.emails.map(e=>`<code>${esc(e)}</code>`).join(" ")}</div></details>`);
    emailRow.querySelector("div").appendChild(copyBtn(intel.emails.join("\n"), "Copy"));
    card.appendChild(emailRow);
  }

  if(intel.phones && intel.phones.length > 0){
    card.appendChild(el(`<div class="row"><b>Phone Numbers:</b> ${intel.phones.map(p=>`<code>${esc(p)}</code>`).join(" ")}</div>`));
  }

  if(intel.socialLinks && intel.socialLinks.length > 0){
    card.appendChild(el(`<details class="row"><summary><b>Social Media (${intel.socialLinks.length})</b></summary><div>${intel.socialLinks.slice(0,10).map(s=>`<a href="${esc(s)}" target="_blank" class="small">${esc(s)}</a>`).join("<br>")}</div></details>`));
  }

  if(intel.comments && intel.comments.length > 0){
    card.appendChild(el(`<details class="row"><summary><b>HTML Comments (${intel.comments.length})</b></summary><div>${intel.comments.map(c=>`<div class="small"><code>${esc(c.slice(0,100))}${c.length>100?'…':''}</code></div>`).join("")}</div></details>`));
  }

  if(!intel.emails?.length && !intel.phones?.length && !intel.socialLinks?.length && !intel.comments?.length){
    card.appendChild(el('<div class="small">no intel extracted</div>'));
  }

  return card;
}

function formsCard(s){
  const card=el(`<div class="card"><h3>Forms Analysis</h3></div>`);
  const forms=s.forms;

  if(!forms){ card.appendChild(el('<div class="small">analyzing…</div>')); return card; }
  if(forms.length === 0){ card.appendChild(el('<div class="small">no forms found</div>')); return card; }

  for(const form of forms.slice(0,10)){
    const sensitive = form.sensitive ? ' style="background:#ffebee;border-color:#ef5350"' : '';
    card.appendChild(el(`<div class="row"${sensitive}>
      <div><b>${esc(form.method)}</b> → <code>${esc(form.action||'(self)')}</code></div>
      <div class="small">${form.inputs} inputs${form.hasPassword?' · 🔑 Password field':''} ${form.hasHidden?' · Hidden fields':''}</div>
    </div>`));
  }

  return card;
}

function aiCorrelationCard(s){
  const card=el(`<div class="card"><h3>🤖 AI Correlation & Insights</h3></div>`);
  if(!s.aiCorrelation){
    card.appendChild(el('<div class="small">AI analysis running in background... (requires OpenAI API key in Options)</div>'));
    return card;
  }
  // Parse markdown lines into safe DOM elements (no innerHTML/insertAdjacentHTML)
  for (const line of s.aiCorrelation.split('\n')) {
    let node;
    if (line.startsWith('###')) {
      node = document.createElement('h4');
      node.style.cssText = 'margin:8px 0 4px 0;font-size:11px';
      node.textContent = line.replace(/^###\s*/, '');
    } else if (line.startsWith('##')) {
      node = document.createElement('h4');
      node.style.cssText = 'margin:10px 0 6px 0;font-size:12px;font-weight:bold';
      node.textContent = line.replace(/^##\s*/, '');
    } else if (line.startsWith('- ')) {
      node = document.createElement('div');
      node.className = 'small';
      node.style.marginLeft = '12px';
      node.textContent = '\u2022 ' + line.replace(/^-\s*/, '');
    } else if (line.trim()) {
      node = document.createElement('div');
      node.className = 'small';
      node.textContent = line;
    }
    if (node) card.appendChild(node);
  }
  return card;
}

function aiEnhancedSubsCard(s){
  const card=el(`<div class="card"><h3>🎯 AI-Filtered Relevant Hosts</h3><div id="aiSubs"></div></div>`);
  const box=card.querySelector("#aiSubs");
  const subs=s.aiEnhancedSubs||[];
  if(!subs || subs.length === 0){
    box.appendChild(el('<div class="small">AI host filtering running in background... (requires OpenAI API key)</div>'));
    return card;
  }
  box.appendChild(el(`<div class="small" style="margin-bottom:8px">AI identified ${subs.length} highly relevant hosts from passive recon</div>`));
  for(const it of subs.slice(0,50)){
    const ips = (it.a||[]).concat(it.aaaa||[]).map(ip=>`<span class="chip">${esc(ip)}</span>`).join(" ");
    const row = el(`<div class="sub"><div class="mono">${esc(it.subdomain)}</div><div>${ips||'<span class="small">no IPs?</span>'}</div><span class="chip" style="background:#e8f5e9;border-color:#4caf50;color:#2e7d32">AI Filtered</span></div>`);
    box.appendChild(row);
  }
  return card;
}

// Copy-to-clipboard helper
function copyBtn(text, label="Copy") {
  const b = document.createElement("button");
  b.className = "btn"; b.textContent = label; b.style.cssText = "font-size:10px;padding:2px 6px;margin-left:4px";
  b.addEventListener("click", () => { navigator.clipboard.writeText(text); b.textContent = "Copied!"; setTimeout(() => b.textContent = label, 1200); });
  return b;
}

// Collapsible card wrapper
function collapsible(title, contentFn, startOpen=true) {
  const card = el(`<div class="card"><h3 style="cursor:pointer;user-select:none" class="collapsible-toggle">${title} <span style="float:right;font-size:10px">${startOpen?'▼':'▶'}</span></h3></div>`);
  const body = document.createElement("div");
  body.style.display = startOpen ? "block" : "none";
  contentFn(body);
  card.appendChild(body);
  card.querySelector(".collapsible-toggle").addEventListener("click", () => {
    const open = body.style.display !== "none";
    body.style.display = open ? "none" : "block";
    card.querySelector(".collapsible-toggle span").textContent = open ? "▶" : "▼";
  });
  return card;
}

// Scan progress tracker
function progressCard(s) {
  const phases = [
    { key: "headers", label: "Headers", done: !!s.headers && Object.values(s.headers).some(Boolean) },
    { key: "ips", label: "IPs", done: Array.isArray(s.ips) },
    { key: "tlsInfo", label: "TLS", done: s.tlsInfo !== undefined },
    { key: "corsFindings", label: "CORS", done: s.corsFindings !== undefined },
    { key: "sensitiveFiles", label: "Files", done: s.sensitiveFiles !== undefined },
    { key: "dmarc", label: "DMARC", done: !!s.dmarc },
    { key: "quickSubs", label: "Subdomains", done: Array.isArray(s.quickSubs) && s.quickSubs.length > 0 },
    { key: "secrets", label: "Secrets", done: Array.isArray(s.secrets) },
    { key: "waybackUrls", label: "Wayback", done: s.waybackUrls !== undefined },
    { key: "tech", label: "Tech", done: !!s.tech }
  ];
  const done = phases.filter(p => p.done).length;
  const pct = Math.round((done / phases.length) * 100);
  const allDone = pct === 100;
  if (allDone) return null; // Hide when complete
  const card = el(`<div class="card" style="padding:8px 10px"><div style="display:flex;align-items:center;gap:8px"><b class="small">Scanning… ${pct}%</b><div style="flex:1;height:4px;background:#eee;border-radius:2px;overflow:hidden"><div style="width:${pct}%;height:100%;background:#1976d2;border-radius:2px;transition:width .3s"></div></div></div><div style="margin-top:4px">${phases.map(p => `<span class="chip" style="${p.done?'background:#e8f5e9;border-color:#4caf50;color:#2e7d32':'opacity:0.4'}">${p.label}</span>`).join(" ")}</div></div>`);
  return card;
}

// Subdomain takeover card
function takeoverCard(s) {
  if (!s.subdomainTakeovers || !s.subdomainTakeovers.length) return null;
  return collapsible("⚠ Subdomain Takeover", body => {
    for (const t of s.subdomainTakeovers) {
      const row = el(`<div class="row" style="background:#ffebee;border:1px solid #ef5350;border-radius:6px;padding:8px;margin:4px 0">
        <div><b style="color:#b71c1c">${esc(t.subdomain)}</b> → <code>${esc(t.cname)}</code></div>
        <div class="small">Service: <b>${esc(t.service)}</b> · Confidence: ${esc(t.confidence)}</div>
      </div>`);
      body.appendChild(row);
    }
  });
}

// Wayback Machine card
function waybackCard(s) {
  if (!s.waybackUrls || !s.waybackUrls.length) return null;
  return collapsible("🕐 Wayback Machine URLs", body => {
    body.appendChild(el(`<div class="small" style="margin-bottom:6px">${s.waybackUrls.length} interesting historical URLs found${s.waybackAll ? ` (${s.waybackAll.length} total)` : ''}</div>`));
    const copyAll = copyBtn(s.waybackUrls.join("\n"), "Copy All");
    body.appendChild(copyAll);
    for (const u of s.waybackUrls.slice(0, 30)) {
      body.appendChild(el(`<div class="mono small" style="margin:2px 0;word-break:break-all">${esc(u)}</div>`));
    }
    if (s.waybackUrls.length > 30) body.appendChild(el(`<div class="small">…and ${s.waybackUrls.length - 30} more (export to see all)</div>`));
  }, false);
}

// LEADS CARD - The main value proposition
function leadsCard(s) {
  if (!s.leads || !s.leads.length) return null;
  const card = el(`<div class="card" style="border-color:#1976d2;border-width:2px"><h3 style="color:#1976d2">🎯 Attack Leads</h3></div>`);
  for (const lead of s.leads) {
    const pColor = lead.priority === 1 ? "#b71c1c" : lead.priority === 2 ? "#e65100" : "#2e7d32";
    const pLabel = lead.priority === 1 ? "P1 CRITICAL" : lead.priority === 2 ? "P2 HIGH" : "P3 MEDIUM";
    const row = document.createElement("div");
    row.className = "row";
    row.style.cssText = "margin:8px 0;padding:8px;border:1px solid #eee;border-radius:6px;border-left:3px solid " + pColor;

    const header = document.createElement("div");
    header.style.cssText = "display:flex;align-items:center;gap:6px;margin-bottom:4px";
    const badge = document.createElement("span");
    badge.className = "chip";
    badge.style.cssText = `background:${pColor};color:white;font-weight:bold;font-size:9px;padding:1px 6px`;
    badge.textContent = pLabel;
    const cat = document.createElement("span");
    cat.className = "chip";
    cat.textContent = lead.category;
    const title = document.createElement("b");
    title.textContent = lead.title;
    header.appendChild(badge);
    header.appendChild(cat);
    row.appendChild(header);

    const titleDiv = document.createElement("div");
    titleDiv.style.fontWeight = "bold";
    titleDiv.style.marginBottom = "2px";
    titleDiv.textContent = lead.title;
    row.appendChild(titleDiv);

    const detail = document.createElement("div");
    detail.className = "small";
    detail.textContent = lead.detail;
    row.appendChild(detail);

    if (lead.action) {
      const actionDiv = document.createElement("div");
      actionDiv.style.cssText = "margin-top:4px;display:flex;align-items:center;gap:4px";
      const code = document.createElement("code");
      code.style.cssText = "font-size:10px;background:#f5f5f5;padding:2px 6px;border-radius:3px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block";
      code.textContent = lead.action.length > 80 ? lead.action.slice(0, 80) + "…" : lead.action;
      code.title = lead.action;
      actionDiv.appendChild(code);
      actionDiv.appendChild(copyBtn(lead.action, "Copy"));
      row.appendChild(actionDiv);
    }
    card.appendChild(row);
  }
  return card;
}

// JS Endpoints card
function endpointsCard(s) {
  if (!s.jsEndpoints || !s.jsEndpoints.length) return null;
  return collapsible(`🔗 JS Endpoints (${s.jsEndpoints.length})`, body => {
    body.appendChild(copyBtn(s.jsEndpoints.join("\n"), "Copy All"));
    for (const ep of s.jsEndpoints.slice(0, 40)) {
      const isAdmin = /admin|internal|debug|config/i.test(ep);
      const d = document.createElement("div");
      d.className = "mono small";
      d.style.cssText = `margin:2px 0;${isAdmin ? "color:#b71c1c;font-weight:bold" : ""}`;
      d.textContent = ep;
      body.appendChild(d);
    }
    if (s.jsEndpoints.length > 40) body.appendChild(el(`<div class="small">…and ${s.jsEndpoints.length - 40} more</div>`));
  }, false);
}

// Discovered parameters card
function paramsCard(s) {
  if (!s.discoveredParams || !s.discoveredParams.length) return null;
  return collapsible(`🧪 URL Parameters (${s.discoveredParams.length})`, body => {
    body.appendChild(el(`<div class="small" style="margin-bottom:6px">Parameters found across Wayback + JS — test for SQLi, XSS, SSRF, IDOR</div>`));
    const injectable = /id|user|name|query|search|q|url|redirect|file|path|page|callback|token|ref/i;
    for (const p of s.discoveredParams.slice(0, 30)) {
      const hot = injectable.test(p.name);
      const d = document.createElement("div");
      d.className = "small";
      d.style.cssText = `margin:2px 0;padding:2px 4px;border-radius:3px;${hot ? "background:#fff3e0;border-left:2px solid #fb8c00" : ""}`;
      d.innerHTML = `<code>${esc(p.name)}</code>${hot ? ' <span style="color:#e65100;font-size:9px">⚡ HIGH INTEREST</span>' : ''} ${p.examples.length ? `<span class="small"> e.g. ${p.examples.slice(0,2).map(v=>`<code>${esc(v)}</code>`).join(", ")}</span>` : ""}`;
      body.appendChild(d);
    }
  }, false);
}

// Auth surfaces card
function authCard(s) {
  if (!s.authSurfaces || !s.authSurfaces.length) return null;
  return collapsible(`🔐 Auth Surfaces (${s.authSurfaces.length})`, body => {
    for (const auth of s.authSurfaces) {
      const d = document.createElement("div");
      d.className = "row";
      d.style.cssText = "margin:4px 0;padding:6px;border:1px solid #eee;border-radius:4px";
      const typeSpan = document.createElement("span");
      typeSpan.className = "chip";
      typeSpan.style.cssText = auth.risk === "high" ? "background:#ffebee;border-color:#ef5350;color:#b71c1c" : "";
      typeSpan.textContent = auth.type.replace(/_/g, " ");
      d.appendChild(typeSpan);
      const detail = document.createElement("div");
      detail.className = "small";
      detail.textContent = `${auth.detail} — ${auth.why}`;
      d.appendChild(detail);
      body.appendChild(d);
    }
  });
}

// Pages visited breadcrumb trail
function pagesVisitedCard(s) {
  const pages = s._domainStats?.pagesVisited;
  if (!pages || pages.length < 2) return null;
  return collapsible(`📍 Pages Browsed (${pages.length})`, body => {
    for (const p of [...pages].reverse().slice(0, 20)) {
      const ago = timeSince(p.ts);
      const path = p.url.replace(/https?:\/\/[^\/]+/, "") || "/";
      const d = document.createElement("div");
      d.className = "small";
      d.style.cssText = "margin:2px 0;display:flex;justify-content:space-between;gap:8px";
      const pathSpan = document.createElement("span");
      pathSpan.className = "mono";
      pathSpan.style.cssText = "overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:320px";
      pathSpan.textContent = path;
      pathSpan.title = p.url;
      const timeSpan = document.createElement("span");
      timeSpan.style.cssText = "opacity:0.5;white-space:nowrap";
      timeSpan.textContent = ago;
      d.appendChild(pathSpan);
      d.appendChild(timeSpan);
      body.appendChild(d);
    }
  }, false);
}

// Passive request log card
function requestLogCard(s) {
  const reqs = s._requestLog;
  if (!reqs || reqs.length < 3) return null;
  const apiReqs = reqs.filter(r => /xmlhttprequest/i.test(r.type) || /\/api|\/v\d|graphql/i.test(r.path));
  if (!apiReqs.length) return null;
  return collapsible(`📡 API Calls Observed (${apiReqs.length})`, body => {
    body.appendChild(el(`<div class="small" style="margin-bottom:6px">Passively captured as you browsed</div>`));
    body.appendChild(copyBtn(apiReqs.map(r => `${r.method} ${r.path}`).join("\n"), "Copy All"));
    for (const r of apiReqs.slice(-30).reverse()) {
      const statusColor = r.status >= 400 ? "#b71c1c" : r.status >= 300 ? "#e65100" : "#2e7d32";
      const d = document.createElement("div");
      d.className = "small mono";
      d.style.cssText = "margin:2px 0;display:flex;gap:6px;align-items:center";
      d.innerHTML = `<span style="color:${statusColor};min-width:24px">${r.status || "?"}</span>
        <b style="min-width:34px">${esc(r.method)}</b>
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.url)}">${esc(r.path)}</span>
        ${r.params?.length ? `<span class="chip" style="font-size:9px">${r.params.length} params</span>` : ""}`;
      body.appendChild(d);
    }
  }, false);
}

async function render(){
  const root=document.getElementById("root");
  // Preserve scroll position across re-renders
  const scrollY = root.parentElement?.scrollTop || 0;
  const s=await chrome.runtime.sendMessage({type:"getState", tabId:TAB_ID}); root.innerHTML="";
  if(!s){ root.textContent="No data yet. Reload the page."; return; } if(s.error){ root.textContent=`Error: ${s.error}`; return; }

  root.appendChild(headerCard(s));

  // Progress bar (auto-hides when complete)
  const prog = progressCard(s);
  if (prog) root.appendChild(prog);

  // LEADS - the main value: actionable attack paths
  const lCard = leadsCard(s);
  if (lCard) root.appendChild(lCard);

  root.appendChild(highlightsCard(s));

  // Critical findings first: subdomain takeover
  const tkCard = takeoverCard(s);
  if (tkCard) root.appendChild(tkCard);

  // Auth surfaces
  const aCard = authCard(s);
  if (aCard) root.appendChild(aCard);

  root.appendChild(headersCard(s.headers));

  // Security analysis cards
  if(s.tlsInfo || s.corsFindings || s.httpMethods || s.sensitiveFiles || s.cookieSecurity) {
    if(s.tlsInfo) root.appendChild(tlsCard(s));
    root.appendChild(securityChecksCard(s));
  }

  root.appendChild(techCard(s));

  // Intelligence gathering
  if(s.intel && (s.intel.emails?.length || s.intel.phones?.length || s.intel.socialLinks?.length || s.intel.comments?.length)) {
    root.appendChild(intelCard(s));
  }

  // Forms analysis
  if(s.forms && s.forms.length > 0) {
    root.appendChild(formsCard(s));
  }

  if(s.aiCorrelation) root.appendChild(aiCorrelationCard(s));
  root.appendChild(ipsCard(s));
  root.appendChild(domainCard(s));
  root.appendChild(mailCard(s));
  root.appendChild(textsCard(s));
  root.appendChild(secretsCard(s));

  // JS endpoints and params
  const epCard = endpointsCard(s);
  if (epCard) root.appendChild(epCard);
  const pmCard = paramsCard(s);
  if (pmCard) root.appendChild(pmCard);

  // Wayback Machine URLs
  const wbCard = waybackCard(s);
  if (wbCard) root.appendChild(wbCard);

  root.appendChild(subsCard(s));
  if(s.aiEnhancedSubs && s.aiEnhancedSubs.length > 0) root.appendChild(aiEnhancedSubsCard(s));
  // Passive capture cards
  const reqCard = requestLogCard(s);
  if (reqCard) root.appendChild(reqCard);
  const pvCard = pagesVisitedCard(s);
  if (pvCard) root.appendChild(pvCard);

  root.appendChild(externalToolsCard(s));
  root.appendChild(exportCard(s));

  // Restore scroll position
  if (scrollY) requestAnimationFrame(() => { root.parentElement.scrollTop = scrollY; });
}

function externalToolsCard(s){
  const card=el(`<div class="card"><h3>🛠️ External Tools</h3><div class="small" style="margin-bottom:12px">Quick access to complementary reconnaissance tools</div></div>`);

  const tools = [
    {
      name: "Burp Suite Export",
      desc: "Export subdomains to Burp Suite scope",
      action: "burp",
      icon: "🎯"
    },
    {
      name: "Nuclei Template",
      desc: "Generate nuclei scan targets file",
      action: "nuclei",
      icon: "🔬"
    },
    {
      name: "Subfinder Format",
      desc: "Export subdomains in subfinder format",
      action: "subfinder",
      icon: "🔍"
    },
    {
      name: "Nmap Scan File",
      desc: "Generate nmap target list",
      action: "nmap",
      icon: "🌐"
    },
    {
      name: "HTTPX Input",
      desc: "Export URLs for httpx scanning",
      action: "httpx",
      icon: "📡"
    },
    {
      name: "Bookmarklet: Quick Recon",
      desc: "Drag to bookmarks bar for instant recon",
      action: "bookmarklet",
      icon: "⚡"
    }
  ];

  for(const tool of tools){
    const row = el(`<div class="row" style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #eee">
      <div>
        <div><span style="font-size:16px;margin-right:6px">${tool.icon}</span><b>${esc(tool.name)}</b></div>
        <div class="small">${esc(tool.desc)}</div>
      </div>
      <button class="btn" data-tool="${tool.action}" style="margin-left:12px;white-space:nowrap">
        ${tool.action === 'bookmarklet' ? 'Get Code' : 'Export'}
      </button>
    </div>`);
    card.appendChild(row);
  }

  // Add event listeners
  card.querySelectorAll("button[data-tool]").forEach(btn => {
    btn.addEventListener("click", () => {
      const tool = btn.dataset.tool;

      if(tool === "burp"){
        exportBurpScope(s);
      } else if(tool === "nuclei"){
        exportNuclei(s);
      } else if(tool === "subfinder"){
        exportSubfinder(s);
      } else if(tool === "nmap"){
        exportNmap(s);
      } else if(tool === "httpx"){
        exportHTTPX(s);
      } else if(tool === "bookmarklet"){
        showBookmarklet();
      }
    });
  });

  return card;
}

// Export functions for external tools
function exportBurpScope(s){
  const scope = {
    target: {
      scope: {
        advanced_mode: true,
        exclude: [],
        include: []
      }
    }
  };

  // Add main domain
  if(s.domain){
    scope.target.scope.include.push({
      enabled: true,
      host: s.domain,
      protocol: "any"
    });
  }

  // Add subdomains
  const subs = s.quickSubs || [];
  subs.forEach(sub => {
    scope.target.scope.include.push({
      enabled: true,
      host: sub.subdomain,
      protocol: "any"
    });
  });

  // Add AI-filtered subs
  const aiSubs = s.aiEnhancedSubs || [];
  aiSubs.forEach(sub => {
    scope.target.scope.include.push({
      enabled: true,
      host: sub.subdomain,
      protocol: "any"
    });
  });

  downloadFile(JSON.stringify(scope, null, 2), `burp-scope-${s.domain}-${Date.now()}.json`, 'application/json');
}

function exportNuclei(s){
  const targets = [];

  if(s.url) targets.push(s.url);

  const subs = s.quickSubs || [];
  subs.forEach(sub => {
    targets.push(`https://${sub.subdomain}`);
    targets.push(`http://${sub.subdomain}`);
  });

  downloadFile(targets.join('\n'), `nuclei-targets-${s.domain}-${Date.now()}.txt`, 'text/plain');
}

function exportSubfinder(s){
  const subs = [];

  if(s.domain) subs.push(s.domain);

  const quickSubs = s.quickSubs || [];
  quickSubs.forEach(sub => subs.push(sub.subdomain));

  const aiSubs = s.aiEnhancedSubs || [];
  aiSubs.forEach(sub => subs.push(sub.subdomain));

  // Deduplicate
  const unique = [...new Set(subs)];

  downloadFile(unique.join('\n'), `subdomains-${s.domain}-${Date.now()}.txt`, 'text/plain');
}

function exportNmap(s){
  const targets = [];

  // Add IPs
  const ips = s.ips || [];
  ips.forEach(ip => targets.push(ip));

  // Add subdomains
  const subs = s.quickSubs || [];
  subs.forEach(sub => targets.push(sub.subdomain));

  downloadFile(targets.join('\n'), `nmap-targets-${s.domain}-${Date.now()}.txt`, 'text/plain');
}

function exportHTTPX(s){
  const urls = [];

  if(s.url) urls.push(s.url);

  const subs = s.quickSubs || [];
  subs.forEach(sub => {
    urls.push(`https://${sub.subdomain}`);
    urls.push(`http://${sub.subdomain}`);
  });

  downloadFile(urls.join('\n'), `httpx-urls-${s.domain}-${Date.now()}.txt`, 'text/plain');
}

function showBookmarklet(){
  // Bookmarklet that performs lightweight inline recon (no extension APIs needed)
  const code = `javascript:void(function(){var d=document.domain,h=location.href,o='';o+='Domain: '+d+'\\n';o+='URL: '+h+'\\n';var c=document.querySelectorAll('script[src]');o+='External scripts: '+c.length+'\\n';c.forEach(function(s){o+='  '+s.src+'\\n'});var m=document.querySelector('meta[name=generator]');if(m)o+='Generator: '+m.content+'\\n';var f=document.querySelectorAll('form');o+='Forms: '+f.length+'\\n';f.forEach(function(x,i){o+='  '+(x.method||'GET').toUpperCase()+' -> '+(x.action||'(self)')+'\\n'});var e=document.documentElement.outerHTML.match(/[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Z|a-z]{2,}/g);if(e&&e.length)o+='Emails: '+[...new Set(e)].join(', ')+'\\n';var cm=document.documentElement.outerHTML.match(/<!--[\\s\\S]*?-->/g);if(cm)o+='HTML comments: '+cm.length+'\\n';var w=document.createElement('div');w.style.cssText='position:fixed;top:10px;right:10px;z-index:999999;background:#111;color:#0f0;padding:16px;border-radius:8px;font:12px monospace;max-width:500px;max-height:80vh;overflow:auto;white-space:pre-wrap';w.textContent=o;var b=document.createElement('button');b.textContent='Close';b.style.cssText='margin-top:8px;padding:4px 12px;cursor:pointer';b.onclick=function(){w.remove()};w.appendChild(b);document.body.appendChild(w)}())`;

  const modal = el(`<div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center" id="bookmarkletModal">
    <div style="background:white;padding:24px;border-radius:8px;max-width:600px;width:90%">
      <h3 style="margin-top:0">Quick Recon Bookmarklet</h3>
      <p class="small">Drag this link to your bookmarks bar, or copy the code. This runs a lightweight page-only recon (no extension required):</p>
      <div style="background:#f5f5f5;padding:12px;border-radius:4px;margin:12px 0;word-break:break-all;font-family:monospace;font-size:11px">
        <a href="${esc(code)}" style="color:#1976d2;text-decoration:none">SnailSploit Quick Recon</a>
      </div>
      <p class="small"><b>Detects:</b> scripts, forms, emails, HTML comments, generator meta. For full recon, use the extension popup.</p>
      <button class="btn" id="closeModal" style="margin-top:12px">Close</button>
      <button class="btn" id="copyCode" style="margin-top:12px;margin-left:8px">Copy Code</button>
    </div>
  </div>`);

  document.body.appendChild(modal);

  modal.querySelector('#closeModal').addEventListener('click', () => modal.remove());
  modal.querySelector('#copyCode').addEventListener('click', () => {
    navigator.clipboard.writeText(code);
    alert('Bookmarklet code copied to clipboard!');
  });

  modal.addEventListener('click', (e) => {
    if(e.target === modal) modal.remove();
  });
}

function downloadFile(content, filename, mimeType){
  const blob = new Blob([content], {type: mimeType});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCard(s){
  const card=el(`<div class="card"><h3>Export</h3><button class="btn" id="exportBtn">Export Results as JSON</button> <button class="btn" id="exportTxtBtn">Export as Text Report</button></div>`);
  card.querySelector("#exportBtn").addEventListener("click", ()=>{
    const dataStr = JSON.stringify(s, null, 2);
    const blob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon-${s.domain||'report'}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
  card.querySelector("#exportTxtBtn").addEventListener("click", ()=>{
    let report = `SnailSploit Recon Report\n${'='.repeat(50)}\n\n`;
    report += `Domain: ${s.domain||'N/A'}\nURL: ${s.url||'N/A'}\nTimestamp: ${new Date(s.ts||Date.now()).toISOString()}\n\n`;
    if(s.highlights?.items?.length){
      report += `Highlights:\n${'-'.repeat(30)}\n`;
      s.highlights.items.forEach(it=>{ report += `- [${(it.severity||'').toUpperCase()}] ${it.title||''}: ${it.detail||''}\n`; });
      report += `\n`;
    }
    report += `Security Headers:\n${'-'.repeat(30)}\n`;
    Object.entries(s.headers||{}).forEach(([k,v])=>report+=`${k}: ${v||'missing'}\n`);
    report += `\nIP Addresses: ${(s.ips||[]).join(', ')}\n`;
    if(s.quickSubs?.length) report += `\nSubdomains (${s.quickSubs.length}):\n${s.quickSubs.map(x=>x.subdomain).join('\n')}\n`;
    if(s.secrets?.length) report += `\nSecrets Found: ${s.secrets.length} sources\n`;
    if(s.waybackUrls?.length) report += `\nWayback Machine URLs (${s.waybackUrls.length} interesting):\n${s.waybackUrls.join('\n')}\n`;
    if(s.subdomainTakeovers?.length) report += `\nSubdomain Takeovers:\n${s.subdomainTakeovers.map(t=>`${t.subdomain} → ${t.service} (${t.cname})`).join('\n')}\n`;
    if(s.jsEndpoints?.length) report += `\nJS Endpoints (${s.jsEndpoints.length}):\n${s.jsEndpoints.join('\n')}\n`;
    if(s.authSurfaces?.length) report += `\nAuth Surfaces:\n${s.authSurfaces.map(a=>`${a.type}: ${a.detail}`).join('\n')}\n`;
    if(s._requestLog?.length) report += `\nPassive Request Log (${s._requestLog.length}):\n${s._requestLog.map(r=>`${r.method} ${r.status} ${r.url}`).join('\n')}\n`;
    if(s._domainStats?.pagesVisited?.length) report += `\nPages Browsed (${s._domainStats.pagesVisited.length}):\n${s._domainStats.pagesVisited.map(p=>p.url).join('\n')}\n`;
    if(s.leads?.length) report += `\nAttack Leads:\n${s.leads.map(l=>`[P${l.priority}] ${l.category}: ${l.title} — ${l.detail}`).join('\n')}\n`;
    const blob = new Blob([report], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon-${s.domain||'report'}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  });
  return card;
}

// Debounce render to prevent flickering from rapid state updates
let renderTimer = null;
function debouncedRender() {
  if (renderTimer) clearTimeout(renderTimer);
  renderTimer = setTimeout(() => { renderTimer = null; render(); }, 250);
}

(async()=>{
  TAB_ID=await getTabId();
  await render();
  chrome.storage.onChanged.addListener((changes, area) => { if(area!=="session") return; const key=`tab:${TAB_ID}`; if(changes[key]) debouncedRender(); });
})();
