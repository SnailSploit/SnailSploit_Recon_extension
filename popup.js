
let TAB_ID = null;
async function getTabId(){ const [t]=await chrome.tabs.query({active:true,currentWindow:true}); return t?.id; }
function el(html){ const t=document.createElement("template"); t.innerHTML=html.trim(); return t.content.firstChild; }
function esc(s){ return (s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

function headerCard(s){
  const fav = (typeof s.faviconHash==="number") ? `<span class="small">favicon mmh3: <code>${s.faviconHash}</code></span>` : "";
  return el(`<div class="card"><div><b>${esc(s.domain||"")}</b><div class="small">${esc(s.url||"")}</div>${fav}</div></div>`);
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
    card.appendChild(el(`<details class="row"><summary><b>Email Addresses (${intel.emails.length})</b></summary><div>${intel.emails.map(e=>`<code>${esc(e)}</code>`).join(" ")}</div></details>`));
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
  // Parse markdown and display
  const content = s.aiCorrelation.split('\n').map(line => {
    if(line.startsWith('###')) return `<h4 style="margin:8px 0 4px 0;font-size:11px">${esc(line.replace(/^###\s*/,''))}</h4>`;
    if(line.startsWith('##')) return `<h4 style="margin:10px 0 6px 0;font-size:12px;font-weight:bold">${esc(line.replace(/^##\s*/,''))}</h4>`;
    if(line.startsWith('- ')) return `<div class="small" style="margin-left:12px">• ${esc(line.replace(/^-\s*/,''))}</div>`;
    if(line.trim()) return `<div class="small">${esc(line)}</div>`;
    return '';
  }).join('');
  card.innerHTML += content;
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

async function render(){
  const root=document.getElementById("root"); const s=await chrome.runtime.sendMessage({type:"getState", tabId:TAB_ID}); root.innerHTML="";
  if(!s){ root.textContent="No data yet. Reload the page."; return; } if(s.error){ root.textContent=`Error: ${s.error}`; return; }
  root.appendChild(headerCard(s));
  root.appendChild(highlightsCard(s));
  root.appendChild(headersCard(s.headers));

  // New security analysis cards
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
  root.appendChild(subsCard(s));
  if(s.aiEnhancedSubs && s.aiEnhancedSubs.length > 0) root.appendChild(aiEnhancedSubsCard(s));
  root.appendChild(externalToolsCard(s));
  root.appendChild(exportCard(s));
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
  const code = `javascript:(function(){
    const d=document.domain;
    chrome.runtime.sendMessage('${chrome.runtime.id}', {type:'quickRecon',domain:d}, r=>{
      alert('SnailSploit Recon started for: '+d);
    });
  })();`;

  const modal = el(`<div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center" id="bookmarkletModal">
    <div style="background:white;padding:24px;border-radius:8px;max-width:600px;width:90%">
      <h3 style="margin-top:0">Quick Recon Bookmarklet</h3>
      <p class="small">Drag this link to your bookmarks bar, or copy the code:</p>
      <div style="background:#f5f5f5;padding:12px;border-radius:4px;margin:12px 0;word-break:break-all;font-family:monospace;font-size:11px">
        <a href="${esc(code)}" style="color:#1976d2;text-decoration:none">⚡ SnailSploit Quick Recon</a>
      </div>
      <p class="small"><b>Usage:</b> Click the bookmark on any website to instantly trigger reconnaissance.</p>
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

(async()=>{
  TAB_ID=await getTabId();
  await render();
  chrome.storage.onChanged.addListener((changes, area) => { if(area!=="session") return; const key=`tab:${TAB_ID}`; if(changes[key]) render(); });
})();
