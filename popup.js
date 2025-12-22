
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
  root.appendChild(techCard(s));
  if(s.aiCorrelation) root.appendChild(aiCorrelationCard(s));
  root.appendChild(ipsCard(s));
  root.appendChild(domainCard(s));
  root.appendChild(mailCard(s));
  root.appendChild(textsCard(s));
  root.appendChild(secretsCard(s));
  root.appendChild(subsCard(s));
  if(s.aiEnhancedSubs && s.aiEnhancedSubs.length > 0) root.appendChild(aiEnhancedSubsCard(s));
  root.appendChild(exportCard(s));
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
