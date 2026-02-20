
<div align="center">

# 🐌 SnailSploit Recon Extension

### *Slow shell. Fast recon. Zero clicks.*

[![Chrome MV3](https://img.shields.io/badge/Chrome-MV3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![SnailSploit](https://img.shields.io/badge/SnailSploit-Red_Team-red?style=for-the-badge)](https://github.com/SnailSploit)

<br>

**A passive recon engine that builds intelligence while you browse.**<br>
No scans to launch. No buttons to click. Just browse the target — come back to leads.

<img width="612" height="606" alt="SnailSploit Recon" src="https://github.com/user-attachments/assets/1ec45fbc-e1f0-4a77-97d9-d62db2ee4560" />

</div>

---

## How It Works

```
You browse target.com normally.

Page 1:  /login       → Captures auth forms, OAuth providers, inline JS
Page 2:  /dashboard   → Extracts API endpoints from fetch() calls
Page 3:  /api/docs    → Logs Swagger routes, parameters, methods
Page 4:  /settings    → Finds debug flags, admin paths in JS configs
  ...

Open popup → 47 endpoints, 12 params, 3 attack leads waiting.
```

SnailSploit Recon is a **passive collector**. It silently captures everything as you browse — scripts, API calls, forms, headers, cookies, redirects — and correlates them into **prioritized attack leads** with copy-pasteable commands.

**Browse 1 page → basic intel. Browse 20 pages → a full dossier.**

---

## What Makes This Different

| Traditional Recon Tools | SnailSploit Recon |
|---|---|
| Run a scan, wait, read output | Browse naturally, check back anytime |
| Per-page, no memory | **Accumulates across pages, tabs, sessions** |
| Shows raw data (IPs, headers) | Shows **attack leads** with commands |
| You figure out what to do | Tells you **where to look and why** |
| One-shot, then forgotten | **Persistent domain store** survives browser restarts |
| Active scanning only | **Passive capture** of API calls, redirects, cookies |

---

## Attack Leads Engine

The lead engine correlates ALL findings and outputs prioritized attack paths:

```
🎯 ATTACK LEADS

P1 CRITICAL │ Source Code Leak
   .git/config accessible — git-dumper to extract full source
   → git-dumper https://target.com/.git/ ./repo              [Copy]

P1 CRITICAL │ Subdomain Takeover
   dev.target.com CNAME → old-app.herokuapp.com (unclaimed)
   → Register on Heroku to claim                             [Copy]

P2 HIGH │ Hidden Endpoints
   14 admin/internal routes found in JS bundles
   → /api/admin/users, /internal/config, /debug/logs          [Copy]

P2 HIGH │ Injection Points
   user_id, redirect, file_path — high-interest params
   → user_id=FUZZ&redirect=FUZZ                               [Copy]

P3 MEDIUM │ XSS / Clickjacking
   No CSP or X-Frame-Options detected
   → <iframe src="https://target.com"></iframe>               [Copy]
```

Each lead includes: **severity, category, detail, and a copy-pasteable action.**

---

## Full Feature Set

### Passive Capture (Zero-Click)
- **Request logging** — XHR/fetch calls captured with status codes, methods, params as you browse
- **Page breadcrumbs** — tracks every page visited with title and timestamp
- **Domain accumulation** — all findings persist in `chrome.storage.local` across tabs/sessions
- **Cookie tracking** — monitors cookie changes across pages
- **Redirect chain capture** — logs 301/302 redirects passively

### Recon Intelligence
- **JS endpoint extraction** — parses `fetch()`, `axios`, `router.get()`, config assignments
- **URL parameter discovery** — mines params from Wayback Machine + JS code, flags injectable ones
- **Auth surface detection** — login forms, OAuth (Google/Facebook/GitHub), SSO (Auth0/Okta/Cognito/Keycloak)
- **JS config leaks** — debug flags, non-prod environments, admin paths, WebSocket URLs, cloud buckets
- **Subdomain takeover detection** — CNAME → unclaimed service check (Heroku, S3, GitHub Pages, Azure, etc.)
- **Wayback Machine URLs** — historical endpoints, forgotten admin panels, old API routes

### Infrastructure Analysis
- **Security headers** — CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy
- **TLS certificate intel** — issuer, expiry, SANs, protocol version
- **IP enrichment** — Shodan InternetDB (ports/CPEs), IP geolocation, RDAP, reverse DNS
- **CPE → CVE mapping** — auto-lookup known vulnerabilities from detected software
- **DNS posture** — DMARC, SPF, DKIM, MX records
- **WAF detection** — Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, ModSecurity, and more

### Active Checks
- **CORS misconfiguration** — reflected origin + credentials = account takeover
- **HTTP methods** — PUT/DELETE/TRACE/CONNECT probing
- **Sensitive files** — `.git/`, `.env`, `robots.txt`, `security.txt`, `swagger.json`, `graphql`
- **Cookie security** — HttpOnly, Secure, SameSite analysis per cookie

### Secrets Scanner
- **50+ regex patterns** — AWS keys, GitHub tokens, JWTs, bearer tokens, private keys, Stripe, Slack, Twilio, etc.
- **Multi-source** — inline scripts, external JS (parallelized), HTML document, source maps
- **API route extraction** — finds `/api/`, `/v1/`, `/graphql`, `/admin/` paths in JS

### Tech Fingerprinting
- **60+ technology patterns** — CDNs, CMS, frameworks, hosting, languages, analytics
- **JS library detection** — jQuery, React, Angular, Vue, Bootstrap, Lodash with version extraction
- **Favicon hash** — Shodan-compatible mmh3 hash for passive recon

### AI Integration (Optional)
- **GPT-powered subdomain recon** — AI-suggested subdomains based on industry patterns
- **AI correlation analysis** — connects findings into risk narratives
- **VirusTotal enrichment** — per-subdomain reputation scoring (API key required)

### UX
- **Scan progress bar** — real-time phase tracking, auto-hides when complete
- **Copy-to-clipboard** — one-click copy on IPs, subdomains, emails, endpoints, params
- **Collapsible cards** — reduce scroll fatigue on data-heavy reports
- **Debounced rendering** — no flickering from rapid background updates
- **Scroll position preservation** — stays where you were across re-renders
- **Domain stats bar** — accumulated totals at a glance (pages, endpoints, secrets, time tracking)
- **JSON + Text export** — full report export including leads, request log, and all accumulated data
- **External tool links** — Burp Suite scope export, Nuclei templates, one-click tool pivots

---

## Install

```bash
# Clone
git clone https://github.com/SnailSploit/SnailSploit_Recon_extension.git

# Load in Chrome
# 1. Go to chrome://extensions
# 2. Enable "Developer mode" (top right)
# 3. Click "Load unpacked"
# 4. Select the cloned folder
```

### Optional Setup
- **VirusTotal API key** — Options page → paste key for subdomain reputation
- **OpenAI API key** — Options page → paste key for AI-powered recon

---

## Usage

1. **Install the extension**
2. **Browse any target site normally** — visit pages, click around, use the app
3. **Click the extension icon anytime** to see accumulated findings
4. **Check back periodically** — the longer you browse, the more intel accumulates
5. **Export** when ready — JSON or text report with everything captured

### What the Popup Shows

| Section | What It Tells You |
|---|---|
| **Domain Stats Bar** | Pages browsed, endpoints found, secrets, tracking duration |
| **Progress Bar** | Which scan phases are still running |
| **Attack Leads** | P1/P2/P3 prioritized attack paths with commands |
| **Pentester Highlights** | Critical findings at a glance |
| **Auth Surfaces** | Login forms, OAuth providers, SSO integrations |
| **JS Endpoints** | API routes extracted from JavaScript (admin routes highlighted) |
| **URL Parameters** | Injectable params flagged with "HIGH INTEREST" |
| **Wayback URLs** | Historical endpoints from the Wayback Machine |
| **API Calls Observed** | Passively captured requests with status codes |
| **Pages Browsed** | Breadcrumb trail of your browsing session |
| **Security Checks** | TLS, CORS, cookies, sensitive files, HTTP methods |

---

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ content.js  │────▶│     sw.js         │────▶│   popup.js      │
│ (per page)  │     │ (service worker)  │     │ (on-demand UI)  │
│             │     │                   │     │                 │
│ • Scripts   │     │ • Analyze         │     │ • Leads card    │
│ • Forms     │     │ • Accumulate      │     │ • Progress bar  │
│ • Meta tags │     │ • Lead gen        │     │ • Domain stats  │
│ • HTML      │     │ • Passive capture │     │ • Copy buttons  │
│ • Title     │     │ • Domain store    │     │ • Collapsible   │
└─────────────┘     └──────────────────┘     └─────────────────┘
                           │
                    ┌──────┴──────┐
                    │   Storage   │
                    │             │
                    │ session:    │ ← per-tab live state
                    │   tab:{id}  │
                    │             │
                    │ local:      │ ← persistent domain store
                    │   domain:{} │    (survives restarts)
                    └─────────────┘
```

### Data Sources (No API Keys Required)
| Source | Data |
|---|---|
| Shodan InternetDB | Open ports, CPEs, hostnames |
| crt.sh | Certificate transparency subdomains |
| BufferOver | DNS subdomain aggregation |
| Anubis (jldc.me) | Subdomain intelligence |
| AlienVault OTX | Passive DNS subdomain discovery |
| Wayback Machine CDX | Historical URL discovery |
| CIRCL CVE / NVD | CPE → CVE vulnerability mapping |
| Google/Cloudflare DoH | DNS resolution (A/AAAA/CNAME) |
| ipwho.is / ipapi.co | IP geolocation |
| RDAP | Domain and IP registration data |

---

## Legal

This tool is for **authorized security testing, research, and education only**.

- Always get written permission before testing targets you don't own
- Respect `robots.txt`, rate limits, and terms of service
- The passive capture features collect only data visible to your browser
- No credentials are stored or transmitted — API keys stay in local storage

---

<div align="center">

**Built for the SnailSploit red team community.**

*Slow and steady wins the shell.*

🐌

</div>
