# Changelog

All notable changes to SnailSploit Recon Extension will be documented in this file.

## [2.0.0] - 2025-12-30 - GOLD STANDARD PENTEST TOOLKIT 🎯⚡

### 🚀 Major Release: Comprehensive Security Analysis Overhaul

This release transforms SnailSploit Recon into a **professional-grade penetration testing reconnaissance toolkit**, adding **15+ new security analysis features** and major performance optimizations. The extension now collects significantly more actionable intelligence for red team operations.

### 🔐 New Security Analysis Features

#### TLS/SSL Certificate Intelligence
- **Certificate details extraction**: Issuer, expiry dates, serial numbers
- **Subject Alternative Names (SANs)**: Discover additional domains from certificates
- **Expiry monitoring**: Visual warnings for expiring/expired certificates (color-coded)
- **Subdomain intelligence**: Extract domains from certificate transparency logs
- **Risk assessment**: Automatic flagging of expired or soon-to-expire certificates

#### CORS Misconfiguration Detection ⚠️
- **Wildcard origin testing**: Detect `Access-Control-Allow-Origin: *`
- **Reflected origin detection**: Test for dangerous origin reflection
- **Credentials exposure**: Flag CORS with `Access-Control-Allow-Credentials: true`
- **Null origin bypass**: Detect sandbox escape vectors
- **Critical severity flagging**: Highlight credential-leaking CORS configs

#### Cookie Security Analysis 🍪
- **HttpOnly flag validation**: Identify XSS-vulnerable cookies
- **Secure flag checking**: Flag cookies transmitted over HTTP
- **SameSite attribute analysis**: Detect CSRF vulnerabilities
- **Per-cookie breakdown**: Detailed security posture for each cookie
- **Issue aggregation**: Summary of insecure cookies

#### HTTP Methods Enumeration
- **OPTIONS probe**: Discover all allowed HTTP methods
- **Dangerous method detection**: Flag PUT, DELETE, TRACE, CONNECT, PATCH
- **Risk highlighting**: Visual warnings for exploitable methods
- **CORS method cross-reference**: Check both Allow and ACAO-Methods headers

#### Sensitive File/Directory Probing 🔍
- **25+ sensitive paths tested**: `.git/`, `.env`, backups, configs, API docs
- **Non-intrusive HEAD requests**: Minimal server impact
- **File metadata collection**: Size, content-type, status codes
- **Critical file highlighting**: Special attention to `.git`, `.env`, database dumps

**Probed files include:**
- `.git/config`, `.git/HEAD` (source code exposure)
- `.env*` variants (API keys, database credentials)
- `package.json`, `composer.json` (dependency intel)
- `web.config`, `.htaccess` (server misconfigurations)
- `phpinfo.php`, `/server-status` (info disclosure)
- `backup.zip`, `database.sql` (data leaks)
- `swagger.json`, `/graphql`, `/api-docs` (API schemas)
- `.DS_Store`, `Dockerfile` (development artifacts)

#### Enhanced WAF Detection 🛡️
- **12+ WAF signatures**: Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, etc.
- **Multi-method detection**: Headers, HTML patterns, cookies
- **Evasion awareness**: Highlights when WAF protection is active

**Detected WAFs:**
- Cloudflare, AWS WAF, Akamai
- Imperva/Incapsula, Sucuri, ModSecurity
- Wordfence, StackPath, Barracuda
- F5 BIG-IP, Fortinet FortiWeb, Citrix NetScaler

#### Intelligence Extraction 📧
- **Email harvesting**: Extract all email addresses from page content
- **Phone number extraction**: Multi-format phone detection (US/international)
- **Social media discovery**: Auto-detect Twitter, LinkedIn, GitHub, Facebook, Instagram, YouTube
- **HTML comments extraction**: Capture developer comments (often leak credentials/TODOs)
- **Contact intelligence**: Build target database for social engineering

#### Form Analysis 📝
- **Password field detection**: Identify authentication forms
- **Hidden input discovery**: Flag suspicious hidden fields
- **Method security**: Warn about GET requests with passwords (critical vuln)
- **Action endpoint mapping**: Track form submission destinations
- **Sensitive form highlighting**: Visual warnings for risky forms

#### JavaScript Library Detection 📚
- **Framework identification**: jQuery, React, Angular, Vue, Bootstrap, Lodash, Moment.js, D3
- **Version extraction**: Identify specific library versions
- **CVE research enablement**: Version info for vulnerability lookups

### ⚡ Performance Optimizations

#### Parallel Subdomain Enumeration (3x Faster!)
- **Concurrent API calls**: crt.sh, BufferOver, Anubis now run simultaneously (was sequential)
- **3x speed improvement**: Subdomain discovery completes in ~3s instead of ~9s
- **Smart result merging**: Deduplication across all sources
- **Progress logging**: Real-time feedback on each source's results

#### Optimized Network Operations
- **Parallel security checks**: TLS, CORS, HTTP methods, cookies, files all run concurrently
- **Better timeout management**: Increased to 8s default (from 3s) for reliability
- **Exponential backoff retry**: Auto-retry failed requests (3 attempts max)
- **Bounded caching**: Memory-safe cache with 128 entry limit

#### Enhanced Highlights System
- **12 highlight slots** (up from 8): More critical findings surfaced
- **15+ new detection rules**: CORS, cookies, files, WAF, TLS, forms, intel
- **Intelligent prioritization**: Critical issues shown first
- **Context-aware severity**: Certificate days, cookie counts, file criticality

### 🎨 UI/UX Improvements

#### New Dashboard Cards
- **TLS Certificate Card**: Full cert details with expiry countdown (color-coded)
- **Security Checks Card**: CORS, HTTP methods, cookies, sensitive files
- **Intelligence Card**: Emails, phones, social links, HTML comments
- **Forms Card**: All forms with security risk indicators
- **Enhanced Tech Card**: Now includes WAF and JS library detection

#### Visual Enhancements
- **Color-coded severity**: Critical (red), High (orange), Medium (yellow), Low (gray)
- **Expandable sections**: Details hidden by default to reduce clutter
- **Risk indicators**: 🔑 for password fields, visual warnings for sensitive forms
- **Certificate expiry colors**: Green (safe), Orange (<30 days), Red (expired)
- **Chip-based display**: Clean, modern UI for tags and findings

### 🔧 Technical Improvements

#### Content Script Enhancement
- **HTML sampling**: Captures up to 100KB of page HTML for analysis
- **Better resource tracking**: Enhanced script and link extraction
- **Throttled updates**: Smart message throttling (500ms) to reduce overhead
- **MutationObserver**: Real-time DOM monitoring for 10 seconds

#### Enhanced Data Collection
**New data points collected:**
- TLS certificate chain and SANs (100+ domains)
- CORS policy configuration
- Cookie security attributes (HttpOnly, Secure, SameSite)
- HTTP method allowlist
- 25+ accessible sensitive files
- WAF presence and type
- 50+ email addresses
- 20+ phone numbers
- 30+ social media profiles
- 20+ HTML comments
- Form structures (10+ forms)
- JS library versions (8+ frameworks)

#### Subdomain Enumeration Optimizations
- **Parallel API fetching**: All sources queried simultaneously
- **Promise.allSettled**: Graceful handling of failed sources
- **Better error recovery**: Individual source failures don't block others
- **Enhanced logging**: Per-source result counts

#### Configuration & Limits
- **Increased timeouts**: More reliable API calls (8s default)
- **Optimized limits**: Balanced between thoroughness and performance
- **Memory safety**: Bounded caches prevent memory leaks
- **Error resilience**: Comprehensive error handling throughout

### 📊 Statistics

**New Features Added:**
- 15+ major security analysis features
- 100+ new lines of reconnaissance logic
- 25+ sensitive file probes
- 12+ WAF detection signatures
- 8+ JavaScript library patterns

**Performance Improvements:**
- 3x faster subdomain enumeration
- 12 parallel security checks (was 7)
- 128-entry bounded caching
- Exponential backoff retry logic

**UI Enhancements:**
- 5 new dashboard cards
- Color-coded severity system
- Expandable detail sections
- Enhanced visual indicators

### 🐛 Bug Fixes
- Fixed subdomain enumeration timeout issues with parallel fetching
- Improved error handling for failed API requests
- Better NDJSON response handling from crt.sh
- Enhanced caching to prevent memory leaks (128 entry bound)
- Fixed cookie parsing for Set-Cookie arrays

### 📝 Developer Notes
- All new checks run asynchronously without blocking main recon flow
- Bounded cache sizes prevent unbounded memory growth
- Retry logic with exponential backoff for flaky APIs
- Comprehensive error logging for debugging
- Clean separation between recon modules

### 🎯 For Penetration Testers & Red Teams

This release makes SnailSploit Recon **essential** for:
- ✅ Initial reconnaissance and attack surface mapping
- ✅ CORS/cookie vulnerability identification
- ✅ Sensitive file discovery (.git, .env, backups)
- ✅ Certificate intelligence and subdomain enumeration
- ✅ WAF detection and evasion planning
- ✅ Email/contact harvesting for social engineering
- ✅ Form analysis for injection testing
- ✅ Technology stack fingerprinting with versions

**Upgrade from 1.x immediately to access these game-changing features!**

---

## [1.1.0] - 2025-11-04 - AI-POWERED RECON 🤖

### 🤖 AI Integration with OpenAI

**Intelligent Host Filtering**
- AI-powered filtering of passive subdomain reconnaissance results
- Automatically identifies relevant hosts vs noise (CDN, cache, test domains)
- Prioritizes production services, APIs, auth endpoints, internal infrastructure
- Smart filtering reduces 100+ hosts down to 10-20 truly relevant targets

**AI Correlation & Security Analysis**
- Automated correlation of all reconnaissance findings
- Security posture assessment (headers, email security, exposed services)
- Attack surface analysis with entry point identification
- Technology stack insights and pattern detection
- Actionable recommendations for further investigation
- Markdown-formatted analysis in popup UI

**Technical Implementation**
- OpenAI GPT-4o-mini integration for cost-effectiveness
- Background processing - doesn't block other reconnaissance
- Graceful degradation if no API key provided
- Configurable via Options page
- API key stored securely in chrome.storage.local

**New UI Components**
- 🤖 "AI Correlation & Insights" card with security analysis
- 🎯 "AI-Filtered Relevant Hosts" card with smart subdomain list
- OpenAI API key configuration field in Options page
- Real-time status indicators during AI processing

### 📊 Enhanced User Experience

**Export Functionality**
- Export all reconnaissance results as JSON
- Export as formatted text report
- One-click download with timestamp
- Preserves all findings including IPs, CVEs, secrets, tech stack

**Configuration**
- Updated options.html with OpenAI API key input
- Enhanced options.js to save/load OpenAI credentials
- config.json template includes openaiApiKey field

### 🔧 Technical Details

**New Functions in sw.js**
- `callOpenAI()` - OpenAI API wrapper with error handling
- `filterHostsWithAI()` - Intelligent subdomain filtering
- `correlateFindings()` - Comprehensive security analysis
- 15-second timeout for AI operations
- Comprehensive error logging and fallback behavior

**Popup UI Enhancements**
- `aiCorrelationCard()` - Renders markdown analysis
- `aiEnhancedSubsCard()` - Displays filtered hosts with IPs
- `exportCard()` - JSON and text export buttons
- Enhanced card rendering with proper formatting

**Updated Permissions**
- Added `https://api.openai.com/*` to host_permissions
- Maintains all existing security and reconnaissance capabilities

## [1.0.0] - 2025-11-04 - PRODUCTION READY 🚀

### 🔥 Major Enhancements - WAY MORE FINDINGS

**Secret Detection - 50+ Patterns (Added 20+ new patterns)**
- AWS: session tokens, access keys, secret keys
- GitHub: OAuth tokens, fine-grained PATs
- GitLab: Personal access tokens
- Databases: MongoDB, PostgreSQL, Redis, MySQL connection strings
- Payment: Square tokens, enhanced Stripe patterns
- Auth: Bearer tokens, Basic auth, SSH keys
- Crypto: Ethereum private keys, Bitcoin addresses
- Cloud Storage: Google Cloud Storage buckets, enhanced S3/Azure patterns
- PaaS: Doppler tokens, enhanced Heroku
- Package Managers: NPM, PyPI, Docker Hub tokens
- Network: IPv6 addresses, enhanced internal IP detection
- API Keys: Enhanced generic API key detection patterns

**Technology Fingerprinting - 60+ Technologies (4x increase)**
- **CDN & Edge (6)**: CloudFront, BunnyCDN, StackPath, Cloudflare, Fastly, Akamai
- **Hosting (5)**: WP Engine, Kinsta, Vercel, Netlify, GitHub Pages
- **CMS (9)**: Wix, Squarespace, Shopify, Magento, PrestaShop, Webflow, WordPress, Drupal, Joomla
- **JS Frameworks (8)**: Angular, React, Vue.js, Svelte, Ember.js, Next.js, Nuxt.js, Gatsby
- **Web Servers (11)**: Nginx, Apache, IIS, Kestrel, LiteSpeed, Tomcat, Jetty, Gunicorn, uWSGI, Passenger, Express.js
- **Languages (10)**: PHP, ASP.NET, Ruby on Rails, Django, Flask, Laravel, Symfony, Spring, JSP/Java, ColdFusion
- **Security (4)**: Sucuri WAF, Wordfence, Plesk, cPanel
- **Analytics**: Google Analytics, Facebook Pixel detection
- **Additional Info**: Cache headers, Runtime info

### 🛡️ Robustness Improvements

**Timeout Increases (2-3x longer for reliability)**
- Fetch operations: 3s → 8s
- DoH resolution: 2.5s → 5s
- CVE lookups (NVD): 4s → 10s
- Subdomain enumeration: Added 8s timeout
- All operations now more forgiving

**Exponential Backoff Retry**
- Automatic retry on failed API calls (up to 3 attempts)
- Smart exponential backoff (500ms → 1s → 2s)
- Max delay cap at 4 seconds
- Applies to: DNS, IP enrichment, CVE lookups, all HTTP requests

**Enhanced Error Handling**
- Comprehensive try-catch blocks throughout
- Detailed error logging (check browser console)
- Graceful degradation when APIs fail
- Better null/undefined checks
- Each recon module isolated - failures don't cascade

**Better Logging**
- `log()` for info messages
- `logError()` for errors with context
- Progress tracking for subdomain enumeration
- CVE enrichment progress logs
- IP resolution detailed logging

### ✨ Features from 0.9.0

## [0.9.0] - 2025-11-04

### Security
- **Fixed XSS vulnerability** in popup.js - Enhanced `esc()` function to properly escape quotes (both single and double) preventing potential XSS attacks
- **Added Content Security Policy** to popup.html and options.html to restrict resource loading and prevent inline script execution
- Improved input sanitization across the extension

### Features
- **Export functionality** - Added ability to export reconnaissance results:
  - Export as JSON for programmatic processing
  - Export as text report for documentation
  - Timestamped filenames for easy organization
- **Enhanced secret detection** - Added 12 new secret patterns:
  - AWS secret access keys
  - Google OAuth tokens (ya29.*)
  - Slack webhooks
  - Twilio tokens
  - Firebase databases
  - Discord tokens and webhooks
  - Telegram bot tokens
  - Heroku API keys
  - Mailgun keys
  - PayPal Braintree tokens
  - Additional API endpoint patterns (v3)

### Code Quality
- **Configuration constants** - Centralized all timeout and limit values in CONFIG object at top of sw.js:
  - All API timeouts configurable (DoH, fetch, VT, CVE, etc.)
  - All limits configurable (IPs, scripts, subdomains, CVEs, etc.)
  - Easier to tune performance and resource usage
- **Improved documentation** - Added comprehensive comments:
  - Explained complex algorithms (MurmurHash3 favicon hashing)
  - Documented CVE enrichment flow (CPE to CVE lookup)
  - Clarified DNS-over-HTTPS usage and benefits
  - Added purpose comments for secret patterns and subdomain enumeration
- **Better logging** - Updated console log prefix from "[ReconRadar]" to "[SnailSploit Recon]" for consistency

### Technical Improvements
- Updated timeouts to use CONFIG constants throughout codebase
- Replaced hardcoded limits with configurable values
- Enhanced code maintainability with better structure
- Added inline comments for complex logic sections

### Changed
- Updated extension description in manifest.json to reflect new features
- Bumped version from 0.8.0 to 0.9.0

## [0.8.0] - Previous Release

Initial stable release with core reconnaissance features:
- Security header analysis
- IP intelligence via Shodan InternetDB
- CVE enrichment from CPEs
- Subdomain enumeration
- Secret scanning
- Technology fingerprinting
- Email security posture checks
- VirusTotal integration
