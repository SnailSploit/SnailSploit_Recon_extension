# Changelog

All notable changes to SnailSploit Recon Extension will be documented in this file.

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
