# Changelog

All notable changes to SnailSploit Recon Extension will be documented in this file.

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
