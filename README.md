# SnailSploit Recon Extension

**SnailSploit Recon** is a Chrome MV3 extension for instant recon the moment you land on a site. It paints fast and then streams results as they arrive.

## Features
- **Security headers** with layered fallback (webRequest → HEAD → tiny GET).
- **IP intel** (DoH A/AAAA, rDNS, RDAP, IP whois fallback ipwho.is→ipapi.co).
- **Shodan InternetDB** (no key) for ports/CPEs, plus **CPE→CVE enrichment** (CIRCL → NVD).
- **Subdomains** from crt.sh + BufferOver + Anubis, live-resolved (A/AAAA).
- **Secrets scanner** (inline + ≤12 external + main HTML + .map) with pragmatic regexes.
- **Tech fingerprints** (headers/meta/DOM hints + favicon mmh3).
- Optional **VirusTotal** subdomain enrichment (provide API key in Options).

## Install (developer mode)
1. Download the ZIP from Releases or build locally.
2. Unzip → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the folder.
3. (Optional) Open the Options page and paste your VT API key.

## Notes
- No `chrome.dns` required; works on Stable channel.
- Network calls are short-timeout & capped for performance.
- For security research & recon. Respect target policies and laws.

**Built with ❤️ for the SnailSploit red team community.**
