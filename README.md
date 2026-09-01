# 🛡️ ObsidianSec // Autonomous DevSecOps & Edge Security Arsenal

<div align="center">

[![npm version](https://img.shields.io/npm/v/obsidiansec.svg?color=10b981&style=for-the-badge)](https://www.npmjs.com/package/obsidiansec)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests: 166 Passed](https://img.shields.io/badge/Tests-166%20Passed%20(100%25)-10b981.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ObsidianSec)
[![Security Tools: 15 Engines](https://img.shields.io/badge/Arsenal-15%20Engines%20in%201%20CLI-blueviolet.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ObsidianSec)
[![Quality Gate](https://img.shields.io/badge/CI%2FCD-Quality%20Gate%20Ready-black.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ObsidianSec)

**The All-In-One DevSecOps, Edge Defense, SAST & Reconnaissance CLI.**  
*Consolidating 15 specialized security tools into a single, zero-dependency `npm install`.*

</div>

---

## ⚡ Quick Start (No Install Needed)

Run any of the 13 tactical commands instantly using `npx`:

```bash
# 🔍 1. Complete Edge Audit (Headers, Cookies, CORS & MITRE Attack Chain)
npx obsidiansec audit https://your-website.com

# 🔒 2. SSL/TLS Certificate & Protocol Security (SSL Labs Engine)
npx obsidiansec ssl https://your-website.com

# 🧬 3. Technology Stack Fingerprinting (Wappalyzer Engine: React, Next.js, Nginx, CDNs)
npx obsidiansec tech https://your-website.com

# 📡 4. HTTP Method Enumeration (Detects dangerous TRACE/XST, PUT, DELETE)
npx obsidiansec methods https://your-website.com

# 🔀 5. Open Redirect Detector (OWASP CWE-601 Parameter Fuzzing)
npx obsidiansec redirects https://your-website.com

# 🛡️ 6. Web Application Firewall Detector (22+ WAFs: Cloudflare, AWS WAF, Fastly, Fortinet)
npx obsidiansec waf https://your-website.com

# 🚪 7. TCP Port Scanner (37 Critical Ports: Redis, Mongo, MSSQL, Oracle, K8s, SMB, VNC)
npx obsidiansec ports your-server-ip-or-domain

# 🔐 8. Secret Hunter & SAST Local (45+ Patterns: AWS, Stripe, Supabase, Slack, Discord, PGP)
npx obsidiansec scan-dir ./

# 🎟️ 9. JWT Token Security Auditor (Detects alg: none, expiration & decodes claims)
npx obsidiansec jwt <your-jwt-token>

# 🌐 10. Passive Subdomain Reconnaissance (Certificate Transparency Logs)
npx obsidiansec subdomains your-domain.com

# 📧 11. DNS & Email Anti-Phishing Suite (SPF, DMARC, DNSSEC)
npx obsidiansec dns your-domain.com

# 🔑 12. Shannon Password Entropy & GPU Cluster Crack Time (Hashcat Model)
npx obsidiansec entropy "YourPasswordHere"

# ⚙️ 13. Generate Scope & AI Budget Config Template
npx obsidiansec init-config
```

---

## 📋 Command Arsenal Matrix

| Command | Category | Engine / Reference | Key Capabilities |
|---|---|---|---|
| `audit <url>` | Edge Security | Mozilla Observatory / Burp | CSP, HSTS, X-Frame-Options, Cookie flags, CORS, MITRE ATT&CK Graph |
| `ssl <url>` | Cryptography | SSL Labs | TLS 1.3/1.2 validation, SAN inspection, weak cipher/hash detection, expiry days |
| `tech <url>` | Reconnaissance | Wappalyzer / BuiltWith | Identifies React, Next.js, Vue, Angular, WordPress, Django, Nginx, Cloudflare |
| `methods <url>` | Protocol Audit | OWASP Testing Guide | Enumerates verbs; detects TRACE (XST vector), unauthenticated PUT/DELETE |
| `redirects <url>` | Web Vulnerability | OWASP CWE-601 | Probes 20+ redirect parameters against malicious external destinations |
| `waf <url>` | Edge Defense | WAFW00F Engine | Identifies 22+ WAF vendors (Cloudflare, AWS, Fastly, Fortinet, Imperva, Akamai) |
| `ports <host>` | Network SAST | Nmap / Shodan Model | Scans 37 critical ports (Databases, Remote Access, K8s, Legacy protocols) |
| `scan-dir [path]` | Code SAST | TruffleHog / Gitleaks Model | 45+ regex patterns for API keys, private keys, database strings, `.env` files |
| `jwt <token>` | Auth Audit | jwt_tool Model | Validates signature presence, `alg: none` bypass, expiration & claim decoding |
| `subdomains <dom>` | OSINT Recon | Subfinder / crt.sh | Passive subdomain enumeration via public Certificate Transparency logs |
| `dns <dom>` | Anti-Phishing | RFC 7208 / 7489 | Audits SPF hardfail mechanisms, DMARC reject policies, and DNSSEC |
| `entropy <pass>` | Cryptanalysis | Shannon Entropy / Hashcat | Bits of entropy, character set diversity & GPU brute-force crack time |
| `init-config` | Configuration | ObsidianSec Core | Generates `obsidiansec.config.json` with authorized scope and AI budget limits |

---

## 🏛️ Architecture & Core Defenses

### 1. 🛡️ Authorized Scope Guard
Prevents accidental audits against forbidden domains (e.g. government, military, unowned infrastructure) with allowlist/blocklist glob patterns:
```json
{
  "scope": {
    "strictMode": false,
    "allowlist": ["localhost", "127.0.0.1", "*.yourcompany.com"],
    "blocklist": ["*.gov.br", "*.mil.br", "*.jus.br"]
  }
}
```

### 2. 🧠 Token Budget Guard & Zero-Token Default
- **100% Free & Local by Default**: Operates without requiring external AI APIs or cloud tokens.
- **SHA-256 Deduplication Cache**: Caches audit findings locally for 72 hours (`0 tokens, 0 network cost` on repeated runs).
- **Circuit Breaker**: Enforces a strict maximum requests-per-hour limit when LLM features are enabled.

### 3. 🕸️ BloodHound MITRE ATT&CK Mapping
Translates missing headers into an **actionable exploitation graph**, demonstrating how an attacker chains missing CSP or CORS into session hijacking (`T1539`) and account takeover (`T1078`).

---

## 🤖 CI/CD Quality Gate Example (GitHub Actions)

Fail pull requests automatically if security standards or perimeter requirements are violated:

```yaml
name: ObsidianSec CI/CD Quality Gate

on: [push, pull_request]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Secret Hunter (SAST)
        run: npx obsidiansec scan-dir ./

      - name: Edge Security Audit (Quality Gate Grade >= A)
        run: npx obsidiansec audit https://staging.yourdomain.com --min-grade=A
```

---

## 🏆 Dynamic GitHub README Badge

Add a live security rating badge to your GitHub repository:

```markdown
[![ObsidianSec Security Grade](https://obsidiansec.dev/api/badge?grade=A%2B&score=100)](https://obsidiansec.dev)
```

---

## 🧪 Automated Testing

ObsidianSec is thoroughly tested with **34 Vitest suites and 166 automated tests (100% GREEN)**:

```bash
# Run complete test suite
npm test

# Build production bundle
npm run build
```

---

## 📜 License & Compliance

MIT License © 2026 Matheus Oliveira & ObsidianSec Contributors.  
Designed in compliance with **OWASP Top 10**, **NIST SP 800-207 (Zero Trust)**, and **CWE Standards**.
