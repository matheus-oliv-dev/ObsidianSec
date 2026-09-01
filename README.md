# 🛡️ ObsidianSec // Autonomous DevSecOps & Edge Security CLI

<div align="center">

[![npm version](https://img.shields.io/npm/v/obsidiansec.svg?color=10b981&style=for-the-badge)](https://www.npmjs.com/package/obsidiansec)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests: 142 Passed](https://img.shields.io/badge/Tests-142%20Passed%20(100%25)-10b981.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ObsidianSec)
[![CVSS: 0.0](https://img.shields.io/badge/Quality%20Gate-CVSS%200.0%20(Secure)-black.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ObsidianSec)

**The Autonomous Edge Defense, DevSecOps Quality Gate & Anti-Phishing CLI.**  
*Zero setup. Instant audit. Automated patches for 10+ server and web frameworks.*

</div>

---

## ⚡ Quick Start (No Install Needed)

Run an immediate tactical edge audit on any web application directly from your terminal:

```bash
# 🔍 1. Run live security header, CORS & attack chain audit
npx obsidiansec audit https://your-website.com

# 🛑 2. Use as a CI/CD Quality Gate (Fails build if security grade < A)
npx obsidiansec audit https://staging.your-website.com --min-grade=A

# 📧 3. Inspect DNS, Email Anti-Phishing & Spoofing (SPF, DMARC, DNSSEC)
npx obsidiansec dns your-domain.com

# 📊 4. Output structured JSON for automation & Slack/Discord webhooks
npx obsidiansec audit https://your-website.com --json
```

---

## 🏛️ Core Features

### 1. 🛡️ Tactical Edge Probe & Security Headers Analyzer
Audits critical HTTP isolation headers with educational point breakdowns:
- **Content-Security-Policy (CSP)**: Deep AST inspection, `'unsafe-inline'`, nonce validation and XSS prevention.
- **X-Frame-Options & COOP**: Zero-clickjacking defense and process-level origin isolation.
- **Strict-Transport-Security (HSTS)**: Enforcement of TLS 1.3 encryption with preload requirements.
- **X-Content-Type-Options & Permissions-Policy**: Strict MIME sniffing and device sensor lockdown.

### 2. ⚡ Passive Session & CORS Inspector (Burp Suite Engine)
- **Cookie Security**: Audits `HttpOnly`, `Secure`, `SameSite=Strict/Lax` and W3C `__Host-` / `__Secure-` prefixes.
- **CORS Matrix**: Detects dangerous wildcards (`Access-Control-Allow-Origin: *` with credentials), origin reflection vulnerabilities, and missing `Vary: Origin` headers.

### 3. 🕸️ BloodHound Attack Chain Graph
Translates missing headers into an **actionable MITRE ATT&CK exploitation graph**, showing developers how an attacker chains a missing CSP into session hijacking (`T1539`) and account takeover (`T1078`).

### 4. 📧 DNS & Email Security Inspector (Anti-Phishing & Anti-Spoofing)
- **SPF (`RFC 7208`)**: Validates hardfail mechanisms (`-all` vs dangerous `+all`) and DNS lookup limits (< 10).
- **DMARC (`RFC 7489`)**: Enforces reject policies (`p=reject`) against Business Email Compromise (BEC).
- **DNSSEC**: Verifies cryptographic DNS zone signing.

### 5. 🔑 Crypto & Shannon Entropy Engine (Hashcat Model)
- Password Shannon entropy calculation with brute-force crack time estimates on RTX 4090 GPU clusters.
- JWT secret brute-force auditor (minimum 256-bit entropy check).

### 6. 🔧 Instant Virtual Patching (Ready for Merge)
Provides hardened, ready-to-paste reverse configuration snippets for:
- **Nginx** (`security.conf`)
- **Apache** (`.htaccess`)
- **Cloudflare Edge** (Transform Rules)
- **Vercel** (`vercel.json`)
- **Node.js Express / Helmet**
- **Python FastAPI & Django**
- **Go Fiber**
- **PHP Laravel**
- **Java Spring Boot**
- **C# ASP.NET Core**

---

## 🤖 CI/CD Quality Gate Example (GitHub Actions)

Block vulnerable pull requests before deploying to production:

```yaml
name: ObsidianSec Quality Gate

on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Audit Preview Deployment
        run: |
          npx obsidiansec audit https://preview.myapp.com --min-grade=A
```

---

## 🏆 Dynamic GitHub README Badges

Add a live security rating badge to your GitHub repository `README.md`:

```markdown
[![ObsidianSec Security Grade](https://obsidiansec.dev/api/badge?grade=A%2B&score=100)](https://obsidiansec.dev)
```

---

## 🧪 Automated Testing & DevSecOps

ObsidianSec is tested with **23 Vitest suites and 142 automated tests**:
- **DAST Fuzzer & BOLA/IDOR Pentest**
- **OWASP API Top 10 & LLM Top 10**
- **SSRF 169.254.169.254 Cloud Metadata Shield**
- **Chaos Engineering & DoS Stress Resilience**
- **W3C Trusted Types & DOM XSS Hardening**

```bash
# Run test suite
npm test

# Run multi-agent DevSecOps squad
npm run security:audit
```

---

## 📜 License & Compliance

MIT License © 2026 ObsidianSec Team.  
Compliant with **LGPD (Lei nº 13.709/2018)**, **NIST SP 800-207**, and **OWASP ASVS 4.0**.
