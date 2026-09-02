import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

export const KNOWLEDGE_BASE = [
  {
    id: "nist-zero-trust-architecture",
    title: "NIST SP 800-207: Zero Trust Architecture in Web and Cloud Environments",
    category: "ZeroTrust",
    difficulty: "Intermediate",
    frameworks: {
      nist: "NIST SP 800-207",
      mitre: "M1030 (Network Segmentation) & M1035 (Execution Prevention)",
      cis: "CIS Control 6 (Access Control Management)",
    },
    summary:
      "The foundational premise of Zero Trust is 'never trust, always verify'. In modern web applications and APIs, this requires continuous authentication, micro-segmentation, and strict identity validation per request.",
    threatMitigated: "Post-compromise lateral movement, long-lived token theft, and unauthorized privilege escalation.",
    mitigations: [
      "Implement mTLS (Mutual TLS) across all internal microservices and pods.",
      "Adopt short-lived access tokens (5-15 minutes max) with cryptographic rotation via DPoP (RFC 9449).",
      "Segment APIs and databases through strict network policies (Kubernetes NetworkPolicies / AWS Security Groups).",
    ],
    codeExample: {
      language: "typescript",
      title: "Zero Trust Middleware with Continuous Context Validation",
      code: `export async function zeroTrustContextGuard(req: Request): Promise<boolean> {
  const clientCert = req.headers.get("x-client-cert");
  const deviceFingerprint = req.headers.get("x-device-fingerprint");
  const token = req.headers.get("authorization");

  if (!token || !deviceFingerprint || !clientCert) return false;
  return true;
}`,
    },
  },
  {
    id: "post-quantum-cryptography",
    title: "Post-Quantum Cryptography (PQC): FIPS 203 ML-KEM & Hybrid Key Exchange",
    category: "Cryptography",
    difficulty: "Advanced",
    frameworks: {
      nist: "NIST FIPS 203 (ML-KEM / Kyber) & FIPS 204 (ML-DSA)",
      owasp: "ASVS V6 (Cryptography)",
    },
    summary:
      "Preparing systems against 'Harvest Now, Decrypt Later' (HNDL) threats, where adversaries intercept encrypted network traffic today to decrypt it using future quantum computers.",
    threatMitigated: "Retroactive decryption of confidential communications and compromise of classic asymmetric algorithms (RSA, ECDH, ECDSA).",
    mitigations: [
      "Enable hybrid X25519Kyber768 (ML-KEM-768) curve support in TLS 1.3 edge proxies.",
      "Establish a Cryptographic Bill of Materials (CBOM) to audit algorithms across your infrastructure.",
    ],
    codeExample: {
      language: "nginx",
      title: "Post-Quantum TLS 1.3 Configuration for Nginx / Cloudflare",
      code: `ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519Kyber768Draft00:X25519:secp256r1;
ssl_prefer_server_ciphers on;`,
    },
  },
  {
    id: "supply-chain-slsa-sbom",
    title: "Supply Chain Security: SLSA Framework & SBOM Validation (CycloneDX)",
    category: "DevSecOps",
    difficulty: "Advanced",
    frameworks: {
      nist: "NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management)",
      owasp: "OWASP CycloneDX & Software Component Verification Standard (SCVS)",
    },
    summary:
      "Defending against third-party dependency compromises, typosquatting attacks, and CI/CD pipeline contamination.",
    threatMitigated: "Backdoor injection into open-source packages, dependency confusion, and build artifact tampering.",
    mitigations: [
      "Generate automated SBOMs in CycloneDX format on every release.",
      "Cryptographically sign build artifacts with Sigstore / Cosign inside GitHub Actions.",
    ],
    codeExample: {
      language: "yaml",
      title: "GitHub Actions Pipeline with SBOM Generation and Cosign Signing",
      code: `name: Supply Chain Defense
on: [push]
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate CycloneDX SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json`,
    },
  },
  {
    id: "container-hardening-cis",
    title: "Container & Cloud-Native Hardening: CIS Benchmarks, Seccomp & Rootless",
    category: "CloudNative",
    difficulty: "Intermediate",
    frameworks: {
      cis: "CIS Docker Benchmark v1.6.0 & CIS Kubernetes Benchmark v1.9.0",
      mitre: "M1047 (Container Sandboxing)",
    },
    summary:
      "Drastically reducing attack surface in Docker containers and Kubernetes pods via least privilege principles and Linux syscall isolation.",
    threatMitigated: "Container escape to the host node, root privilege execution, and kernel vulnerability exploitation.",
    mitigations: [
      "Never run processes as root (UID 0) inside production containers.",
      "Drop all default Linux capabilities (CAP_DROP ALL).",
      "Mount root filesystem as Read-Only (readOnlyRootFilesystem: true).",
    ],
    codeExample: {
      language: "yaml",
      title: "Hardened SecurityContext for Kubernetes Pods",
      code: `securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault`,
    },
  },
  {
    id: "browser-trusted-types-csp3",
    title: "Browser Hardening: CSP Level 3 Strict-Dynamic & W3C Trusted Types",
    category: "ApplicationSecurity",
    difficulty: "Advanced",
    frameworks: {
      owasp: "ASVS V14.4 (HTTP Headers)",
      mitre: "D3-EPH (Execution Prevention in Host)",
    },
    summary:
      "Complete elimination of DOM XSS through W3C Trusted Types policies and CSP with cryptographic nonces and 'strict-dynamic'.",
    threatMitigated: "Malicious script injection into dangerous DOM sinks (innerHTML, eval, document.write).",
    mitigations: [
      "Configure require-trusted-types-for 'script' in Content-Security-Policy.",
      "Implement a TrustedHTML policy using DOMPurify sanitizer.",
    ],
    codeExample: {
      language: "typescript",
      title: "Creating a W3C Trusted Types Policy",
      code: `if (window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy("obsidianPolicy", {
    createHTML: (string) => DOMPurify.sanitize(string),
  });
}`,
    },
  },
  {
    id: "data-privacy-by-design",
    title: "Privacy by Design & Data Protection: Compliance in Web Applications",
    category: "Governance",
    difficulty: "Beginner",
    frameworks: {
      nist: "NIST Privacy Framework v1.0",
      owasp: "ASVS V8 (Data Protection) & OWASP Top 10 Privacy Risks",
      cis: "CIS Control 3 (Data Protection)",
    },
    summary:
      "Practical guidelines for architecting compliant systems: collection minimization, data pseudonymization/anonymization, encryption at rest/transit, and audit-ready logging without PII leakage.",
    threatMitigated: "Personally Identifiable Information (PII) leakage, regulatory fines, and unauthorized data harvesting.",
    mitigations: [
      "Apply the data minimization principle: collect only fields strictly necessary for the business logic.",
      "Encrypt sensitive database columns using AES-256-GCM before persisting.",
      "Anonymize analytics streams and scrub IP addresses or PII from application logs.",
    ],
    codeExample: {
      language: "typescript",
      title: "PII Masking and Anonymization Function for Error Logging",
      code: `export function maskPiiForLogging(email: string, idNumber?: string): { maskedEmail: string; maskedId?: string } {
  const [user, domain] = email.split("@");
  const maskedEmail = user.length > 2 
    ? \`\${user.slice(0, 2)}***@\${domain}\` 
    : \`*@\${domain}\`;

  const maskedId = idNumber ? idNumber.replace(/^(\\d{3})\\.(\\d{3})\\.(\\d{3})-(\\d{2})$/, "$1.***.***-$4") : undefined;

  return { maskedEmail, maskedId };
}`,
    },
  },
];

export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  if (req.method !== "GET") {
    res.status(405).json({ error: "Method not allowed. Use GET." });
    return;
  }

  res.status(200).json({
    total: KNOWLEDGE_BASE.length,
    items: KNOWLEDGE_BASE,
  });
}
