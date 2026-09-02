import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

// ============================================================================
// BURP SUITE & BLOODHOUND EMBEDDED ANALYZERS (SELF-CONTAINED FOR VERCEL)
// ============================================================================
function analyzeSetCookieHeader(cookieStr: string) {
  const parts = cookieStr.split(";").map((p) => p.trim());
  const [nameValue, ...attributes] = parts;
  const name = nameValue.split("=")[0] || "";
  const attrLower = attributes.map((a) => a.toLowerCase());

  const isHttpOnly = attrLower.some((a) => a === "httponly");
  const isSecure = attrLower.some((a) => a === "secure");
  
  let sameSite: "Strict" | "Lax" | "None" | "Missing" = "Missing";
  const sameSiteAttr = attributes.find((a) => a.toLowerCase().startsWith("samesite="));
  if (sameSiteAttr) {
    const val = sameSiteAttr.split("=")[1]?.trim().toLowerCase();
    if (val === "strict") sameSite = "Strict";
    else if (val === "lax") sameSite = "Lax";
    else if (val === "none") sameSite = "None";
  }

  const issues: string[] = [];
  if (!isHttpOnly) issues.push("Missing 'HttpOnly' flag.");
  if (!isSecure) issues.push("Missing 'Secure' flag.");
  if (sameSite === "Missing" || sameSite === "None") issues.push("Permissive SameSite configuration.");

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (!isHttpOnly && !isSecure) severity = "HIGH";
  else if (!isHttpOnly || !isSecure) severity = "MEDIUM";
  else if (sameSite === "Missing") severity = "LOW";

  return { name, isHttpOnly, isSecure, sameSite, issues, severity };
}

function analyzeCorsHeaders(headers: Headers) {
  const allowOrigin = headers.get("access-control-allow-origin") || undefined;
  const allowCredentials = headers.get("access-control-allow-credentials")?.toLowerCase() === "true";
  const vary = headers.get("vary") || "";

  const issues: string[] = [];
  let hasWildcardWithCredentials = false;

  if (allowOrigin === "*" && allowCredentials) {
    hasWildcardWithCredentials = true;
    issues.push("Critical CORS: 'Access-Control-Allow-Origin: *' combined with 'Credentials: true'.");
  }
  if (allowOrigin === "null") {
    issues.push("Insecure CORS: 'Access-Control-Allow-Origin: null' vulnerable to sandboxed iframes.");
  }
  if (allowOrigin && allowOrigin !== "*" && !vary.toLowerCase().includes("origin")) {
    issues.push("Cache Poisoning Risk: Missing 'Vary: Origin'.");
  }

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (hasWildcardWithCredentials || allowOrigin === "null") severity = "HIGH";
  else if (issues.length > 0) severity = "MEDIUM";

  return { allowOrigin, allowCredentials, hasWildcardWithCredentials, issues, severity };
}

function runBurpHeaderAudit(headers: Headers, rawCookies: string[] = []) {
  const cookies = rawCookies.map(analyzeSetCookieHeader);
  const cors = analyzeCorsHeaders(headers);
  const findingsCount = cookies.filter((c) => c.severity !== "PASSED").length + (cors.severity !== "PASSED" ? 1 : 0);
  return { cookies, cors, findingsCount };
}

function buildAttackChainGraph(targetUrl: string, defenses: {
  hasCsp: boolean;
  hasXFrameOptions: boolean;
  hasHsts: boolean;
  hasNosniff: boolean;
  hasPermissionsPolicy: boolean;
  hasSecureCookies: boolean;
  hasStrictCors: boolean;
  serverVersionExposed: boolean;
}) {
  const nodes: Array<{ id: string; stage: string; title: string; description: string; mitreTechnique: string }> = [];
  const primaryPath: string[] = [];
  const priorities: string[] = [];

  if (defenses.serverVersionExposed) {
    nodes.push({
      id: "node-recon-server",
      stage: "RECON",
      title: "Web Server Version Fingerprinting",
      description: "The 'Server' header exposes exact software and version information.",
      mitreTechnique: "T1592.002",
    });
    primaryPath.push("Version Fingerprinting");
  }

  if (!defenses.hasCsp) {
    nodes.push({
      id: "node-xss-injection",
      stage: "INITIAL_ACCESS",
      title: "Malicious Script Injection (Cross-Site Scripting - XSS)",
      description: "Absence of Content-Security-Policy allows unrestricted script execution.",
      mitreTechnique: "T1189",
    });
    primaryPath.push("Script Injection (XSS)");
    priorities.push("Configure a strict Content-Security-Policy (CSP).");
  }

  if (!defenses.hasCsp && !defenses.hasSecureCookies) {
    nodes.push({
      id: "node-session-hijack",
      stage: "EXECUTION",
      title: "Cookie Exfiltration & Session Hijacking",
      description: "Cookies lacking HttpOnly can be exfiltrated by malicious client-side scripts.",
      mitreTechnique: "T1539",
    });
    primaryPath.push("Session Hijacking");
    priorities.push("Enable the HttpOnly flag on all session cookies.");
  }

  if (!defenses.hasXFrameOptions) {
    nodes.push({
      id: "node-clickjacking",
      stage: "INITIAL_ACCESS",
      title: "UI Redressing & Invisible Action Hijacking (Clickjacking)",
      description: "Authenticated pages can be embedded within transparent external iframes.",
      mitreTechnique: "T1204.001",
    });
    priorities.push("Add 'X-Frame-Options: DENY'.");
  }

  let maxImpactLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";
  if (nodes.some((n) => n.id === "node-session-hijack")) {
    nodes.push({
      id: "node-account-takeover",
      stage: "IMPACT",
      title: "Full Account Takeover",
      description: "Attacker leverages stolen session credentials to assume victim identity.",
      mitreTechnique: "T1078",
    });
    primaryPath.push("Account Takeover");
    maxImpactLevel = "CRITICAL";
  } else if (nodes.some((n) => n.id === "node-xss-injection") || nodes.some((n) => n.id === "node-clickjacking")) {
    maxImpactLevel = "HIGH";
  } else if (nodes.length > 0) {
    maxImpactLevel = "MEDIUM";
  }

  const riskSummary =
    primaryPath.length > 1
      ? `Attack Chain Detected: ${primaryPath.join(" ➔ ")}`
      : nodes.length > 0
        ? `Risk Surface Identified with ${nodes.length} potential attack vectors.`
        : "Isolated and hardened perimeter: No exploitable attack paths found.";

  return {
    target: targetUrl,
    riskSummary,
    primaryAttackPath: primaryPath,
    nodes,
    maxImpactLevel,
    tacticalDefensePriority: priorities,
  };
}

// ============================================================================
// VALIDAÇÃO DE SEGURANÇA & SSRF SHIELD
// ============================================================================
function validateTargetUrlSafety(targetUrl: string): { safe: boolean; reason?: string } {
  try {
    const parsed = new URL(targetUrl);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { safe: false, reason: "Protocolo não suportado. Utilize HTTP ou HTTPS." };
    }

    const hostname = parsed.hostname.toLowerCase();

    // 1. Bloqueio de IP de Metadados de Nuvem (AWS/GCP/Azure/Oracle/Vercel)
    if (
      hostname === "169.254.169.254" ||
      hostname === "metadata.google.internal" ||
      hostname === "instance-data"
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Tentativa de acesso a serviços de metadados de nuvem bloqueada.",
      };
    }

    // 2. Bloqueio de Redes Locais e Loopback (RFC 1918 & RFC 6890)
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "::1" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Access to internal networks and loopback interfaces is blocked for security.",
      };
    }

    return { safe: true };
  } catch (err: any) {
    return { safe: false, reason: `Malformed URL: ${err.message}` };
  }
}

// ============================================================================
// AUDITORIA UNIVERSAL DE CABEÇALHOS E BORDAS
// ============================================================================
async function auditUniversalEndpoint(targetUrl: string) {
  const safety = validateTargetUrlSafety(targetUrl);
  if (!safety.safe) {
    throw new Error(safety.reason);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);

  try {
    const res = await fetch(targetUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "ObsidianSec-DevSecOps-Auditor/1.0 (+https://obsidiansec.dev)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    clearTimeout(timeoutId);

    const headers = res.headers;
    const serverHeader = headers.get("server") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";

    const cspVal = headers.get("content-security-policy");
    const cspReportOnly = headers.get("content-security-policy-report-only");
    const xfoVal = headers.get("x-frame-options");
    const xctoVal = headers.get("x-content-type-options");
    const permVal = headers.get("permissions-policy");
    const hstsVal = headers.get("strict-transport-security");
    const refVal = headers.get("referrer-policy");
    const coopVal = headers.get("cross-origin-opener-policy");

    // Detectar Servidor / CDN
    let serverDetected = "Unknown / Hidden Proxy";
    const sLower = serverHeader.toLowerCase();
    if (sLower.includes("cloudflare")) serverDetected = "Cloudflare Edge";
    else if (sLower.includes("nginx")) serverDetected = "Nginx Web Server";
    else if (sLower.includes("apache")) serverDetected = "Apache HTTP Server";
    else if (sLower.includes("caddy")) serverDetected = "Caddy Web Server";
    else if (sLower.includes("vercel")) serverDetected = "Vercel Edge Network";
    else if (sLower.includes("netlify")) serverDetected = "Netlify Edge";
    else if (sLower.includes("iis") || sLower.includes("microsoft")) serverDetected = "Microsoft IIS";
    else if (serverHeader) serverDetected = serverHeader;

    // Detectar Framework
    let frameworkDetected: string | undefined;
    const pLower = xPoweredBy.toLowerCase();
    if (pLower.includes("express")) frameworkDetected = "Node.js / Express";
    else if (pLower.includes("next")) frameworkDetected = "Next.js";
    else if (pLower.includes("php")) frameworkDetected = `PHP Runtime (${xPoweredBy})`;
    else if (xPoweredBy) frameworkDetected = xPoweredBy;

    // Snippets de Remediação
    const remediationSnippets = [
      {
        serverType: "Nginx (nginx.conf)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // NGINX HARDENING
# =========================================================
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
server_tokens off;`,
      },
      {
        serverType: "Apache (.htaccess)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // APACHE HTTP HARDENING
# =========================================================
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header unset X-Powered-By
</IfModule>
ServerSignature Off`,
      },
      {
        serverType: "Node.js (Helmet / Express)",
        snippet: `// =========================================================
// OBSIDIANSEC DEFENSE PATCH // NODE.JS & EXPRESS HELMET
// =========================================================
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));`,
      },
      {
        serverType: "Cloudflare (Transform Rules)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // CLOUDFLARE EDGE HEADERS
# HTTP Response Header Modification Rules
# =========================================================
Set Dynamic Header:
- Content-Security-Policy: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
- X-Frame-Options: "DENY"
- X-Content-Type-Options: "nosniff"
- Referrer-Policy: "strict-origin-when-cross-origin"
- Permissions-Policy: "camera=(), microphone=(), geolocation=()"
- Cross-Origin-Opener-Policy: "same-origin"`,
      },
      {
        serverType: "Vercel (vercel.json)",
        snippet: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Cross-Origin-Opener-Policy", "value": "same-origin" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" }
      ]
    }
  ]
}`,
      },
    ];

    const rawSetCookies: string[] = [];
    if (typeof (headers as any).getSetCookie === "function") {
      rawSetCookies.push(...(headers as any).getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }

    const burpInspection = runBurpHeaderAudit(headers, rawSetCookies);

    const attackChain = buildAttackChainGraph(targetUrl, {
      hasCsp: !!cspVal,
      hasXFrameOptions: !!xfoVal,
      hasHsts: !!hstsVal,
      hasNosniff: !!xctoVal,
      hasPermissionsPolicy: !!permVal,
      hasSecureCookies: burpInspection.cookies.length === 0 || burpInspection.cookies.every((c) => c.isHttpOnly && c.isSecure),
      hasStrictCors: burpInspection.cors.severity === "PASSED",
      serverVersionExposed: /\d+\.\d+/.test(serverHeader),
    });

    return {
      targetUrl,
      httpStatus: res.status,
      serverDetected,
      frameworkDetected,
      securityHeaders: {
        csp: {
          present: !!cspVal || !!cspReportOnly,
          value: cspVal || cspReportOnly || undefined,
          isReportOnly: !cspVal && !!cspReportOnly,
        },
        xFrameOptions: { present: !!xfoVal, value: xfoVal || undefined },
        xContentTypeOptions: { present: !!xctoVal, value: xctoVal || undefined },
        permissionsPolicy: { present: !!permVal, value: permVal || undefined },
        hsts: { present: !!hstsVal, value: hstsVal || undefined },
        referrerPolicy: { present: !!refVal, value: refVal || undefined },
        coop: { present: !!coopVal, value: coopVal || undefined },
      },
      burpInspection,
      attackChain,
      remediationSnippets,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const msg = (err?.message || "").toLowerCase();
    const causeMsg = String(err?.cause?.message || err?.cause?.code || "").toLowerCase();

    if (msg.includes("abort") || msg.includes("timeout")) {
      throw new Error("Connection timeout. The target server took too long to respond.");
    }
    if (msg.includes("fetch failed") || causeMsg.includes("enotfound") || causeMsg.includes("eai_again")) {
      throw new Error("Target address could not be resolved (DNS/Domain not found). Verify that the domain was entered correctly.");
    }
    if (causeMsg.includes("econnrefused")) {
      throw new Error("Connection refused by target server.");
    }
    throw new Error(err?.message || "Failed to connect to target server.");
  }
}

// ============================================================================
// GEMINI 3.7 FLASH & FALLBACK COGNITIVO
// ============================================================================
async function generateAiDiagnosis(auditReport: any, score: number, grade: string, apiKey?: string) {
  const finalApiKey = apiKey || process.env.GEMINI_API_KEY || "";
  const models = ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3-flash-preview", "gemini-3.6-flash"];

  const prompt = `You are CyberBrain from the ObsidianSec DevSecOps platform. Analyze this target security audit report: ${auditReport.targetUrl}
- Score: ${score}/100 (Grade ${grade})
- Server / Edge: ${auditReport.serverDetected}
- CSP: ${auditReport.securityHeaders.csp.present ? "Present" : "MISSING"}
- X-Frame-Options: ${auditReport.securityHeaders.xFrameOptions.present ? "Present" : "MISSING"}
- X-Content-Type-Options: ${auditReport.securityHeaders.xContentTypeOptions.present ? "Present" : "MISSING"}
- Permissions-Policy: ${auditReport.securityHeaders.permissionsPolicy.present ? "Present" : "MISSING"}
- HSTS: ${auditReport.securityHeaders.hsts.present ? "Present" : "MISSING"}
- COOP: ${auditReport.securityHeaders.coop.present ? "Present" : "MISSING"}

Generate a pedagogical, tactical, and defensive security analysis (3 to 4 paragraphs) in English, highlighting real-world attack vectors and how to apply edge hardening remediation.`;

  if (finalApiKey) {
    const maestroSystemPrompt = `You are the OBSIDIANSEC MASTER ORCHESTRATOR (CyberBrain Maestro), the supreme AI core of the ObsidianSec DevSecOps squad.
Your mission: provide authoritative, pedagogical, investigative, and tactical technical diagnoses on edge security, HTTP response headers, Zero Trust Architecture (NIST SP 800-207), OWASP Top 10, and data privacy frameworks.
Tone of voice: Tactical, analytical, authoritative, precise, and actionable.`;

    for (const model of models) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${finalApiKey}`;
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: maestroSystemPrompt }] },
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 1000, temperature: 0.2 },
          }),
          signal: AbortSignal.timeout(3000),
        });

        if (resp.ok) {
          const data = await resp.json();
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) return { provider: "Google Gemini AI Core", analysis: text };
        }

        if (resp.status === 503 || resp.status === 429) {
          break; // Fallback instantâneo
        }
      } catch {
        break; // Timeout ou erro de rede: ativa fallback cognitivo
      }
    }
  }

  // Motor Cognitivo Embutido (Offline Fallback Instantâneo em Inglês)
  let fallbackText = `### 🧠 COGNITIVE VERDICT // OBSIDIANSEC DEFENSE CORE\n\n`;
  fallbackText += `Target **${auditReport.targetUrl}** scored **${score}/100 (Grade ${grade})** with infrastructure identified as **${auditReport.serverDetected}**.\n\n`;

  if (score >= 90) {
    fallbackText += `**Verdict:** The environment demonstrates an **Excellent Security Posture**, implementing rigorous isolation headers against Cross-Site Scripting (XSS), Clickjacking, and MIME Sniffing attacks.\n\n`;
  } else if (score >= 60) {
    fallbackText += `**Verdict:** The environment maintains a **Moderate Security Posture**, but leaves key attack surfaces exposed that could facilitate Clickjacking or malicious script execution.\n\n`;
  } else {
    fallbackText += `**Verdict:** The environment is in a **Critical Vulnerability State**, lacking essential perimeter isolation policies and allowing unauthorized framing and browser policy bypasses.\n\n`;
  }

  fallbackText += `**Immediate Recommendation:** Apply the response header remediation patches provided below to your proxy/CDN layer to elevate your rating to **A+ (100/100)** immediately.`;

  return { provider: "ObsidianSec Cognitive Core", analysis: fallbackText };
}

// ============================================================================
// CONFIGURAÇÃO DA SERVERLESS FUNCTION (VERCEL EDGE / NODE RUNTIME)
// ============================================================================
export const config = {
  maxDuration: 15,
};

// ============================================================================
// HANDLER PRINCIPAL DA SERVERLESS FUNCTION
// ============================================================================
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed. Use POST." });
    return;
  }

  try {
    const rawBody = req.body;
    const body = typeof rawBody === "string" ? JSON.parse(rawBody || "{}") : rawBody || {};
    const { url, acceptedTerms, apiKey } = body;

    if (!acceptedTerms) {
      res.status(403).json({
        error: "Acceptance of Terms of Use and Disclaimer is required to proceed.",
      });
      return;
    }
    let targetUrl = typeof url === "string" ? url.trim() : "";
    if (!targetUrl) {
      res.status(400).json({
        error: "Invalid URL. Please provide a domain or web address for probing.",
      });
      return;
    }

    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = `https://${targetUrl}`;
    }

    // 1. Auditoria de Rede e Cabeçalhos
    const auditReport = await auditUniversalEndpoint(targetUrl);

    // 2. Cálculo Pedagógico da Pontuação
    const earnedItems: Array<{ control: string; points: number; explanation: string; lesson: string }> = [];
    const missedItems: Array<{ control: string; lostPoints: number; risk: string; lesson: string }> = [];

    const h = auditReport.securityHeaders;

    if (h.csp.present) {
      earnedItems.push({
        control: "Content-Security-Policy (CSP)",
        points: 30,
        explanation: "Active directive restricting authorized script and resource execution origins.",
        lesson: "Mitigates devastating Cross-Site Scripting (XSS) and malicious data injection attacks.",
      });
    } else {
      missedItems.push({
        control: "Content-Security-Policy (CSP)",
        lostPoints: 30,
        risk: "Open attack surface for script injection (XSS) and unauthorized iframe embedding.",
        lesson: "Define 'Content-Security-Policy: default-src 'self'' to block unvetted external scripts.",
      });
    }

    if (h.xFrameOptions.present) {
      earnedItems.push({
        control: "X-Frame-Options",
        points: 20,
        explanation: `Active protection configured with value '${h.xFrameOptions.value}'.`,
        lesson: "Prevents phishing pages from embedding your application inside invisible iframes.",
      });
    } else {
      missedItems.push({
        control: "X-Frame-Options",
        lostPoints: 20,
        risk: "Severe risk of Clickjacking / UI Redressing attacks.",
        lesson: "Configure 'X-Frame-Options: DENY' or use CSP 'frame-ancestors 'none''.",
      });
    }

    if (h.xContentTypeOptions.present) {
      earnedItems.push({
        control: "X-Content-Type-Options",
        points: 15,
        explanation: "Active 'nosniff' protection against MIME-type confusion attacks.",
        lesson: "Prevents browsers from executing user-uploaded images or text files as JavaScript.",
      });
    } else {
      missedItems.push({
        control: "X-Content-Type-Options",
        lostPoints: 15,
        risk: "Vulnerable to MIME-Sniffing and disguised polyglot file uploads.",
        lesson: "Add 'X-Content-Type-Options: nosniff' to HTTP response headers.",
      });
    }

    if (h.hsts.present) {
      earnedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        points: 15,
        explanation: "Cryptographic HTTPS enforcement enabled across all connections.",
        lesson: "Prevents SSL-strip downgrade attacks and interception on public Wi-Fi networks.",
      });
    } else {
      missedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        lostPoints: 15,
        risk: "Vulnerable to Man-in-the-Middle (MitM) attacks via plaintext HTTP downgrade.",
        lesson: "Enable 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
      });
    }

    if (h.permissionsPolicy.present) {
      earnedItems.push({
        control: "Permissions-Policy",
        points: 10,
        explanation: "Hardware API restriction and device isolation active.",
        lesson: "Blocks third-party scripts from accessing microphone, camera, and geolocation.",
      });
    } else {
      missedItems.push({
        control: "Permissions-Policy",
        lostPoints: 10,
        risk: "Malicious scripts can attempt to invoke device sensors, camera, or payment APIs.",
        lesson: "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
      });
    }

    if (h.coop.present) {
      earnedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        points: 5,
        explanation: "Active window context isolation ('same-origin').",
        lesson: "Protects browser process memory against side-channel attacks like Spectre.",
      });
    } else {
      missedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        lostPoints: 5,
        risk: "Opened windows may retain context references accessible to malicious origins.",
        lesson: "Add 'Cross-Origin-Opener-Policy: same-origin'.",
      });
    }

    if (h.referrerPolicy.present) {
      earnedItems.push({
        control: "Referrer-Policy",
        points: 5,
        explanation: "Active metadata isolation on cross-origin navigation.",
        lesson: "Prevents sensitive internal URL paths from leaking to third-party domains.",
      });
    } else {
      missedItems.push({
        control: "Referrer-Policy",
        lostPoints: 5,
        risk: "Sensitive query parameters in URLs can leak via the Referer header on external links.",
        lesson: "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
      });
    }

    const totalScore = earnedItems.reduce((acc, curr) => acc + curr.points, 0);

    let grade = "F";
    let gradeVerdict = "Critical Security Posture: Multiple essential perimeter defenses are missing.";
    if (totalScore >= 95) {
      grade = "A+";
      gradeVerdict = "Excellent! Edge Fortress: Maximum level of isolation and edge security controls.";
    } else if (totalScore >= 80) {
      grade = "A";
      gradeVerdict = "Strong Perimeter: Most defensive controls are active and safeguarding users.";
    } else if (totalScore >= 60) {
      grade = "B";
      gradeVerdict = "Moderate Posture: Partial controls active. Applying recommended patches is advised.";
    } else if (totalScore >= 40) {
      grade = "C";
      gradeVerdict = "Weak Posture: Significant header deficiencies expose users to exploitation.";
    }

    // 3. Síntese com Inteligência Artificial
    const aiDiagnosis = await generateAiDiagnosis(auditReport, totalScore, grade, apiKey);

    // Retornar JSON completo
    res.status(200).json({
      url: auditReport.targetUrl,
      httpStatus: auditReport.httpStatus,
      serverDetected: auditReport.serverDetected,
      frameworkDetected: auditReport.frameworkDetected,
      score: totalScore,
      grade,
      gradeVerdict,
      scoreBreakdown: {
        earned: earnedItems,
        missed: missedItems,
        earnedItems,
        missedItems,
        totalEarned: totalScore,
      },
      securityHeaders: auditReport.securityHeaders,
      burpInspection: auditReport.burpInspection,
      attackChain: auditReport.attackChain,
      aiDiagnosis,
      aiAnalysis: {
        providerUsed: aiDiagnosis.provider,
        customAnalysis: aiDiagnosis.analysis,
      },
      remediationSnippets: auditReport.remediationSnippets,
    });
  } catch (err: any) {
    res.status(500).json({
      error: `Error processing security audit: ${err.message || "Unknown error."}`,
    });
  }
}
