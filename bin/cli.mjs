#!/usr/bin/env node

// src/agents/polyglot/detector.ts
function detectRemoteTechStack(headers) {
  const getH = (name) => (headers.get(name) || "").toLowerCase();
  const serverHeader = headers.get("server") || "";
  const xPowered = headers.get("x-powered-by") || "";
  const via = headers.get("via") || "";
  const sLower = serverHeader.toLowerCase();
  const vLower = via.toLowerCase();
  let server = "Servidor Web Oculto / Personalizado";
  let cdnOrProxy;
  let frameworkHint;
  let versionExposed = false;
  if (sLower.includes("cloudflare") || headers.get("cf-ray") || headers.get("cf-cache-status")) {
    cdnOrProxy = "Cloudflare Edge Global CDN";
    server = "Cloudflare Edge";
  } else if (vLower.includes("cloudfront") || headers.get("x-amz-cf-id") || headers.get("x-amz-cf-pop")) {
    cdnOrProxy = "AWS CloudFront CDN";
    server = "Amazon Web Services (CloudFront)";
  } else if (vLower.includes("fastly") || headers.get("x-served-by")?.includes("cache-") || headers.get("fastly-restarts")) {
    cdnOrProxy = "Fastly Real-Time Edge";
    server = "Fastly Edge Network";
  } else if (headers.get("x-akamai-transformed") || sLower.includes("akamaighost")) {
    cdnOrProxy = "Akamai Intelligent Edge";
    server = "Akamai Edge Platform";
  } else if (headers.get("x-vercel-id") || headers.get("x-vercel-cache") || sLower.includes("vercel")) {
    cdnOrProxy = "Vercel Edge Network";
    server = "Vercel Serverless Edge";
  } else if (headers.get("x-nf-request-id") || sLower.includes("netlify")) {
    cdnOrProxy = "Netlify Global Edge";
    server = "Netlify Edge Server";
  } else if (vLower.includes("varnish") || headers.get("x-varnish")) {
    cdnOrProxy = "Varnish Cache Reverse Proxy";
  }
  if (sLower.includes("nginx")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("apache")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("caddy")) {
    server = "Caddy Modern Web Server";
  } else if (sLower.includes("litespeed") || sLower.includes("openlitespeed")) {
    server = "LiteSpeed High-Performance Web Server";
  } else if (sLower.includes("traefik")) {
    server = "Traefik Cloud Native Edge Router";
  } else if (sLower.includes("envoy") || headers.get("x-envoy-upstream-service-time")) {
    server = "Envoy Proxy (Service Mesh / Cloud Native)";
  } else if (sLower.includes("openresty")) {
    server = "OpenResty (Nginx + Lua Engine)";
  } else if (sLower.includes("microsoft-iis") || sLower.includes("iis")) {
    server = serverHeader || "Microsoft IIS Web Server";
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("gunicorn") || sLower.includes("uvicorn")) {
    server = "Python WSGI/ASGI Server (Gunicorn/Uvicorn)";
  } else if (sLower.includes("kestrel")) {
    server = "Kestrel (.NET Core Web Server)";
  } else if (sLower.includes("kong")) {
    server = "Kong API Gateway";
  } else if (serverHeader && server === "Servidor Web Oculto / Personalizado") {
    server = serverHeader;
  }
  const xpLower = xPowered.toLowerCase();
  if (xpLower.includes("next.js") || headers.get("x-nextjs-cache")) frameworkHint = "Next.js (React Fullstack)";
  else if (xpLower.includes("express")) frameworkHint = "Express.js (Node.js)";
  else if (xpLower.includes("php")) frameworkHint = xPowered;
  else if (xpLower.includes("asp.net")) frameworkHint = "ASP.NET (.NET)";
  else if (xpLower.includes("nuxt")) frameworkHint = "Nuxt.js (Vue Fullstack)";
  else if (headers.get("x-drupal-cache")) frameworkHint = "Drupal CMS (PHP)";
  else if (headers.get("x-pingback")?.includes("xmlrpc.php")) frameworkHint = "WordPress CMS (PHP)";
  else if (headers.get("x-django-version")) frameworkHint = "Django (Python)";
  return {
    server,
    frameworkHint,
    cdnOrProxy,
    rawServerHeader: serverHeader || void 0,
    versionExposed
  };
}

// src/lib/security/cookie-cors-analyzer.ts
function analyzeSetCookieHeader(cookieStr) {
  const parts = cookieStr.split(";").map((p) => p.trim());
  const [nameValue, ...attributes] = parts;
  const name = nameValue.split("=")[0] || "";
  const attrLower = attributes.map((a) => a.toLowerCase());
  const isHttpOnly = attrLower.some((a) => a === "httponly");
  const isSecure = attrLower.some((a) => a === "secure");
  let sameSite = "Missing";
  const sameSiteAttr = attributes.find((a) => a.toLowerCase().startsWith("samesite="));
  if (sameSiteAttr) {
    const val = sameSiteAttr.split("=")[1]?.trim().toLowerCase();
    if (val === "strict") sameSite = "Strict";
    else if (val === "lax") sameSite = "Lax";
    else if (val === "none") sameSite = "None";
  }
  const issues = [];
  let prefixType = "none";
  let hasPrefix = false;
  if (name.startsWith("__Host-")) {
    prefixType = "__Host-";
    hasPrefix = true;
  } else if (name.startsWith("__Secure-")) {
    prefixType = "__Secure-";
    hasPrefix = true;
  }
  if (!isHttpOnly) {
    issues.push("Aus\xEAncia da flag 'HttpOnly': Cookie vulner\xE1vel a exfiltra\xE7\xE3o via Cross-Site Scripting (XSS).");
  }
  if (!isSecure) {
    issues.push("Aus\xEAncia da flag 'Secure': Cookie pode ser transmitido em conex\xF5es HTTP inseguras.");
  }
  if (sameSite === "Missing" || sameSite === "None") {
    issues.push("Configura\xE7\xE3o frouxa de SameSite: Cookie vulner\xE1vel a ataques de Cross-Site Request Forgery (CSRF).");
  }
  if (prefixType === "__Host-") {
    if (!isSecure) {
      issues.push("Prefixo __Host- exige flag 'Secure' ativa.");
    }
  }
  let severity = "PASSED";
  if (!isHttpOnly && !isSecure) severity = "HIGH";
  else if (!isHttpOnly || !isSecure) severity = "MEDIUM";
  else if (sameSite === "Missing") severity = "LOW";
  return {
    name,
    isHttpOnly,
    isSecure,
    sameSite,
    hasPrefix,
    prefixType,
    issues,
    severity
  };
}
function analyzeCorsHeaders(headers) {
  const getHeader = (key) => {
    if (typeof headers.get === "function") {
      return headers.get(key);
    }
    const rec = headers;
    const lowerKey = key.toLowerCase();
    for (const [k, v] of Object.entries(rec)) {
      if (k.toLowerCase() === lowerKey) return v;
    }
    return null;
  };
  const allowOrigin = getHeader("access-control-allow-origin") || void 0;
  const allowCredsStr = getHeader("access-control-allow-credentials");
  const allowCredentials = allowCredsStr?.toLowerCase() === "true";
  const allowMethodsStr = getHeader("access-control-allow-methods");
  const allowMethods = allowMethodsStr ? allowMethodsStr.split(",").map((m) => m.trim()) : void 0;
  const exposeHeadersStr = getHeader("access-control-expose-headers");
  const exposeHeaders = exposeHeadersStr ? exposeHeadersStr.split(",").map((h) => h.trim()) : void 0;
  const maxAgeStr = getHeader("access-control-max-age");
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : void 0;
  const vary = getHeader("vary") || "";
  const issues = [];
  let hasWildcardWithCredentials = false;
  let hasInsecureOriginReflection = false;
  let isMissingVaryOrigin = false;
  if (allowOrigin === "*" && allowCredentials) {
    hasWildcardWithCredentials = true;
    issues.push("CORS Cr\xEDtico: 'Access-Control-Allow-Origin: *' combinado com 'Access-Control-Allow-Credentials: true' permite roubo de credenciais cross-origin.");
  }
  if (allowOrigin === "null") {
    issues.push("CORS Inseguro: 'Access-Control-Allow-Origin: null' pode ser explorado via iframes 'sandboxed' maliciosos.");
  }
  if (allowOrigin && allowOrigin !== "*" && !vary.toLowerCase().includes("origin")) {
    isMissingVaryOrigin = true;
    issues.push("Cache Poisoning Risk: Falta o cabe\xE7alho 'Vary: Origin' quando origens din\xE2micas s\xE3o permitidas.");
  }
  let severity = "PASSED";
  if (hasWildcardWithCredentials || allowOrigin === "null") severity = "HIGH";
  else if (issues.length > 0) severity = "MEDIUM";
  return {
    allowOrigin,
    allowCredentials,
    allowMethods,
    exposeHeaders,
    maxAge,
    hasWildcardWithCredentials,
    hasInsecureOriginReflection,
    isMissingVaryOrigin,
    issues,
    severity
  };
}
function runBurpHeaderAudit(headers, rawCookies = []) {
  const cookieResults = rawCookies.map(analyzeSetCookieHeader);
  const corsResult = analyzeCorsHeaders(headers);
  const findingsCount = cookieResults.filter((c) => c.severity !== "PASSED").length + (corsResult.severity !== "PASSED" ? 1 : 0);
  return {
    cookies: cookieResults,
    cors: corsResult,
    findingsCount
  };
}

// src/lib/security/attack-chain-analyzer.ts
function buildAttackChainGraph(targetUrl, defenses) {
  const nodes = [];
  const edges = [];
  const primaryPath = [];
  const priorities = [];
  if (defenses.serverVersionExposed) {
    nodes.push({
      id: "node-recon-server",
      stage: "RECON",
      title: "Identifica\xE7\xE3o de Vers\xE3o de Servidor Web (Server Fingerprinting)",
      description: "O cabe\xE7alho 'Server' exp\xF5e a vers\xE3o exata do software, permitindo mapeamento de CVEs conhecidas.",
      vector: "Banner Grabbing / Version Header",
      mitreTechnique: "T1592.002 (Gather Victim Host Information: Software)"
    });
    primaryPath.push("Identifica\xE7\xE3o de Vers\xE3o");
  }
  if (!defenses.hasCsp) {
    nodes.push({
      id: "node-xss-injection",
      stage: "INITIAL_ACCESS",
      title: "Inje\xE7\xE3o de Scripts Maliciosos (Cross-Site Scripting - XSS)",
      description: "A aus\xEAncia de Content-Security-Policy permite execu\xE7\xE3o irrestrita de scripts no contexto da v\xEDtima.",
      vector: "DOM / Reflected / Stored XSS",
      mitreTechnique: "T1189 (Drive-by Compromise / Browser Exploitation)"
    });
    primaryPath.push("Inje\xE7\xE3o de Script (XSS)");
    priorities.push("Configurar Content-Security-Policy (CSP) com restri\xE7\xE3o default-src e nonce/hashes.");
    if (nodes.some((n) => n.id === "node-recon-server")) {
      edges.push({
        fromNodeId: "node-recon-server",
        toNodeId: "node-xss-injection",
        condition: "Atacante seleciona payloads compat\xEDveis com a vers\xE3o do servidor.",
        likelihood: "HIGH"
      });
    }
  }
  if (!defenses.hasCsp && !defenses.hasSecureCookies) {
    nodes.push({
      id: "node-session-hijack",
      stage: "EXECUTION",
      title: "Exfiltra\xE7\xE3o de Cookies e Sequestro de Sess\xE3o (Session Hijacking)",
      description: "Cookies de autentica\xE7\xE3o sem a flag HttpOnly s\xE3o lidos via document.cookie pelo script XSS e enviados para servidor C2.",
      vector: "Document Cookie Exfiltration",
      mitreTechnique: "T1539 (Steal Web Session Cookie)"
    });
    primaryPath.push("Roubo de Cookie (Session Hijacking)");
    priorities.push("Habilitar flag HttpOnly e prefixos __Host- em todos os cookies de sess\xE3o.");
    edges.push({
      fromNodeId: "node-xss-injection",
      toNodeId: "node-session-hijack",
      condition: "Script malicioso executa document.cookie no navegador da v\xEDtima.",
      likelihood: "HIGH"
    });
  }
  if (!defenses.hasXFrameOptions) {
    nodes.push({
      id: "node-clickjacking",
      stage: "INITIAL_ACCESS",
      title: "Sequestro de Interface e A\xE7\xF5es Invis\xEDveis (Clickjacking)",
      description: "P\xE1ginas autenticadas podem ser incorporadas em iframes transparentes para induzir cliques involunt\xE1rios.",
      vector: "Transparent iFrame Overlay",
      mitreTechnique: "T1204.001 (User Execution: Malicious Link / UI Redress)"
    });
    priorities.push("Adicionar 'X-Frame-Options: DENY' e diretiva CSP 'frame-ancestors 'none''.");
    if (primaryPath.length === 0) {
      primaryPath.push("Clickjacking / UI Redressing");
    }
  }
  if (!defenses.hasHsts) {
    nodes.push({
      id: "node-hsts-downgrade",
      stage: "INITIAL_ACCESS",
      title: "Intercepta\xE7\xE3o de Tr\xE1fego e Downgrade para HTTP (SSL Strip)",
      description: "A falta de HSTS permite que atacantes na mesma rede interceptem a primeira requisi\xE7\xE3o e forcem HTTP plano.",
      vector: "ARP Spoofing / SSL Striping",
      mitreTechnique: "T1557.001 (Man-in-the-Middle: LLMNR/NBT-NS & SSL Strip)"
    });
    priorities.push("Habilitar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.");
  }
  let maxImpactLevel = "LOW";
  if (nodes.some((n) => n.id === "node-session-hijack")) {
    nodes.push({
      id: "node-account-takeover",
      stage: "IMPACT",
      title: "Tomada Completa de Conta & Acesso Administrativo (Account Takeover)",
      description: "Atacante utiliza a sess\xE3o roubada para assumir identidade leg\xEDtima e acessar dados internos.",
      vector: "Authenticated Impersonation",
      mitreTechnique: "T1078 (Valid Accounts)"
    });
    primaryPath.push("Comprometimento de Conta (Account Takeover)");
    maxImpactLevel = "CRITICAL";
    edges.push({
      fromNodeId: "node-session-hijack",
      toNodeId: "node-account-takeover",
      condition: "Atacante replica token em cabe\xE7alho Authorization/Cookie.",
      likelihood: "HIGH"
    });
  } else if (nodes.some((n) => n.id === "node-xss-injection") || nodes.some((n) => n.id === "node-clickjacking")) {
    maxImpactLevel = "HIGH";
  } else if (nodes.length > 0) {
    maxImpactLevel = "MEDIUM";
  }
  const riskSummary = primaryPath.length > 1 ? `Cadeia de Ataque Detectada: ${primaryPath.join(" \u2794 ")}` : nodes.length > 0 ? `Superf\xEDcie de Risco Identificada com ${nodes.length} vetores potenciais de invas\xE3o.` : "Nenhum vetor cr\xEDtico de encadeamento de ataque detectado nas camadas de borda.";
  return {
    target: targetUrl,
    riskSummary,
    primaryAttackPath: primaryPath,
    nodes,
    edges,
    maxImpactLevel,
    tacticalDefensePriority: priorities
  };
}

// src/scanner/universal-web-scanner.ts
function generateRemediationSnippets(serverName) {
  const snippets = [];
  snippets.push({
    serverType: "NGINX (/etc/nginx/conf.d/security.conf)",
    snippet: `add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "microphone=(self), camera=(), geolocation=(), payment=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';" always;
server_tokens off;`
  });
  snippets.push({
    serverType: "APACHE (.htaccess / httpd.conf)",
    snippet: `<IfModule mod_headers.c>
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "microphone=(self), camera=(), geolocation=(), payment=()"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';"
</IfModule>
ServerSignature Off
ServerTokens Prod`
  });
  snippets.push({
    serverType: "VERCEL (vercel.json)",
    snippet: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "microphone=(self), camera=(), geolocation=(), payment=()" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';" }
      ]
    }
  ]
}`
  });
  snippets.push({
    serverType: "PYTHON FASTAPI (main.py)",
    snippet: `from fastapi import FastAPI, Response, Request
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response

app.add_middleware(SecurityHeadersMiddleware)`
  });
  snippets.push({
    serverType: "NODE.JS EXPRESS (app.js / server.ts)",
    snippet: `import express from "express";
import helmet from "helmet";

const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: "deny" },
  noSniff: true,
}));`
  });
  snippets.push({
    serverType: "GO FIBER (main.go)",
    snippet: `package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/helmet"
)

func main() {
    app := fiber.New()
    app.Use(helmet.New(helmet.Config{
        XFrameOptions: "DENY",
        ContentTypeNosniff: "nosniff",
        HSTSMaxAge: 31536000,
        ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none';",
        ReferrerPolicy: "strict-origin-when-cross-origin",
    }))
    app.Listen(":3000")
}`
  });
  snippets.push({
    serverType: "PYTHON DJANGO (settings.py)",
    snippet: `SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")`
  });
  snippets.push({
    serverType: "PHP LARAVEL (app/Http/Middleware/SecurityHeaders.php)",
    snippet: `public function handle($request, Closure $next)
{
    $response = $next($request);
    $response->headers->set('X-Frame-Options', 'DENY');
    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
    $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';");
    return $response;
}`
  });
  snippets.push({
    serverType: "JAVA SPRING BOOT (SecurityConfig.java)",
    snippet: `@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .frameOptions(frame -> frame.deny())
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"))
    );
    return http.build();
}`
  });
  snippets.push({
    serverType: "C# ASP.NET CORE (Program.cs)",
    snippet: `app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none';");
    await next();
});`
  });
  return snippets;
}
async function auditUniversalEndpoint(targetUrl) {
  const url = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
  let res;
  try {
    res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(5e3)
    });
  } catch (err) {
    const msg = (err?.message || "").toLowerCase();
    const causeMsg = String(err?.cause?.message || err?.cause?.code || "").toLowerCase();
    if (msg.includes("abort") || msg.includes("timeout")) {
      throw new Error("Tempo limite de conex\xE3o esgotado (timeout). O servidor alvo demorou a responder.");
    }
    if (msg.includes("fetch failed") || causeMsg.includes("enotfound") || causeMsg.includes("eai_again")) {
      throw new Error("N\xE3o foi poss\xEDvel localizar o endere\xE7o (DNS/Dom\xEDnio n\xE3o encontrado). Verifique se o dom\xEDnio foi digitado corretamente.");
    }
    if (causeMsg.includes("econnrefused")) {
      throw new Error("Conex\xE3o recusada pelo servidor de destino.");
    }
    throw new Error(err?.message || "Falha ao conectar com o servidor alvo.");
  }
  const headers = res.headers;
  const finalUrl = res.url || url;
  const stack = detectRemoteTechStack(headers);
  const cspEnforcing = headers.get("content-security-policy");
  const cspReportOnly = headers.get("content-security-policy-report-only");
  const cspValue = cspEnforcing || cspReportOnly;
  const xFrame = headers.get("x-frame-options");
  const nosniff = headers.get("x-content-type-options");
  const perm = headers.get("permissions-policy");
  const hsts = headers.get("strict-transport-security");
  const referrer = headers.get("referrer-policy");
  const coop = headers.get("cross-origin-opener-policy");
  const rawSetCookies = [];
  if (typeof headers.getSetCookie === "function") {
    rawSetCookies.push(...headers.getSetCookie());
  } else {
    const sc = headers.get("set-cookie");
    if (sc) rawSetCookies.push(sc);
  }
  const burpInspection = runBurpHeaderAudit(headers, rawSetCookies);
  const attackChain = buildAttackChainGraph(finalUrl, {
    hasCsp: !!cspEnforcing,
    hasXFrameOptions: !!xFrame,
    hasHsts: !!hsts,
    hasNosniff: !!nosniff,
    hasPermissionsPolicy: !!perm,
    hasSecureCookies: burpInspection.cookies.length === 0 || burpInspection.cookies.every((c) => c.isHttpOnly && c.isSecure),
    hasStrictCors: burpInspection.cors.severity === "PASSED",
    serverVersionExposed: stack.versionExposed
  });
  const isSecure = !!(cspEnforcing && xFrame && nosniff && perm && hsts);
  const snippets = generateRemediationSnippets(stack.server);
  return {
    targetUrl: finalUrl,
    httpStatus: res.status,
    serverDetected: stack.server,
    frameworkDetected: stack.frameworkHint,
    cdnOrProxy: stack.cdnOrProxy,
    versionExposed: stack.versionExposed,
    securityHeaders: {
      csp: {
        present: !!cspValue,
        value: cspValue || void 0,
        isReportOnly: !cspEnforcing && !!cspReportOnly
      },
      xFrameOptions: { present: !!xFrame, value: xFrame || void 0 },
      xContentTypeOptions: { present: !!nosniff, value: nosniff || void 0 },
      permissionsPolicy: { present: !!perm, value: perm || void 0 },
      hsts: { present: !!hsts, value: hsts || void 0 },
      referrerPolicy: { present: !!referrer, value: referrer || void 0 },
      coop: { present: !!coop, value: coop || void 0 }
    },
    burpInspection,
    attackChain,
    remediationSnippets: snippets,
    overallStatus: isSecure ? "SECURE" : "ACTION_REQUIRED"
  };
}

// src/lib/security/captcha.ts
var CAPTCHA_TTL_MS = 120 * 1e3;

// src/lib/security/token.ts
var DEFAULT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.RATE_LIMIT_SECRET || "default-secret-jwt-key-min-32-chars";

// src/lib/security/dns-security-analyzer.ts
function parseSpfRecord(txtRecords) {
  const spfRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=spf1"));
  if (!spfRaw) {
    return {
      present: false,
      hasWildcardPass: false,
      lookupCountEstimate: 0,
      isCompliant: false,
      verdict: "Aus\xEAncia de SPF: Qualquer servidor no mundo pode forjar emails em nome do dom\xEDnio.",
      issues: ["Crie uma entrada TXT com 'v=spf1 ... -all' autorizando apenas seus servidores de email leg\xEDtimos."]
    };
  }
  const parts = spfRaw.split(/\s+/);
  let qualifier = "~all";
  const issues = [];
  let lookupCount = 0;
  for (const part of parts) {
    const pLower = part.toLowerCase();
    if (pLower.startsWith("include:") || pLower.startsWith("a") || pLower.startsWith("mx") || pLower.startsWith("ptr:") || pLower.startsWith("exists:")) {
      lookupCount++;
    }
    if (pLower === "-all") qualifier = "-all";
    else if (pLower === "~all") qualifier = "~all";
    else if (pLower === "?all") qualifier = "?all";
    else if (pLower === "+all" || pLower === "all") qualifier = "+all";
  }
  const hasWildcardPass = qualifier === "+all";
  if (hasWildcardPass) {
    issues.push("VULNERABILIDADE CR\xCDTICA: '+all' autoriza qualquer IP na internet a enviar emails em seu nome.");
  }
  if (qualifier === "?all") {
    issues.push("Qualificador neutro '?all' n\xE3o instrui servidores a rejeitarem mensagens n\xE3o autorizadas.");
  }
  if (lookupCount > 10) {
    issues.push(`Excesso de Lookups DNS (${lookupCount} > 10). Excede o limite da RFC 7208 e pode invalidar o SPF (PermError).`);
  }
  const isCompliant = (qualifier === "-all" || qualifier === "~all") && !hasWildcardPass && lookupCount <= 10;
  let verdict = "SPF configurado corretamente com restri\xE7\xE3o de remetentes.";
  if (hasWildcardPass) verdict = "SPF Perigoso (+all): Permite spoofing irrestrito de email.";
  else if (qualifier === "-all") verdict = "SPF Blindado (HardFail -all): Rejei\xE7\xE3o estrita de remetentes n\xE3o autorizados.";
  else if (qualifier === "~all") verdict = "SPF Moderado (SoftFail ~all): Mensagens n\xE3o autorizadas s\xE3o marcadas como spam.";
  return {
    present: true,
    rawRecord: spfRaw,
    qualifier,
    hasWildcardPass,
    lookupCountEstimate: lookupCount,
    isCompliant,
    verdict,
    issues
  };
}
function parseDmarcRecord(txtRecords) {
  const dmarcRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (!dmarcRaw) {
    return {
      present: false,
      percentage: 0,
      isEnforcing: false,
      verdict: "Aus\xEAncia de DMARC: Dom\xEDnio desprotegido contra ataques de Business Email Compromise (BEC) e Phishing.",
      issues: ["Configure uma entrada TXT em '_dmarc.seudominio.com' com pol\xEDtica 'v=DMARC1; p=reject; rua=mailto:dmarc@seudominio.com'."]
    };
  }
  const tags = dmarcRaw.split(";").map((t) => t.trim());
  let policy = "none";
  let subdomainPolicy;
  let percentage = 100;
  let aggregateReportUri;
  let forensicReportUri;
  const issues = [];
  for (const tag of tags) {
    const [key, val] = tag.split("=").map((s) => s?.trim());
    if (!key || !val) continue;
    const kLower = key.toLowerCase();
    const vLower = val.toLowerCase();
    if (kLower === "p") {
      if (vLower === "reject") policy = "reject";
      else if (vLower === "quarantine") policy = "quarantine";
      else policy = "none";
    }
    if (kLower === "sp") {
      if (vLower === "reject") subdomainPolicy = "reject";
      else if (vLower === "quarantine") subdomainPolicy = "quarantine";
      else subdomainPolicy = "none";
    }
    if (kLower === "pct") {
      percentage = parseInt(val, 10) || 100;
    }
    if (kLower === "rua") aggregateReportUri = val;
    if (kLower === "ruf") forensicReportUri = val;
  }
  if (policy === "none") {
    issues.push("Pol\xEDtica DMARC 'p=none' atua apenas como telemetria e N\xC3O bloqueia emails falsificados.");
  }
  if (percentage < 100) {
    issues.push(`Apenas ${percentage}% das mensagens sofrem aplica\xE7\xE3o da regra DMARC.`);
  }
  if (!aggregateReportUri) {
    issues.push("Nenhum endere\xE7o 'rua' configurado para receber relat\xF3rios agregados de tentativas de spoofing.");
  }
  const isEnforcing = policy === "reject" || policy === "quarantine";
  let verdict = "DMARC Ativo em Modo de Bloqueio.";
  if (policy === "reject") verdict = "DMARC M\xE1ximo (p=reject): Emails falsificados s\xE3o terminantemente descartados.";
  else if (policy === "quarantine") verdict = "DMARC M\xE9dio (p=quarantine): Emails falsificados s\xE3o isolados em quarentena/spam.";
  else verdict = "DMARC Apenas Monitoramento (p=none): N\xE3o impede envio de emails falsos.";
  return {
    present: true,
    rawRecord: dmarcRaw,
    policy,
    subdomainPolicy,
    percentage,
    aggregateReportUri,
    forensicReportUri,
    isEnforcing,
    verdict,
    issues
  };
}
async function queryDohRecords(domain, type) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(3500)
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return [];
    return data.Answer.map((a) => {
      let dataStr = String(a.data || "");
      if (dataStr.startsWith('"') && dataStr.endsWith('"')) {
        dataStr = dataStr.slice(1, -1);
      }
      return dataStr;
    });
  } catch {
    return [];
  }
}
async function auditDomainDnsSecurity(domainInput) {
  const cleanDomain = domainInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  const [domainTxt, dmarcTxt, mxRecords, dsRecords] = await Promise.all([
    queryDohRecords(cleanDomain, "TXT"),
    queryDohRecords(`_dmarc.${cleanDomain}`, "TXT"),
    queryDohRecords(cleanDomain, "MX"),
    queryDohRecords(cleanDomain, "DS")
  ]);
  const spf = parseSpfRecord(domainTxt);
  const dmarc = parseDmarcRecord(dmarcTxt);
  const dnssecActive = dsRecords.length > 0;
  const hasMxRecords = mxRecords.length > 0;
  let score = 0;
  const recommendations = [];
  if (spf.present && spf.isCompliant) {
    score += spf.qualifier === "-all" ? 40 : 30;
  } else if (spf.present) {
    score += 15;
  } else {
    recommendations.push("Publicar registro SPF (TXT) com '-all' para autenticar provedores de envio.");
  }
  if (dmarc.present && dmarc.isEnforcing) {
    score += dmarc.policy === "reject" ? 45 : 35;
  } else if (dmarc.present) {
    score += 15;
    recommendations.push("Evoluir a pol\xEDtica DMARC de 'p=none' para 'p=quarantine' ou 'p=reject'.");
  } else {
    recommendations.push("Configurar registro DMARC (_dmarc) para prote\xE7\xE3o ativa contra Phishing e BEC.");
  }
  if (dnssecActive) {
    score += 15;
  } else {
    recommendations.push("Ativar DNSSEC no registrador do dom\xEDnio para prote\xE7\xE3o contra envenenamento de cache DNS.");
  }
  score = Math.min(100, score);
  let overallStatus = "CRITICAL";
  if (score >= 80) overallStatus = "SECURE";
  else if (score >= 50) overallStatus = "WARNING";
  return {
    domain: cleanDomain,
    hasMxRecords,
    mxServers: mxRecords,
    spf,
    dmarc,
    dnssecActive,
    emailSecurityScore: score,
    overallStatus,
    recommendations
  };
}

// src/lib/security/crypto-entropy-analyzer.ts
function calculatePasswordEntropy(password) {
  const len = password.length;
  if (len === 0) {
    return {
      entropyBits: 0,
      charsetSize: 0,
      length: 0,
      strengthCategory: "VERY_WEAK",
      estimatedCrackTimeGpuCluster: "Instant\xE2neo (0s)",
      recommendations: ["Forne\xE7a uma senha n\xE3o vazia."]
    };
  }
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 33;
  const entropyBits = Math.round(len * Math.log2(charset || 1));
  const recommendations = [];
  let strength = "VERY_WEAK";
  let crackTime = "Instant\xE2neo (< 1 segundo)";
  if (entropyBits < 36) {
    strength = "VERY_WEAK";
    crackTime = "Menos de 1 segundo";
    recommendations.push("Aumente o comprimento da senha para pelo menos 14 caracteres.");
  } else if (entropyBits < 56) {
    strength = "WEAK";
    crackTime = "Alguns minutos / horas em GPU cluster (RTX 4090)";
    recommendations.push("Adicione caracteres especiais, n\xFAmeros e letras mai\xFAsculas.");
  } else if (entropyBits < 72) {
    strength = "FAIR";
    crackTime = "Alguns meses a anos";
    recommendations.push("Considere utilizar uma frase-senha (passphrase) de 4+ palavras aleat\xF3rias.");
  } else if (entropyBits < 96) {
    strength = "STRONG";
    crackTime = "Centenas de anos (Resistente a ataques de for\xE7a bruta)";
  } else {
    strength = "VERY_STRONG";
    crackTime = "Milh\xF5es de anos (Seguran\xE7a criptogr\xE1fica de n\xEDvel militar)";
  }
  return {
    entropyBits,
    charsetSize: charset,
    length: len,
    strengthCategory: strength,
    estimatedCrackTimeGpuCluster: crackTime,
    recommendations
  };
}

// src/lib/security/local-secret-scanner.ts
import fs from "node:fs";
import path from "node:path";
var SECRET_PATTERNS = [
  {
    id: "aws-access-key",
    category: "API_KEY",
    description: "Chave de Acesso AWS (Access Key ID)",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: "CRITICAL"
  },
  {
    id: "openai-api-key",
    category: "API_KEY",
    description: "Chave de API da OpenAI (sk-...)",
    regex: /\b(sk-[a-zA-Z0-9_-]{32,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "stripe-secret-key",
    category: "API_KEY",
    description: "Chave Secreta do Stripe (sk_live / rk_live)",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "github-pat",
    category: "API_KEY",
    description: "Token de Acesso Pessoal do GitHub (PAT)",
    regex: /\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "google-api-key",
    category: "API_KEY",
    description: "Chave de API do Google Cloud (AIza...)",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    severity: "HIGH"
  },
  {
    id: "ssh-private-key",
    category: "PRIVATE_KEY",
    description: "Chave Privada SSH / RSA / OpenSSL",
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    severity: "CRITICAL"
  },
  {
    id: "slack-webhook",
    category: "API_KEY",
    description: "URL de Webhook do Slack",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}/,
    severity: "HIGH"
  },
  {
    id: "db-connection-string",
    category: "CREDENTIAL",
    description: "String de Conex\xE3o com Banco de Dados contendo senha",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+/,
    severity: "HIGH"
  },
  {
    id: "dangerous-eval",
    category: "DANGEROUS_CODE",
    description: "Execu\xE7\xE3o Din\xE2mica Insegura de C\xF3digo (eval)",
    regex: /\beval\s*\([^\)]+\)/,
    severity: "MEDIUM"
  }
];
var SENSITIVE_FILENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  "id_rsa",
  "id_ed25519",
  "credentials.json",
  "serviceAccountKey.json"
];
var IGNORED_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".cache",
  ".vercel"
]);
var IGNORED_EXTENSIONS = /* @__PURE__ */ new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".mp4",
  ".mp3",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".map",
  ".lock"
]);
function redactSecret(match) {
  if (match.length <= 8) return "********";
  return match.slice(0, 4) + "..." + match.slice(-4);
}
function scanDirectoryForSecrets(targetDir, maxFiles = 1e3) {
  const startTime = Date.now();
  const findings = [];
  let filesCount = 0;
  function walk(currentDir, depth = 0) {
    if (depth > 6 || filesCount >= maxFiles) return;
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(targetDir, fullPath);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith(".gemini")) {
          walk(fullPath, depth + 1);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (IGNORED_EXTENSIONS.has(ext)) continue;
        filesCount++;
        if (SENSITIVE_FILENAMES.includes(entry.name)) {
          findings.push({
            ruleId: "sensitive-file-exposed",
            category: "SENSITIVE_FILE",
            description: `Arquivo de credenciais ou ambiente exposto: ${entry.name}`,
            filePath: relPath,
            lineNumber: 1,
            snippet: `Arquivo detectado no disco: ${entry.name}`,
            severity: entry.name.includes(".env") ? "HIGH" : "CRITICAL"
          });
        }
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > 1024 * 500) continue;
          const content = fs.readFileSync(fullPath, "utf-8");
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const pattern of SECRET_PATTERNS) {
              const match = line.match(pattern.regex);
              if (match) {
                const rawMatch = match[1] || match[0];
                const cleanSnippet = line.replace(rawMatch, redactSecret(rawMatch)).trim();
                findings.push({
                  ruleId: pattern.id,
                  category: pattern.category,
                  description: pattern.description,
                  filePath: relPath,
                  lineNumber: i + 1,
                  snippet: cleanSnippet.slice(0, 140),
                  severity: pattern.severity
                });
              }
            }
          }
        } catch {
        }
      }
    }
  }
  walk(targetDir, 0);
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  return {
    directory: targetDir,
    totalFilesScanned: filesCount,
    findings,
    criticalCount,
    highCount,
    mediumCount,
    isClean: findings.length === 0,
    scanDurationMs: Date.now() - startTime
  };
}

// src/lib/security/jwt-token-analyzer.ts
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}
function auditJwtToken(tokenStr) {
  const clean = tokenStr.trim();
  const parts = clean.split(".");
  if (parts.length !== 3) {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: false,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Formato de token JWT inv\xE1lido. Deve conter 3 partes separadas por ponto (Header.Payload.Signature)." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  let header = {};
  let payload = {};
  try {
    header = JSON.parse(base64UrlDecode(headerPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o cabe\xE7alho Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  try {
    payload = JSON.parse(base64UrlDecode(payloadPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header,
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: header.alg || "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o payload Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  const issues = [];
  const algorithm = String(header.alg || "none").toUpperCase();
  const signaturePresent = signaturePart.length > 0;
  if (algorithm === "NONE" || !signaturePresent) {
    issues.push({
      severity: "CRITICAL",
      message: "Vulnerabilidade Cr\xEDtica 'alg: none': Token sem assinatura criptogr\xE1fica, permitindo forja irrestrita de identidade."
    });
  }
  if (algorithm === "HS256") {
    issues.push({
      severity: "LOW",
      message: "Algoritmo sim\xE9trico HS256: Requer segredo com no m\xEDnimo 256 bits de entropia. Prefira algoritmos assim\xE9tricos (RS256/ES256/EdDSA)."
    });
  }
  const nowInSeconds = Math.floor(Date.now() / 1e3);
  let isExpired = false;
  let expiresInSeconds;
  const hasExpiration = typeof payload.exp === "number";
  if (!hasExpiration) {
    issues.push({
      severity: "HIGH",
      message: "Aus\xEAncia do claim 'exp' (Token Infinito): Tokens sem expira\xE7\xE3o permanecem v\xE1lidos permanentemente se vazados."
    });
  } else {
    expiresInSeconds = payload.exp - nowInSeconds;
    if (expiresInSeconds <= 0) {
      isExpired = true;
      issues.push({
        severity: "MEDIUM",
        message: `Token expirado h\xE1 ${Math.abs(expiresInSeconds)} segundos.`
      });
    }
  }
  const sensitiveKeys = ["password", "senha", "credit_card", "secret", "cvv", "cpf", "ssn"];
  for (const k of Object.keys(payload)) {
    if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
      issues.push({
        severity: "HIGH",
        message: `Vazamento de PII/Segredo no payload: O claim '${k}' est\xE1 exposto em texto claro (JWT n\xE3o \xE9 criptografado, apenas assinado).`
      });
    }
  }
  let score = 100;
  for (const iss of issues) {
    if (iss.severity === "CRITICAL") score -= 60;
    else if (iss.severity === "HIGH") score -= 25;
    else if (iss.severity === "MEDIUM") score -= 15;
    else if (iss.severity === "LOW") score -= 5;
  }
  score = Math.max(0, score);
  let status = "CRITICAL";
  if (score >= 80) status = "SECURE";
  else if (score >= 50) status = "WARNING";
  return {
    rawToken: clean,
    isValidStructure: true,
    header,
    payload,
    signaturePresent,
    algorithm,
    isExpired,
    expiresInSeconds,
    hasExpiration,
    issues,
    securityScore: score,
    status
  };
}

// src/lib/security/subdomain-recon-analyzer.ts
async function discoverSubdomains(domainInput) {
  const startTime = Date.now();
  const cleanDomain = domainInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  if (!cleanDomain) {
    return {
      domain: "",
      totalFound: 0,
      subdomains: [],
      durationMs: 0,
      source: "crt.sh",
      status: "ERROR",
      error: "Dom\xEDnio inv\xE1lido fornecido."
    };
  }
  const url = `https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6e3);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "ObsidianSec-PassiveRecon/1.1 (+https://obsidiansec.dev)",
        Accept: "application/json"
      }
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "ERROR",
        error: `Servi\xE7o de Certificate Transparency retornou HTTP ${res.status}.`
      };
    }
    const data = await res.json();
    if (!Array.isArray(data)) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "EMPTY"
      };
    }
    const uniqueSubs = /* @__PURE__ */ new Set();
    for (const entry of data) {
      const nameValue = String(entry.name_value || "");
      const lines = nameValue.split("\n");
      for (const line of lines) {
        const sub = line.trim().toLowerCase();
        if (sub && sub.endsWith(cleanDomain) && !sub.includes("@")) {
          const normalized = sub.startsWith("*.") ? sub.slice(2) : sub;
          if (normalized) uniqueSubs.add(normalized);
        }
      }
    }
    const sortedSubs = Array.from(uniqueSubs).sort((a, b) => a.localeCompare(b));
    return {
      domain: cleanDomain,
      totalFound: sortedSubs.length,
      subdomains: sortedSubs,
      durationMs: Date.now() - startTime,
      source: "Certificate Transparency Logs (crt.sh)",
      status: sortedSubs.length > 0 ? "SUCCESS" : "EMPTY"
    };
  } catch (err) {
    return {
      domain: cleanDomain,
      totalFound: 0,
      subdomains: [],
      durationMs: Date.now() - startTime,
      source: "crt.sh",
      status: "ERROR",
      error: err.message?.includes("abort") ? "Tempo limite esgotado ao consultar logs p\xFAblicos de certificados." : `Erro na consulta de subdom\xEDnios: ${err.message || "Falha de rede"}`
    };
  }
}

// src/lib/security/waf-detector-analyzer.ts
var WAF_SIGNATURES = [
  {
    id: "cloudflare",
    name: "Cloudflare Web Application Firewall",
    vendor: "Cloudflare, Inc.",
    headerMatches: [
      { name: "server", valuePattern: /cloudflare/i },
      { name: "cf-ray" },
      { name: "cf-cache-status" }
    ],
    cookieMatches: [/_cfuvid/i, /cf_clearance/i, /__cfduid/i],
    bodyMatches: [/Attention Required! \| Cloudflare/i, /CLOUDFLARE_ERROR_500S_BOX/i, /Cloudflare Ray ID/i]
  },
  {
    id: "aws-waf",
    name: "AWS WAF / Amazon CloudFront Shield",
    vendor: "Amazon Web Services (AWS)",
    headerMatches: [
      { name: "x-amzn-requestid" },
      { name: "x-amz-cf-id" },
      { name: "x-amzn-errortype", valuePattern: /waf/i }
    ],
    cookieMatches: [/aws-waf-token/i, /AWSALB/i, /AWSALBCORS/i],
    bodyMatches: [/Request blocked by AWS WAF/i, /<title>AWS WAF/i, /The request could not be satisfied/i]
  },
  {
    id: "modsecurity",
    name: "ModSecurity (Trustwave / OWASP Core Rule Set)",
    vendor: "OWASP / Trustwave",
    headerMatches: [
      { name: "server", valuePattern: /mod_security|modsecurity/i },
      { name: "x-mod-security" }
    ],
    bodyMatches: [/This error was generated by Mod_Security/i, /OWASP_CRS/i, /blocked by ModSecurity/i],
    statusCodes: [403, 406, 501]
  },
  {
    id: "imperva",
    name: "Imperva Incapsula WAF",
    vendor: "Imperva, Inc.",
    headerMatches: [
      { name: "x-cdn", valuePattern: /incapsula|imperva/i },
      { name: "x-iinfo" }
    ],
    cookieMatches: [/incap_ses_/i, /visid_incap_/i, /nlbi_/i, /___utmvc/i],
    bodyMatches: [/Request unsuccessful\. Incapsula incident ID/i, /_Incapsula_Resource/i]
  },
  {
    id: "akamai",
    name: "Akamai Kona Site Defender / App Protector",
    vendor: "Akamai Technologies",
    headerMatches: [
      { name: "server", valuePattern: /AkamaiGHost|Ghost/i },
      { name: "x-akamai-transformed" },
      { name: "x-akamai-request-id" }
    ],
    cookieMatches: [/ak_bmsc/i, /bm_sz/i, /bm_sv/i],
    bodyMatches: [/Access Denied - Akamai/i, /Reference&#32;&#35;/i, /AkamaiGHost/i]
  },
  {
    id: "azure-waf",
    name: "Microsoft Azure Front Door / Application Gateway WAF",
    vendor: "Microsoft Corporation",
    headerMatches: [
      { name: "x-azure-ref" },
      { name: "x-azure-fdid" },
      { name: "server", valuePattern: /Microsoft-Azure-Application-Gateway/i }
    ],
    cookieMatches: [/ApplicationGatewayAffinity/i],
    bodyMatches: [/Azure Front Door/i, /The request is blocked\. Azure Front Door/i]
  },
  {
    id: "sucuri",
    name: "Sucuri CloudProxy WAF",
    vendor: "Sucuri (GoDaddy)",
    headerMatches: [
      { name: "server", valuePattern: /sucuri/i },
      { name: "x-sucuri-id" },
      { name: "x-sucuri-cache" }
    ],
    cookieMatches: [/sucuri_cloudproxy/i],
    bodyMatches: [/Access Denied - Sucuri Website Firewall/i, /Questions\? cloudproxy@sucuri\.net/i]
  },
  {
    id: "f5-bigip",
    name: "F5 BIG-IP Application Security Manager (ASM)",
    vendor: "F5 Networks",
    headerMatches: [
      { name: "server", valuePattern: /BigIP|BIG-IP/i },
      { name: "x-cnection" }
    ],
    cookieMatches: [/BIGipServer/i, /TS[a-zA-Z0-9]{6,}/i],
    bodyMatches: [/The requested URL was rejected\. Please consult with your administrator/i]
  }
];
async function detectWaf(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }
  const indicators = [];
  let detectedWaf = null;
  let phase = "NONE";
  let confidence = "NONE";
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4e3);
    const baselineRes = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ObsidianSec/1.2",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });
    clearTimeout(timeout);
    const headers = baselineRes.headers;
    const rawSetCookies = [];
    if (typeof headers.getSetCookie === "function") {
      rawSetCookies.push(...headers.getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }
    const cookieStr = rawSetCookies.join("; ");
    for (const waf of WAF_SIGNATURES) {
      if (waf.headerMatches) {
        for (const hm of waf.headerMatches) {
          const val = headers.get(hm.name);
          if (val !== null) {
            if (!hm.valuePattern || hm.valuePattern.test(val)) {
              indicators.push(`Cabe\xE7alho identificador: '${hm.name}: ${val.slice(0, 50)}'`);
              detectedWaf = waf;
              confidence = "HIGH";
              phase = "PASSIVE";
            }
          }
        }
      }
      if (waf.cookieMatches) {
        for (const cm of waf.cookieMatches) {
          if (cm.test(cookieStr)) {
            indicators.push(`Cookie exclusivo de WAF: padr\xE3o '${cm.source}'`);
            detectedWaf = waf;
            confidence = "HIGH";
            phase = "PASSIVE";
          }
        }
      }
    }
  } catch (err) {
    indicators.push(`Aviso na inspe\xE7\xE3o passiva: ${err.message}`);
  }
  if (!detectedWaf) {
    try {
      const parsed = new URL(url);
      parsed.searchParams.set("obsidian_waf_probe", "<script>alert('obsidiansec_probe')</script>");
      const probeController = new AbortController();
      const probeTimeout = setTimeout(() => probeController.abort(), 4e3);
      const probeRes = await fetch(parsed.toString(), {
        method: "GET",
        signal: probeController.signal,
        headers: {
          "User-Agent": "ObsidianSec-WAF-Probe/1.2 (+https://obsidiansec.dev)"
        }
      });
      clearTimeout(probeTimeout);
      const status = probeRes.status;
      const body = await probeRes.text();
      const headers = probeRes.headers;
      if (status === 403 || status === 406 || status === 429 || status === 501) {
        for (const waf of WAF_SIGNATURES) {
          if (waf.bodyMatches) {
            for (const bm of waf.bodyMatches) {
              if (bm.test(body)) {
                indicators.push(`Padr\xE3o de bloqueio de WAF detectado no corpo da resposta: '${bm.source}'`);
                detectedWaf = waf;
                confidence = "HIGH";
                phase = "ACTIVE_PROBE";
                break;
              }
            }
          }
        }
        if (!detectedWaf) {
          detectedWaf = {
            id: "generic-waf",
            name: "Firewall / WAF Gen\xE9rico (Bloqueio Detectado)",
            vendor: "Desconhecido / Provedor Customizado"
          };
          indicators.push(`A requisi\xE7\xE3o de teste retornou HTTP ${status} (Bloqueio de ataque sint\xE9tico).`);
          confidence = "MEDIUM";
          phase = "ACTIVE_PROBE";
        }
      }
    } catch {
    }
  }
  const isDetected = detectedWaf !== null;
  const wafName = isDetected ? detectedWaf.name : "Nenhum WAF Detectado (Exposi\xE7\xE3o Direta ao Servidor)";
  const vendor = isDetected ? detectedWaf.vendor : "Servidor Web Convencional";
  let recommendation = "WAF ativo e monitorando requisi\xE7\xF5es de borda.";
  if (!isDetected) {
    recommendation = "Recomendado colocar a aplica\xE7\xE3o atr\xE1s de um WAF (ex: Cloudflare WAF, AWS WAF ou ModSecurity) para mitigar ataques automatizados de inje\xE7\xE3o SQL, XSS e botnets.";
  }
  return {
    targetUrl: url,
    detected: isDetected,
    wafName,
    vendor,
    confidence,
    detectionPhase: phase,
    indicators,
    recommendation,
    durationMs: Date.now() - startTime
  };
}

// src/lib/security/tcp-port-scanner.ts
import net from "node:net";
var CRITICAL_PORTS = [
  {
    port: 21,
    service: "FTP (File Transfer Protocol)",
    category: "REMOTE_ACCESS",
    riskLevel: "HIGH",
    exposureRisk: "Credenciais e arquivos transmitidos em texto claro sem criptografia.",
    mitigation: "Desativar FTP e utilizar SFTP (porta 22) ou FTPS com TLS."
  },
  {
    port: 22,
    service: "SSH (Secure Shell)",
    category: "REMOTE_ACCESS",
    riskLevel: "MEDIUM",
    exposureRisk: "Alvo cont\xEDnuo de botnets de for\xE7a bruta e varreduras automatizadas.",
    mitigation: "Desabilitar autentica\xE7\xE3o por senha e restringir a IPs confi\xE1veis ou VPN."
  },
  {
    port: 23,
    service: "Telnet (Terminal Remoto Legado)",
    category: "LEGACY_INSECURE",
    riskLevel: "CRITICAL",
    exposureRisk: "Protocolo inseguro sem criptografia. Vetor de botnets IoT (Mirai).",
    mitigation: "Desativar imediatamente o servi\xE7o Telnet e migrar para SSH."
  },
  {
    port: 80,
    service: "HTTP (Web Server)",
    category: "WEB",
    riskLevel: "INFO",
    exposureRisk: "Porta web padr\xE3o (deve redirecionar para HTTPS).",
    mitigation: "Configurar redirecionamento 301 permanente para HTTPS com HSTS."
  },
  {
    port: 443,
    service: "HTTPS (Web Seguro)",
    category: "WEB",
    riskLevel: "INFO",
    exposureRisk: "Porta web segura padr\xE3o.",
    mitigation: "Manter certificados TLS atualizados e habilitar HTTP/2 e TLS 1.3."
  },
  {
    port: 3306,
    service: "MySQL / MariaDB Database",
    category: "DATABASE",
    riskLevel: "HIGH",
    exposureRisk: "Banco de dados exposto a ataques de for\xE7a bruta contra usu\xE1rio root.",
    mitigation: "Vincular a 127.0.0.1 ou rede privada interna (VPC Security Group)."
  },
  {
    port: 3389,
    service: "RDP (Windows Remote Desktop)",
    category: "REMOTE_ACCESS",
    riskLevel: "CRITICAL",
    exposureRisk: "Vetor #1 de acesso inicial para grupos de ransomware corporativo.",
    mitigation: "Bloquear na borda da nuvem e utilizar VPN com MFA ou Azure Bastion."
  },
  {
    port: 5432,
    service: "PostgreSQL Database",
    category: "DATABASE",
    riskLevel: "HIGH",
    exposureRisk: "Banco de dados relacional exposto \xE0 internet p\xFAblica.",
    mitigation: "Configurar pg_hba.conf para rejeitar conex\xF5es externas e isolar em subnet privada."
  },
  {
    port: 6379,
    service: "Redis Cache & Database",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "RCE e exfiltra\xE7\xE3o total de dados via grava\xE7\xE3o de chaves SSH ou dump de mem\xF3ria.",
    mitigation: "Nunca expor na internet! Habilitar autentica\xE7\xE3o forte e isolar em rede local."
  },
  {
    port: 8080,
    service: "HTTP-Alt / Proxy / Dev Server",
    category: "WEB",
    riskLevel: "MEDIUM",
    exposureRisk: "Porta frequentemente usada para pain\xE9is de administra\xE7\xE3o (Tomcat, Jenkins) ou dev.",
    mitigation: "Proteger com autentica\xE7\xE3o forte e n\xE3o expor ambientes de desenvolvimento."
  },
  {
    port: 9200,
    service: "Elasticsearch REST API",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "Acesso unauthenticated a logs, dados de clientes e clusters de busca.",
    mitigation: "Ativar X-Pack Security com TLS e restringir o acesso apenas a backends autorizados."
  },
  {
    port: 27017,
    service: "MongoDB NoSQL Database",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "Alvo priorit\xE1rio de ataques automatizados de ransomware de banco de dados.",
    mitigation: "Ativar autentica\xE7\xE3o SCRAM-SHA-256 e fechar portas no Security Group da nuvem."
  }
];
function checkTcpPort(host, portDef, timeoutMs = 1500) {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;
    const finalize = (status) => {
      if (isResolved) return;
      isResolved = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({
        port: portDef.port,
        service: portDef.service,
        category: portDef.category,
        riskLevel: portDef.riskLevel,
        status,
        responseTimeMs: Date.now() - start,
        exposureRisk: portDef.exposureRisk,
        mitigation: portDef.mitigation
      });
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finalize("OPEN"));
    socket.once("timeout", () => finalize("FILTERED"));
    socket.once("error", (err) => {
      if (err.code === "ECONNREFUSED") finalize("CLOSED");
      else finalize("FILTERED");
    });
    try {
      socket.connect(portDef.port, host);
    } catch {
      finalize("FILTERED");
    }
  });
}
async function scanHostCriticalPorts(hostInput, timeoutMs = 1500) {
  const startTime = Date.now();
  const cleanHost = hostInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim();
  const checks = CRITICAL_PORTS.map((p) => checkTcpPort(cleanHost, p, timeoutMs));
  const results = await Promise.all(checks);
  const openCount = results.filter((r) => r.status === "OPEN").length;
  const filteredCount = results.filter((r) => r.status === "FILTERED").length;
  const closedCount = results.filter((r) => r.status === "CLOSED").length;
  const criticalExposures = results.filter(
    (r) => r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")
  );
  let overallVerdict = "SECURE";
  if (criticalExposures.some((r) => r.riskLevel === "CRITICAL")) {
    overallVerdict = "CRITICAL";
  } else if (criticalExposures.length > 0) {
    overallVerdict = "WARNING";
  }
  return {
    targetHost: cleanHost,
    totalScanned: results.length,
    openCount,
    filteredCount,
    closedCount,
    criticalExposuresCount: criticalExposures.length,
    results,
    overallVerdict,
    durationMs: Date.now() - startTime
  };
}

// src/cli-source.ts
var args = process.argv.slice(2);
var command = args[0] || "help";
var ANSI = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  green: "\x1B[32m",
  yellow: "\x1B[33m",
  red: "\x1B[31m",
  cyan: "\x1B[36m",
  gray: "\x1B[90m",
  magenta: "\x1B[35m"
};
function printBanner() {
  console.log(`
${ANSI.bold}${ANSI.cyan}\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551    \u{1F6E1}\uFE0F  OBSIDIANSEC CLI // DEVSECOPS & EDGE AUDITING ARSENAL 2026      \u2551
\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D${ANSI.reset}
`);
}
async function runAudit() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec audit <url> [--min-grade=A] [--json]${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const minGradeArg = args.find((a) => a.startsWith("--min-grade="));
  const minGrade = minGradeArg ? minGradeArg.split("=")[1].toUpperCase() : "B";
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F50D} [1/2] Disparando sondagem t\xE1tica de borda em ${ANSI.bold}${targetUrl}${ANSI.reset}...`);
  try {
    const report = await auditUniversalEndpoint(targetUrl);
    let score = 0;
    const h = report.securityHeaders;
    if (h.csp.present) score += h.csp.isReportOnly ? 15 : 30;
    if (h.xFrameOptions.present) score += 20;
    if (h.hsts.present) score += 20;
    if (h.xContentTypeOptions.present) score += 15;
    if (h.permissionsPolicy.present) score += 15;
    score = Math.min(100, score);
    let grade = "F";
    if (score >= 85) grade = "A+";
    else if (score >= 70) grade = "A";
    else if (score >= 50) grade = "B";
    else if (score >= 30) grade = "C";
    if (isJson) {
      console.log(JSON.stringify({ ...report, score, grade }, null, 2));
      process.exit(0);
    }
    const gradeColor = grade === "A+" || grade === "A" ? ANSI.green : grade === "B" ? ANSI.yellow : ANSI.red;
    console.log(`
======================================================================`);
    console.log(`\u{1F4CA} RESULTADO DA AUDITORIA DE SEGURAN\xC7A`);
    console.log(`======================================================================`);
    console.log(`\u2022 Alvo Auditado:           ${report.targetUrl}`);
    console.log(`\u2022 Servidor / Borda:        ${report.serverDetected}`);
    console.log(`\u2022 Score de Blindagem:      ${score} / 100`);
    console.log(`\u2022 Nota Final:              ${gradeColor}${ANSI.bold}GRADE ${grade}${ANSI.reset}`);
    console.log(`\u2022 Status:                  ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "A\xC7\xC3O REQUERIDA"}${ANSI.reset}`);
    console.log(`\u2022 Cadeia de Ataque:        ${report.attackChain.riskSummary}`);
    console.log(`======================================================================
`);
    console.log(`\u{1F6E1}\uFE0F  CONTROLES DE BORDA:`);
    console.log(`  [${h.csp.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Content-Security-Policy (CSP)`);
    console.log(`  [${h.xFrameOptions.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] X-Frame-Options (Anti-Clickjacking)`);
    console.log(`  [${h.hsts.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Strict-Transport-Security (HSTS)`);
    console.log(`  [${h.xContentTypeOptions.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] X-Content-Type-Options (nosniff)`);
    console.log(`  [${h.permissionsPolicy.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Permissions-Policy`);
    console.log(`
======================================================================
`);
    const gradeRanks = { "A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "ERR": 0 };
    const currentRank = gradeRanks[grade] || 0;
    const requiredRank = gradeRanks[minGrade] || 3;
    if (currentRank < requiredRank) {
      console.error(`${ANSI.red}\u274C [CI/CD Quality Gate]: Reprovado! A nota ${grade} \xE9 inferior \xE0 nota m\xEDnima exigida (${minGrade}).${ANSI.reset}
`);
      process.exit(1);
    }
    console.log(`${ANSI.green}\u2705 [CI/CD Quality Gate]: Aprovado com sucesso! O deploy atende aos requisitos de seguran\xE7a.${ANSI.reset}
`);
    process.exit(0);
  } catch (err) {
    console.error(`
${ANSI.red}\u274C Falha na auditoria:${ANSI.reset} ${err.message}
`);
    process.exit(1);
  }
}
async function runDns() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}\u274C Erro: Dom\xEDnio n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec dns <dominio>${ANSI.reset}`);
    process.exit(1);
  }
  printBanner();
  console.log(`\u{1F50D} Consultando registros DNS e Anti-Phishing para ${ANSI.bold}${domain}${ANSI.reset}...
`);
  try {
    const report = await auditDomainDnsSecurity(domain);
    console.log(`\u2022 Dom\xEDnio:             ${report.domain}`);
    console.log(`\u2022 Score de Email:      ${report.emailSecurityScore} / 100`);
    console.log(`\u2022 Status:              ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "ALERTA"}${ANSI.reset}`);
    console.log(`\u2022 SPF:                 ${report.spf.present ? ANSI.green + "ATIVO (" + report.spf.qualifier + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`\u2022 DMARC:               ${report.dmarc.present ? ANSI.green + "ATIVO (p=" + report.dmarc.policy + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`\u2022 DNSSEC:              ${report.dnssecActive ? ANSI.green + "ATIVO" : ANSI.gray + "INATIVO"}${ANSI.reset}`);
    console.log(`
======================================================================
`);
  } catch (err) {
    console.error(`
${ANSI.red}\u274C Falha na auditoria DNS:${ANSI.reset} ${err.message}
`);
  }
}
async function runScanDir() {
  const dirInput = args[1] || process.cwd();
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F50D} Varrendo arquivos e ca\xE7ando segredos em ${ANSI.bold}${dirInput}${ANSI.reset}...
`);
  const report = scanDirectoryForSecrets(dirInput);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.isClean ? 0 : 1);
  }
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DO CA\xC7ADOR DE SEGREDOS & SAST LOCAL`);
  console.log(`======================================================================`);
  console.log(`\u2022 Arquivos Analisados:     ${report.totalFilesScanned}`);
  console.log(`\u2022 Dura\xE7\xE3o:                 ${report.scanDurationMs}ms`);
  console.log(`\u2022 Vulnerabilidades:        ${report.isClean ? ANSI.green + "0 (LIMPO)" : ANSI.red + report.findings.length + " ENCONTRADAS"}${ANSI.reset}`);
  console.log(`\u2022 Cr\xEDticas:                ${report.criticalCount > 0 ? ANSI.red + report.criticalCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`\u2022 Altas:                   ${report.highCount > 0 ? ANSI.yellow + report.highCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`======================================================================
`);
  if (report.findings.length > 0) {
    console.log(`\u26A0\uFE0F  VULNERABILIDADES DETECTADAS:`);
    report.findings.forEach((f, idx) => {
      const color = f.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`
  [#${idx + 1}] ${color}${ANSI.bold}[${f.severity}] ${f.description}${ANSI.reset}`);
      console.log(`      \u{1F4C1} Arquivo: ${ANSI.cyan}${f.filePath}:${f.lineNumber}${ANSI.reset}`);
      console.log(`      \u{1F50D} Trecho:  ${ANSI.gray}${f.snippet}${ANSI.reset}`);
    });
    console.log(`
${ANSI.red}\u274C [SAST Gate]: Foram encontrados segredos sens\xEDveis no c\xF3digo. Remova-os antes de publicar!${ANSI.reset}
`);
    process.exit(1);
  } else {
    console.log(`${ANSI.green}\u2705 [SAST Gate]: Nenhum segredo ou credencial vazada detectada no c\xF3digo!${ANSI.reset}
`);
    process.exit(0);
  }
}
async function runJwt() {
  const token = args[1];
  if (!token) {
    console.error(`${ANSI.red}\u274C Erro: Token JWT n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec jwt <token>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const report = auditJwtToken(token);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.status === "CRITICAL" ? 1 : 0);
  }
  printBanner();
  console.log(`\u{1F39F}\uFE0F AUDITORIA DE SEGURAN\xC7A DE TOKEN JWT
`);
  if (!report.isValidStructure) {
    console.error(`${ANSI.red}\u274C Formato inv\xE1lido de JWT.${ANSI.reset}`);
    report.issues.forEach((i) => console.log(`  - ${i.message}`));
    process.exit(1);
  }
  const statusColor = report.status === "SECURE" ? ANSI.green : report.status === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`\u2022 Algoritmo:           ${ANSI.bold}${report.algorithm}${ANSI.reset}`);
  console.log(`\u2022 Score de Seguran\xE7a:  ${report.securityScore} / 100`);
  console.log(`\u2022 Status:              ${statusColor}${ANSI.bold}${report.status}${ANSI.reset}`);
  console.log(`\u2022 Assinatura Presente: ${report.signaturePresent ? ANSI.green + "SIM" : ANSI.red + "N\xC3O (alg: none)"}${ANSI.reset}`);
  console.log(`\u2022 Expira\xE7\xE3o:           ${report.hasExpiration ? report.isExpired ? ANSI.red + "EXPIRADO" : ANSI.green + "V\xC1LIDO" : ANSI.yellow + "SEM EXPIRA\xC7\xC3O"}${ANSI.reset}`);
  console.log(`
\u{1F4DC} HEADER DECODIFICADO:`);
  console.log(JSON.stringify(report.header, null, 2));
  console.log(`
\u{1F4E6} PAYLOAD (CLAIMS):`);
  console.log(JSON.stringify(report.payload, null, 2));
  if (report.issues.length > 0) {
    console.log(`
\u26A0\uFE0F  RISCOS DETECTADOS:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
  }
  console.log(`
======================================================================
`);
  process.exit(report.status === "CRITICAL" ? 1 : 0);
}
async function runSubdomains() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}\u274C Erro: Dom\xEDnio n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec subdomains <dominio>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F310} Buscando subdom\xEDnios via Certificate Transparency Logs para ${ANSI.bold}${domain}${ANSI.reset}...
`);
  const report = await discoverSubdomains(domain);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} SUPERF\xCDCIE DE ATAQUE PASSIVA (SUBDOM\xCDNIOS)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Dom\xEDnio Alvo:        ${report.domain}`);
  console.log(`\u2022 Total Descoberto:    ${ANSI.bold}${report.totalFound} subdom\xEDnios \xFAnicos${ANSI.reset}`);
  console.log(`\u2022 Fonte:               ${report.source}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.subdomains.length > 0) {
    report.subdomains.forEach((s) => console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${s}`));
  } else {
    console.log(`  Nenhum subdom\xEDnio adicional encontrado nos registros p\xFAblicos.`);
  }
  console.log(`
======================================================================
`);
}
async function runEntropy() {
  const password = args[1];
  if (!password) {
    console.error(`${ANSI.red}\u274C Erro: Senha n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec entropy <senha>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const entropy = calculatePasswordEntropy(password);
  if (isJson) {
    console.log(JSON.stringify(entropy, null, 2));
    process.exit(0);
  }
  printBanner();
  console.log(`\u{1F511} CALCULADORA DE ENTROPIA SHANNON & HASHCAT
`);
  const strengthColor = entropy.strengthCategory === "VERY_STRONG" || entropy.strengthCategory === "STRONG" ? ANSI.green : entropy.strengthCategory === "FAIR" ? ANSI.yellow : ANSI.red;
  console.log(`\u2022 Tamanho da Senha:    ${entropy.length} caracteres`);
  console.log(`\u2022 Bits de Entropia:    ${ANSI.bold}${entropy.entropyBits} bits${ANSI.reset}`);
  console.log(`\u2022 Charset Estimado:    ${entropy.charsetSize} s\xEDmbolos`);
  console.log(`\u2022 N\xEDvel de For\xE7a:      ${strengthColor}${ANSI.bold}${entropy.strengthCategory}${ANSI.reset}`);
  console.log(`\u2022 Tempo Estimado GPU:  ${ANSI.bold}${entropy.estimatedCrackTimeGpuCluster}${ANSI.reset} (Cluster RTX 4090 / Hashcat)`);
  console.log(`
======================================================================
`);
}
async function runWaf() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec waf <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F6E1}\uFE0F  Inspecionando assinaturas de WAF e Firewall de Borda para ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await detectWaf(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  const statusColor = report.detected ? ANSI.green : ANSI.yellow;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} DETECTOR DE WAF // WEB APPLICATION FIREWALL (WAFW00F ENGINE)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo:                ${report.targetUrl}`);
  console.log(`\u2022 Status do WAF:       ${statusColor}${ANSI.bold}${report.detected ? "ATIVO & DETECTADO" : "N\xC3O DETECTADO"}${ANSI.reset}`);
  console.log(`\u2022 Firewall / Shield:   ${ANSI.bold}${report.wafName}${ANSI.reset}`);
  console.log(`\u2022 Fabricante / Vendor: ${report.vendor}`);
  console.log(`\u2022 N\xEDvel de Confian\xE7a:  ${report.confidence}`);
  console.log(`\u2022 Fase de Detec\xE7\xE3o:    ${report.detectionPhase}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`\u2022 Recomenda\xE7\xE3o:        ${report.recommendation}`);
  console.log(`======================================================================
`);
  if (report.indicators.length > 0) {
    console.log(`\u{1F50D} EVID\xCANCIAS E ASSINATURAS IDENTIFICADAS:`);
    report.indicators.forEach((ind) => console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${ind}`));
  }
  console.log(`
======================================================================
`);
}
async function runPorts() {
  const host = args[1];
  if (!host) {
    console.error(`${ANSI.red}\u274C Erro: Host / IP alvo n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec ports <host>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F6AA} [Nmap Engine] Auditando 12 portas cr\xEDticas e ca\xE7ando bancos de dados em ${ANSI.bold}${host}${ANSI.reset}...
`);
  const report = await scanHostCriticalPorts(host);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
  }
  const verdictColor = report.overallVerdict === "SECURE" ? ANSI.green : report.overallVerdict === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DE AUDITORIA DE PORTAS CR\xCDTICAS & SERVI\xC7OS EXPOSTOS`);
  console.log(`======================================================================`);
  console.log(`\u2022 Host Auditado:       ${report.targetHost}`);
  console.log(`\u2022 Portas Analisadas:   ${report.totalScanned}`);
  console.log(`\u2022 Portas Abertas:      ${report.openCount > 0 ? ANSI.yellow + report.openCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`\u2022 Exposi\xE7\xE3o Cr\xEDtica:   ${report.criticalExposuresCount > 0 ? ANSI.red + report.criticalExposuresCount + " (RISCO GRAVE)" : ANSI.green + "0 (LIMPO)"}${ANSI.reset}`);
  console.log(`\u2022 Diagn\xF3stico:         ${verdictColor}${ANSI.bold}${report.overallVerdict}${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  console.log(`\u{1F4CB} RESULTADO POR PORTA AUDITADA:`);
  report.results.forEach((r) => {
    const statusBadge = r.status === "OPEN" ? ANSI.red + "[OPEN]" : r.status === "FILTERED" ? ANSI.green + "[FILTERED]" : ANSI.gray + "[CLOSED]";
    console.log(`  ${statusBadge}${ANSI.reset} ${ANSI.bold}Porta ${r.port}/TCP${ANSI.reset} - ${r.service} (${r.responseTimeMs}ms)`);
    if (r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")) {
      console.log(`      \u26A0\uFE0F  ${ANSI.red}${ANSI.bold}RISCO:${ANSI.reset} ${r.exposureRisk}`);
      console.log(`      \u{1F4A1} ${ANSI.cyan}Mitiga\xE7\xE3o:${ANSI.reset} ${r.mitigation}`);
    }
  });
  console.log(`
======================================================================
`);
  process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
}
function printHelp() {
  printBanner();
  console.log(`Arsenal de Comandos Dispon\xEDveis:

  ${ANSI.bold}obsidiansec audit <url>${ANSI.reset}            Audita cabe\xE7alhos de borda, cookies, CORS e MITRE attack chain
    Op\xE7\xF5es:
      --min-grade=<A|B|C>         Define a nota m\xEDnima para o Quality Gate de CI/CD (padr\xE3o: B)
      --json                      Retorna o relat\xF3rio completo em formato JSON

  ${ANSI.bold}obsidiansec waf <url>${ANSI.reset}              Detector de WAF & Firewall de Borda (Cloudflare, AWS WAF, ModSecurity, Imperva)

  ${ANSI.bold}obsidiansec ports <host>${ANSI.reset}           Auditoria de portas TCP cr\xEDticas (Redis, MongoDB, MySQL, Postgres, RDP, Telnet)

  ${ANSI.bold}obsidiansec scan-dir [pasta]${ANSI.reset}       Ca\xE7ador de segredos & SAST local (AWS, OpenAI, Stripe, .env, chaves privadas)
  
  ${ANSI.bold}obsidiansec jwt <token>${ANSI.reset}            Auditor de tokens JWT (detecta alg: none, expira\xE7\xE3o e decodifica claims)

  ${ANSI.bold}obsidiansec subdomains <dominio>${ANSI.reset}   Descoberta passiva de subdom\xEDnios via Certificate Transparency

  ${ANSI.bold}obsidiansec dns <dominio>${ANSI.reset}          Inspeciona registros anti-phishing SPF, DMARC e DNSSEC

  ${ANSI.bold}obsidiansec entropy <senha>${ANSI.reset}        Calcula bits de Shannon e tempo de quebra em GPU cluster

  ${ANSI.bold}obsidiansec help${ANSI.reset}                   Exibe este menu de ajuda
`);
}
switch (command) {
  case "audit":
    runAudit();
    break;
  case "waf":
  case "firewall":
    runWaf();
    break;
  case "ports":
  case "port-scan":
  case "nmap":
    runPorts();
    break;
  case "dns":
    runDns();
    break;
  case "scan-dir":
  case "scan":
  case "sast":
    runScanDir();
    break;
  case "jwt":
    runJwt();
    break;
  case "subdomains":
  case "subs":
    runSubdomains();
    break;
  case "entropy":
    runEntropy();
    break;
  case "version":
  case "-v":
  case "--version":
    console.log("ObsidianSec CLI v1.2.0");
    break;
  default:
    printHelp();
    break;
}
