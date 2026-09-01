import { detectRemoteTechStack } from "../agents/polyglot/detector.ts";
import { runBurpHeaderAudit, type HeaderAuditBurpResult } from "../lib/security/cookie-cors-analyzer.ts";
import { buildAttackChainGraph, type AttackChainReport } from "../lib/security/attack-chain-analyzer.ts";

export interface UniversalAuditReport {
  targetUrl: string;
  httpStatus: number;
  serverDetected: string;
  frameworkDetected?: string;
  cdnOrProxy?: string;
  versionExposed: boolean;
  securityHeaders: {
    csp: { present: boolean; value?: string; isReportOnly?: boolean };
    xFrameOptions: { present: boolean; value?: string };
    xContentTypeOptions: { present: boolean; value?: string };
    permissionsPolicy: { present: boolean; value?: string };
    hsts: { present: boolean; value?: string };
    referrerPolicy: { present: boolean; value?: string };
    coop: { present: boolean; value?: string };
  };
  burpInspection: HeaderAuditBurpResult;
  attackChain: AttackChainReport;
  remediationSnippets: {
    serverType: string;
    snippet: string;
  }[];
  overallStatus: "SECURE" | "ACTION_REQUIRED";
}

/**
 * Gera snippets de configuração específicos para o servidor ou framework detectado.
 */
export function generateRemediationSnippets(serverName: string): { serverType: string; snippet: string }[] {
  const snippets = [];

  // NGINX
  snippets.push({
    serverType: "NGINX (/etc/nginx/conf.d/security.conf)",
    snippet: `add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "microphone=(self), camera=(), geolocation=(), payment=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';" always;
server_tokens off;`,
  });

  // APACHE / .HTACCESS
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
ServerTokens Prod`,
  });

  // VERCEL / NEXT.JS
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
}`,
  });

  // PYTHON / FASTAPI
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

app.add_middleware(SecurityHeadersMiddleware)`,
  });

  // NODE.JS / EXPRESS (HELMET)
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
}));`,
  });

  // GO / FIBER
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
}`,
  });

  // PYTHON / DJANGO
  snippets.push({
    serverType: "PYTHON DJANGO (settings.py)",
    snippet: `SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")`,
  });

  // PHP LARAVEL
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
}`,
  });

  // JAVA / SPRING BOOT
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
}`,
  });

  // C# / ASP.NET CORE
  snippets.push({
    serverType: "C# ASP.NET CORE (Program.cs)",
    snippet: `app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none';");
    await next();
});`,
  });

  return snippets;
}

/**
 * Realiza uma auditoria universal de segurança em qualquer URL web ao vivo.
 */
export async function auditUniversalEndpoint(targetUrl: string): Promise<UniversalAuditReport> {
  const url = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;

  let res;
  try {
    res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(5000),
    });
  } catch (err: any) {
    const msg = (err?.message || "").toLowerCase();
    const causeMsg = String(err?.cause?.message || err?.cause?.code || "").toLowerCase();

    if (msg.includes("abort") || msg.includes("timeout")) {
      throw new Error("Tempo limite de conexão esgotado (timeout). O servidor alvo demorou a responder.");
    }
    if (msg.includes("fetch failed") || causeMsg.includes("enotfound") || causeMsg.includes("eai_again")) {
      throw new Error("Não foi possível localizar o endereço (DNS/Domínio não encontrado). Verifique se o domínio foi digitado corretamente.");
    }
    if (causeMsg.includes("econnrefused")) {
      throw new Error("Conexão recusada pelo servidor de destino.");
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

  const rawSetCookies: string[] = [];
  if (typeof (headers as any).getSetCookie === "function") {
    rawSetCookies.push(...(headers as any).getSetCookie());
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
    serverVersionExposed: stack.versionExposed,
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
        value: cspValue || undefined,
        isReportOnly: !cspEnforcing && !!cspReportOnly,
      },
      xFrameOptions: { present: !!xFrame, value: xFrame || undefined },
      xContentTypeOptions: { present: !!nosniff, value: nosniff || undefined },
      permissionsPolicy: { present: !!perm, value: perm || undefined },
      hsts: { present: !!hsts, value: hsts || undefined },
      referrerPolicy: { present: !!referrer, value: referrer || undefined },
      coop: { present: !!coop, value: coop || undefined },
    },
    burpInspection,
    attackChain,
    remediationSnippets: snippets,
    overallStatus: isSecure ? "SECURE" : "ACTION_REQUIRED",
  };
}
