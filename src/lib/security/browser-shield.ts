import crypto from "node:crypto";
import type { BrowserShieldConfig } from "@/types";

export interface CookieOptions {
  name: string;
  value: string;
  maxAgeSeconds?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  path?: string;
  domain?: string;
  useHostPrefix?: boolean;
}

export interface ModernBrowserShieldConfig extends BrowserShieldConfig {
  enableStrictDynamic?: boolean;
  enableTrustedTypes?: boolean;
  trustedPolicyName?: string;
  coepMode?: "require-corp" | "credentialless";
}

/**
 * Gera um Nonce criptográfico aleatório para ser usado em scripts inline no CSP
 */
export function generateCspNonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

/**
 * Constrói os cabeçalhos HTTP defensivos para blindagem do Navegador (Browser Shield - Padrão 2025/2026).
 */
export function createBrowserSecurityHeaders(
  config: ModernBrowserShieldConfig = {},
  nonce?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };

  // 1. Strict Transport Security (HSTS)
  if (config.enableHSTS !== false) {
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
  }

  // 2. Permissions Policy (Desativa APIs sensíveis de hardware)
  if (config.enablePermissionsPolicy !== false) {
    headers["Permissions-Policy"] =
      "microphone=(self), camera=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()";
  }

  // 3. Cross-Origin Isolation (COOP, COEP, CORP)
  if (config.enableCOOP !== false) {
    headers["Cross-Origin-Opener-Policy"] = "same-origin";
  }
  if (config.enableCOEP !== false) {
    const coepVal = config.coepMode || "require-corp";
    headers["Cross-Origin-Embedder-Policy"] = coepVal;
  }
  if (config.enableCORP !== false) {
    headers["Cross-Origin-Resource-Policy"] = "same-origin";
  }

  // 4. Content Security Policy (CSP Level 3 com Nonces, Strict-Dynamic e Trusted Types)
  if (config.enableCSP !== false) {
    const currentNonce = nonce || generateCspNonce();

    let scriptSrc: string;
    if (config.enableStrictDynamic) {
      // Padrão de ponta Google/W3C CSP Level 3
      scriptSrc = `'nonce-${currentNonce}' 'strict-dynamic' 'unsafe-inline' https:`;
    } else if (nonce) {
      scriptSrc = `'self' 'nonce-${nonce}'`;
    } else {
      scriptSrc = "'self'";
    }

    const defaultDirectives: Record<string, string[]> = {
      "default-src": ["'self'"],
      "script-src": [scriptSrc],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:", "blob:", "https:"],
      "media-src": ["'self'", "blob:", "https:"],
      "font-src": ["'self'", "data:"],
      "connect-src": ["'self'", "wss:", "https:"],
      "frame-ancestors": ["'none'"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "upgrade-insecure-requests": [],
    };

    // Trusted Types
    if (config.enableTrustedTypes) {
      const policyName = config.trustedPolicyName || "bomberPolicy";
      defaultDirectives["require-trusted-types-for"] = ["'script'"];
      defaultDirectives["trusted-types"] = [policyName, "'allow-duplicates'"];
    }

    const mergedDirectives = { ...defaultDirectives, ...config.cspDirectives };
    const cspString = Object.entries(mergedDirectives)
      .map(([key, values]) => {
        if (values.length === 0) return key;
        return `${key} ${values.join(" ")}`;
      })
      .join("; ");

    headers["Content-Security-Policy"] = cspString;
  }

  return headers;
}

/**
 * Cria uma string de Cookie com atributos de máxima segurança (__Host- prefix, SameSite=Strict, HttpOnly, Secure)
 */
export function buildSecureCookieString(options: CookieOptions): string {
  let cookieName = options.name;
  if (options.useHostPrefix && !cookieName.startsWith("__Host-")) {
    cookieName = `__Host-${cookieName}`;
  }

  const parts = [`${cookieName}=${encodeURIComponent(options.value)}`];

  if (options.path || options.useHostPrefix) {
    parts.push(`Path=${options.path || "/"}`);
  }

  if (options.domain && !options.useHostPrefix) {
    parts.push(`Domain=${options.domain}`);
  }

  if (options.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${options.maxAgeSeconds}`);
  }

  if (options.httpOnly !== false) {
    parts.push("HttpOnly");
  }

  if (options.secure !== false) {
    parts.push("Secure");
  }

  const sameSite = options.sameSite || "Strict";
  parts.push(`SameSite=${sameSite}`);

  return parts.join("; ");
}

/**
 * Aplica os cabeçalhos de segurança a uma resposta HTTP (Edge / Serverless Response)
 */
export function applySecurityHeadersToResponse(
  response: Response,
  config: ModernBrowserShieldConfig = {},
  nonce?: string,
): Response {
  const headers = createBrowserSecurityHeaders(config, nonce);
  for (const [key, value] of Object.entries(headers)) {
    response.headers.set(key, value);
  }
  return response;
}
