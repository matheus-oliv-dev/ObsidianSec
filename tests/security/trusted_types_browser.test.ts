import { describe, expect, it } from "vitest";
import { createTrustedTypePolicy } from "@/lib/security/trusted-types";
import { createBrowserSecurityHeaders } from "@/lib/security/browser-shield";

describe("🌐 Browser Hardening: CSP Strict-Dynamic & Trusted Types", () => {
  describe("1. Política de Trusted Types", () => {
    it("sanitiza strings de HTML geradas através da política chimeraPolicy", () => {
      const policy = createTrustedTypePolicy("chimeraPolicy");
      const sanitized = policy.createHTML('<img src=x onerror="alert(1)">');

      expect(sanitized).not.toContain("<img");
      expect(sanitized).toContain("&lt;img");
    });

    it("bloqueia esquemas perigosos (javascript:) em URLs de scripts", () => {
      const policy = createTrustedTypePolicy("chimeraPolicy");
      expect(() => policy.createScriptURL("javascript:alert(document.cookie)")).toThrow(
        /SecurityError/i,
      );
    });

    it("permite URLs de scripts seguras e confiáveis", () => {
      const policy = createTrustedTypePolicy("chimeraPolicy");
      const safeUrl = policy.createScriptURL("https://bot.matheusdev.com.br/app.js");
      expect(safeUrl).toBe("https://bot.matheusdev.com.br/app.js");
    });
  });

  describe("2. CSP Level 3 com 'strict-dynamic' & Trusted Types Directives", () => {
    it("gera cabeçalho CSP moderno com 'strict-dynamic', nonces e require-trusted-types-for", () => {
      const nonce = "testNonce12345678";
      const headers = createBrowserSecurityHeaders(
        {
          enableStrictDynamic: true,
          enableTrustedTypes: true,
          trustedPolicyName: "chimeraPolicy",
          coepMode: "credentialless",
        },
        nonce,
      );

      const csp = headers["Content-Security-Policy"];
      expect(csp).toBeDefined();
      expect(csp).toContain("'strict-dynamic'");
      expect(csp).toContain(`nonce-${nonce}`);
      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain("trusted-types chimeraPolicy 'allow-duplicates'");
      expect(headers["Cross-Origin-Embedder-Policy"]).toBe("credentialless");
    });
  });
});
