import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { validateCorsOrigin, validateFetchMetadata } from "@/lib/security/browser-advanced";
import { buildSecureCookieString, createBrowserSecurityHeaders } from "@/lib/security/browser-shield";
import { sanitizeInput } from "@/lib/security/sanitizer";

describe("🌐 Advanced Browser & Frontend Security Suite", () => {
  describe("1. Matriz de CORS Misconfigurations", () => {
    const corsConfig = {
      allowedOrigins: ["https://bombercyber.io", "https://bot.matheusdev.com.br"],
      allowCredentials: true,
    };

    it("TEST-026: bloqueia requisições CORS de origens não autorizadas (sem reflection)", () => {
      const result = validateCorsOrigin("https://evil-attacker.com", corsConfig);
      expect(result.allowed).toBe(false);
      expect(result.originHeaderValue).toBeUndefined();
    });

    it("TEST-027: rejeita expressamente Origin: null (sandboxed iframes / data URIs)", () => {
      const result = validateCorsOrigin("null", corsConfig);
      expect(result.allowed).toBe(false);
    });

    it("TEST-028: impede bypass de regex com subdomínios forjados", () => {
      const result = validateCorsOrigin("https://bombercyber.io.evil.com", corsConfig);
      expect(result.allowed).toBe(false);
    });

    it("TEST-029: aprova origens estritamente declaradas na lista branca", () => {
      const result = validateCorsOrigin("https://bot.matheusdev.com.br", corsConfig);
      expect(result.allowed).toBe(true);
      expect(result.originHeaderValue).toBe("https://bot.matheusdev.com.br");
    });
  });

  describe("2. CSRF & Double Submit Cookie Validation", () => {
    it("TEST-031: valida tokens Anti-CSRF via Double Submit Cookie HMAC", () => {
      const secret = "csrf-secret-key-32-chars-minimo";
      const sessionId = "sess-123456";
      const csrfToken = crypto.createHmac("sha256", secret).update(sessionId).digest("hex");

      const validateCsrf = (cookieVal: string, headerVal: string) => {
        const a = Buffer.from(cookieVal);
        const b = Buffer.from(headerVal);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
      };

      expect(validateCsrf(csrfToken, csrfToken)).toBe(true);
      expect(validateCsrf(csrfToken, "forged-csrf-token")).toBe(false);
    });
  });

  describe("3. Fetch Metadata Shield (Sec-Fetch-Site & Sec-Fetch-Mode)", () => {
    it("TEST-032: bloqueia requisições mutativas disparadas cross-site", () => {
      const headers = new Headers({
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "navigate",
      });

      const isAllowed = validateFetchMetadata(headers, true);
      expect(isAllowed).toBe(false);
    });

    it("TEST-033: autoriza requisições same-origin e same-site", () => {
      const headers = new Headers({
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
      });

      const isAllowed = validateFetchMetadata(headers, true);
      expect(isAllowed).toBe(true);
    });
  });

  describe("4. Isolamento de Cookies (__Host- Prefix & Strict SameSite)", () => {
    it("TEST-040: cria cookie ultra-seguro com prefixo __Host-, HttpOnly e SameSite=Strict", () => {
      const cookie = buildSecureCookieString({
        name: "auth_session",
        value: "token-12345",
        useHostPrefix: true,
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/",
      });

      expect(cookie).toContain("__Host-auth_session=");
      expect(cookie).toContain("HttpOnly");
      expect(cookie).toContain("Secure");
      expect(cookie).toContain("SameSite=Strict");
      expect(cookie).toContain("Path=/");
    });
  });

  describe("5. Sanitização de Payloads XSS Polyglot Avançados", () => {
    it("TEST-046: neutraliza payload <svg/onload>", () => {
      const payload = "<svg/onload=alert(1)>";
      const sanitized = sanitizeInput(payload);
      expect(sanitized).not.toContain("<svg");
      expect(sanitized).not.toContain("onload");
    });

    it("TEST-047: neutraliza injeção em <iframe> com srcdoc", () => {
      const payload = "<iframe srcdoc='<script>alert(1)</script>'></iframe>";
      const sanitized = sanitizeInput(payload);
      expect(sanitized).not.toContain("<iframe");
      expect(sanitized).not.toContain("<script>");
    });

    it("TEST-048: neutraliza tags <math> e <mtext> maliciosas", () => {
      const payload = "<math><mtext><table><mglyph src=x onerror=alert(1)>";
      const sanitized = sanitizeInput(payload);
      expect(sanitized).not.toContain("<math");
      expect(sanitized).not.toContain("<mglyph");
    });
  });
});
