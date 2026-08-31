import { describe, expect, it } from "vitest";
import {
  analyzeCorsHeaders,
  analyzeSetCookieHeader,
  runBurpHeaderAudit,
} from "@/lib/security/cookie-cors-analyzer";

describe("⚡ Burp Suite Passive Security Suite (Cookies & CORS)", () => {
  describe("1. Set-Cookie Flag & Prefix Security", () => {
    it("TEST-119: detecta cookie inseguro sem HttpOnly e sem Secure", () => {
      const res = analyzeSetCookieHeader("session_id=abc123xyz; Path=/; Domain=.site.com");
      expect(res.isHttpOnly).toBe(false);
      expect(res.isSecure).toBe(false);
      expect(res.sameSite).toBe("Missing");
      expect(res.severity).toBe("HIGH");
      expect(res.issues.length).toBeGreaterThanOrEqual(2);
    });

    it("TEST-120: aprova cookie blindado com HttpOnly, Secure e SameSite=Strict", () => {
      const res = analyzeSetCookieHeader(
        "auth=token999; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
      );
      expect(res.isHttpOnly).toBe(true);
      expect(res.isSecure).toBe(true);
      expect(res.sameSite).toBe("Strict");
      expect(res.severity).toBe("PASSED");
      expect(res.issues.length).toBe(0);
    });

    it("TEST-121: valida prefixos rígidos do padrão W3C (__Host- e __Secure-)", () => {
      const hostCookie = analyzeSetCookieHeader(
        "__Host-sess=secret; Path=/; Secure; HttpOnly; SameSite=Strict",
      );
      expect(hostCookie.hasPrefix).toBe(true);
      expect(hostCookie.prefixType).toBe("__Host-");
      expect(hostCookie.severity).toBe("PASSED");

      const brokenHostCookie = analyzeSetCookieHeader("__Host-sess=secret; Path=/; HttpOnly");
      expect(brokenHostCookie.prefixType).toBe("__Host-");
      expect(brokenHostCookie.issues).toContain("Prefixo __Host- exige flag 'Secure' ativa.");
    });
  });

  describe("2. CORS Misconfiguration Engine", () => {
    it("TEST-122: detecta vulnerabilidade crítica de Wildcard Origin com Credentials", () => {
      const cors = analyzeCorsHeaders({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      });
      expect(cors.hasWildcardWithCredentials).toBe(true);
      expect(cors.severity).toBe("HIGH");
    });

    it("TEST-123: detecta exploração de Origin 'null' via iframes sandboxed", () => {
      const cors = analyzeCorsHeaders({
        "access-control-allow-origin": "null",
      });
      expect(cors.severity).toBe("HIGH");
      expect(cors.issues).toContain(
        "CORS Inseguro: 'Access-Control-Allow-Origin: null' pode ser explorado via iframes 'sandboxed' maliciosos.",
      );
    });

    it("TEST-124: detecta ausência de cabeçalho 'Vary: Origin' em origens dinâmicas", () => {
      const cors = analyzeCorsHeaders({
        "access-control-allow-origin": "https://app.obsidiansec.dev",
      });
      expect(cors.isMissingVaryOrigin).toBe(true);
      expect(cors.severity).toBe("MEDIUM");
    });

    it("TEST-125: consolida auditoria passiva em lote com contagem de vulnerabilidades", () => {
      const audit = runBurpHeaderAudit(
        {
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        },
        [
          "session=123; Path=/",
          "secure_tok=456; Path=/; Secure; HttpOnly; SameSite=Strict",
        ],
      );
      expect(audit.cookies.length).toBe(2);
      expect(audit.findingsCount).toBe(2); // 1 cookie falho + 1 cors falho
    });
  });
});