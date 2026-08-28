import { describe, expect, it } from "vitest";
import {
  createBrowserSecurityHeaders,
  buildSecureCookieString,
  generateCspNonce,
  applySecurityHeadersToResponse,
} from "@/lib/security/browser-shield";
import { readLimitedJson, PayloadTooLargeError } from "@/lib/security/stream-guard";
import { sanitizeInput, escapeHtml } from "@/lib/security/sanitizer";
import { recordAuditLog, getAuditLogs, clearAuditLogs } from "@/lib/security/audit";

describe("🌐 Browser Security Shield & Client-Side Defenses", () => {
  describe("1. Blindagem de Cabeçalhos HTTP do Navegador", () => {
    it("gera conjunto completo de cabeçalhos de defesa com CSP Level 3, HSTS e Anti-Clickjacking", () => {
      const nonce = generateCspNonce();
      const headers = createBrowserSecurityHeaders({}, nonce);

      // Verificações de cabeçalhos fundamentais
      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
      expect(headers["X-Frame-Options"]).toBe("DENY");
      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
      expect(headers["Strict-Transport-Security"]).toContain("max-age=31536000");

      // Verificações de CSP
      expect(headers["Content-Security-Policy"]).toBeDefined();
      expect(headers["Content-Security-Policy"]).toContain(`nonce-${nonce}`);
      expect(headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
      expect(headers["Content-Security-Policy"]).toContain("object-src 'none'");
      expect(headers["Content-Security-Policy"]).toContain("base-uri 'self'");

      // Verificações de Isolamento de Origem (COOP / COEP / CORP)
      expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
      expect(headers["Cross-Origin-Embedder-Policy"]).toBe("require-corp");
      expect(headers["Cross-Origin-Resource-Policy"]).toBe("same-origin");

      // Verificação de Restrição de Permissões de Hardware
      expect(headers["Permissions-Policy"]).toContain("camera=()");
      expect(headers["Permissions-Policy"]).toContain("geolocation=()");
      expect(headers["Permissions-Policy"]).toContain("payment=()");
    });

    it("aplica os cabeçalhos diretamente a um objeto Response web padrão", () => {
      const baseResponse = new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });

      const securedResponse = applySecurityHeadersToResponse(baseResponse);
      expect(securedResponse.headers.get("X-Frame-Options")).toBe("DENY");
      expect(securedResponse.headers.get("X-Content-Type-Options")).toBe("nosniff");
    });
  });

  describe("2. Políticas de Cookies Ultraseguros (__Host- Prefix, SameSite=Strict)", () => {
    it("cria cookies protegidos com __Host- prefix, HttpOnly, Secure e SameSite=Strict", () => {
      const cookieStr = buildSecureCookieString({
        name: "session_token",
        value: "jwt-super-secreto-12345",
        useHostPrefix: true,
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAgeSeconds: 3600,
      });

      expect(cookieStr).toContain("__Host-session_token=");
      expect(cookieStr).toContain("HttpOnly");
      expect(cookieStr).toContain("Secure");
      expect(cookieStr).toContain("SameSite=Strict");
      expect(cookieStr).toContain("Path=/");
    });
  });

  describe("3. Defesa contra Exaustão de Memória / OOM Payload DoS", () => {
    it("processa JSON válido dentro do limite seguro", async () => {
      const payload = { message: "teste seguro", id: 123 };
      const req = new Request("https://bombercyber.io/api/upload", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      const result = await readLimitedJson(req, { maxBytes: 1024 });
      expect(result).toEqual(payload);
    });

    it("aborta imediatamente e lança PayloadTooLargeError se o payload exceder o limite em bytes", async () => {
      const hugePayload = { data: "X".repeat(5000) };
      const req = new Request("https://bombercyber.io/api/upload", {
        method: "POST",
        body: JSON.stringify(hugePayload),
      });

      await expect(readLimitedJson(req, { maxBytes: 1000 })).rejects.toThrow(
        PayloadTooLargeError,
      );
    });
  });

  describe("4. Sanitização contra Injeções de Script (XSS & DOM Clobbering)", () => {
    it("escapa entidades HTML para exibição no DOM seguro", () => {
      const unsafe = '<img src=x onerror="alert(document.cookie)">';
      const escaped = escapeHtml(unsafe);
      expect(escaped).not.toContain("<img");
      expect(escaped).toContain("&lt;img");
    });

    it("sanitiza entradas complexas preservando caracteres válidos e removendo controles", () => {
      const rawInput = "  Super Hacker \u0000 <script>eval('xss')</script> Vencedor!  ";
      const sanitized = sanitizeInput(rawInput);
      expect(sanitized).toBe("Super Hacker  eval('xss') Vencedor!");
      expect(sanitized).not.toContain("<script>");
      expect(sanitized).not.toContain("\u0000");
    });
  });

  describe("5. Trilha Forense de Auditoria Imutável (Zero-Trust Audit Trail)", () => {
    it("registra ações com identificador único e hash SHA-256 da carga útil", () => {
      clearAuditLogs();
      const entry = recordAuditLog(
        "admin-user-01",
        "DELETE_SCENE",
        "203.0.113.10",
        { sceneId: "scene-999", reason: "Copyright infringement" },
        "admin@bombercyber.io",
      );

      expect(entry.id).toBeDefined();
      expect(entry.actorId).toBe("admin-user-01");
      expect(entry.actorEmail).toBe("admin@bombercyber.io");
      expect(entry.payloadHash).toHaveLength(64); // SHA-256 Hex length

      const allLogs = getAuditLogs();
      expect(allLogs.length).toBe(1);
      expect(allLogs[0].action).toBe("DELETE_SCENE");
    });
  });
});
