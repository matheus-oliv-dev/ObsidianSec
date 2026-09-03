import { describe, expect, it } from "vitest";
import { WebSocketSecurityGuard } from "@/lib/security/ws-guard";

describe("⚡ WebSockets & Realtime Security Suite", () => {
  const allowedOrigins = ["https://chimeraguard.io", "https://redubla.com.br"];
  const wsGuard = new WebSocketSecurityGuard(allowedOrigins, {
    maxPayloadBytes: 100 * 1024, // 100 KB
    maxMessagesPerSecond: 10,
  });

  describe("1. Cross-Site WebSocket Hijacking (CSWSH)", () => {
    it("TEST-073: rejeita handshake de upgrade originado de site malicioso (CSWSH)", () => {
      const result = wsGuard.validateHandshake("https://evil-attacker.com");
      expect(result.allowed).toBe(false);
      expect(result.code).toBe(403);
      expect(result.reason).toContain("CSWSH detectado");
    });

    it("TEST-074: rejeita handshake sem cabeçalho Origin", () => {
      const result = wsGuard.validateHandshake(null);
      expect(result.allowed).toBe(false);
      expect(result.code).toBe(403);
    });

    it("TEST-075: aceita handshake de origens confiáveis declaradas", () => {
      const result = wsGuard.validateHandshake("https://redubla.com.br");
      expect(result.allowed).toBe(true);
    });
  });

  describe("2. WebSocket Flooding & Message Size Limits", () => {
    it("TEST-076: rejeita frames que excedem o tamanho máximo permitido (Message Bomb)", () => {
      const smallPayloadSize = 50 * 1024;
      const hugePayloadSize = 500 * 1024; // 500 KB (Limite é 100 KB)

      expect(wsGuard.validatePayloadSize(smallPayloadSize).allowed).toBe(true);
      const hugeResult = wsGuard.validatePayloadSize(hugePayloadSize);
      expect(hugeResult.allowed).toBe(false);
      expect(hugeResult.closeCode).toBe(1009); // Message Too Big
    });

    it("TEST-077: bloqueia conexões que disparam rajadas acima do limite por segundo", () => {
      const socketId = `ws-client-${Date.now()}`;

      // 10 mensagens permitidas
      for (let i = 0; i < 10; i++) {
        expect(wsGuard.checkMessageRateLimit(socketId)).toBe(true);
      }

      // A 11ª mensagem deve ser bloqueada
      expect(wsGuard.checkMessageRateLimit(socketId)).toBe(false);
    });
  });

  describe("3. Channel & Room Authorization", () => {
    it("TEST-082: impede que usuários comuns subscrevam em canais administrativos de WebSocket", () => {
      expect(wsGuard.isAuthorizedForChannel("USER", "admin_audit_stream")).toBe(false);
      expect(wsGuard.isAuthorizedForChannel("ADMIN", "admin_audit_stream")).toBe(true);
      expect(wsGuard.isAuthorizedForChannel("USER", "public_chat_room")).toBe(true);
    });
  });
});
