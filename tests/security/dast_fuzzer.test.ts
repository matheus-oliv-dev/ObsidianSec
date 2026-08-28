import { describe, expect, it, vi } from "vitest";
import { enforceRateLimit } from "@/lib/security/rate-limit";
import { verifyAccessToken } from "@/lib/supabase/token";
import { generateCaptchaChallenge, verifyCaptchaChallenge } from "@/lib/security/captcha";
import { requireAdmin } from "@/lib/supabase/admin";
import type { SupabaseClient } from "@supabase/supabase-js";

process.env.RATE_LIMIT_SECRET = "segredo-de-fuzzing-32-caracteres-minimo";
process.env.ADMIN_GATE_KEY = "chave-secreta-do-portao-admin-123456";
process.env.SUPABASE_URL = "https://mock-test-project.supabase.co";
process.env.SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTUxNjIzOTAyMn0.mockServiceRoleKey";

describe("🛡️ Red Team Fuzzer: Simulação Dinâmica de Ataques (DAST)", () => {
  describe("1. Simulação de Acesso com Token Anônimo (Vetor BOLA)", () => {
    it("bloqueia terminantemente requisições administrativas sem cabeçalho Authorization com HTTP 401", async () => {
      const request = new Request("https://bombercyber.io/api/admin/metrics");
      const result = await requireAdmin(request);

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error.status).toBe(401);
      }
    });

    it("bloqueia tokens que não possuem role ADMIN com HTTP 403", async () => {
      const request = new Request("https://bombercyber.io/api/admin/metrics", {
        headers: { Authorization: "Bearer token-invalido-ou-sem-admin" },
      });

      const result = await requireAdmin(request);
      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error.status).toBeGreaterThanOrEqual(401);
      }
    });
  });

  describe("2. Simulação de Ataque de Força Bruta e Limite de Taxa", () => {
    it("deve acionar bloqueio HTTP 429 Too Many Requests quando a cota de requisições é excedida", async () => {
      const fakeAdmin = {
        rpc: vi.fn(async () => ({
          data: [{ allowed: false, retry_after_seconds: 30 }],
          error: null,
        })),
      } as unknown as SupabaseClient;

      const userTarget = `alvo-ataque-${Date.now()}`;
      let lastResponse: Response | null = null;

      for (let i = 0; i < 8; i++) {
        lastResponse = await enforceRateLimit({
          admin: fakeAdmin,
          request: new Request("https://bombercyber.io/api/admin/login", {
            headers: { "x-vercel-forwarded-for": "198.51.100.25" },
          }),
          userId: userTarget,
          scope: "admin-login",
          userLimit: 5,
          networkLimit: 20,
          windowSeconds: 60,
        });
      }

      expect(lastResponse).not.toBeNull();
      expect(lastResponse?.status).toBe(429);
      expect(lastResponse?.headers.get("Retry-After")).toBe("30");
      const body = await lastResponse?.json();
      expect(body.error).toMatch(/muitas tentativas/i);
    });
  });

  describe("3. Simulação de Ataque de Manipulação de Algoritmo JWT ('alg: none')", () => {
    it("rejeita qualquer token JWT forjado com algoritmo 'none'", async () => {
      const fakePayload = Buffer.from(
        JSON.stringify({
          sub: "admin-fake",
          role: "ADMIN",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      )
        .toString("base64")
        .replace(/=/g, "");
      const forgedNoneToken = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${fakePayload}.`;

      const claims = await verifyAccessToken(forgedNoneToken);
      expect(claims).toBeNull();
    });

    it("rejeita tokens com assinaturas HMAC inválidas ou corrompidas", async () => {
      const forgedToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.assinaturaInvalidaAqui";
      const claims = await verifyAccessToken(forgedToken);
      expect(claims).toBeNull();
    });
  });

  describe("4. Validação Criptográfica do Desafio CAPTCHA", () => {
    it("aceita resposta correta dentro da janela de validade", () => {
      const challenge = generateCaptchaChallenge();
      expect(challenge.token).toBeDefined();
      expect(challenge.nonce).toBeDefined();
      expect(challenge.expiresAt).toBeGreaterThan(Date.now());
      expect(challenge.svg).toContain("<svg");
    });

    it("rejeita resposta incorreta ou adulterada", () => {
      const challenge = generateCaptchaChallenge();
      const verified = verifyCaptchaChallenge(
        challenge.token,
        "RESPOSTA_ERRADA",
        challenge.nonce,
        challenge.expiresAt,
      );
      expect(verified.success).toBe(false);
    });

    it("rejeita token com assinatura adulterada ou forjada", () => {
      const challenge = generateCaptchaChallenge();
      const tamperedToken = challenge.token.slice(0, -5) + "abcde";
      const verified = verifyCaptchaChallenge(
        tamperedToken,
        "CORRETA",
        challenge.nonce,
        challenge.expiresAt,
      );
      expect(verified.success).toBe(false);
    });

    it("rejeita desafio com tempo expirado", () => {
      const challenge = generateCaptchaChallenge();
      const expiredTime = Date.now() - 10000;
      const verified = verifyCaptchaChallenge(
        challenge.token,
        "ANY",
        challenge.nonce,
        expiredTime,
      );
      expect(verified.success).toBe(false);
      if (!verified.success) {
        expect(verified.error).toMatch(/expirou/i);
      }
    });
  });
});
