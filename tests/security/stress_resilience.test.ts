import { describe, expect, it, vi } from "vitest";
import { enforceRateLimit } from "@/lib/security/rate-limit";
import type { SupabaseClient } from "@supabase/supabase-js";

process.env.RATE_LIMIT_SECRET = "segredo-de-estresse-32-caracteres-minimo";

function createMockSupabaseWithLatency(retryAfter = 60) {
  const counts = new Map<string, number>();
  return {
    rpc: vi.fn(async (_fn: string, params: { p_key_hash: string; p_limit: number }) => {
      const key = params.p_key_hash;
      const current = (counts.get(key) ?? 0) + 1;
      counts.set(key, current);
      if (current <= params.p_limit) {
        return {
          data: [{ allowed: true, retry_after_seconds: 0 }],
          error: null,
        };
      }
      return {
        data: [{ allowed: false, retry_after_seconds: retryAfter }],
        error: null,
      };
    }),
  } as unknown as SupabaseClient;
}

describe("🛡️ Resiliência e Proteção contra Ataques de Sobrecarga (DoS)", () => {
  describe("1. Simulação de Rajada Concorrente de Requisições (HTTP Flood)", () => {
    it("deve conter rajada simultânea de 20 requisições disparadas em paralelo via Promise.all", async () => {
      const mockAdmin = createMockSupabaseWithLatency(45);
      const targetUser = `user-flood-${Date.now()}`;

      const promises = Array.from({ length: 20 }, (_, idx) =>
        enforceRateLimit({
          admin: mockAdmin,
          request: new Request("https://bombercyber.io/api/rooms", {
            headers: {
              "x-vercel-forwarded-for": "203.0.113.50",
            },
          }),
          userId: targetUser,
          scope: "room-create",
          userLimit: 5,
          networkLimit: 15,
          windowSeconds: 60,
        }),
      );

      const results = await Promise.all(promises);
      const blocked = results.filter((res) => res !== null && res.status === 429);
      const allowed = results.filter((res) => res === null);

      expect(allowed.length).toBeLessThanOrEqual(5);
      expect(blocked.length).toBeGreaterThanOrEqual(15);
    });
  });

  describe("2. Simulação de Botnet: 50 Contas Criadas em Massa no Mesmo IP", () => {
    it("deve bloquear flood de contas anônimas diferentes criadas pelo mesmo bot no mesmo IP", async () => {
      const mockAdmin = createMockSupabaseWithLatency(60);
      const botIP = "198.51.100.99";
      const results: Array<Response | null> = [];

      for (let i = 0; i < 50; i++) {
        const fakeUserId = `bot-anon-${i}-${Date.now()}`;
        const res = await enforceRateLimit({
          admin: mockAdmin,
          request: new Request("https://bombercyber.io/api/rooms", {
            headers: { "x-forwarded-for": botIP },
          }),
          userId: fakeUserId,
          scope: "room-create",
          userLimit: 5,
          networkLimit: 20,
          windowSeconds: 60,
        });
        results.push(res);
      }

      const blockedByNetwork = results.filter((r) => r?.status === 429);
      expect(blockedByNetwork.length).toBeGreaterThanOrEqual(30);
    });
  });

  describe("3. Recuperação em Memória após expiração", () => {
    it("permite novas requisições quando a cota em memória é respeitada", async () => {
      const targetUser = `user-ok-${Date.now()}`;
      const res = await enforceRateLimit({
        request: new Request("https://bombercyber.io/api/test"),
        userId: targetUser,
        scope: "test-single",
        userLimit: 5,
        networkLimit: 10,
        windowSeconds: 60,
      });

      expect(res).toBeNull();
    });
  });
});
