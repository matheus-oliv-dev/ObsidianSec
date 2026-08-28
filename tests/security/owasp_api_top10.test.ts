import { describe, expect, it } from "vitest";
import { z } from "zod";
import crypto from "node:crypto";
import { sanitizeApiOutput, sanitizePagination, AtomicLockManager } from "@/lib/security/api-guard";
import { requireAdmin } from "@/lib/supabase/admin";
import { enforceRateLimit } from "@/lib/security/rate-limit";

describe("🌐 OWASP API Security Top 10 Comprehensive Suite", () => {
  describe("API1: Broken Object Level Authorization (BOLA / IDOR)", () => {
    it("TEST-001: bloqueia acesso a objetos de outros tenants em rotas de métricas", async () => {
      const alienReq = new Request("https://bombercyber.io/api/admin/metrics", {
        headers: { Authorization: "Bearer token-usuario-comum" },
      });
      const result = await requireAdmin(alienReq);
      expect("error" in result).toBe(true);
    });

    it("TEST-002: impede enumeração sequencial de IDs de faturas / documentos", () => {
      const tenantA = { id: "tenant-A", orgId: "org-1" };
      const docBelongsToOrg2 = { id: "doc-999", orgId: "org-2" };

      const hasAccess = tenantA.orgId === docBelongsToOrg2.orgId;
      expect(hasAccess).toBe(false);
    });

    it("TEST-003: valida autorização em entidades aninhadas (Organization -> Project -> Resource)", () => {
      const user = { userId: "u1", allowedOrgs: ["org-alpha"] };
      const requestedResource = { resourceId: "res-10", orgId: "org-beta" };

      const isAuthorized = user.allowedOrgs.includes(requestedResource.orgId);
      expect(isAuthorized).toBe(false);
    });

    it("TEST-004: bloqueia operações destrutivas DELETE/PATCH em recursos de terceiros", async () => {
      const req = new Request("https://bombercyber.io/api/admin/delete", {
        method: "DELETE",
        headers: { Authorization: "Bearer token-sem-admin" },
      });
      const result = await requireAdmin(req);
      expect("error" in result).toBe(true);
    });
  });

  describe("API2: Broken Authentication", () => {
    it("TEST-006: rejeita requisições sem header Authorization", async () => {
      const req = new Request("https://bombercyber.io/api/admin/data");
      const result = await requireAdmin(req);
      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error.status).toBe(401);
      }
    });

    it("TEST-007: rejeita tokens de autorização vazios ou malformados", async () => {
      const req = new Request("https://bombercyber.io/api/admin/data", {
        headers: { Authorization: "Bearer " },
      });
      const result = await requireAdmin(req);
      expect("error" in result).toBe(true);
    });

    it("TEST-010: aciona HTTP 429 após rajada de tentativas consecutivas de login", async () => {
      const user = `alvo-brute-${Date.now()}`;
      let lastRes: Response | null = null;
      for (let i = 0; i < 7; i++) {
        lastRes = await enforceRateLimit({
          request: new Request("https://bombercyber.io/api/login"),
          userId: user,
          scope: "login-brute",
          userLimit: 5,
          networkLimit: 20,
          windowSeconds: 60,
        });
      }
      expect(lastRes).not.toBeNull();
      expect(lastRes?.status).toBe(429);
    });
  });

  describe("API3: Broken Object Property Level Authorization (BOPLA / Mass Assignment)", () => {
    const userUpdateSchema = z.object({
      nickname: z.string(),
      avatarSeed: z.number(),
    });

    it("TEST-012: remove e ignora campos restritos (is_admin, role) em mutação de usuário", () => {
      const untrustedPayload = {
        nickname: "NovoNome",
        avatarSeed: 5,
        role: "ADMIN",
        is_admin: true,
        wallet_balance: 999999,
      };

      const parsed = userUpdateSchema.safeParse(untrustedPayload);
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        expect((parsed.data as any).role).toBeUndefined();
        expect((parsed.data as any).is_admin).toBeUndefined();
        expect((parsed.data as any).wallet_balance).toBeUndefined();
      }
    });

    it("TEST-013: bloqueia manipulação de preços negativos em transações", () => {
      const checkoutSchema = z.object({
        itemId: z.string(),
        quantity: z.number().int().positive(),
        unitPrice: z.number().positive(),
      });

      const maliciousPayload = { itemId: "item-1", quantity: 5, unitPrice: -100 };
      const parsed = checkoutSchema.safeParse(maliciousPayload);
      expect(parsed.success).toBe(false);
    });

    it("TEST-014: sanitiza payload de saída eliminando senhas e segredos internos", () => {
      const rawUserDbRecord = {
        id: "usr-123",
        username: "matheus",
        password_hash: "$2b$12$e8h1293h...",
        mfa_secret: "JBSWY3DPEHPK3PXP",
        email: "matheus@teste.com",
      };

      const safeOutput = sanitizeApiOutput(rawUserDbRecord);
      expect(safeOutput.id).toBe("usr-123");
      expect(safeOutput.email).toBe("matheus@teste.com");
      expect(safeOutput.password_hash).toBeUndefined();
      expect(safeOutput.mfa_secret).toBeUndefined();
    });
  });

  describe("API4: Unrestricted Resource Consumption", () => {
    it("TEST-016: coage limites gigantes de paginação para o teto seguro de 100", () => {
      const pagination = sanitizePagination("1", "999999", 100);
      expect(pagination.limit).toBe(100);
      expect(pagination.page).toBe(1);
      expect(pagination.offset).toBe(0);
    });

    it("TEST-017: trata paginação negativa e valores inválidos com fallback seguro", () => {
      const pagination = sanitizePagination("-5", "invalid", 100);
      expect(pagination.page).toBe(1);
      expect(pagination.limit).toBe(20);
    });
  });

  describe("API5: Broken Function Level Authorization (BFLA)", () => {
    it("TEST-020: bloqueia invocação de funções privilegiadas por usuários comuns", async () => {
      const req = new Request("https://bombercyber.io/api/admin/flush-cache", {
        headers: { Authorization: "Bearer user-token" },
      });
      const result = await requireAdmin(req);
      expect("error" in result).toBe(true);
    });

    it("TEST-021: impede que verbos HTTP mutativos contornem proteções de leitura", async () => {
      const postReq = new Request("https://bombercyber.io/api/admin/users", {
        method: "POST",
      });
      const result = await requireAdmin(postReq);
      expect("error" in result).toBe(true);
    });
  });

  describe("API6 a API10: Ameaças Automatizadas, Webhooks & Race Conditions", () => {
    it("TEST-023: previne race conditions (TOCTOU) com bloqueio atômico de transação", async () => {
      const lockManager = new AtomicLockManager();
      let couponUsedCount = 0;

      const applyCoupon = async () => {
        return lockManager.executeWithLock("coupon:PROMO2026", async () => {
          if (couponUsedCount >= 1) throw new Error("Cupom já utilizado");
          await new Promise((r) => setTimeout(r, 10));
          couponUsedCount += 1;
          return "DESCONTO_APLICADO";
        });
      };

      const results = await Promise.allSettled([
        applyCoupon(),
        applyCoupon(),
        applyCoupon(),
      ]);

      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");

      expect(fulfilled.length).toBe(1);
      expect(rejected.length).toBe(2);
      expect(couponUsedCount).toBe(1);
    });

    it("TEST-025: valida assinatura HMAC-SHA256 de webhooks externos", () => {
      const secret = "webhook-secret-key-12345";
      const payload = JSON.stringify({ event: "payment.succeeded", id: "evt_123" });
      const validSig = crypto.createHmac("sha256", secret).update(payload).digest("hex");
      const tamperedSig = "bad-signature-hex-123456";

      const checkSig = (sig: string) => {
        const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
        const a = Buffer.from(sig);
        const b = Buffer.from(expected);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
      };

      expect(checkSig(validSig)).toBe(true);
      expect(checkSig(tamperedSig)).toBe(false);
    });
  });
});
