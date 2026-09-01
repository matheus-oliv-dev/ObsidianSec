import { describe, it, expect, beforeEach } from "vitest";
import { TokenBudgetGuard } from "../../src/agents/ai/token-budget-guard.ts";
import { type ObsidianConfig } from "../../src/lib/config/obsidian-config.ts";
import fs from "node:fs";
import path from "node:path";

describe("💰 TokenBudgetGuard: Controle de Custo, Rate Limit & Cache de Deduplicação", () => {
  const testCacheDir = path.resolve(process.cwd(), ".obsidiansec_test_cache");
  let guard: TokenBudgetGuard;

  beforeEach(() => {
    if (fs.existsSync(testCacheDir)) {
      fs.rmSync(testCacheDir, { recursive: true, force: true });
    }
    guard = new TokenBudgetGuard(testCacheDir);
  });

  it("gera fingerprints criptográficos SHA-256 idênticos para os mesmos achados", () => {
    const findings = { missingCsp: true, openPort: 8080 };
    const fp1 = guard.generateFingerprint("https://myapp.com", findings);
    const fp2 = guard.generateFingerprint("https://myapp.com", findings);
    const fpDiff = guard.generateFingerprint("https://myapp.com", { missingCsp: false });

    expect(fp1).toHaveLength(64);
    expect(fp1).toBe(fp2);
    expect(fp1).not.toBe(fpDiff);
  });

  it("retorna AI_DISABLED e custo zero quando a IA não está habilitada", () => {
    const config: ObsidianConfig = {
      version: "1.2.2",
      scope: { allowlist: [], blocklist: [], strictMode: false },
      ai: { enabled: false, provider: "offline", maxRequestsPerHour: 10, cacheTtlHours: 72 },
    };

    const status = guard.evaluateBudget("test-fp-1", config);
    expect(status.canInvoke).toBe(false);
    expect(status.source).toBe("AI_DISABLED");

    const fallback = guard.generateDeterministicFallback("https://myapp.com", ["Content-Security-Policy"]);
    expect(fallback.cognitiveDiagnosis.threatAssessment).toContain("Content-Security-Policy");
    expect(fallback.thoughtProcess).toContain("Zero chamadas de API externas disparadas.");
  });

  it("recupera do cache local sem gastar tokens quando o achado já foi analisado", () => {
    const config: ObsidianConfig = {
      version: "1.2.2",
      scope: { allowlist: [], blocklist: [], strictMode: false },
      ai: { enabled: true, provider: "gemini", maxRequestsPerHour: 10, cacheTtlHours: 72 },
    };

    const fp = "cached-fp-123";
    const sampleAIResponse = { verdict: "SECURE", note: "Análise prévia armazenada" };

    // Registra no cache
    guard.recordAndCache(fp, sampleAIResponse, "gemini-3-flash");

    // Próxima consulta deve vir do cache
    const status = guard.evaluateBudget(fp, config);
    expect(status.canInvoke).toBe(false);
    expect(status.source).toBe("CACHE");
    expect(status.cachedData).toEqual(sampleAIResponse);
  });

  it("bloqueia invocações quando o limite por hora (Circuit Breaker) é atingido", () => {
    const config: ObsidianConfig = {
      version: "1.2.2",
      scope: { allowlist: [], blocklist: [], strictMode: false },
      ai: { enabled: true, provider: "gemini", maxRequestsPerHour: 2, cacheTtlHours: 72 },
    };

    // Faz 2 requisições permitidas
    guard.recordAndCache("fp-1", { data: 1 });
    guard.recordAndCache("fp-2", { data: 2 });

    // A terceira requisição deve ser bloqueada por estouro de cota
    const status = guard.evaluateBudget("fp-3", config);
    expect(status.canInvoke).toBe(false);
    expect(status.source).toBe("BUDGET_EXCEEDED");
  });
});
