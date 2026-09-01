import { describe, it, expect } from "vitest";
import {
  validateTargetScope,
  normalizeTargetToHost,
  matchesHostPattern,
} from "../../src/lib/security/scope-guard.ts";
import { type ObsidianConfig, DEFAULT_OBSIDIAN_CONFIG } from "../../src/lib/config/obsidian-config.ts";

describe("🛡️ ScopeGuard: Validação de Perímetro e Escopo Autorizado", () => {
  it("normaliza URLs completas para hostnames limpos", () => {
    expect(normalizeTargetToHost("https://staging.myapp.com/api/v1?token=123#test")).toBe("staging.myapp.com");
    expect(normalizeTargetToHost("http://localhost:3000/dashboard")).toBe("localhost");
    expect(normalizeTargetToHost("192.168.1.50:8080")).toBe("192.168.1.50");
  });

  it("identifica casamento de padrões glob e wildcards", () => {
    expect(matchesHostPattern("api.empresa.com", "*.empresa.com")).toBe(true);
    expect(matchesHostPattern("empresa.com", "*.empresa.com")).toBe(true);
    expect(matchesHostPattern("sub.api.empresa.com", "*.empresa.com")).toBe(true);
    expect(matchesHostPattern("outro.com", "*.empresa.com")).toBe(false);
  });

  it("bloqueia alvos presentes na blocklist (ex: governamentais/militares)", () => {
    const config: ObsidianConfig = {
      version: "1.2.2",
      scope: {
        allowlist: ["*.empresa.com"],
        blocklist: ["*.gov.br", "*.mil.br"],
        strictMode: false,
      },
      ai: { enabled: false, provider: "offline", maxRequestsPerHour: 10, cacheTtlHours: 72 },
    };

    const resGov = validateTargetScope("https://receita.gov.br", config);
    expect(resGov.allowed).toBe(false);
    expect(resGov.errorCode).toBe("SCOPE_BLOCKED");

    const resMil = validateTargetScope("https://exercito.mil.br/portal", config);
    expect(resMil.allowed).toBe(false);
    expect(resMil.errorCode).toBe("SCOPE_BLOCKED");
  });

  it("permite alvos explicitamente autorizados na allowlist", () => {
    const config: ObsidianConfig = {
      version: "1.2.2",
      scope: {
        allowlist: ["staging.empresa.com", "localhost", "127.0.0.1"],
        blocklist: ["*.gov.br"],
        strictMode: true,
      },
      ai: { enabled: false, provider: "offline", maxRequestsPerHour: 10, cacheTtlHours: 72 },
    };

    const resStaging = validateTargetScope("https://staging.empresa.com", config);
    expect(resStaging.allowed).toBe(true);
    expect(resStaging.matchedRule).toBe("staging.empresa.com");

    const resLocal = validateTargetScope("http://localhost:8080", config);
    expect(resLocal.allowed).toBe(true);

    const resUnlisted = validateTargetScope("https://alvo-nao-autorizado.com", config);
    expect(resUnlisted.allowed).toBe(false);
    expect(resUnlisted.errorCode).toBe("SCOPE_NOT_IN_ALLOWLIST");
  });

  it("opera no modo permissivo por padrão quando a allowlist está vazia e strictMode é false", () => {
    const res = validateTargetScope("https://meusite-qualquer.com", DEFAULT_OBSIDIAN_CONFIG);
    expect(res.allowed).toBe(true);
  });
});
