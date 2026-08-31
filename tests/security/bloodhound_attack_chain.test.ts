import { describe, expect, it } from "vitest";
import { buildAttackChainGraph } from "@/lib/security/attack-chain-analyzer";

describe("🩸 BloodHound Attack Graph & Exploit Path Suite", () => {
  it("TEST-126: constrói cadeia de ataque completa e severidade CRÍTICA quando CSP e Cookies falham", () => {
    const report = buildAttackChainGraph("https://alvo-vulneravel.com", {
      hasCsp: false,
      hasXFrameOptions: false,
      hasHsts: false,
      hasNosniff: false,
      hasPermissionsPolicy: false,
      hasSecureCookies: false,
      hasStrictCors: false,
      serverVersionExposed: true,
    });

    expect(report.maxImpactLevel).toBe("CRITICAL");
    expect(report.nodes.length).toBeGreaterThanOrEqual(4);
    expect(report.primaryAttackPath).toContain("Identificação de Versão");
    expect(report.primaryAttackPath).toContain("Injeção de Script (XSS)");
    expect(report.primaryAttackPath).toContain("Roubo de Cookie (Session Hijacking)");
    expect(report.primaryAttackPath).toContain("Comprometimento de Conta (Account Takeover)");
    expect(report.edges.length).toBeGreaterThanOrEqual(2);
    expect(report.tacticalDefensePriority.length).toBeGreaterThan(0);
  });

  it("TEST-127: mitiga cadeia de ataque quando CSP e Cookies com HttpOnly estão ativos", () => {
    const report = buildAttackChainGraph("https://alvo-blindado.com", {
      hasCsp: true,
      hasXFrameOptions: true,
      hasHsts: true,
      hasNosniff: true,
      hasPermissionsPolicy: true,
      hasSecureCookies: true,
      hasStrictCors: true,
      serverVersionExposed: false,
    });

    expect(report.maxImpactLevel).toBe("LOW");
    expect(report.nodes.length).toBe(0);
    expect(report.primaryAttackPath.length).toBe(0);
    expect(report.riskSummary).toContain("Nenhum vetor crítico");
  });

  it("TEST-128: mapeia vetor isolado de Clickjacking quando apenas X-Frame-Options está ausente", () => {
    const report = buildAttackChainGraph("https://clickjack-test.com", {
      hasCsp: true,
      hasXFrameOptions: false,
      hasHsts: true,
      hasNosniff: true,
      hasPermissionsPolicy: true,
      hasSecureCookies: true,
      hasStrictCors: true,
      serverVersionExposed: false,
    });

    expect(report.maxImpactLevel).toBe("HIGH");
    expect(report.nodes.some((n) => n.id === "node-clickjacking")).toBe(true);
  });
});