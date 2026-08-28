import { describe, expect, it } from "vitest";
import { KNOWLEDGE_BASE } from "@/data/knowledge";

describe("📚 InfoSec Open Knowledge Base & Defense Encyclopedia", () => {
  it("contém artigos estruturados com frameworks internacionais (NIST, OWASP, MITRE, CIS)", () => {
    expect(KNOWLEDGE_BASE.length).toBeGreaterThanOrEqual(5);

    for (const item of KNOWLEDGE_BASE) {
      expect(item.id).toBeDefined();
      expect(item.title).toBeDefined();
      expect(item.category).toBeDefined();
      expect(item.difficulty).toBeDefined();
      expect(item.summary.length).toBeGreaterThan(20);
      expect(item.threatMitigated.length).toBeGreaterThan(10);
      expect(item.mitigations.length).toBeGreaterThan(0);
      expect(item.codeExample.code.length).toBeGreaterThan(10);
    }
  });

  it("possui artigo especializado sobre Criptografia Pós-Quântica (PQC FIPS 203)", () => {
    const pqcItem = KNOWLEDGE_BASE.find((k) => k.id === "pqc-mlkem-hybrid");
    expect(pqcItem).toBeDefined();
    expect(pqcItem?.frameworks.nist).toContain("FIPS 203");
  });

  it("possui artigo sobre Arquitetura Zero Trust (NIST SP 800-207)", () => {
    const ztItem = KNOWLEDGE_BASE.find((k) => k.id === "zero-trust-sp800-207");
    expect(ztItem).toBeDefined();
    expect(ztItem?.frameworks.nist).toContain("800-207");
  });
});
