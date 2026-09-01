import { describe, expect, it } from "vitest";
import {
  parseSpfRecord,
  parseDmarcRecord,
  auditDomainDnsSecurity,
} from "@/lib/security/dns-security-analyzer";

describe("📧 DNS & Email Security Suite (SPF / DMARC / DNSSEC)", () => {
  describe("1. SPF Policy Parser & Qualifier Hardening", () => {
    it("TEST-135: valida SPF rigoroso com '-all' (HardFail)", () => {
      const spf = parseSpfRecord(["v=spf1 include:_spf.google.com include:mailgun.org -all"]);
      expect(spf.present).toBe(true);
      expect(spf.qualifier).toBe("-all");
      expect(spf.hasWildcardPass).toBe(false);
      expect(spf.isCompliant).toBe(true);
      expect(spf.verdict).toContain("SPF Blindado");
    });

    it("TEST-136: detecta vulnerabilidade crítica em SPF com wildcard '+all'", () => {
      const spf = parseSpfRecord(["v=spf1 a mx +all"]);
      expect(spf.present).toBe(true);
      expect(spf.hasWildcardPass).toBe(true);
      expect(spf.isCompliant).toBe(false);
      expect(spf.issues.some((i) => i.includes("VULNERABILIDADE CRÍTICA"))).toBe(true);
    });

    it("TEST-137: detecta excesso de lookups DNS (> 10) violando a RFC 7208", () => {
      const spf = parseSpfRecord([
        "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all",
      ]);
      expect(spf.lookupCountEstimate).toBeGreaterThan(10);
      expect(spf.isCompliant).toBe(false);
      expect(spf.issues.some((i) => i.includes("Excesso de Lookups"))).toBe(true);
    });
  });

  describe("2. DMARC Policy Parser & Enforcement Mode", () => {
    it("TEST-138: valida DMARC em modo de bloqueio máximo (p=reject)", () => {
      const dmarc = parseDmarcRecord(["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@dominio.com"]);
      expect(dmarc.present).toBe(true);
      expect(dmarc.policy).toBe("reject");
      expect(dmarc.isEnforcing).toBe(true);
      expect(dmarc.verdict).toContain("DMARC Máximo");
    });

    it("TEST-139: alerta sobre DMARC frouxo apenas para monitoramento (p=none)", () => {
      const dmarc = parseDmarcRecord(["v=DMARC1; p=none; rua=mailto:dmarc@dominio.com"]);
      expect(dmarc.present).toBe(true);
      expect(dmarc.policy).toBe("none");
      expect(dmarc.isEnforcing).toBe(false);
      expect(dmarc.issues.some((i) => i.includes("apenas como telemetria"))).toBe(true);
    });
  });

  describe("3. Auditoria Completa de Domínio (DoH)", () => {
    it("TEST-140: calcula pontuação e status seguro para domínio com SPF e DMARC", async () => {
      // Teste com o próprio domínio público conhecido
      const report = await auditDomainDnsSecurity("github.com");
      expect(report.domain).toBe("github.com");
      expect(report.spf.present).toBe(true);
      expect(report.dmarc.present).toBe(true);
      expect(report.emailSecurityScore).toBeGreaterThanOrEqual(50);
    });
  });
});