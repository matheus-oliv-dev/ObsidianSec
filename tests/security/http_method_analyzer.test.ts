import { describe, it, expect } from "vitest";
import { analyzeHttpMethods } from "../../src/lib/security/http-method-analyzer.ts";

describe("📡 HTTP Method Enumeration & Dangerous Verb Analyzer", () => {
  it("enumera métodos HTTP e classifica riscos conforme padrões de segurança", async () => {
    const report = await analyzeHttpMethods("https://127.0.0.1:9999");
    expect(report).toBeDefined();
    expect(report.targetUrl).toContain("127.0.0.1");
    expect(Array.isArray(report.results)).toBe(true);
    expect(report.results.length).toBeGreaterThan(0);
    expect(["SECURE", "WARNING", "CRITICAL"]).toContain(report.overallStatus);
  });
});
