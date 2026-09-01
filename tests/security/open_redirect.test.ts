import { describe, it, expect } from "vitest";
import { detectOpenRedirects } from "../../src/lib/security/open-redirect-analyzer.ts";

describe("🔀 Open Redirect Detector (OWASP CWE-601)", () => {
  it("varre parâmetros comuns de redirecionamento e gera relatório defensivo", async () => {
    const report = await detectOpenRedirects("https://127.0.0.1:9999");
    expect(report).toBeDefined();
    expect(report.targetUrl).toContain("127.0.0.1");
    expect(typeof report.totalTested).toBe("number");
    expect(report.totalTested).toBeGreaterThan(0);
    expect(["SECURE", "WARNING", "VULNERABLE"]).toContain(report.overallStatus);
  });
});
