import { describe, it, expect } from "vitest";
import { fingerprintTechStack } from "../../src/lib/security/tech-fingerprint-analyzer.ts";

describe("🧬 Tech Stack Fingerprinter (Wappalyzer Engine)", () => {
  it("executa e retorna estrutura válida de tecnologias detectadas", async () => {
    const report = await fingerprintTechStack("https://127.0.0.1:9999");
    expect(report).toBeDefined();
    expect(report.targetUrl).toContain("127.0.0.1");
    expect(Array.isArray(report.detections)).toBe(true);
    expect(typeof report.totalDetected).toBe("number");
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });
});
