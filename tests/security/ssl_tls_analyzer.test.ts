import { describe, it, expect } from "vitest";
import { analyzeSslTls } from "../../src/lib/security/ssl-tls-analyzer.ts";

describe("🔒 SSL/TLS Certificate & Protocol Analyzer", () => {
  it("lida com URLs e retorna estrutura completa de relatório", async () => {
    const report = await analyzeSslTls("https://127.0.0.1:9999");
    expect(report).toBeDefined();
    expect(report.targetUrl).toBe("https://127.0.0.1:9999");
    expect(report.grade).toBeDefined();
    expect(Array.isArray(report.issues)).toBe(true);
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("atribui nota F e registra issue para conexões que falham no handshake", async () => {
    const report = await analyzeSslTls("https://invalid-host-that-does-not-exist.local");
    expect(report.valid).toBe(false);
    expect(report.grade).toBe("F");
    expect(report.issues.length).toBeGreaterThan(0);
  });
});
