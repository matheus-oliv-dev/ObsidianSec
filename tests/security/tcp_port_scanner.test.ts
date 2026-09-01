import { describe, expect, it } from "vitest";
import { scanHostCriticalPorts, CRITICAL_PORTS } from "@/lib/security/tcp-port-scanner";

describe("🚪 TCP Critical Port & Database Exposure Scanner Suite", () => {
  it("TEST-151: valida dicionário de portas críticas e mitigações", () => {
    expect(CRITICAL_PORTS.length).toBeGreaterThanOrEqual(10);
    const redis = CRITICAL_PORTS.find((p) => p.port === 6379);
    const mongo = CRITICAL_PORTS.find((p) => p.port === 27017);
    const rdp = CRITICAL_PORTS.find((p) => p.port === 3389);

    expect(redis?.riskLevel).toBe("CRITICAL");
    expect(mongo?.riskLevel).toBe("CRITICAL");
    expect(rdp?.riskLevel).toBe("CRITICAL");
  });

  it("TEST-152: executa varredura de portas com timeout rápido", async () => {
    // Escaneia 127.0.0.1 com timeout de 300ms
    const report = await scanHostCriticalPorts("127.0.0.1", 300);

    expect(report.targetHost).toBe("127.0.0.1");
    expect(report.totalScanned).toBe(CRITICAL_PORTS.length);
    expect(report.results.length).toBe(CRITICAL_PORTS.length);
    expect(["SECURE", "WARNING", "CRITICAL"]).toContain(report.overallVerdict);
  });
});