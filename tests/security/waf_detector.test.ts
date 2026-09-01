import { describe, expect, it, vi } from "vitest";
import { detectWaf } from "@/lib/security/waf-detector-analyzer";

describe("🛡️ WAF & Edge Shield Detector Suite (WAFW00F Engine)", () => {
  it("TEST-149: identifica Cloudflare WAF via headers e cf-ray", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({
        Server: "cloudflare",
        "cf-ray": "8a1b2c3d4e-GRU",
      }),
      text: async () => "<html>OK</html>",
    } as any);

    const report = await detectWaf("https://example.com");
    fetchSpy.mockRestore();

    expect(report.detected).toBe(true);
    expect(report.wafName).toContain("Cloudflare");
    expect(report.confidence).toBe("HIGH");
    expect(report.detectionPhase).toBe("PASSIVE");
  });

  it("TEST-150: identifica AWS WAF via cabeçalho x-amzn-errortype ou bloco", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 403,
      headers: new Headers({
        "x-amzn-requestid": "abcd-1234-efgh",
        "x-amzn-errortype": "WAFBlock",
      }),
      text: async () => "Request blocked by AWS WAF",
    } as any);

    const report = await detectWaf("https://aws-app.com");
    fetchSpy.mockRestore();

    expect(report.detected).toBe(true);
    expect(report.wafName).toContain("AWS WAF");
    expect(report.vendor).toContain("Amazon Web Services");
  });
});