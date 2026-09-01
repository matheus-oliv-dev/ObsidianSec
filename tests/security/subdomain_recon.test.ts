import { describe, expect, it, vi } from "vitest";
import { discoverSubdomains } from "@/lib/security/subdomain-recon-analyzer";

describe("🌐 Subdomain Passive Reconnaissance Suite", () => {
  it("TEST-147: descobre subdomínios públicos e normaliza wildcards", async () => {
    const mockCrtResponse = [
      { name_value: "api.github.com\n*.internal.github.com" },
      { name_value: "docs.github.com" },
      { name_value: "github.com" },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockCrtResponse,
    } as any);

    const report = await discoverSubdomains("github.com");

    fetchSpy.mockRestore();

    expect(report.domain).toBe("github.com");
    expect(report.source).toContain("Certificate Transparency");
    expect(report.status).toBe("SUCCESS");
    expect(report.totalFound).toBe(4);
    expect(report.subdomains).toContain("api.github.com");
    expect(report.subdomains).toContain("internal.github.com"); // Wildcard *. removido
    expect(report.subdomains).toContain("docs.github.com");
  });

  it("TEST-148: lida com domínio vazio ou inválido graciosamente", async () => {
    const report = await discoverSubdomains("");
    expect(report.status).toBe("ERROR");
    expect(report.totalFound).toBe(0);
  });
});