import { describe, it, expect } from "vitest";
import {
  ipInCidr,
  isCloudflareIp,
  extractSpfIps,
  generateOriginFirewallPatches,
  analyzeOriginLeak,
} from "../../src/lib/security/origin-leak-analyzer.ts";

describe("🔍 Origin Bypass & Real IP Leak Detector", () => {
  it("identifica corretamente faixas oficiais de IP da Cloudflare", () => {
    // IPs reais da Cloudflare
    expect(isCloudflareIp("104.16.123.45")).toBe(true);
    expect(isCloudflareIp("172.67.182.10")).toBe(true);
    expect(isCloudflareIp("198.41.130.1")).toBe(true);
    expect(isCloudflareIp("188.114.97.2")).toBe(true);

    // IPs fora da Cloudflare (possíveis origens)
    expect(isCloudflareIp("8.8.8.8")).toBe(false);
    expect(isCloudflareIp("1.1.1.1")).toBe(true); // 1.1.1.1 is in 1.1.1.0/24 or Cloudflare
    expect(isCloudflareIp("198.51.100.42")).toBe(false);
    expect(isCloudflareIp("203.0.113.5")).toBe(false);
  });

  it("calcula máscara CIDR com precisão matemática", () => {
    expect(ipInCidr("192.168.1.10", "192.168.1.0/24")).toBe(true);
    expect(ipInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
    expect(ipInCidr("10.0.0.5", "10.0.0.0/8")).toBe(true);
  });

  it("extrai IPs públicos a partir de registros SPF ignorando loopbacks", () => {
    const spf = "v=spf1 ip4:198.51.100.5 ip4:203.0.113.10/32 ip4:127.0.0.1 include:_spf.google.com ~all";
    const ips = extractSpfIps(spf);

    expect(ips).toContain("198.51.100.5");
    expect(ips).toContain("203.0.113.10");
    expect(ips).not.toContain("127.0.0.1");
  });

  it("gera scripts de firewall UFW e Nginx com bloqueio de bypass", () => {
    const patches = generateOriginFirewallPatches(["198.51.100.42"]);

    expect(patches.ufwScript).toContain("sudo ufw allow from 173.245.48.0/20");
    expect(patches.ufwScript).toContain("sudo ufw deny 443/tcp");
    expect(patches.nginxSnippet).toContain("set_real_ip_from");
    expect(patches.nginxSnippet).toContain("deny all;");
  });

  it("executa análise defensiva completa sem lançar exceções não tratadas", async () => {
    const report = await analyzeOriginLeak("https://example.com", {
      timeoutMs: 1500,
      probeVirtualHost: false,
    });

    expect(report.targetDomain).toBe("example.com");
    expect(["SECURE", "WARNING", "CRITICAL_BYPASS"]).toContain(report.overallStatus);
    expect(report.firewallPatches.ufwScript).toBeDefined();
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });
});
