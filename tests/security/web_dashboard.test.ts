import { describe, expect, it, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createWebServer } from "@/server/web-server";

describe("🌐 BomberCyber Web Dashboard & Legal Compliance API", () => {
  let serverInstance: http.Server;
  let testPort: number;

  beforeAll(async () => {
    const { server, port } = createWebServer();
    testPort = Number(port) + 120;
    serverInstance = server;

    await new Promise<void>((resolve) => {
      serverInstance.listen(testPort, () => resolve());
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      serverInstance.close(() => resolve());
    });
  });

  it("REJEITA requisição de auditoria se os Termos de Uso (LGPD) não forem aceitos (acceptedTerms: false)", async () => {
    const res = await fetch(`http://localhost:${testPort}/api/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://bot.matheusdev.com.br",
        acceptedTerms: false,
      }),
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toContain("Termos de Uso");
  });

  it("PROCESSA a auditoria com sucesso quando acceptedTerms é true e retorna nota e patches pedagógicos", async () => {
    const res = await fetch(`http://localhost:${testPort}/api/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://bot.matheusdev.com.br",
        acceptedTerms: true,
        aiProvider: "builtin", // Teste determinístico
      }),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.score).toBeDefined();
    expect(data.grade).toBeDefined();
    expect(data.scoreBreakdown).toBeDefined();
    expect(data.scoreBreakdown.earnedItems.length).toBeGreaterThan(0);
    expect(data.remediationSnippets.length).toBeGreaterThan(0);
    expect(data.securityHeaders.hsts.present).toBe(true);
  }, 25000);

  it("EXPOE a base de conhecimento aberta com guia LGPD & Privacy by Design via /api/knowledge", async () => {
    const res = await fetch(`http://localhost:${testPort}/api/knowledge`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.total).toBeGreaterThanOrEqual(6);
    
    const lgpdItem = data.items.find((item: any) => item.id === "lgpd-privacy-by-design");
    expect(lgpdItem).toBeDefined();
    expect(lgpdItem.title).toContain("LGPD");
    expect(lgpdItem.title).toContain("13.709/2018");
    expect(lgpdItem.summary).toContain("LGPD");
  });

  it("RETORNA cabecalhos X-RateLimit e bloqueia abusos com HTTP 429 e Retry-After", async () => {
    const res = await fetch(`http://localhost:${testPort}/api/knowledge`);
    expect(res.headers.get("X-RateLimit-Limit")).toBe("60");
    expect(res.headers.get("X-RateLimit-Remaining")).toBeDefined();

    // Disparar requisições em lote simulando bot flood
    const promises = [];
    for (let i = 0; i < 15; i++) {
      promises.push(
        fetch(`http://localhost:${testPort}/api/audit`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": "203.0.113.195", // IP de teste isolado
          },
          body: JSON.stringify({
            url: "https://bot.matheusdev.com.br",
            acceptedTerms: true,
            aiProvider: "builtin",
          }),
        }),
      );
    }

    const responses = await Promise.all(promises);
    const rateLimited = responses.filter((r) => r.status === 429);
    expect(rateLimited.length).toBeGreaterThan(0);
    expect(rateLimited[0].headers.get("Retry-After")).toBeDefined();
  });
});
