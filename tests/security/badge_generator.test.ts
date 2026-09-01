import { describe, expect, it } from "vitest";
import badgeHandler from "../../api/badge";

describe("🏆 GitHub README SVG Badge Generator Suite", () => {
  it("TEST-141: gera SVG com status 200, Content-Type correto e cor verde para Grade A+", async () => {
    let responseStatus = 0;
    let responseHeaders: Record<string, string> = {};
    let responseBody = "";

    const req: any = {
      query: { grade: "A+", score: "100" },
    };

    const res: any = {
      setHeader(k: string, v: string) {
        responseHeaders[k.toLowerCase()] = v;
      },
      status(code: number) {
        responseStatus = code;
        return this;
      },
      send(body: string) {
        responseBody = body;
      },
    };

    await badgeHandler(req, res);

    expect(responseStatus).toBe(200);
    expect(responseHeaders["content-type"]).toContain("image/svg+xml");
    expect(responseBody).toContain("<svg");
    expect(responseBody).toContain("OBSIDIANSEC");
    expect(responseBody).toContain("GRADE A+ (100/100)");
    expect(responseBody).toContain("#10b981"); // Verde
  });

  it("TEST-142: gera cor vermelha para Grade F", async () => {
    let responseBody = "";

    const req: any = {
      query: { grade: "F", score: "20" },
    };

    const res: any = {
      setHeader() {},
      status() { return this; },
      send(body: string) { responseBody = body; },
    };

    await badgeHandler(req, res);

    expect(responseBody).toContain("GRADE F (20/100)");
    expect(responseBody).toContain("#ef4444"); // Vermelho
  });
});