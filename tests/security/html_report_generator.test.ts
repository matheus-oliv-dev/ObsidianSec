import { describe, it, expect } from "vitest";
import { generateHtmlSecurityReport } from "../../src/lib/security/html-report-generator.ts";
import { type UniversalAuditReport } from "../../src/scanner/universal-web-scanner.ts";

describe("📄 Standalone HTML Security Report Generator", () => {
  const mockReport: UniversalAuditReport = {
    targetUrl: "https://test-company.com",
    httpStatus: 200,
    serverDetected: "nginx/1.24.0",
    frameworkDetected: "Next.js",
    cdnOrProxy: "Cloudflare Edge",
    versionExposed: false,
    securityHeaders: {
      csp: { present: true, value: "default-src 'self'" },
      xFrameOptions: { present: true, value: "DENY" },
      xContentTypeOptions: { present: true, value: "nosniff" },
      permissionsPolicy: { present: false },
      hsts: { present: true, value: "max-age=31536000" },
      referrerPolicy: { present: true, value: "strict-origin" },
      coop: { present: false },
    },
    burpInspection: {
      cookies: [],
      cors: {
        severity: "PASSED",
        hasWildcardWithCredentials: false,
        hasInsecureOriginReflection: false,
        isMissingVaryOrigin: false,
        issues: [],
      },
      findingsCount: 0,
    },
    attackChain: {
      targetUrl: "https://test-company.com",
      nodes: [
        {
          id: "node-1",
          label: "Missing Permissions-Policy",
          type: "ENTRY_POINT",
          description: "Sensors unconstrained",
          mitreTechnique: "T1125",
        },
      ],
      edges: [],
      riskSummary: "Low exploitation surface",
      criticalPathLength: 1,
    },
    remediationSnippets: [
      {
        serverType: "NGINX",
        snippet: "add_header X-Frame-Options DENY;",
      },
    ],
    overallStatus: "SECURE",
  };

  it("gera documento HTML completo, válido e estilizável", () => {
    const html = generateHtmlSecurityReport(mockReport, 85, "A+");

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("https://test-company.com");
    expect(html).toContain("A+");
    expect(html).toContain("Score: 85/100");
    expect(html).toContain("nginx/1.24.0");
    expect(html).toContain("Cloudflare Edge");
    expect(html).toContain("MITRE T1125");
    expect(html).toContain("add_header X-Frame-Options DENY;");
  });

  it("renderiza alertas corretos para notas baixas (Grade F)", () => {
    const html = generateHtmlSecurityReport(mockReport, 20, "F");
    expect(html).toContain("Score: 20/100");
    expect(html).toContain(">F<");
    expect(html).toContain("#ef4444"); // Red color for grade F
  });
});
