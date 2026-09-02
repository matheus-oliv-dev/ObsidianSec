import { describe, it, expect } from "vitest";
import { convertSecretReportToSarif } from "../../src/lib/security/sarif-formatter.ts";
import { type SecretScanReport } from "../../src/lib/security/local-secret-scanner.ts";

describe("📋 OASIS SARIF v2.1.0 Formatter (GitHub Code Scanning Standard)", () => {
  it("converte relatório de segredos no schema oficial SARIF v2.1.0", () => {
    const mockReport: SecretScanReport = {
      directory: "/app",
      totalFilesScanned: 50,
      findings: [
        {
          ruleId: "aws-access-key",
          category: "API_KEY",
          description: "AWS Access Key ID",
          filePath: "config/aws.ts",
          lineNumber: 12,
          snippet: "const key = 'AKIA1234567890123456';",
          severity: "CRITICAL",
        },
        {
          ruleId: "slack-webhook",
          category: "API_KEY",
          description: "Slack Webhook URL",
          filePath: "services/notify.ts",
          lineNumber: 45,
          snippet: "const url = 'https://hooks.slack.com/services/...';",
          severity: "HIGH",
        },
      ],
      criticalCount: 1,
      highCount: 1,
      mediumCount: 0,
      isClean: false,
      scanDurationMs: 15,
    };

    const sarif = convertSecretReportToSarif(mockReport, "1.3.1");

    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs.length).toBe(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("ObsidianSec");
    expect(run.tool.driver.version).toBe("1.3.1");
    expect(run.tool.driver.rules.length).toBe(2);

    expect(run.results.length).toBe(2);
    expect(run.results[0].ruleId).toBe("aws-access-key");
    expect(run.results[0].level).toBe("error");
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("config/aws.ts");
    expect(run.results[0].locations[0].physicalLocation.region.startLine).toBe(12);
  });

  it("gera documento SARIF vazio válido quando o projeto está limpo", () => {
    const cleanReport: SecretScanReport = {
      directory: "/app",
      totalFilesScanned: 100,
      findings: [],
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      isClean: true,
      scanDurationMs: 8,
    };

    const sarif = convertSecretReportToSarif(cleanReport);
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });
});
