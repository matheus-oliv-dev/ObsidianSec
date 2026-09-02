/**
 * OASIS SARIF v2.1.0 Formatter (Static Analysis Results Interchange Format)
 * Converte achados de segurança do ObsidianSec no padrão oficial aceito pelo
 * GitHub Code Scanning, SonarQube, DefectDojo e AWS Security Hub.
 */

import { type SecretFinding, type SecretScanReport } from "./local-secret-scanner.ts";

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription: {
    text: string;
  };
  defaultConfiguration?: {
    level: "error" | "warning" | "note";
  };
  helpUri?: string;
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: {
    text: string;
  };
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId?: string;
      };
      region: {
        startLine: number;
        startColumn?: number;
        snippet?: {
          text: string;
        };
      };
    };
  }>;
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

function mapSeverityToSarifLevel(severity: SecretFinding["severity"]): "error" | "warning" | "note" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    default:
      return "note";
  }
}

/**
 * Converte um relatório de varredura de segredos (SAST) em um documento SARIF v2.1.0
 */
export function convertSecretReportToSarif(
  report: SecretScanReport,
  version: string = "1.3.1"
): SarifLog {
  const ruleMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of report.findings) {
    const level = mapSeverityToSarifLevel(finding.severity);

    // Registra a regra se ainda não foi registrada
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.category,
        shortDescription: {
          text: finding.description,
        },
        defaultConfiguration: {
          level,
        },
        helpUri: "https://obsidiansec.dev/docs/rules/" + finding.ruleId,
      });
    }

    // Cria o resultado com localização precisa no código
    results.push({
      ruleId: finding.ruleId,
      level,
      message: {
        text: `${finding.description} detected in ${finding.filePath}:${finding.lineNumber}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.filePath.replace(/\\/g, "/"),
            },
            region: {
              startLine: finding.lineNumber || 1,
              snippet: {
                text: finding.snippet,
              },
            },
          },
        },
      ],
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ObsidianSec",
            version,
            informationUri: "https://obsidiansec.dev",
            rules: Array.from(ruleMap.values()),
          },
        },
        results,
      },
    ],
  };
}
