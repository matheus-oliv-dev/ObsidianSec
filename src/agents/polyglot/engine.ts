import fs from "node:fs";
import path from "node:path";
import { POLYGLOT_SECURITY_RULES, type PolyglotSecurityRule, type TargetLanguage } from "./rules.ts";
import { detectLocalTechStack, type TechStackInfo } from "./detector.ts";

export interface PolyglotFinding {
  ruleId: string;
  ruleName: string;
  language: TargetLanguage;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cwe: string;
  owasp: string;
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

export interface PolyglotAuditReport {
  techStack: TechStackInfo;
  filesScanned: number;
  findings: PolyglotFinding[];
  cvssScore: number;
  status: "PASSED" | "FAILED";
  timestamp: string;
}

const EXT_TO_LANG: Record<string, TargetLanguage> = {
  ".py": "python",
  ".php": "php",
  ".java": "java",
  ".cs": "csharp",
  ".go": "go",
  ".rb": "ruby",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".sql": "sql",
};

/**
 * Escaneia uma pasta em busca de arquivos de código
 */
function collectCodeFiles(dir: string, fileList: Array<{ fullPath: string; lang: TargetLanguage }> = []) {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name !== "node_modules" &&
        entry.name !== ".git" &&
        entry.name !== "dist" &&
        entry.name !== "vendor" &&
        entry.name !== "target" &&
        entry.name !== "bin" &&
        entry.name !== "obj" &&
        entry.name !== ".venv" &&
        entry.name !== "venv"
      ) {
        collectCodeFiles(fullPath, fileList);
      }
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      const lang = EXT_TO_LANG[ext];
      if (lang) {
        fileList.push({ fullPath, lang });
      }
    }
  }

  return fileList;
}

/**
 * Motor de Auditoria SAST Poliglota (Python, PHP, Java, C#, Go, JavaScript, TypeScript, SQL).
 */
export function runPolyglotAudit(targetDir = "."): PolyglotAuditReport {
  const techStack = detectLocalTechStack(targetDir);
  const files = collectCodeFiles(targetDir);
  const findings: PolyglotFinding[] = [];

  for (const { fullPath, lang } of files) {
    const content = fs.readFileSync(fullPath, "utf-8");
    const lines = content.split("\n");

    // Seleciona as regras pertinentes à linguagem do arquivo
    const relevantRules = POLYGLOT_SECURITY_RULES.filter(
      (r) => r.language === lang || (lang === "typescript" && r.language === "javascript"),
    );

    for (const rule of relevantRules) {
      lines.forEach((line, index) => {
        // Ignora comentários comuns
        const trimmed = line.trim();
        if (
          trimmed.startsWith("//") ||
          trimmed.startsWith("#") ||
          trimmed.startsWith("/*") ||
          trimmed.startsWith("*")
        ) {
          return;
        }

        if (rule.regex.test(line)) {
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            language: lang,
            severity: rule.severity,
            cwe: rule.cwe,
            owasp: rule.owasp,
            file: path.relative(targetDir, fullPath),
            line: index + 1,
            snippet: line.trim().slice(0, 100),
            description: rule.description,
            remediation: rule.remediation,
          });
        }
      });
    }
  }

  // Cálculo ponderado de CVSS
  let maxCvss = 0.0;
  for (const f of findings) {
    if (f.severity === "CRITICAL" && maxCvss < 9.0) maxCvss = 9.0;
    if (f.severity === "HIGH" && maxCvss < 7.5) maxCvss = 7.5;
    if (f.severity === "MEDIUM" && maxCvss < 5.0) maxCvss = 5.0;
  }

  return {
    techStack,
    filesScanned: files.length,
    findings,
    cvssScore: maxCvss,
    status: findings.length === 0 ? "PASSED" : "FAILED",
    timestamp: new Date().toISOString(),
  };
}
