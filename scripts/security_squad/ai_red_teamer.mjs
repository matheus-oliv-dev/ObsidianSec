import fs from "node:fs";
import path from "node:path";

/**
 * Agente AI Red Teamer & LLM Guard Sentinel (OWASP LLM Top 10)
 * Analisa chamadas a APIs de IA, templates de prompt e tratamento de respostas.
 */

const AI_RISK_PATTERNS = [
  {
    name: "Prompt sem isolamento de delimitadores com Nonce",
    regex: /(?:openai|gemini|anthropic|chatCompletion)\s*\([^)]*prompt:\s*`[^`]*\${(?![^}]*nonce)/i,
    severity: "MEDIUM",
  },
  {
    name: "Insecure Output Handling: Saída de IA injetada diretamente no DOM sem validação Zod",
    regex: /(?:innerHTML|insertAdjacentHTML)\s*=\s*(?:aiResponse|data\.text|response\.text)/i,
    severity: "HIGH",
  },
];

function scanDirectory(dir, fileList = []) {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== ".git" && entry.name !== "dist") {
        scanDirectory(fullPath, fileList);
      }
    } else if (/\.(ts|js|mjs|tsx|jsx)$/.test(entry.name)) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

export function runAiRedTeamerAudit(rootDir = ".") {
  const srcFiles = scanDirectory(path.join(rootDir, "src"));
  const findings = [];

  for (const file of srcFiles) {
    const content = fs.readFileSync(file, "utf-8");
    const lines = content.split("\n");

    for (const pattern of AI_RISK_PATTERNS) {
      lines.forEach((line, index) => {
        if (pattern.regex.test(line)) {
          findings.push({
            file: path.relative(rootDir, file),
            line: index + 1,
            rule: pattern.name,
            severity: pattern.severity,
            snippet: line.trim().slice(0, 80),
          });
        }
      });
    }
  }

  return {
    agent: "AI Red Teamer (OWASP LLM Guard)",
    status: findings.length === 0 ? "PASSED" : "WARNING",
    filesScanned: srcFiles.length,
    findings,
  };
}

if (process.argv[1] === import.meta.filename) {
  console.log("🧠 Executando AI Red Teamer...");
  const result = runAiRedTeamerAudit();
  console.log(JSON.stringify(result, null, 2));
}
