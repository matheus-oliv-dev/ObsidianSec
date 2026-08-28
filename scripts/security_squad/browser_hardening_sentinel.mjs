import fs from "node:fs";
import path from "node:path";

/**
 * Agente Browser Hardening Sentinel
 * Analisa o frontend procurando uso de DOM Sinks perigosos e falta de Trusted Types.
 */

const DOM_SINK_PATTERNS = [
  {
    name: "DOM Sink perigoso: Atribuição direta a innerHTML",
    regex: /(?<!trustedTypes\.)\binnerHTML\s*=\s*(?!["'`]\s*["'`])(?!\s*escapeHtml)/,
    severity: "HIGH",
  },
  {
    name: "Atribuição perigosa a document.write()",
    regex: /document\.write\s*\(/,
    severity: "CRITICAL",
  },
  {
    name: "Script injection via location.href sem validação de protocolo",
    regex: /location\.href\s*=\s*(?:url|input|param)/,
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
    } else if (/\.(ts|js|mjs|tsx|jsx|html)$/.test(entry.name)) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

export function runBrowserHardeningAudit(rootDir = ".") {
  const srcFiles = scanDirectory(path.join(rootDir, "src"));
  const findings = [];

  for (const file of srcFiles) {
    const content = fs.readFileSync(file, "utf-8");
    const lines = content.split("\n");

    for (const pattern of DOM_SINK_PATTERNS) {
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
    agent: "Browser Hardening Sentinel (DOM & Trusted Types)",
    status: findings.length === 0 ? "PASSED" : "WARNING",
    filesScanned: srcFiles.length,
    findings,
  };
}

if (process.argv[1] === import.meta.filename) {
  console.log("🛡️ Executando Browser Hardening Sentinel...");
  const result = runBrowserHardeningAudit();
  console.log(JSON.stringify(result, null, 2));
}
