import fs from "node:fs";
import path from "node:path";

/**
 * Agente Code Sentinel (SAST - Static Application Security Testing)
 * Analisa a árvore de código estaticamente em busca de vulnerabilidades e segredos.
 */

const SECRET_PATTERNS = [
  { name: "Chave Privada RSA/EC", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "Chave de Produção Supabase Service Role exposta", regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{20,}/ },
  { name: "Uso inseguro de eval()", regex: /\beval\s*\(/ },
  { name: "Uso inseguro de new Function()", regex: /new\s+Function\s*\(/ },
  { name: "Algoritmo JWT 'none' em produção", regex: /['"]alg['"]\s*:\s*['"]none['"]/i },
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

export function runSastAudit(rootDir = ".") {
  const srcFiles = scanDirectory(path.join(rootDir, "src"));
  const findings = [];

  for (const file of srcFiles) {
    const content = fs.readFileSync(file, "utf-8");
    const lines = content.split("\n");

    for (const pattern of SECRET_PATTERNS) {
      lines.forEach((line, index) => {
        if (pattern.regex.test(line)) {
          findings.push({
            file: path.relative(rootDir, file),
            line: index + 1,
            rule: pattern.name,
            snippet: line.trim().slice(0, 80),
          });
        }
      });
    }
  }

  return {
    agent: "Code Sentinel (SAST)",
    status: findings.length === 0 ? "PASSED" : "FAILED",
    filesScanned: srcFiles.length,
    findings,
  };
}

if (process.argv[1] === import.meta.filename) {
  console.log("🔍 Executando Code Sentinel (SAST)...");
  const result = runSastAudit();
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.status === "PASSED" ? 0 : 1);
}
