/**
 * Local Secret & SAST Scanner (Secret Leak Hunter)
 * Varre o diretório do projeto em busca de credenciais vazadas, chaves de API,
 * chaves privadas e funções perigosas conforme padrões OWASP e CIS.
 */

import fs from "node:fs";
import path from "node:path";

export interface SecretFinding {
  ruleId: string;
  category: "API_KEY" | "PRIVATE_KEY" | "SENSITIVE_FILE" | "CREDENTIAL" | "DANGEROUS_CODE";
  description: string;
  filePath: string;
  lineNumber: number;
  snippet: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

export interface SecretScanReport {
  directory: string;
  totalFilesScanned: number;
  findings: SecretFinding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  isClean: boolean;
  scanDurationMs: number;
}

interface SecretPattern {
  id: string;
  category: SecretFinding["category"];
  description: string;
  regex: RegExp;
  severity: SecretFinding["severity"];
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "aws-access-key",
    category: "API_KEY",
    description: "Chave de Acesso AWS (Access Key ID)",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: "CRITICAL",
  },
  {
    id: "openai-api-key",
    category: "API_KEY",
    description: "Chave de API da OpenAI (sk-...)",
    regex: /\b(sk-[a-zA-Z0-9_-]{32,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "stripe-secret-key",
    category: "API_KEY",
    description: "Chave Secreta do Stripe (sk_live / rk_live)",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "github-pat",
    category: "API_KEY",
    description: "Token de Acesso Pessoal do GitHub (PAT)",
    regex: /\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "google-api-key",
    category: "API_KEY",
    description: "Chave de API do Google Cloud (AIza...)",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    severity: "HIGH",
  },
  {
    id: "ssh-private-key",
    category: "PRIVATE_KEY",
    description: "Chave Privada SSH / RSA / OpenSSL",
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    severity: "CRITICAL",
  },
  {
    id: "slack-webhook",
    category: "API_KEY",
    description: "URL de Webhook do Slack",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}/,
    severity: "HIGH",
  },
  {
    id: "db-connection-string",
    category: "CREDENTIAL",
    description: "String de Conexão com Banco de Dados contendo senha",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+/,
    severity: "HIGH",
  },
  {
    id: "dangerous-eval",
    category: "DANGEROUS_CODE",
    description: "Execução Dinâmica Insegura de Código (eval)",
    regex: /\beval\s*\([^\)]+\)/,
    severity: "MEDIUM",
  },
];

const SENSITIVE_FILENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  "id_rsa",
  "id_ed25519",
  "credentials.json",
  "serviceAccountKey.json",
];

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".cache",
  ".vercel",
]);

const IGNORED_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".mp4",
  ".mp3",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".map",
  ".lock",
]);

function redactSecret(match: string): string {
  if (match.length <= 8) return "********";
  return match.slice(0, 4) + "..." + match.slice(-4);
}

export function scanDirectoryForSecrets(targetDir: string, maxFiles = 1000): SecretScanReport {
  const startTime = Date.now();
  const findings: SecretFinding[] = [];
  let filesCount = 0;

  function walk(currentDir: string, depth = 0) {
    if (depth > 6 || filesCount >= maxFiles) return;

    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(targetDir, fullPath);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith(".gemini")) {
          walk(fullPath, depth + 1);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (IGNORED_EXTENSIONS.has(ext)) continue;

        filesCount++;

        // Checagem de nome de arquivo sensível
        if (SENSITIVE_FILENAMES.includes(entry.name)) {
          findings.push({
            ruleId: "sensitive-file-exposed",
            category: "SENSITIVE_FILE",
            description: `Arquivo de credenciais ou ambiente exposto: ${entry.name}`,
            filePath: relPath,
            lineNumber: 1,
            snippet: `Arquivo detectado no disco: ${entry.name}`,
            severity: entry.name.includes(".env") ? "HIGH" : "CRITICAL",
          });
        }

        // Checagem de conteúdo
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > 1024 * 500) continue; // Ignora arquivos maiores que 500KB

          const content = fs.readFileSync(fullPath, "utf-8");
          const lines = content.split("\n");

          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const pattern of SECRET_PATTERNS) {
              const match = line.match(pattern.regex);
              if (match) {
                const rawMatch = match[1] || match[0];
                const cleanSnippet = line.replace(rawMatch, redactSecret(rawMatch)).trim();
                findings.push({
                  ruleId: pattern.id,
                  category: pattern.category,
                  description: pattern.description,
                  filePath: relPath,
                  lineNumber: i + 1,
                  snippet: cleanSnippet.slice(0, 140),
                  severity: pattern.severity,
                });
              }
            }
          }
        } catch {
          // Ignora arquivos ilegíveis/binários
        }
      }
    }
  }

  walk(targetDir, 0);

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;

  return {
    directory: targetDir,
    totalFilesScanned: filesCount,
    findings,
    criticalCount,
    highCount,
    mediumCount,
    isClean: findings.length === 0,
    scanDurationMs: Date.now() - startTime,
  };
}