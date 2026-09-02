/**
 * Local Secret & SAST Scanner (Secret Leak Hunter)
 * Varre o diretório do projeto em busca de credenciais vazadas, chaves de API,
 * chaves privadas e funções perigosas conforme padrões OWASP e CIS.
 *
 * 45+ patterns de detecção cobrindo AWS, GCP, Azure, GitHub, GitLab, Slack,
 * Discord, Stripe, Twilio, SendGrid, Telegram, Docker, Shopify, Supabase e mais.
 */

import fs from "node:fs";
import path from "node:path";
import { loadCustomSecurityRules, mergeSecretPatterns } from "./custom-rule-loader.ts";

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

export interface SecretPattern {
  id: string;
  category: SecretFinding["category"];
  description: string;
  regex: RegExp;
  severity: SecretFinding["severity"];
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // ═══════════════════════════════════════════════════════════════
  // CLOUD PROVIDERS (AWS, GCP, Azure)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "aws-access-key",
    category: "API_KEY",
    description: "AWS Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: "CRITICAL",
  },
  {
    id: "aws-secret-key",
    category: "API_KEY",
    description: "AWS Secret Access Key",
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/,
    severity: "CRITICAL",
  },
  {
    id: "google-api-key",
    category: "API_KEY",
    description: "Google Cloud / Firebase API Key (AIza...)",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    severity: "HIGH",
  },
  {
    id: "gcp-service-account",
    category: "API_KEY",
    description: "GCP Service Account Private Key ID",
    regex: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/,
    severity: "CRITICAL",
  },
  {
    id: "azure-storage-key",
    category: "API_KEY",
    description: "Azure Storage Account Key (Base64 88 chars)",
    regex: /(?:AccountKey|AZURE_STORAGE_KEY|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?/,
    severity: "CRITICAL",
  },
  {
    id: "azure-client-secret",
    category: "API_KEY",
    description: "Azure AD Client Secret",
    regex: /(?:AZURE_CLIENT_SECRET|client_secret)\s*[=:]\s*['"]([a-zA-Z0-9~._\-]{34,})['"]/,
    severity: "CRITICAL",
  },

  // ═══════════════════════════════════════════════════════════════
  // AI / ML PROVIDERS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "openai-api-key",
    category: "API_KEY",
    description: "OpenAI API Key (sk-...)",
    regex: /\b(sk-[a-zA-Z0-9_-]{32,})\b/,
    severity: "CRITICAL",
  },

  // ═══════════════════════════════════════════════════════════════
  // PAYMENTS & COMMERCE
  // ═══════════════════════════════════════════════════════════════
  {
    id: "stripe-secret-key",
    category: "API_KEY",
    description: "Stripe Secret / Restricted Key (sk_live / rk_live)",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "shopify-api-key",
    category: "API_KEY",
    description: "Shopify Admin API Token (shpat_)",
    regex: /\b(shpat_[a-fA-F0-9]{32})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // GIT PLATFORMS (GitHub, GitLab, Bitbucket)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "github-pat",
    category: "API_KEY",
    description: "GitHub Personal Access Token (PAT)",
    regex: /\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "gitlab-pat",
    category: "API_KEY",
    description: "GitLab Personal Access Token (glpat-)",
    regex: /\b(glpat-[0-9A-Za-z\-_]{20,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "bitbucket-app-password",
    category: "API_KEY",
    description: "Bitbucket App Password (ATBB)",
    regex: /\b(ATBB[A-Za-z0-9]{32,})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // MESSAGING & CHAT (Slack, Discord, Telegram, Twitter)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "slack-bot-token",
    category: "API_KEY",
    description: "Slack Bot / User / App Token (xoxb-, xoxp-, xoxa-)",
    regex: /\b(xox[bporsca]-[0-9a-zA-Z-]{10,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "slack-webhook",
    category: "API_KEY",
    description: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}/,
    severity: "HIGH",
  },
  {
    id: "discord-bot-token",
    category: "API_KEY",
    description: "Discord Bot Token",
    regex: /\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "discord-webhook",
    category: "API_KEY",
    description: "Discord Webhook URL",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/,
    severity: "HIGH",
  },
  {
    id: "telegram-bot-token",
    category: "API_KEY",
    description: "Telegram Bot Token",
    regex: /\b(\d{8,10}:[A-Za-z0-9_-]{35})\b/,
    severity: "HIGH",
  },
  {
    id: "twitter-bearer",
    category: "API_KEY",
    description: "Twitter / X API Bearer Token",
    regex: /\b(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{20,})\b/,
    severity: "HIGH",
  },
  {
    id: "facebook-access-token",
    category: "API_KEY",
    description: "Facebook / Meta Access Token",
    regex: /\b(EAA[A-Za-z0-9]{100,})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // EMAIL & COMMUNICATION (Twilio, SendGrid, Mailgun)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "twilio-api-key",
    category: "API_KEY",
    description: "Twilio Account SID",
    regex: /\b(AC[0-9a-fA-F]{32})\b/,
    severity: "CRITICAL",
  },
  {
    id: "sendgrid-api-key",
    category: "API_KEY",
    description: "SendGrid API Key (SG.)",
    regex: /\b(SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,})\b/,
    severity: "HIGH",
  },
  {
    id: "mailgun-api-key",
    category: "API_KEY",
    description: "Mailgun API Key (key-)",
    regex: /\b(key-[0-9a-zA-Z]{32})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // HOSTING & DEVOPS (Heroku, DigitalOcean, Vercel, Netlify, Docker)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "heroku-api-key",
    category: "API_KEY",
    description: "Heroku API Key (UUID)",
    regex: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?/,
    severity: "HIGH",
  },
  {
    id: "digitalocean-pat",
    category: "API_KEY",
    description: "DigitalOcean Personal Access Token",
    regex: /\b(dop_v1_[a-f0-9]{64})\b/,
    severity: "CRITICAL",
  },
  {
    id: "vercel-token",
    category: "API_KEY",
    description: "Vercel Deployment Token",
    regex: /(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?/,
    severity: "HIGH",
  },
  {
    id: "netlify-token",
    category: "API_KEY",
    description: "Netlify Access Token",
    regex: /(?:NETLIFY_AUTH_TOKEN|netlify_token)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{40,})['"]?/,
    severity: "HIGH",
  },
  {
    id: "docker-hub-token",
    category: "API_KEY",
    description: "Docker Hub Access Token (dckr_pat_)",
    regex: /\b(dckr_pat_[A-Za-z0-9_-]{24,})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // PACKAGE REGISTRIES (NPM, PyPI, NuGet)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "npm-auth-token",
    category: "API_KEY",
    description: "NPM Auth Token",
    regex: /\/\/registry\.npmjs\.org\/:_authToken=([^\s'"]+)/,
    severity: "CRITICAL",
  },
  {
    id: "pypi-api-token",
    category: "API_KEY",
    description: "PyPI API Token (pypi-)",
    regex: /\b(pypi-[A-Za-z0-9_]{16,})\b/,
    severity: "HIGH",
  },
  {
    id: "nuget-api-key",
    category: "API_KEY",
    description: "NuGet API Key (oy2)",
    regex: /\b(oy2[a-z0-9]{43})\b/,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // DATABASES & INFRASTRUCTURE (Supabase, PlanetScale, Cloudflare, Vault)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "supabase-key",
    category: "API_KEY",
    description: "Supabase Service Role Key (JWT)",
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase_key)\s*[=:]\s*['"]?(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})['"]?/,
    severity: "CRITICAL",
  },
  {
    id: "cloudflare-api-token",
    category: "API_KEY",
    description: "Cloudflare API Token",
    regex: /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare_api_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?/,
    severity: "CRITICAL",
  },
  {
    id: "datadog-api-key",
    category: "API_KEY",
    description: "Datadog API Key",
    regex: /(?:DD_API_KEY|DATADOG_API_KEY|datadog_api_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/,
    severity: "HIGH",
  },
  {
    id: "hashicorp-vault-token",
    category: "API_KEY",
    description: "HashiCorp Vault Token (hvs.)",
    regex: /\b(hvs\.[A-Za-z0-9_-]{24,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "linear-api-key",
    category: "API_KEY",
    description: "Linear API Key (lin_api_)",
    regex: /\b(lin_api_[A-Za-z0-9]{40})\b/,
    severity: "HIGH",
  },
  {
    id: "planetscale-password",
    category: "API_KEY",
    description: "PlanetScale Database Password (pscale_pw_)",
    regex: /\b(pscale_pw_[A-Za-z0-9_-]{32,})\b/,
    severity: "CRITICAL",
  },
  {
    id: "sentry-dsn",
    category: "API_KEY",
    description: "Sentry DSN (contains auth key)",
    regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/\d+/,
    severity: "MEDIUM",
  },

  // ═══════════════════════════════════════════════════════════════
  // PRIVATE KEYS & CERTIFICATES
  // ═══════════════════════════════════════════════════════════════
  {
    id: "ssh-private-key",
    category: "PRIVATE_KEY",
    description: "SSH / RSA / OpenSSL Private Key",
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    severity: "CRITICAL",
  },
  {
    id: "pkcs8-private-key",
    category: "PRIVATE_KEY",
    description: "PKCS#8 Encrypted Private Key",
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    severity: "CRITICAL",
  },
  {
    id: "pgp-private-key",
    category: "PRIVATE_KEY",
    description: "PGP Private Key Block",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: "CRITICAL",
  },

  // ═══════════════════════════════════════════════════════════════
  // CREDENTIALS & CONNECTIONS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "db-connection-string",
    category: "CREDENTIAL",
    description: "Database Connection String with Password",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+/,
    severity: "HIGH",
  },
  {
    id: "password-assignment",
    category: "CREDENTIAL",
    description: "Hardcoded Password in Variable Assignment",
    regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{4,}['"]/i,
    severity: "HIGH",
  },
  {
    id: "jwt-hardcoded",
    category: "CREDENTIAL",
    description: "Hardcoded JWT Secret in Code",
    regex: /(?:jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    severity: "HIGH",
  },

  // ═══════════════════════════════════════════════════════════════
  // DANGEROUS CODE PATTERNS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "dangerous-eval",
    category: "DANGEROUS_CODE",
    description: "Dynamic Code Execution (eval)",
    regex: /\beval\s*\([^\)]+\)/,
    severity: "MEDIUM",
  },
];

const SENSITIVE_FILENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  ".env.development",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "credentials.json",
  "serviceAccountKey.json",
  ".npmrc",
  ".pypirc",
  ".htpasswd",
  "wp-config.php",
  "application.yml",
  "secrets.yml",
  "vault.json",
  "docker-compose.override.yml",
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
  ".obsidiansec",
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

export function scanDirectoryForSecrets(
  targetDir: string,
  maxFiles = 1000,
  options?: { customPatterns?: SecretPattern[] }
): SecretScanReport {
  const startTime = Date.now();
  const findings: SecretFinding[] = [];
  let filesCount = 0;

  const custom = options?.customPatterns || loadCustomSecurityRules(targetDir);
  const activePatterns = custom.length > 0 ? mergeSecretPatterns(SECRET_PATTERNS, custom) : SECRET_PATTERNS;

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
            description: `Sensitive credentials or environment file exposed: ${entry.name}`,
            filePath: relPath,
            lineNumber: 1,
            snippet: `Sensitive file detected on disk: ${entry.name}`,
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
            for (const pattern of activePatterns) {
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