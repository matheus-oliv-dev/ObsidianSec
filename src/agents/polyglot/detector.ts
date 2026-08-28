import fs from "node:fs";
import path from "node:path";
import type { TargetLanguage, TargetFramework } from "./rules";

export interface TechStackInfo {
  languages: TargetLanguage[];
  frameworks: TargetFramework[];
  server?: string;
  databaseHints: string[];
  totalFiles: number;
}

const EXTENSION_MAP: Record<string, TargetLanguage> = {
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
 * Detecta automaticamente o ecossistema tecnológico (linguagens, frameworks e servidores)
 * a partir de uma pasta de código ou de respostas HTTP.
 */
export function detectLocalTechStack(rootDir: string): TechStackInfo {
  const languages = new Set<TargetLanguage>();
  const frameworks = new Set<TargetFramework>();
  const dbHints = new Set<string>();
  let totalFiles = 0;

  function scan(dir: string) {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
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
          scan(path.join(dir, entry.name));
        }
      } else {
        totalFiles += 1;
        const ext = path.extname(entry.name).toLowerCase();
        const lang = EXTENSION_MAP[ext];
        if (lang) languages.add(lang);

        // Detecção de Frameworks por arquivos de configuração
        const fname = entry.name.toLowerCase();
        if (fname === "package.json") {
          try {
            const content = fs.readFileSync(path.join(dir, entry.name), "utf-8");
            if (content.includes('"next"')) frameworks.add("nextjs");
            if (content.includes('"express"')) frameworks.add("express");
            if (content.includes('"react"')) frameworks.add("react");
            if (content.includes('"pg"') || content.includes('"postgres"')) dbHints.add("PostgreSQL");
            if (content.includes('"mysql"')) dbHints.add("MySQL");
            if (content.includes('"sqlite"')) dbHints.add("SQLite");
          } catch {}
        }

        if (fname === "requirements.txt" || fname === "pyproject.toml" || fname === "pipfile") {
          try {
            const content = fs.readFileSync(path.join(dir, entry.name), "utf-8").toLowerCase();
            if (content.includes("django")) frameworks.add("django");
            if (content.includes("fastapi")) frameworks.add("fastapi");
            if (content.includes("flask")) frameworks.add("flask");
            if (content.includes("psycopg") || content.includes("asyncpg")) dbHints.add("PostgreSQL");
            if (content.includes("sqlalchemy")) dbHints.add("SQLAlchemy");
          } catch {}
        }

        if (fname === "composer.json") {
          try {
            const content = fs.readFileSync(path.join(dir, entry.name), "utf-8").toLowerCase();
            if (content.includes("laravel/framework")) frameworks.add("laravel");
            if (content.includes("wordpress")) frameworks.add("wordpress");
          } catch {}
        }

        if (fname === "pom.xml" || fname === "build.gradle") {
          try {
            const content = fs.readFileSync(path.join(dir, entry.name), "utf-8").toLowerCase();
            if (content.includes("spring-boot")) frameworks.add("springboot");
          } catch {}
        }

        if (fname.endsWith(".csproj")) {
          frameworks.add("aspnet");
        }

        if (fname === "go.mod") {
          try {
            const content = fs.readFileSync(path.join(dir, entry.name), "utf-8").toLowerCase();
            if (content.includes("gin-gonic")) frameworks.add("gin");
          } catch {}
        }
      }
    }
  }

  scan(rootDir);

  return {
    languages: Array.from(languages),
    frameworks: Array.from(frameworks),
    databaseHints: Array.from(dbHints),
    totalFiles,
  };
}

/**
 * Detecta servidores e tecnologias a partir dos cabeçalhos HTTP de um site ao vivo.
 */
export function detectRemoteTechStack(headers: Headers): { server: string; frameworkHint?: string } {
  const server = headers.get("server") || headers.get("x-powered-by") || "Desconhecido / Genérico";
  const xPowered = headers.get("x-powered-by")?.toLowerCase() || "";
  let frameworkHint: string | undefined;

  if (xPowered.includes("php")) frameworkHint = "PHP";
  if (xPowered.includes("express")) frameworkHint = "Express (Node.js)";
  if (xPowered.includes("next.js")) frameworkHint = "Next.js";
  if (xPowered.includes("asp.net")) frameworkHint = "ASP.NET (.NET)";

  return {
    server,
    frameworkHint,
  };
}
