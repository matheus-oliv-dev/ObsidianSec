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
 * Detecta servidores e tecnologias a partir dos cabeçalhos HTTP de um site ao vivo (Inspirado no Nmap Service Fingerprinting).
 */
export function detectRemoteTechStack(headers: Headers): {
  server: string;
  frameworkHint?: string;
  cdnOrProxy?: string;
  rawServerHeader?: string;
  versionExposed: boolean;
} {
  const getH = (name: string): string => (headers.get(name) || "").toLowerCase();

  const serverHeader = headers.get("server") || "";
  const xPowered = headers.get("x-powered-by") || "";
  const via = headers.get("via") || "";
  const sLower = serverHeader.toLowerCase();
  const vLower = via.toLowerCase();

  let server = "Servidor Web Oculto / Personalizado";
  let cdnOrProxy: string | undefined;
  let frameworkHint: string | undefined;
  let versionExposed = false;

  // 1. CDN & Edge Networks (Nmap Edge Fingerprinting)
  if (sLower.includes("cloudflare") || headers.get("cf-ray") || headers.get("cf-cache-status")) {
    cdnOrProxy = "Cloudflare Edge Global CDN";
    server = "Cloudflare Edge";
  } else if (vLower.includes("cloudfront") || headers.get("x-amz-cf-id") || headers.get("x-amz-cf-pop")) {
    cdnOrProxy = "AWS CloudFront CDN";
    server = "Amazon Web Services (CloudFront)";
  } else if (vLower.includes("fastly") || headers.get("x-served-by")?.includes("cache-") || headers.get("fastly-restarts")) {
    cdnOrProxy = "Fastly Real-Time Edge";
    server = "Fastly Edge Network";
  } else if (headers.get("x-akamai-transformed") || sLower.includes("akamaighost")) {
    cdnOrProxy = "Akamai Intelligent Edge";
    server = "Akamai Edge Platform";
  } else if (headers.get("x-vercel-id") || headers.get("x-vercel-cache") || sLower.includes("vercel")) {
    cdnOrProxy = "Vercel Edge Network";
    server = "Vercel Serverless Edge";
  } else if (headers.get("x-nf-request-id") || sLower.includes("netlify")) {
    cdnOrProxy = "Netlify Global Edge";
    server = "Netlify Edge Server";
  } else if (vLower.includes("varnish") || headers.get("x-varnish")) {
    cdnOrProxy = "Varnish Cache Reverse Proxy";
  }

  // 2. Servidores Web e Reverse Proxies
  if (sLower.includes("nginx")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("apache")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("caddy")) {
    server = "Caddy Modern Web Server";
  } else if (sLower.includes("litespeed") || sLower.includes("openlitespeed")) {
    server = "LiteSpeed High-Performance Web Server";
  } else if (sLower.includes("traefik")) {
    server = "Traefik Cloud Native Edge Router";
  } else if (sLower.includes("envoy") || headers.get("x-envoy-upstream-service-time")) {
    server = "Envoy Proxy (Service Mesh / Cloud Native)";
  } else if (sLower.includes("openresty")) {
    server = "OpenResty (Nginx + Lua Engine)";
  } else if (sLower.includes("microsoft-iis") || sLower.includes("iis")) {
    server = serverHeader || "Microsoft IIS Web Server";
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("gunicorn") || sLower.includes("uvicorn")) {
    server = "Python WSGI/ASGI Server (Gunicorn/Uvicorn)";
  } else if (sLower.includes("kestrel")) {
    server = "Kestrel (.NET Core Web Server)";
  } else if (sLower.includes("kong")) {
    server = "Kong API Gateway";
  } else if (serverHeader && server === "Servidor Web Oculto / Personalizado") {
    server = serverHeader;
  }

  // 3. Frameworks
  const xpLower = xPowered.toLowerCase();
  if (xpLower.includes("next.js") || headers.get("x-nextjs-cache")) frameworkHint = "Next.js (React Fullstack)";
  else if (xpLower.includes("express")) frameworkHint = "Express.js (Node.js)";
  else if (xpLower.includes("php")) frameworkHint = xPowered;
  else if (xpLower.includes("asp.net")) frameworkHint = "ASP.NET (.NET)";
  else if (xpLower.includes("nuxt")) frameworkHint = "Nuxt.js (Vue Fullstack)";
  else if (headers.get("x-drupal-cache")) frameworkHint = "Drupal CMS (PHP)";
  else if (headers.get("x-pingback")?.includes("xmlrpc.php")) frameworkHint = "WordPress CMS (PHP)";
  else if (headers.get("x-django-version")) frameworkHint = "Django (Python)";

  return {
    server,
    frameworkHint,
    cdnOrProxy,
    rawServerHeader: serverHeader || undefined,
    versionExposed,
  };
}
