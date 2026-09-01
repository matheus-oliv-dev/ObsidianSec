import fs from "node:fs";
import path from "node:path";

export interface ObsidianScopeConfig {
  allowlist: string[];
  blocklist: string[];
  strictMode: boolean;
}

export interface ObsidianAIConfig {
  enabled: boolean;
  provider: "gemini" | "openai" | "anthropic" | "offline";
  maxRequestsPerHour: number;
  cacheTtlHours: number;
}

export interface ObsidianConfig {
  version: string;
  scope: ObsidianScopeConfig;
  ai: ObsidianAIConfig;
}

export const DEFAULT_OBSIDIAN_CONFIG: ObsidianConfig = {
  version: "1.3.1",
  scope: {
    allowlist: [],
    blocklist: ["*.gov.br", "*.mil.br", "*.jus.br"],
    strictMode: false,
  },
  ai: {
    enabled: false,
    provider: "offline",
    maxRequestsPerHour: 10,
    cacheTtlHours: 72,
  },
};

/**
 * Procura e carrega o arquivo de configuração obsidiansec.config.json
 * Se não encontrar, retorna as configurações padrão seguras (zero-AI, custo zero).
 */
export function loadObsidianConfig(customPath?: string): ObsidianConfig {
  const configPath = customPath || path.resolve(process.cwd(), "obsidiansec.config.json");

  try {
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, "utf-8");
      const parsed = JSON.parse(raw);
      return {
        version: parsed.version || DEFAULT_OBSIDIAN_CONFIG.version,
        scope: {
          ...DEFAULT_OBSIDIAN_CONFIG.scope,
          ...(parsed.scope || {}),
        },
        ai: {
          ...DEFAULT_OBSIDIAN_CONFIG.ai,
          ...(parsed.ai || {}),
        },
      };
    }
  } catch (err) {
    console.warn(`[CONFIG] Aviso: Não foi possível ler ${configPath}. Usando configuração padrão segura.`);
  }

  return { ...DEFAULT_OBSIDIAN_CONFIG };
}

/**
 * Gera um template do obsidiansec.config.json no diretório informado
 */
export function generateDefaultConfigFile(targetDir: string = process.cwd()): string {
  const targetPath = path.resolve(targetDir, "obsidiansec.config.json");
  const template = {
    "$schema": "https://obsidiansec.dev/schema.json",
    "version": "1.2.2",
    "scope": {
      "strictMode": false,
      "allowlist": [
        "localhost",
        "127.0.0.1",
        "staging.yourdomain.com",
        "*.yourdomain.com"
      ],
      "blocklist": [
        "*.gov.br",
        "*.mil.br",
        "*.jus.br"
      ]
    },
    "ai": {
      "enabled": false,
      "provider": "offline",
      "maxRequestsPerHour": 10,
      "cacheTtlHours": 72
    }
  };

  fs.writeFileSync(targetPath, JSON.stringify(template, null, 2), "utf-8");
  return targetPath;
}
