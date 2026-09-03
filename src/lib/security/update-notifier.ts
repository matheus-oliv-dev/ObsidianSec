/**
 * Automated Version Update Notifier
 * Verifica assincronamente se existe uma versão mais recente publicada no NPM
 * com cache local de 24 horas para garantir zero impacto de latência.
 */

import fs from "node:fs";
import path from "node:path";

export interface VersionCacheData {
  lastChecked: number;
  latestVersion: string;
}

/**
 * Compara duas versões SemVer (ex: '1.4.1' com '1.4.0')
 * Retorna true se latest for estritamente superior a current
 */
export function isNewerVersion(latest: string, current: string): boolean {
  const parse = (v: string) => v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const [lMaj, lMin, lPatch] = parse(latest);
  const [cMaj, cMin, cPatch] = parse(current);

  if (lMaj > cMaj) return true;
  if (lMaj < cMaj) return false;

  if (lMin > cMin) return true;
  if (lMin < cMin) return false;

  return lPatch > cPatch;
}

/**
 * Formata um banner amigável e elegante para o terminal
 */
export function formatUpdateNotification(currentVersion: string, latestVersion: string): string {
  const ANSI = {
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
    green: "\x1b[32m",
    bold: "\x1b[1m",
    reset: "\x1b[0m",
  };

  return `${ANSI.yellow}┌──────────────────────────────────────────────────────────┐
│                                                          │
│   ${ANSI.bold}Atualização disponível:${ANSI.reset} ${currentVersion} → ${ANSI.green}${latestVersion}${ANSI.reset}${ANSI.yellow}                │
│   Execute: ${ANSI.cyan}npm install -g chimeraguard${ANSI.reset}${ANSI.yellow} para atualizar    │
│                                                          │
└──────────────────────────────────────────────────────────┘${ANSI.reset}`;
}

/**
 * Checa o cache local sincronamente (0ms de latência)
 */
export function checkCachedUpdateSync(
  currentVersion: string,
  cacheDir?: string
): string | null {
  const dir = cacheDir || (fs.existsSync(path.resolve(process.cwd(), ".chimeraguard")) 
    ? path.resolve(process.cwd(), ".chimeraguard") 
    : path.resolve(process.cwd(), ".obsidiansec"));
  const cacheFile = path.join(dir, "version-cache.json");

  try {
    if (fs.existsSync(cacheFile)) {
      const raw = fs.readFileSync(cacheFile, "utf-8");
      const data: VersionCacheData = JSON.parse(raw);
      if (data.latestVersion && isNewerVersion(data.latestVersion, currentVersion)) {
        return formatUpdateNotification(currentVersion, data.latestVersion);
      }
    }
  } catch {
    // Silencioso
  }
  return null;
}

/**
 * Dispara verificação assíncrona em background para atualizar o cache
 */
export function triggerBackgroundUpdateCheck(
  currentVersion: string,
  cacheDir?: string
): void {
  const dir = cacheDir || path.resolve(process.cwd(), ".obsidiansec");
  const cacheFile = path.join(dir, "version-cache.json");

  try {
    if (fs.existsSync(cacheFile)) {
      const raw = fs.readFileSync(cacheFile, "utf-8");
      const data: VersionCacheData = JSON.parse(raw);
      const isFresh = Date.now() - data.lastChecked < 24 * 60 * 60 * 1000;
      if (isFresh) return; // Cache recente, dispensa requisição de rede
    }
  } catch {
    // Continua
  }

  // Requisição em background não-bloqueante
  checkCliUpdate(currentVersion, { cacheDir: dir, timeoutMs: 1200 }).catch(() => {});
}

/**
 * Checa se há atualizações no registro do NPM
 */
export async function checkCliUpdate(
  currentVersion: string,
  options?: { cacheDir?: string; timeoutMs?: number }
): Promise<string | null> {
  const timeoutMs = options?.timeoutMs ?? 800;
  const cacheDir = options?.cacheDir || path.resolve(process.cwd(), ".obsidiansec");
  const cacheFile = path.join(cacheDir, "version-cache.json");

  // 1. Tenta ler do cache
  try {
    if (fs.existsSync(cacheFile)) {
      const raw = fs.readFileSync(cacheFile, "utf-8");
      const data: VersionCacheData = JSON.parse(raw);
      const isFresh = Date.now() - data.lastChecked < 24 * 60 * 60 * 1000;

      if (isFresh && data.latestVersion) {
        if (isNewerVersion(data.latestVersion, currentVersion)) {
          return formatUpdateNotification(currentVersion, data.latestVersion);
        }
        return null;
      }
    }
  } catch {
    // Ignora erro
  }

  // 2. Consulta o registro oficial do NPM com timeout curto
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res = await fetch("https://registry.npmjs.org/chimeraguard/latest", {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      res = await fetch("https://registry.npmjs.org/obsidiansec/latest", {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
    }
    clearTimeout(timer);

    if (!res.ok) return null;

    const data: any = await res.json();
    const latestVersion = data.version;

    // Salva no cache local
    try {
      if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(
        cacheFile,
        JSON.stringify({ lastChecked: Date.now(), latestVersion }, null, 2),
        "utf-8"
      );
    } catch {
      // Ignora erro de gravação
    }

    if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
      return formatUpdateNotification(currentVersion, latestVersion);
    }
  } catch {
    // Silencioso
  }

  return null;
}
