import path from "node:path";

/**
 * Normaliza representações de IP (incluindo hexadecimal 0x7f000001 e decimal puro 2130706433)
 * para o formato IPv4 padrão (ex: 127.0.0.1).
 */
export function normalizeIp(rawIp: string): string {
  const trimmed = rawIp.trim();

  // Tratamento de Hexadecimal (ex: 0x7f000001)
  if (/^0x[0-9a-fA-F]{1,8}$/i.test(trimmed)) {
    const num = parseInt(trimmed, 16);
    return [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255,
    ].join(".");
  }

  // Tratamento de Decimal puro (ex: 2130706433)
  if (/^\d{8,10}$/.test(trimmed)) {
    const num = parseInt(trimmed, 10);
    return [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255,
    ].join(".");
  }

  return trimmed;
}

/**
 * Valida se um IP pertence a faixas privadas RFC 1918, loopback ou IPs de metadados Cloud (AWS/GCP/Azure).
 * Proteção crítica contra Server-Side Request Forgery (SSRF).
 */
export function isPrivateOrMetadataIp(inputIp: string): boolean {
  const ip = normalizeIp(inputIp);

  // Metadados Cloud (AWS, GCP, Azure, OpenStack) - 169.254.169.254 ou sub-rede 169.254.0.0/16
  if (ip.startsWith("169.254.")) return true;

  // Loopback (127.0.0.0/8 e IPv6 ::1)
  if (ip.startsWith("127.") || ip === "localhost" || ip === "::1" || ip === "0.0.0.0") return true;

  // RFC 1918 - Classe A (10.0.0.0/8)
  if (ip.startsWith("10.")) return true;

  // RFC 1918 - Classe B (172.16.0.0/12: 172.16 - 172.31)
  if (ip.startsWith("172.")) {
    const parts = ip.split(".");
    if (parts.length >= 2) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
  }

  // RFC 1918 - Classe C (192.168.0.0/16)
  if (ip.startsWith("192.168.")) return true;

  // Metadados GCP internos
  if (ip.toLowerCase() === "metadata.google.internal") return true;

  return false;
}

/**
 * Valida e resolve um caminho de arquivo de forma segura contra Path Traversal (CWE-22 / CWE-23).
 * Garante que o arquivo final permaneça estritamente contido dentro do diretório base.
 */
export function resolveSafePath(baseDir: string, userPath: string): string {
  // Rejeita Null Bytes imediatamente
  if (userPath.includes("\0") || userPath.includes("%00")) {
    throw new Error("[SecurityError]: Null Byte injection detectado no caminho.");
  }

  // Decodifica percent-encoding duplo recursivamente
  let decoded = userPath;
  try {
    while (decoded.includes("%")) {
      const nextDecoded = decodeURIComponent(decoded);
      if (nextDecoded === decoded) break;
      decoded = nextDecoded;
    }
  } catch {
    throw new Error("[SecurityError]: Codificação URI inválida no caminho.");
  }

  // Remove caracteres de controle perigosos
  decoded = decoded.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");

  // Normaliza barras invertidas (\) para forward slashes (/) garantindo bloqueio em Windows e Linux
  const normalizedUserPath = decoded.replace(/\\/g, "/");

  // Resolve o caminho canônico
  const canonicalBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(canonicalBase, normalizedUserPath);

  // Verifica se o caminho resolvido escapa do diretório base permitido
  const relative = path.relative(canonicalBase, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative) || !resolvedTarget.startsWith(canonicalBase)) {
    throw new Error("[SecurityError]: Path traversal detectado. Acesso negado fora do diretório base.");
  }

  return resolvedTarget;
}

/**
 * Validador de URLs seguras contra SSRF para webhooks e requisições externas.
 */
export function validateSafeUrl(rawUrl: string): { isAllowed: boolean; reason?: string } {
  try {
    const parsed = new URL(rawUrl);

    // Permite estritamente esquemas http e https
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { isAllowed: false, reason: `Esquema de protocolo proibido: ${parsed.protocol}` };
    }

    // Bloqueia IPs privados ou metadados de cloud
    if (isPrivateOrMetadataIp(parsed.hostname)) {
      return { isAllowed: false, reason: `Destino bloqueado: IP privado ou metadados de cloud (${parsed.hostname})` };
    }

    return { isAllowed: true };
  } catch {
    return { isAllowed: false, reason: "URL malformada ou inválida." };
  }
}
