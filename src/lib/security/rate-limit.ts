import crypto from "node:crypto";
import type { RateLimitOptions } from "@/types";

interface MemoryBucket {
  count: number;
  resetAt: number;
}

const memoryStore = new Map<string, MemoryBucket>();

/**
 * Limpa periodicamente chaves expiradas do armazenamento em memória
 */
function cleanupExpired() {
  const now = Date.now();
  for (const [key, bucket] of memoryStore.entries()) {
    if (bucket.resetAt <= now) {
      memoryStore.delete(key);
    }
  }
}

/**
 * Obtém o IP do cliente a partir dos cabeçalhos da requisição
 */
export function extractClientIp(request: Request): string {
  const forwarded =
    request.headers.get("x-vercel-forwarded-for") ||
    request.headers.get("x-forwarded-for") ||
    request.headers.get("cf-connecting-ip") ||
    "127.0.0.1";
  return forwarded.split(",")[0].trim();
}

/**
 * Gera um hash SHA-256 da chave para anonimização e isolamento seguro
 */
export function hashKey(secret: string, key: string): string {
  return crypto.createHmac("sha256", secret).update(key).digest("hex");
}

/**
 * Aplica Rate Limiting em duas camadas: Usuário e Rede (IP).
 * Retorna null se permitido, ou Response HTTP 429 com cabeçalho Retry-After se bloqueado.
 */
export async function enforceRateLimit(options: RateLimitOptions): Promise<Response | null> {
  const secret = process.env.RATE_LIMIT_SECRET || "default-rate-limit-secret-32-chars-min";
  const ip = extractClientIp(options.request);
  const now = Date.now();
  const windowMs = options.windowSeconds * 1000;

  cleanupExpired();

  // 1. Se um cliente admin com RPC foi fornecido, usa a verificação RPC (PostgreSQL)
  if (options.admin && typeof options.admin.rpc === "function") {
    const userKeyHash = hashKey(secret, `user:${options.scope}:${options.userId || ip}`);
    const networkKeyHash = hashKey(secret, `net:${options.scope}:${ip}`);

    // Checagem de usuário
    const userResult = await options.admin.rpc("check_rate_limit", {
      p_key_hash: userKeyHash,
      p_limit: options.userLimit,
    });

    if (userResult?.data?.[0]?.allowed === false) {
      const retryAfter = userResult.data[0].retry_after_seconds || options.windowSeconds;
      return new Response(
        JSON.stringify({ error: "Muitas tentativas. Por favor, aguarde antes de tentar novamente." }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(retryAfter),
          },
        },
      );
    }

    // Checagem de rede (IP)
    const netResult = await options.admin.rpc("check_rate_limit", {
      p_key_hash: networkKeyHash,
      p_limit: options.networkLimit,
    });

    if (netResult?.data?.[0]?.allowed === false) {
      const retryAfter = netResult.data[0].retry_after_seconds || options.windowSeconds;
      return new Response(
        JSON.stringify({ error: "Muitas tentativas originadas desta rede (IP). Aguarde." }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(retryAfter),
          },
        },
      );
    }

    return null;
  }

  // 2. Armazenamento em memória rápida (Edge / In-Memory Bucket)
  const userKey = `user:${options.scope}:${options.userId || ip}`;
  const netKey = `net:${options.scope}:${ip}`;

  // Validação do Limite de Usuário
  const userBucket = memoryStore.get(userKey) || { count: 0, resetAt: now + windowMs };
  if (userBucket.resetAt <= now) {
    userBucket.count = 0;
    userBucket.resetAt = now + windowMs;
  }
  userBucket.count += 1;
  memoryStore.set(userKey, userBucket);

  if (userBucket.count > options.userLimit) {
    const retryAfter = Math.max(1, Math.ceil((userBucket.resetAt - now) / 1000));
    return new Response(
      JSON.stringify({ error: "Muitas tentativas. Por favor, aguarde antes de tentar novamente." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(retryAfter),
        },
      },
    );
  }

  // Validação do Limite de Rede (IP)
  const netBucket = memoryStore.get(netKey) || { count: 0, resetAt: now + windowMs };
  if (netBucket.resetAt <= now) {
    netBucket.count = 0;
    netBucket.resetAt = now + windowMs;
  }
  netBucket.count += 1;
  memoryStore.set(netKey, netBucket);

  if (netBucket.count > options.networkLimit) {
    const retryAfter = Math.max(1, Math.ceil((netBucket.resetAt - now) / 1000));
    return new Response(
      JSON.stringify({ error: "Muitas tentativas originadas desta rede (IP). Aguarde." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(retryAfter),
        },
      },
    );
  }

  return null;
}
