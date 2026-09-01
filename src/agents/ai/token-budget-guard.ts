import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { type ObsidianConfig, DEFAULT_OBSIDIAN_CONFIG } from "../../lib/config/obsidian-config.ts";

export interface AICacheEntry {
  fingerprint: string;
  timestamp: number;
  data: any;
  provider: string;
}

export interface TokenBudgetStatus {
  canInvoke: boolean;
  reason: string;
  source: "CACHE" | "BUDGET_AVAILABLE" | "BUDGET_EXCEEDED" | "AI_DISABLED" | "OFFLINE_FALLBACK";
  cachedData?: any;
}

/**
 * TokenBudgetGuard: Gerenciador de cota, cache de deduplicação e salvaguarda de custos para LLMs.
 * Impede loops de requisições, chamadas repetidas sobre os mesmos achados e garante operação 100% gratuita por padrão.
 */
export class TokenBudgetGuard {
  private requestTimestamps: number[] = [];
  private cache: Map<string, AICacheEntry> = new Map();
  private cacheFilePath: string;

  constructor(customCacheDir?: string) {
    const dir = customCacheDir || path.resolve(process.cwd(), ".obsidiansec");
    this.cacheFilePath = path.join(dir, "ai-cache.json");
    this.loadCacheFromDisk();
  }

  /**
   * Gera um hash criptográfico SHA-256 único a partir dos achados de segurança
   */
  public generateFingerprint(target: string, findingsSummary: any): string {
    const serialized = typeof findingsSummary === "string" ? findingsSummary : JSON.stringify(findingsSummary);
    return crypto.createHash("sha256").update(`${target}::${serialized}`).digest("hex");
  }

  /**
   * Avalia se a IA deve ser acionada ou se devemos reaproveitar o cache / fallback
   */
  public evaluateBudget(
    fingerprint: string,
    config: ObsidianConfig = DEFAULT_OBSIDIAN_CONFIG,
    forceAI: boolean = false
  ): TokenBudgetStatus {
    // 1. Se IA estiver explicitamente desativada na config e sem override de flag
    if (!config.ai.enabled && !forceAI) {
      return {
        canInvoke: false,
        source: "AI_DISABLED",
        reason: "IA desativada na configuração (Zero-Token Mode). Usando motor heurístico local.",
      };
    }

    // 2. Verifica se o achado já foi analisado e está dentro do TTL de cache
    const cached = this.cache.get(fingerprint);
    if (cached) {
      const ttlMs = (config.ai.cacheTtlHours || 72) * 60 * 60 * 1000;
      const age = Date.now() - cached.timestamp;
      if (age < ttlMs) {
        return {
          canInvoke: false,
          source: "CACHE",
          reason: `Achado idêntico já analisado há ${Math.round(age / 1000 / 60)} minutos. Reutilizando parecer do cache local (Custo: 0 tokens).`,
          cachedData: cached.data,
        };
      }
    }

    // 3. Limpa timestamps antigos de requisições (janela móvel de 1 hora)
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    this.requestTimestamps = this.requestTimestamps.filter((t) => t > oneHourAgo);

    // 4. Checa o limite de requisições por hora (Circuit Breaker)
    const maxPerHour = config.ai.maxRequestsPerHour || 10;
    if (this.requestTimestamps.length >= maxPerHour) {
      return {
        canInvoke: false,
        source: "BUDGET_EXCEEDED",
        reason: `Limite de orçamento atingido (${this.requestTimestamps.length}/${maxPerHour} req/h). Bloqueando chamada para evitar custos desnecessários.`,
      };
    }

    // 5. Orçamento liberado para 1 chamada
    return {
      canInvoke: true,
      source: "BUDGET_AVAILABLE",
      reason: `Orçamento de IA disponível (${this.requestTimestamps.length + 1}/${maxPerHour} req/h).`,
    };
  }

  /**
   * Registra a realização de uma requisição de IA e persiste o resultado no cache
   */
  public recordAndCache(fingerprint: string, data: any, provider: string = "gemini"): void {
    this.requestTimestamps.push(Date.now());
    this.cache.set(fingerprint, {
      fingerprint,
      timestamp: Date.now(),
      data,
      provider,
    });
    this.saveCacheToDisk();
  }

  /**
   * Gera um diagnóstico heurístico determinístico e gratuito (fallback instantâneo)
   */
  public generateDeterministicFallback(target: string, missedControls: string[] = []): any {
    return {
      thoughtProcess: [
        "Motor heurístico offline acionado.",
        "Análise estática dos controles de borda concluída com sucesso.",
        "Zero chamadas de API externas disparadas.",
      ],
      cognitiveDiagnosis: {
        threatAssessment: missedControls.length > 0 
          ? `Perímetro requer atenção em ${missedControls.join(", ")} (${missedControls.length} controles de cabeçalho pendentes).`
          : "Perímetro blindado com todas as defesas ativas.",
        rootCause: "Configuração base de servidor web.",
        attackVectors: missedControls.map((c) => `Ausência ou parametrização fraca de ${c}`),
      },
      recommendedExploratoryTests: missedControls.map((c) => ({
        testName: `Auditoria de Conformidade para ${c}`,
        targetScope: target,
        rationale: `Garantir inclusão do cabeçalho ${c} nas respostas HTTP.`,
      })),
      autoPatches: missedControls.map((c) => ({
        file: "server.conf",
        description: `Patch de mitigação para ${c}`,
        patchCode: `# Aplicar diretiva ${c} no proxy reverso`,
      })),
      qualityGateAdvice: missedControls.length === 0 ? "PASSED" : "REVIEW_RECOMMENDED",
      verdict: missedControls.length === 0 ? "EXCELLENT_EDGE_SECURITY" : "HARDENING_REQUIRED",
    };
  }

  private loadCacheFromDisk(): void {
    try {
      if (fs.existsSync(this.cacheFilePath)) {
        const content = fs.readFileSync(this.cacheFilePath, "utf-8");
        const parsed = JSON.parse(content);
        if (Array.isArray(parsed)) {
          parsed.forEach((item: AICacheEntry) => {
            if (item && item.fingerprint) {
              this.cache.set(item.fingerprint, item);
            }
          });
        }
      }
    } catch {
      // Falha silenciosa em caso de arquivo corrompido
    }
  }

  private saveCacheToDisk(): void {
    try {
      const dir = path.dirname(this.cacheFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const serialized = Array.from(this.cache.values());
      fs.writeFileSync(this.cacheFilePath, JSON.stringify(serialized, null, 2), "utf-8");
    } catch {
      // Ignora erro de gravação se estiver em ambiente read-only
    }
  }
}
