export interface WebSocketHandshakeOptions {
  origin: string | null;
  allowedOrigins: string[];
  protocolToken?: string | null;
}

export interface WebSocketMessageGuardOptions {
  maxPayloadBytes?: number;
  maxMessagesPerSecond?: number;
}

export class WebSocketSecurityGuard {
  private allowedOrigins: Set<string>;
  private maxPayloadBytes: number;
  private messageCounters: Map<string, { count: number; resetAt: number }> = new Map();
  private maxPerSecond: number;

  constructor(allowedOrigins: string[], options: WebSocketMessageGuardOptions = {}) {
    this.allowedOrigins = new Set(allowedOrigins.map((o) => o.toLowerCase().trim()));
    this.maxPayloadBytes = options.maxPayloadBytes ?? 256 * 1024; // 256 KB
    this.maxPerSecond = options.maxMessagesPerSecond ?? 30;
  }

  /**
   * Valida o handshake de conexão contra Cross-Site WebSocket Hijacking (CSWSH).
   */
  public validateHandshake(origin: string | null): { allowed: boolean; code?: number; reason?: string } {
    if (!origin) {
      return { allowed: false, code: 403, reason: "Cabeçalho Origin obrigatório no handshake WebSocket." };
    }

    const normalizedOrigin = origin.toLowerCase().trim();
    if (!this.allowedOrigins.has(normalizedOrigin)) {
      return {
        allowed: false,
        code: 403,
        reason: `Origem não autorizada para WebSocket (CSWSH detectado): ${origin}`,
      };
    }

    return { allowed: true };
  }

  /**
   * Valida o tamanho do frame para mitigar WebSocket Floods e Message Bombs.
   */
  public validatePayloadSize(payloadLength: number): { allowed: boolean; closeCode?: number } {
    if (payloadLength > this.maxPayloadBytes) {
      return { allowed: false, closeCode: 1009 }; // 1009 = Message Too Big
    }
    return { allowed: true };
  }

  /**
   * Controla a taxa de mensagens por conexão em tempo real (Rate Limiting de socket).
   */
  public checkMessageRateLimit(socketId: string): boolean {
    const now = Date.now();
    const entry = this.messageCounters.get(socketId) || { count: 0, resetAt: now + 1000 };

    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + 1000;
    }

    entry.count += 1;
    this.messageCounters.set(socketId, entry);

    return entry.count <= this.maxPerSecond;
  }

  /**
   * Valida a autorização de canais/salas privadas.
   */
  public isAuthorizedForChannel(userRole: string, channelName: string): boolean {
    if (channelName.startsWith("admin_") && userRole !== "ADMIN") {
      return false;
    }
    return true;
  }
}
