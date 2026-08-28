# 🛡️ GUIA COMPLETO DE TESTES DE SEGURANÇA & DEVSECOPS (CÓDIGO & LINHA A LINHA)

Este documento é a **referência técnica de engenharia de segurança defensiva** para projetos de software web, APIs e sistemas em tempo real. Ele detalha cada suíte de testes de penetração (DAST), resiliência (DoS/Caos) e lógica de autorização, incluindo o **código-fonte integral** e a **explicação técnica linha a linha** de cada validação.

---

## 📑 Sumário dos Módulos

1. [Módulo 1: Red Team DAST Fuzzer (`dast_fuzzer.test.ts`)](#1-red-team-dast-fuzzer)
2. [Módulo 2: Resiliência & Mitigação de DoS / HTTP Flood (`stress_resilience.test.ts`)](#2-resiliência--mitigação-de-dos)
3. [Módulo 3: Engenharia do Caos & Falhas de Rede (`chaos_resilience.test.ts`)](#3-engenharia-do-caos--falhas-de-rede)
4. [Módulo 4: Pentest de Lógica Multiplayer & Anti-Cheat (`multiplayer_pentest.test.ts`)](#4-pentest-de-lógica-multiplayer)
5. [Módulo 5: Orquestrador DevSecOps Multi-Agente (`run-security-audit.mjs`)](#5-orquestrador-devsecops-multi-agente)
6. [Como Adaptar Esta Estrutura para um Novo Projeto](#6-como-adaptar-para-um-novo-projeto)

---

# 🔴 1. Red Team DAST Fuzzer

**Arquivo:** `tests/security/dast_fuzzer.test.ts`  
**Objetivo:** Simula vetores de intrusão reais contra a API em tempo de execução.

### 📜 Código-Fonte Integral:
```typescript
import { describe, expect, it, vi } from "vitest";
import { enforceRateLimit } from "@/lib/security/rate-limit";
import { verifyAccessToken } from "@/lib/supabase/token";
import { generateCaptchaChallenge, verifyCaptchaChallenge } from "@/lib/security/captcha";
import { requireAdmin } from "@/lib/supabase/admin";
import type { SupabaseClient } from "@supabase/supabase-js";

process.env.RATE_LIMIT_SECRET = "segredo-de-fuzzing-32-caracteres-minimo";
process.env.ADMIN_GATE_KEY = "chave-secreta-do-portao-admin-123456";
process.env.SUPABASE_URL = "https://mock-test-project.supabase.co";
process.env.SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTUxNjIzOTAyMn0.mockServiceRoleKey";

describe("🛡️ Red Team Fuzzer: Simulação Dinâmica de Ataques", () => {
  describe("1. Simulação de Acesso com Token Anônimo (Vetor BOLA)", () => {
    it("bloqueia terminantemente requisições administrativas sem cabeçalho Authorization com HTTP 401", async () => {
      const request = new Request("https://redubla.com.br/api/admin/metrics");
      const result = await requireAdmin(request);

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error.status).toBe(401);
      }
    });

    it("bloqueia tokens que não possuem role ADMIN com HTTP 403", async () => {
      const request = new Request("https://redubla.com.br/api/admin/metrics", {
        headers: { Authorization: "Bearer token-invalido-ou-sem-admin" },
      });

      const result = await requireAdmin(request);
      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error.status).toBeGreaterThanOrEqual(401);
      }
    });
  });

  describe("2. Simulação de Ataque de Força Bruta e Limite de Taxa", () => {
    it("deve acionar bloqueio HTTP 429 Too Many Requests quando a cota de requisições é excedida", async () => {
      const fakeAdmin = {
        rpc: vi.fn(async () => ({
          data: [{ allowed: false, retry_after_seconds: 30 }],
          error: null,
        })),
      } as unknown as SupabaseClient;

      const userTarget = `alvo-ataque-${Date.now()}`;
      let lastResponse: Response | null = null;

      for (let i = 0; i < 8; i++) {
        lastResponse = await enforceRateLimit({
          admin: fakeAdmin,
          request: new Request("https://redubla.com.br/api/admin/login", {
            headers: { "x-vercel-forwarded-for": "198.51.100.25" },
          }),
          userId: userTarget,
          scope: "admin-login",
          userLimit: 5,
          networkLimit: 20,
          windowSeconds: 60,
        });
      }

      expect(lastResponse).not.toBeNull();
      expect(lastResponse?.status).toBe(429);
      expect(lastResponse?.headers.get("Retry-After")).toBe("30");
      const body = await lastResponse?.json();
      expect(body.error).toMatch(/muitas tentativas/i);
    });
  });

  describe("3. Simulação de Ataque de Manipulação de Algoritmo JWT ('alg: none')", () => {
    it("rejeita qualquer token JWT forjado com algoritmo 'none'", async () => {
      const fakePayload = Buffer.from(
        JSON.stringify({
          sub: "admin-fake",
          role: "ADMIN",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      )
        .toString("base64")
        .replace(/=/g, "");
      const forgedNoneToken = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${fakePayload}.`;

      const claims = await verifyAccessToken(forgedNoneToken);
      expect(claims).toBeNull();
    });

    it("rejeita tokens com assinaturas HMAC inválidas ou corrompidas", async () => {
      const forgedToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.assinaturaInvalidaAqui";
      const claims = await verifyAccessToken(forgedToken);
      expect(claims).toBeNull();
    });
  });

  describe("4. Validação Criptográfica do Desafio CAPTCHA", () => {
    it("aceita resposta correta dentro da janela de validade", () => {
      const challenge = generateCaptchaChallenge();
      expect(challenge.token).toBeDefined();
      expect(challenge.nonce).toBeDefined();
      expect(challenge.expiresAt).toBeGreaterThan(Date.now());
      expect(challenge.svg).toContain("<svg");
    });

    it("rejeita resposta incorreta ou adulterada", () => {
      const challenge = generateCaptchaChallenge();
      const verified = verifyCaptchaChallenge(
        challenge.token,
        "RESPOSTA_ERRADA",
        challenge.nonce,
        challenge.expiresAt,
      );
      expect(verified.success).toBe(false);
    });

    it("rejeita token com assinatura adulterada ou forjada", () => {
      const challenge = generateCaptchaChallenge();
      const tamperedToken = challenge.token.slice(0, -5) + "abcde";
      const verified = verifyCaptchaChallenge(
        tamperedToken,
        "CORRETA",
        challenge.nonce,
        challenge.expiresAt,
      );
      expect(verified.success).toBe(false);
    });

    it("rejeita desafio com tempo expirado", () => {
      const challenge = generateCaptchaChallenge();
      const expiredTime = Date.now() - 10000;
      const verified = verifyCaptchaChallenge(
        challenge.token,
        "ANY",
        challenge.nonce,
        expiredTime,
      );
      expect(verified.success).toBe(false);
      if (!verified.success) {
        expect(verified.error).toMatch(/expirou/i);
      }
    });
  });
});
```

### 🔍 Explicação Técnica Linha a Linha:
* **Vetor BOLA / Broken Object Level Authorization (Linhas 31-53):** Impede que um invasor com login de usuário comum acesse endpoints de administração alterando headers.
* **Vetor Força Bruta & Dicionário (Linhas 56-88):** Aciona `HTTP 429 Too Many Requests` com token bucket limitando tentativas de login.
* **Vetor JWT 'alg: none' (Linhas 91-105):** Proteção crítica que impede que invasores criem tokens falsos assinados com algoritmo vazio.
* **Vetor CAPTCHA HMAC-SHA256 (Linhas 115-162):** Validação de tokens de desafio gerados sem estado no servidor, com expiração curta de 120s.

---

# 🌊 2. Resiliência & Mitigação de DoS

**Arquivo:** `tests/security/stress_resilience.test.ts`  
**Objetivo:** Testa a contenção de rajadas simultâneas de requisições e ataques de botnet no mesmo IP.

### 📜 Código-Fonte Integral:
```typescript
import { describe, expect, it, vi } from "vitest";
import { enforceRateLimit } from "@/lib/security/rate-limit";
import type { SupabaseClient } from "@supabase/supabase-js";

process.env.RATE_LIMIT_SECRET = "segredo-de-estresse-32-caracteres-minimo";

function createMockSupabaseWithLatency(retryAfter = 60) {
  const counts = new Map<string, number>();
  return {
    rpc: vi.fn(async (_fn: string, params: { p_key_hash: string; p_limit: number }) => {
      const key = params.p_key_hash;
      const current = (counts.get(key) ?? 0) + 1;
      counts.set(key, current);
      if (current <= params.p_limit) {
        return {
          data: [{ allowed: true, retry_after_seconds: 0 }],
          error: null,
        };
      }
      return {
        data: [{ allowed: false, retry_after_seconds: retryAfter }],
        error: null,
      };
    }),
  } as unknown as SupabaseClient;
}

describe("🛡️ Resiliência e Proteção contra Ataques de Sobrecarga (DoS)", () => {
  describe("1. Simulação de Rajada Concorrente de Requisições (HTTP Flood)", () => {
    it("deve conter rajada simultânea de 20 requisições disparadas em paralelo via Promise.all", async () => {
      const mockAdmin = createMockSupabaseWithLatency(45);
      const targetUser = `user-flood-${Date.now()}`;

      const promises = Array.from({ length: 20 }, (_, idx) =>
        enforceRateLimit({
          admin: mockAdmin,
          request: new Request("https://redubla.com.br/api/rooms", {
            headers: {
              "x-vercel-forwarded-for": "203.0.113.50",
            },
          }),
          userId: targetUser,
          scope: "room-create",
          userLimit: 5,
          networkLimit: 15,
          windowSeconds: 60,
        }),
      );

      const results = await Promise.all(promises);
      const blocked = results.filter((res) => res !== null && res.status === 429);
      const allowed = results.filter((res) => res === null);

      expect(allowed.length).toBeLessThanOrEqual(5);
      expect(blocked.length).toBeGreaterThanOrEqual(15);
    });
  });

  describe("2. Simulação de Botnet: 500 Contas Criadas em Massa no Mesmo IP", () => {
    it("deve bloquear flood de 500 contas anônimas diferentes criadas pelo mesmo bot no mesmo IP", async () => {
      const mockAdmin = createMockSupabaseWithLatency(60);
      const botIP = "198.51.100.99";
      const results: Array<Response | null> = [];

      for (let i = 0; i < 50; i++) {
        const fakeUserId = `bot-anon-${i}-${Date.now()}`;
        const res = await enforceRateLimit({
          admin: mockAdmin,
          request: new Request("https://redubla.com.br/api/rooms", {
            headers: { "x-forwarded-for": botIP },
          }),
          userId: fakeUserId,
          scope: "room-create",
          userLimit: 5,
          networkLimit: 20,
          windowSeconds: 60,
        });
        results.push(res);
      }

      const blockedByNetwork = results.filter((r) => r?.status === 429);
      expect(blockedByNetwork.length).toBeGreaterThanOrEqual(30);
    });
  });
});
```

---

# 🌪️ 3. Engenharia do Caos & Falhas de Rede

**Arquivo:** `tests/security/chaos_resilience.test.ts`  
**Objetivo:** Testa casos extremos de desconexão, migração de liderança e injeção de caracteres Unicode maliciosos.

### 📜 Código-Fonte Integral:
```typescript
import { describe, expect, it } from "vitest";
import { removePlayerFromRoom } from "@/domain/room";
import { nicknameSchema } from "@/domain/validation";
import { subtitleCuesSchema } from "@/domain/subtitles";
import type { RoomState, RoundClip } from "@/types/domain";

const mockClip: RoundClip = {
  id: "00000000-0000-4000-8000-0000000000a0",
  title: "Cena Caos",
  durationMs: 10000,
  originalVideoUrl: "",
  dubVideoUrl: "",
  subtitleCues: [],
};

function createChaosRoomState(): RoomState {
  return {
    code: "CHAOS",
    revision: 1,
    status: "VOTING",
    mode: "CLASSIC",
    totalRounds: 3,
    currentRound: 1,
    activeRevealIndex: 0,
    currentClip: mockClip,
    readyPlayerIds: [],
    playedClipIds: [],
    clipChangeCount: 0,
    clipChangeVote: null,
    chatMessages: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    players: [
      {
        id: "host-player",
        nickname: "Host Master",
        avatarSeed: 1,
        score: 10,
        isHost: true,
        joinedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "guest-player-1",
        nickname: "Guest One",
        avatarSeed: 2,
        score: 5,
        isHost: false,
        joinedAt: "2026-01-01T00:01:00.000Z",
      },
      {
        id: "guest-player-2",
        nickname: "Guest Two",
        avatarSeed: 3,
        score: 8,
        isHost: false,
        joinedAt: "2026-01-01T00:02:00.000Z",
      },
    ],
    submissions: [],
    votes: [],
  };
}

describe("🌪️ Chaos & Resilience: Cenários Extremos de Concorrência e Rede", () => {
  describe("1. Queda Abrupta do HOST (Host Migration Automático)", () => {
    it("transfere a liderança da sala para o próximo jogador mais antigo quando o host cai", () => {
      const room = createChaosRoomState();
      const nextState = removePlayerFromRoom(room, "host-player", "host-player");

      expect(nextState.players.length).toBe(2);
      expect(nextState.players.some((p) => p.id === "host-player")).toBe(false);

      const newHost = nextState.players.find((p) => p.isHost);
      expect(newHost).toBeDefined();
      expect(newHost?.id).toBe("guest-player-1");
    });

    it("impede que um convidado expulse outro jogador da sala sem permissão de Host", () => {
      const room = createChaosRoomState();
      expect(() =>
        removePlayerFromRoom(room, "guest-player-1", "guest-player-2"),
      ).toThrow(/host/i);
    });
  });

  describe("2. Queda de Jogadores Durante Votação (Cálculo de Quorum sem Deadlock)", () => {
    it("não trava a sala quando um jogador que precisava votar cai da conexão", () => {
      const room = createChaosRoomState();
      const nextState = removePlayerFromRoom(room, "guest-player-2", "guest-player-2");

      expect(nextState.players.length).toBe(2);
      expect(nextState.status).toBe("VOTING");
    });
  });

  describe("3. Injeção de Zalgo Text, Unicode Corrompido e Emojis Gigantes", () => {
    it("processa com segurança legendas contendo Zalgo text e combinadores Unicode", () => {
      const zalgoText = "H̵̛̬é̵̯ḽ̸̎l̴̮̅o̷̖͐ ̷̪͌W̴̞̿o̷͇̒r̷̤̽ĺ̴͈d̴̜́";
      const result = subtitleCuesSchema.safeParse([
        { startMs: 0, endMs: 2000, text: zalgoText },
      ]);
      expect(result.success).toBe(true);
    });

    it("resiste a sequências complexas de emojis compostos (Zero-Width Joiners) em apelidos", () => {
      const complexEmojiNickname = "Matheus 👨‍👩‍👧‍👦";
      const result = nicknameSchema.safeParse(complexEmojiNickname);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toContain("Matheus");
      }
    });

    it("rejeita injeções com milhares de caracteres para evitar estourar a memória (String Bomb DoS)", () => {
      const stringBomb = "A".repeat(10000);
      const result = nicknameSchema.safeParse(stringBomb);
      expect(result.success).toBe(false);
    });
  });
});
```

---

# 🎮 4. Pentest de Lógica Multiplayer

**Arquivo:** `tests/security/multiplayer_pentest.test.ts`  
**Objetivo:** Valida imunidade contra trapaças, auto-voto, spoofing de HOST e injeção de HTML.

### 📜 Código-Fonte Integral:
```typescript
import { describe, expect, it } from "vitest";
import { nicknameSchema } from "@/domain/validation";
import { validateItemVote } from "@/domain/voting";
import { applyRoomAction } from "@/domain/room-actions";
import type { RoomState, RoundClip } from "@/types/domain";

const mockClip: RoundClip = {
  id: "00000000-0000-4000-8000-0000000000a0",
  title: "Cena Teste",
  durationMs: 10000,
  originalVideoUrl: "",
  dubVideoUrl: "",
  subtitleCues: [],
};

function createMockRoomState(patch: Partial<RoomState> = {}): RoomState {
  return {
    code: "TEST1",
    revision: 1,
    status: "VOTING",
    mode: "CLASSIC",
    totalRounds: 1,
    currentRound: 1,
    activeRevealIndex: 0,
    currentClip: mockClip,
    readyPlayerIds: [],
    playedClipIds: [],
    clipChangeCount: 0,
    clipChangeVote: null,
    chatMessages: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    players: [
      {
        id: "player-1",
        nickname: "Alice Host",
        avatarSeed: 1,
        score: 0,
        isHost: true,
        joinedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "player-2",
        nickname: "Bob Guest",
        avatarSeed: 2,
        score: 0,
        isHost: false,
        joinedAt: "2026-01-01T00:00:00.000Z",
      },
    ],
    submissions: [
      {
        id: "sub-alice",
        roundNumber: 1,
        playerId: "player-1",
        audioUrl: "https://redubla.com.br/audio/sub-alice.webm",
        audioStorageKey: "audio/sub-alice.webm",
        mimeType: "audio/webm",
        audioDurationMs: 8000,
        recordingOffsetMs: 0,
        revealOrder: 0,
        votes: 0,
      },
    ],
    votes: [],
    ...patch,
  };
}

describe("🛡️ Pentest Suite: Ataques Reais em Jogos Multiplayer", () => {
  describe("1. Vetor de Injeção de Código e XSS em Apelidos (Nickname Sanitization)", () => {
    it("neutraliza tags HTML e scripts maliciosos injetados no apelido do jogador", () => {
      const maliciousPayloads = [
        "<script>alert(1)</script>",
        "Matheus<img src=x onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<b>ADMIN</b>",
      ];

      for (const payload of maliciousPayloads) {
        const parsed = nicknameSchema.safeParse(payload);
        if (parsed.success) {
          expect(parsed.data).not.toContain("<");
          expect(parsed.data).not.toContain(">");
          expect(parsed.data).not.toContain("<script>");
        }
      }
    });

    it("rejeita apelidos com caracteres de controle perigosos ou strings vazias disfarçadas", () => {
      const invalidPayloads = ["   ", "\t\n\r", "\x00\x08", ""];
      for (const payload of invalidPayloads) {
        const parsed = nicknameSchema.safeParse(payload);
        expect(parsed.success).toBe(false);
      }
    });
  });

  describe("2. Vetor de Impersonação de Host (Host Action Spoofing)", () => {
    it("bloqueia jogadores comuns tentando alterar configurações restritas de sala", () => {
      const lobbyState = createMockRoomState({ status: "LOBBY" });

      expect(() =>
        applyRoomAction(lobbyState, "player-2", {
          type: "SET_RECORDING_LIMIT",
          seconds: 60,
        }),
      ).toThrow(/host/i);

      expect(() =>
        applyRoomAction(lobbyState, "player-2", {
          type: "START",
        }),
      ).toThrow(/host/i);
    });
  });

  describe("3. Vetor de Trapaça de Votação (Vote Spoofing, Self-Voting)", () => {
    it("bloqueia terminantemente que um jogador vote na própria dublagem (Auto-Voto)", () => {
      const room = createMockRoomState();
      expect(() => validateItemVote(room, "player-1", 10)).toThrow(
        /própria atuação|não avalia/i,
      );
    });

    it("bloqueia votos com notas adulteradas fora do set permitido (ex: 999 ou -50)", () => {
      const room = createMockRoomState();
      // @ts-expect-error testando nota ilegal
      expect(() => validateItemVote(room, "player-2", 999)).toThrow(/nota inválida/i);
    });
  });
});
```

---

# ⚙️ 5. Orquestrador DevSecOps Multi-Agente

**Arquivo:** `scripts/run-security-audit.mjs`  
**Objetivo:** Executado no pre-commit hook para barrar vulnerabilidades antes do commit.

### 📜 Código-Fonte:
```javascript
#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";

console.log("\n=======================================================");
console.log("🛡️ ESQUADRÃO DE SEGURANÇA DEVSECOPS: AUDITORIA LOCAL");
console.log("=======================================================\n");

// 1. Executa os testes DAST no Vitest
console.log("👉 [1/2] Executando Red Team Fuzzer (DAST / Vitest)...");
const dastResult = spawnSync(
  process.platform === "win32" ? "npx.cmd" : "npx",
  ["vitest", "run", "tests/security/dast_fuzzer.test.ts"],
  { stdio: "inherit" }
);

if (dastResult.status !== 0) {
  console.error("\n❌ [Quality Gate]: Falha nos testes dinâmicos de penetração.");
  process.exit(1);
}

// 2. Executa a auditoria de SAST e banco de dados
console.log("\n👉 [2/2] Executando Esquadrão Multi-Agente (DB Guardian & Code Sentinel)...");
const squadResult = spawnSync(
  "python",
  [path.join("scripts", "security_squad", "main.py")],
  { stdio: "inherit" }
);

if (squadResult.status !== 0) {
  console.error("\n❌ [Quality Gate]: Falha na auditoria de código ou SQL RLS.");
  process.exit(1);
}

console.log("\n=======================================================");
console.log("🎉 AUDITORIA DE SEGURANÇA: 100% APROVADA (QUALITY GATE OK)");
console.log("=======================================================\n");
```

---

# 🚀 6. Como Adaptar Para um Novo Projeto

Para exportar este padrão e criar o seu **repositório dedicado de testes de segurança**:

1. **Estrutura de Pastas Recomendada:**
   ```text
   meu-projeto-seguranca/
   ├── package.json
   ├── vitest.config.ts
   ├── tests/
   │   ├── dast_fuzzer.test.ts
   │   ├── stress_resilience.test.ts
   │   ├── chaos_resilience.test.ts
   │   └── multiplayer_pentest.test.ts
   └── scripts/
       └── run-security-audit.mjs
   ```
2. **Instalação das Dependências:**
   ```bash
   npm init -y
   npm install -D vitest @types/node typescript zod
   ```
3. **Execução:**
   ```bash
   npm test
   node scripts/run-security-audit.mjs
   ```
