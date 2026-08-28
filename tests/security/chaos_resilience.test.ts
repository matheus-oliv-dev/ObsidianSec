import { describe, expect, it } from "vitest";
import { removePlayerFromRoom } from "@/lib/domain/room";
import { nicknameSchema } from "@/lib/domain/validation";
import { subtitleCuesSchema } from "@/lib/domain/subtitles";
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
