import type { RoomState, Player } from "@/types/domain";

/**
 * Remove um jogador da sala. Suporta saída voluntária ou expulsão pelo Host.
 * Realiza migração automática de liderança se o Host desconectar.
 */
export function removePlayerFromRoom(
  room: RoomState,
  actorId: string,
  targetPlayerId: string,
): RoomState {
  const actor = room.players.find((p) => p.id === actorId);
  const target = room.players.find((p) => p.id === targetPlayerId);

  if (!actor || !target) {
    throw new Error("Jogador não encontrado na sala.");
  }

  // Apenas o próprio jogador pode sair ou o HOST pode expulsar
  if (actorId !== targetPlayerId && !actor.isHost) {
    throw new Error("Permissão negada: apenas o Host pode expulsar outros participantes.");
  }

  let remainingPlayers: Player[] = room.players.filter((p) => p.id !== targetPlayerId);

  // Se o Host saiu e ainda restam jogadores, migra a liderança para o jogador mais antigo
  if (target.isHost && remainingPlayers.length > 0) {
    const sortedByJoined = [...remainingPlayers].sort(
      (a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime(),
    );
    const newHostId = sortedByJoined[0].id;
    remainingPlayers = remainingPlayers.map((p) => ({
      ...p,
      isHost: p.id === newHostId,
    }));
  }

  return {
    ...room,
    revision: room.revision + 1,
    players: remainingPlayers,
    updatedAt: new Date().toISOString(),
  };
}
