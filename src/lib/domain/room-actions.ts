import type { RoomState, RoomAction } from "@/types/domain";

/**
 * Executa uma ação de controle de sala garantindo verificação estrita de privilégios de Host.
 */
export function applyRoomAction(
  room: RoomState,
  playerId: string,
  action: RoomAction,
): RoomState {
  const player = room.players.find((p) => p.id === playerId);
  if (!player) {
    throw new Error("Jogador não encontrado na sala.");
  }

  // Ações restritas ao HOST
  const hostRestrictedActions: RoomAction["type"][] = [
    "START",
    "SET_RECORDING_LIMIT",
    "NEXT_ROUND",
  ];

  if (hostRestrictedActions.includes(action.type) && !player.isHost) {
    throw new Error(`Permissão negada: apenas o Host da sala pode executar a ação '${action.type}'.`);
  }

  const nextState: RoomState = {
    ...room,
    revision: room.revision + 1,
    updatedAt: new Date().toISOString(),
  };

  switch (action.type) {
    case "START":
      if (nextState.status !== "LOBBY") {
        throw new Error("A sala já foi iniciada.");
      }
      nextState.status = "RECORDING";
      break;

    case "SET_RECORDING_LIMIT":
      if (action.seconds < 5 || action.seconds > 120) {
        throw new Error("Limite de gravação inválido (deve ser entre 5 e 120 segundos).");
      }
      nextState.recordingLimitSeconds = action.seconds;
      break;

    case "NEXT_ROUND":
      nextState.currentRound += 1;
      nextState.status = "RECORDING";
      break;

    default:
      break;
  }

  return nextState;
}
