import type { RoomState } from "@/types/domain";

export const ALLOWED_SCORES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/**
 * Valida a integridade de um voto submetido por um jogador.
 * Impede que jogadores avaliem a própria submissão (Auto-Voto) e bloqueia notas manipuladas.
 */
export function validateItemVote(
  room: RoomState,
  voterId: string,
  score: number,
  targetSubmissionId?: string,
): boolean {
  // Verifica se a nota está no intervalo permitido
  if (typeof score !== "number" || !Number.isInteger(score) || score < 0 || score > 10) {
    throw new Error("Nota inválida: a pontuação deve ser um número inteiro entre 0 e 10.");
  }

  // Identifica a submissão ativa ou especificada
  const currentSubmission = targetSubmissionId
    ? room.submissions.find((s) => s.id === targetSubmissionId)
    : room.submissions[room.activeRevealIndex] || room.submissions[0];

  if (!currentSubmission) {
    throw new Error("Nenhuma submissão ativa encontrada para votação.");
  }

  // Impede Auto-Voto
  if (currentSubmission.playerId === voterId) {
    throw new Error("Trapaça detectada: você não pode votar na sua própria atuação!");
  }

  // Verifica se o votante existe na sala
  const voterExists = room.players.some((p) => p.id === voterId);
  if (!voterExists) {
    throw new Error("Jogador não encontrado na sala.");
  }

  return true;
}
