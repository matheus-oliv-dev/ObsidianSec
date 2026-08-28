import crypto from "node:crypto";
import type { AuditLogEntry } from "@/types";

const auditTrail: AuditLogEntry[] = [];

/**
 * Registra uma entrada imutável na trilha de auditoria administrativa Zero-Trust.
 */
export function recordAuditLog(
  actorId: string,
  action: string,
  ipAddress: string,
  payload: Record<string, unknown>,
  actorEmail?: string,
): AuditLogEntry {
  const payloadJson = JSON.stringify(payload);
  const payloadHash = crypto.createHash("sha256").update(payloadJson).digest("hex");

  const entry: AuditLogEntry = {
    id: crypto.randomUUID(),
    actorId,
    actorEmail,
    action,
    ipAddress,
    payloadHash,
    timestamp: new Date().toISOString(),
    metadata: {
      payloadSummary: payload,
    },
  };

  auditTrail.push(entry);
  return entry;
}

/**
 * Retorna os registros de auditoria em memória (para testes e inspeção)
 */
export function getAuditLogs(): AuditLogEntry[] {
  return [...auditTrail];
}

/**
 * Limpa o histórico de auditoria em memória
 */
export function clearAuditLogs(): void {
  auditTrail.length = 0;
}
