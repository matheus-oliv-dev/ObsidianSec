export type AgentRole =
  | "SECURITY_LEAD"
  | "CODE_SENTINEL_SAST"
  | "DAST_FUZZER"
  | "EDGE_GUARDIAN"
  | "CHAOS_ENGINEER"
  | "THREAT_MODELER"
  | "AI_RED_TEAMER"
  | "BROWSER_HARDENING_SENTINEL";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SecurityFinding {
  id: string;
  agent: AgentRole;
  title: string;
  severity: Severity;
  cvssScore: number;
  cwe?: string;
  owaspCategory?: string;
  location?: string;
  description: string;
  evidence?: string;
  remediation: string;
  timestamp: string;
}

export interface AgentContext {
  targetUrl?: string;
  workspacePath?: string;
  findings: SecurityFinding[];
  metadata: Record<string, unknown>;
}

export interface AgentResponse {
  agent: AgentRole;
  status: "SUCCESS" | "WARNING" | "FAILED";
  findings: SecurityFinding[];
  summary: string;
  durationMs: number;
}

export interface AgentPersona {
  role: AgentRole;
  name: string;
  avatar: string;
  description: string;
  systemPrompt: string;
}
