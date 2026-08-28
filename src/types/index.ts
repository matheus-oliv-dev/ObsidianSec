export interface SubtitleCue {
  startMs: number;
  endMs: number;
  text: string;
}

export interface RoundClip {
  id: string;
  title: string;
  durationMs: number;
  originalVideoUrl: string;
  dubVideoUrl: string;
  subtitleCues: SubtitleCue[];
}

export interface Player {
  id: string;
  nickname: string;
  avatarSeed: number;
  score: number;
  isHost: boolean;
  joinedAt: string;
}

export interface Submission {
  id: string;
  roundNumber: number;
  playerId: string;
  audioUrl: string;
  audioStorageKey: string;
  mimeType: string;
  audioDurationMs: number;
  recordingOffsetMs: number;
  revealOrder: number;
  votes: number;
}

export interface Vote {
  voterId: string;
  targetPlayerId: string;
  score: number;
}

export interface ChatMessage {
  id: string;
  playerId: string;
  nickname: string;
  message: string;
  timestamp: string;
}

export interface RoomState {
  code: string;
  revision: number;
  status: "LOBBY" | "RECORDING" | "VOTING" | "REVEAL" | "FINISHED";
  mode: "CLASSIC" | "CHALLENGE" | "CHAOS";
  totalRounds: number;
  currentRound: number;
  activeRevealIndex: number;
  currentClip: RoundClip | null;
  readyPlayerIds: string[];
  playedClipIds: string[];
  clipChangeCount: number;
  clipChangeVote: { yes: string[]; no: string[] } | null;
  chatMessages: ChatMessage[];
  createdAt: string;
  updatedAt: string;
  players: Player[];
  submissions: Submission[];
  votes: Vote[];
  recordingLimitSeconds?: number;
}

export type RoomAction =
  | { type: "START" }
  | { type: "SET_RECORDING_LIMIT"; seconds: number }
  | { type: "SUBMIT_AUDIO"; submission: Omit<Submission, "id" | "revealOrder" | "votes"> }
  | { type: "CAST_VOTE"; targetPlayerId: string; score: number }
  | { type: "NEXT_ROUND" };

export interface RateLimitOptions {
  admin?: any;
  request: Request;
  userId?: string;
  scope: string;
  userLimit: number;
  networkLimit: number;
  windowSeconds: number;
}

export interface CaptchaChallenge {
  token: string;
  nonce: string;
  expiresAt: number;
  svg: string;
}

export interface CaptchaVerifyResult {
  success: boolean;
  error?: string;
}

export interface AccessTokenClaims {
  sub: string;
  role: string;
  iss?: string;
  exp: number;
  email?: string;
  [key: string]: unknown;
}

export interface AuditLogEntry {
  id: string;
  actorId: string;
  actorEmail?: string;
  action: string;
  ipAddress: string;
  payloadHash: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface BrowserShieldConfig {
  enableCSP?: boolean;
  cspDirectives?: Record<string, string[]>;
  enableHSTS?: boolean;
  enableAntiClickjacking?: boolean;
  enablePermissionsPolicy?: boolean;
  enableCORP?: boolean;
  enableCOEP?: boolean;
  enableCOOP?: boolean;
}
