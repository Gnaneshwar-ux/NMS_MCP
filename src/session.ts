import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { Client, ClientChannel } from "ssh2";

import { HandledError } from "./utils.js";

export type CommandRiskLevel = "read-only" | "mutating" | "destructive";
export type ShellPrivilegeMode = "standard" | "sudo" | "su" | "root";

export interface PendingApproval {
  approvalId: string;
  command: string;
  riskLevel: CommandRiskLevel;
  requiredConfirmationToken: "CONFIRM" | "EXEC";
  summary: string;
  createdAt: number;
  expiresAt: number;
}

export interface AuditEntry {
  timestamp: number;
  level: "info" | "warning" | "error";
  event:
    | "session_opened"
    | "session_closed"
    | "db_session_opened"
    | "db_session_closed"
    | "db_session_interrupted"
    | "command_reviewed"
    | "command_blocked"
    | "command_started"
    | "command_completed"
    | "command_timed_out"
    | "command_failed"
    | "sql_reviewed"
    | "sql_blocked"
    | "sql_started"
    | "sql_completed"
    | "sql_timed_out"
    | "sql_interrupted"
    | "sql_failed"
    | "stdin_blocked"
    | "stdin_written"
    | "session_interrupted";
  message: string;
  sessionId?: string;
  host?: string;
  username?: string;
  command?: string;
  riskLevel?: CommandRiskLevel;
  details?: Record<string, unknown>;
}

export interface ActiveCommandState {
  command: string;
  submittedCommand: string;
  executionMode: "oneshot" | "interactive";
  sentinelId: string;
  startedAt: number;
  timeoutMs: number;
  buffer: string;
  sudoPassword?: string;
  sudoPromptAttempts: number;
  lastSudoPromptBufferLength: number;
  completed: boolean;
  completedAt?: number;
  exitCode?: number;
  output?: string;
  closedReason?: string;
  timedOutReported: boolean;
  stripAnsiOutput: boolean;
}

export interface ShellIdentity {
  loginUser: string;
  effectiveUser: string;
  privilegeMode: ShellPrivilegeMode;
  promptMarkerActive: boolean;
  source: "login" | "bootstrap" | "inferred";
  lastDetectedAt: number;
}

export interface ShellBootstrapState {
  successful: boolean;
  lastBootstrapAt?: number;
  lastBootstrapReason?: string;
  lastBootstrapError?: string;
  lastReadyMarker?: string;
  recoveryCount: number;
  adoptedShellCount: number;
}

export interface SessionOperationState {
  activeLabel?: string;
  activeSince?: number;
  queuedCount: number;
}

export interface ShellSession {
  id: string;
  client: Client;
  shell: ClientChannel;
  buffer: string;
  ready: boolean;
  host: string;
  username: string;
  createdAt: number;
  lastUsedAt: number;
  label?: string;
  serverBanner?: string;
  isSudo: boolean;
  cols: number;
  rows: number;
  closed: boolean;
  closing: boolean;
  closeReason?: string;
  manualMode: boolean;
  identity: ShellIdentity;
  bootstrap: ShellBootstrapState;
  operationState: SessionOperationState;
  operationChain?: Promise<void>;
  activeCommand?: ActiveCommandState;
  pendingApproval?: PendingApproval;
}

interface SessionManagerOptions {
  idleTimeoutMs: number;
  maxSessions: number;
  closeSession: (session: ShellSession, reason: string) => void;
  auditLogFilePath?: string | null;
}

export function createInitialShellIdentity(loginUser: string): ShellIdentity {
  return {
    loginUser,
    effectiveUser: loginUser,
    privilegeMode: "standard",
    promptMarkerActive: false,
    source: "login",
    lastDetectedAt: Date.now(),
  };
}

export function setSessionIdentity(
  session: ShellSession,
  update: Partial<Omit<ShellIdentity, "loginUser">> & { loginUser?: string },
): ShellIdentity {
  const nextIdentity: ShellIdentity = {
    ...session.identity,
    ...update,
    loginUser: update.loginUser ?? session.identity.loginUser,
    lastDetectedAt: Date.now(),
  };

  session.identity = nextIdentity;
  session.isSudo = nextIdentity.privilegeMode !== "standard";
  return nextIdentity;
}

export function recordShellBootstrap(
  session: ShellSession,
  reason: string,
  readyMarker: string,
  recovered = false,
): void {
  session.bootstrap = {
    ...session.bootstrap,
    successful: true,
    lastBootstrapAt: Date.now(),
    lastBootstrapReason: reason,
    lastBootstrapError: undefined,
    lastReadyMarker: readyMarker,
    recoveryCount: session.bootstrap.recoveryCount + (recovered ? 1 : 0),
  };
}

export function recordShellBootstrapFailure(
  session: ShellSession,
  reason: string,
  errorMessage: string,
): void {
  session.bootstrap = {
    ...session.bootstrap,
    successful: false,
    lastBootstrapReason: reason,
    lastBootstrapError: errorMessage,
  };
}

export function recordShellAdoption(session: ShellSession): void {
  session.bootstrap = {
    ...session.bootstrap,
    adoptedShellCount: session.bootstrap.adoptedShellCount + 1,
  };
}

export async function runExclusiveShellOperation<T>(
  session: ShellSession,
  label: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = session.operationChain ?? Promise.resolve();
  let release: (() => void) | undefined;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const currentTail = previous.catch(() => undefined).then(() => current);

  session.operationChain = currentTail;
  session.operationState.queuedCount += 1;

  await previous.catch(() => undefined);

  session.operationState.queuedCount = Math.max(0, session.operationState.queuedCount - 1);
  session.operationState.activeLabel = label;
  session.operationState.activeSince = Date.now();

  try {
    return await operation();
  } finally {
    session.operationState.activeLabel = undefined;
    session.operationState.activeSince = undefined;

    if (release) {
      release();
    }

    if (session.operationChain === currentTail) {
      session.operationChain = undefined;
    }
  }
}

export class SessionManager {
  private readonly sessions = new Map<string, ShellSession>();
  private readonly auditEntries: AuditEntry[] = [];
  private readonly cleanupTimer: NodeJS.Timeout;
  private static readonly MAX_AUDIT_ENTRIES = 500;

  constructor(private readonly options: SessionManagerOptions) {
    const intervalMs = Math.max(30_000, Math.min(this.options.idleTimeoutMs, 300_000));
    this.cleanupTimer = setInterval(() => {
      this.sweepIdleSessions();
    }, intervalMs);
    this.cleanupTimer.unref?.();
  }

  assertCapacity(): void {
    if (this.sessions.size >= this.options.maxSessions) {
      throw new HandledError(
        "MAX_SESSIONS_REACHED",
        `The server already has ${this.sessions.size} active SSH session(s), which matches the configured limit of ${this.options.maxSessions}.`,
      );
    }
  }

  add(session: ShellSession): void {
    this.assertCapacity();
    this.sessions.set(session.id, session);
    this.recordAudit({
      level: "info",
      event: "session_opened",
      message: `Opened SSH PTY session to ${session.username}@${session.host}.`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
    });
  }

  get(sessionId: string): ShellSession | undefined {
    return this.sessions.get(sessionId);
  }

  require(sessionId: string): ShellSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new HandledError(
        "SESSION_NOT_FOUND",
        `Session "${sessionId}" was not found. Open a new SSH session before retrying.`,
      );
    }

    return session;
  }

  list(): ShellSession[] {
    return Array.from(this.sessions.values()).sort((left, right) => left.createdAt - right.createdAt);
  }

  touch(session: ShellSession): void {
    session.lastUsedAt = Date.now();
  }

  clearBuffer(session: ShellSession, includeActiveCommand = true): void {
    session.buffer = "";
    if (includeActiveCommand && session.activeCommand) {
      session.activeCommand.buffer = "";
      session.activeCommand.lastSudoPromptBufferLength = 0;
    }
    session.lastUsedAt = Date.now();
  }

  recordAudit(entry: Omit<AuditEntry, "timestamp">): AuditEntry {
    const finalized: AuditEntry = {
      timestamp: Date.now(),
      ...entry,
    };

    this.auditEntries.push(finalized);
    if (this.auditEntries.length > SessionManager.MAX_AUDIT_ENTRIES) {
      this.auditEntries.splice(
        0,
        this.auditEntries.length - SessionManager.MAX_AUDIT_ENTRIES,
      );
    }

    const auditLogFilePath = this.options.auditLogFilePath?.trim();
    if (auditLogFilePath) {
      try {
        mkdirSync(dirname(auditLogFilePath), {
          recursive: true,
        });
        appendFileSync(auditLogFilePath, `${JSON.stringify(finalized)}\n`, "utf8");
      } catch {
        // Do not fail MCP execution if file logging is unavailable.
      }
    }

    return finalized;
  }

  listAudit(options: { sessionId?: string; limit?: number } = {}): AuditEntry[] {
    const limit = Math.max(1, options.limit ?? 50);
    const filtered = options.sessionId
      ? this.auditEntries.filter((entry) => entry.sessionId === options.sessionId)
      : this.auditEntries;

    return filtered.slice(Math.max(filtered.length - limit, 0)).reverse();
  }

  close(sessionId: string, reason: string): ShellSession {
    const session = this.require(sessionId);
    this.sessions.delete(sessionId);
    this.finalize(session, reason);
    this.options.closeSession(session, reason);
    this.recordAudit({
      level: "info",
      event: "session_closed",
      message: `Closed SSH PTY session for ${session.username}@${session.host}.`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
      details: {
        reason,
      },
    });
    return session;
  }

  unregister(sessionId: string, reason: string): ShellSession | undefined {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return undefined;
    }

    this.sessions.delete(sessionId);
    this.finalize(session, reason);
    return session;
  }

  closeAll(reason: string): void {
    for (const sessionId of Array.from(this.sessions.keys())) {
      this.close(sessionId, reason);
    }
  }

  dispose(): void {
    clearInterval(this.cleanupTimer);
  }

  private sweepIdleSessions(): void {
    const cutoff = Date.now() - this.options.idleTimeoutMs;

    for (const session of this.sessions.values()) {
      if (session.lastUsedAt < cutoff) {
        this.close(session.id, "Closed after reaching the configured idle timeout.");
      }
    }
  }

  private finalize(session: ShellSession, reason: string): void {
    session.closed = true;
    session.ready = false;
    session.closing = true;
    session.closeReason = reason;
    session.operationState.activeLabel = undefined;
    session.operationState.activeSince = undefined;
    session.operationState.queuedCount = 0;
    session.pendingApproval = undefined;
    session.identity.promptMarkerActive = false;

    if (session.activeCommand && !session.activeCommand.completed) {
      session.activeCommand.closedReason = reason;
    }
  }
}
