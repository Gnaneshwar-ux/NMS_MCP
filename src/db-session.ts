import type { Connection } from "oracledb";

import { HandledError } from "./utils.js";

export type SqlRiskLevel = "read-only" | "mutating" | "destructive";

export interface PendingSqlApproval {
  approvalId: string;
  sql: string;
  riskLevel: SqlRiskLevel;
  requiredConfirmationToken: "CONFIRM" | "EXEC";
  summary: string;
  createdAt: number;
  expiresAt: number;
}

export interface ActiveSqlExecution {
  sql: string;
  startedAt: number;
  timeoutMs: number;
  interruptRequestedAt?: number;
}

export interface OracleDbSession {
  id: string;
  connection: Connection;
  username: string;
  connectTarget: string;
  createdAt: number;
  lastUsedAt: number;
  label?: string;
  currentSchema?: string;
  dbName?: string;
  dbDomain?: string;
  serviceName?: string;
  serverVersion?: string;
  closed: boolean;
  closing: boolean;
  closeReason?: string;
  pendingApproval?: PendingSqlApproval;
  activeExecution?: ActiveSqlExecution;
}

interface DbSessionManagerOptions {
  idleTimeoutMs: number;
  maxSessions: number;
  closeSession: (session: OracleDbSession, reason: string) => Promise<void> | void;
}

export class DbSessionManager {
  private readonly sessions = new Map<string, OracleDbSession>();
  private readonly cleanupTimer: NodeJS.Timeout;

  constructor(private readonly options: DbSessionManagerOptions) {
    const intervalMs = Math.max(30_000, Math.min(this.options.idleTimeoutMs, 300_000));
    this.cleanupTimer = setInterval(() => {
      void this.sweepIdleSessions();
    }, intervalMs);
    this.cleanupTimer.unref?.();
  }

  assertCapacity(): void {
    if (this.sessions.size >= this.options.maxSessions) {
      throw new HandledError(
        "MAX_DB_SESSIONS_REACHED",
        `The server already has ${this.sessions.size} active Oracle DB session(s), which matches the configured limit of ${this.options.maxSessions}.`,
      );
    }
  }

  add(session: OracleDbSession): void {
    this.assertCapacity();
    this.sessions.set(session.id, session);
  }

  get(sessionId: string): OracleDbSession | undefined {
    return this.sessions.get(sessionId);
  }

  require(sessionId: string): OracleDbSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new HandledError(
        "DB_SESSION_NOT_FOUND",
        `Database session "${sessionId}" was not found. Open a new Oracle DB session before retrying.`,
      );
    }

    return session;
  }

  list(): OracleDbSession[] {
    return Array.from(this.sessions.values()).sort((left, right) => left.createdAt - right.createdAt);
  }

  touch(session: OracleDbSession): void {
    session.lastUsedAt = Date.now();
  }

  async close(sessionId: string, reason: string): Promise<OracleDbSession> {
    const session = this.require(sessionId);
    this.sessions.delete(sessionId);
    this.finalize(session, reason);
    await this.options.closeSession(session, reason);
    return session;
  }

  unregister(sessionId: string, reason: string): OracleDbSession | undefined {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return undefined;
    }

    this.sessions.delete(sessionId);
    this.finalize(session, reason);
    return session;
  }

  async closeAll(reason: string): Promise<void> {
    for (const sessionId of Array.from(this.sessions.keys())) {
      await this.close(sessionId, reason);
    }
  }

  dispose(): void {
    clearInterval(this.cleanupTimer);
  }

  private async sweepIdleSessions(): Promise<void> {
    const cutoff = Date.now() - this.options.idleTimeoutMs;

    for (const session of this.sessions.values()) {
      if (session.lastUsedAt < cutoff) {
        await this.close(session.id, "Closed after reaching the configured DB idle timeout.");
      }
    }
  }

  private finalize(session: OracleDbSession, reason: string): void {
    session.closed = true;
    session.closing = true;
    session.closeReason = reason;
    session.pendingApproval = undefined;
    session.activeExecution = undefined;
  }
}
