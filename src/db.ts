import { randomUUID } from "node:crypto";

import oracledb from "oracledb";

import type { DbSessionManager, OracleDbSession } from "./db-session.js";
import { getErrorMessage, HandledError } from "./utils.js";

const DEFAULT_DB_STMT_CACHE_SIZE = 30;

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
oracledb.fetchAsString = Array.from(
  new Set([...(oracledb.fetchAsString ?? []), oracledb.CLOB, oracledb.NCLOB]),
);

export interface OracleConnectOptions {
  username: string;
  password: string;
  connectString?: string;
  host?: string;
  port: number;
  serviceName?: string;
  sid?: string;
  sessionLabel?: string;
  connectTimeoutMs: number;
  configDir?: string;
  walletLocation?: string;
  walletPassword?: string;
  httpsProxy?: string;
  httpsProxyPort?: number;
}

export interface ExecuteSqlOptions {
  sql: string;
  binds?: Record<string, unknown> | unknown[];
  timeoutMs: number;
  maxRows: number;
}

export interface ExecuteSqlResult {
  rows: Array<Record<string, unknown>>;
  rowCount: number;
  rowsAffected: number | null;
  metaData: Array<Record<string, unknown>>;
  executionMs: number;
  timedOut: boolean;
  transactionInProgress: boolean;
  warning?: string;
}

function trimOptional(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function normalizeJdbcConnectString(connectString: string): string {
  return connectString
    .trim()
    .replace(/^jdbc:oracle:thin:@/i, "")
    .replace(/^@/, "");
}

function buildSidDescriptor(host: string, port: number, sid: string): string {
  return `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${host})(PORT=${port}))(CONNECT_DATA=(SID=${sid})))`;
}

function resolveConnectString(options: OracleConnectOptions): string {
  const directConnectString = trimOptional(options.connectString);
  if (directConnectString) {
    return normalizeJdbcConnectString(directConnectString);
  }

  const host = trimOptional(options.host);
  if (!host) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      "Provide connectString, or provide host plus either serviceName or sid.",
    );
  }

  const serviceName = trimOptional(options.serviceName);
  const sid = trimOptional(options.sid);
  if (serviceName && sid) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      "Provide either serviceName or sid, not both.",
    );
  }

  if (serviceName) {
    return `${host}:${options.port}/${serviceName}`;
  }

  if (sid) {
    return buildSidDescriptor(host, options.port, sid);
  }

  throw new HandledError(
    "INVALID_ARGUMENT",
    "Provide connectString, or provide host plus either serviceName or sid.",
  );
}

function toConnectTarget(options: OracleConnectOptions, resolvedConnectString: string): string {
  if (trimOptional(options.connectString)) {
    return normalizeJdbcConnectString(trimOptional(options.connectString) ?? resolvedConnectString);
  }

  const host = trimOptional(options.host) ?? "unknown-host";
  const serviceName = trimOptional(options.serviceName);
  if (serviceName) {
    return `${host}:${options.port}/${serviceName}`;
  }

  const sid = trimOptional(options.sid) ?? "unknown-sid";
  return `${host}:${options.port}:${sid}`;
}

function toTransportConnectTimeoutSeconds(connectTimeoutMs: number): number {
  return Math.max(1, Math.ceil(connectTimeoutMs / 1000));
}

function isOracleAuthError(message: string): boolean {
  return /ORA-01017|ORA-01005|ORA-28000|ORA-28001|ORA-28040|NJS-116/i.test(message);
}

function isOracleConnectTimeout(message: string): boolean {
  return /timeout|timed out|NJS-040|ETIMEDOUT/i.test(message);
}

function isOracleExecutionTimeout(message: string): boolean {
  return /call timeout|ORA-01013|DPI-1067|DPI-1080|NJS-040|timeout/i.test(message);
}

export function isOracleConnectionUnusable(message: string): boolean {
  return /DPI-1080/i.test(message);
}

function normalizeSessionSnapshot(session: OracleDbSession): void {
  session.currentSchema = session.connection.currentSchema || undefined;
  session.dbName = session.connection.dbName || undefined;
  session.dbDomain = session.connection.dbDomain || undefined;
  session.serviceName = session.connection.serviceName || undefined;
  session.serverVersion = session.connection.oracleServerVersionString || undefined;
}

function normalizeDbValue(value: unknown): unknown {
  if (
    value == null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "bigint") {
    return value.toString();
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Buffer.isBuffer(value)) {
    return {
      type: "buffer",
      encoding: "base64",
      data: value.toString("base64"),
    };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalizeDbValue(entry));
  }

  if (typeof value === "object") {
    const constructorName = (value as { constructor?: { name?: string } }).constructor?.name ?? "";
    if (constructorName.toLowerCase() === "lob") {
      return "[LOB]";
    }

    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        key,
        normalizeDbValue(entry),
      ]),
    );
  }

  return String(value);
}

function normalizeRows(rows: unknown[] | undefined): Array<Record<string, unknown>> {
  if (!Array.isArray(rows)) {
    return [];
  }

  return rows.map((row) => {
    const normalized = normalizeDbValue(row);
    if (normalized && typeof normalized === "object" && !Array.isArray(normalized)) {
      return normalized as Record<string, unknown>;
    }

    return {
      value: normalized,
    };
  });
}

function normalizeMetaData(
  metaData: unknown[] | undefined,
): Array<Record<string, unknown>> {
  if (!Array.isArray(metaData)) {
    return [];
  }

  return metaData.map((entry) => {
    const normalized = normalizeDbValue(entry);
    return normalized && typeof normalized === "object" && !Array.isArray(normalized)
      ? (normalized as Record<string, unknown>)
      : { value: normalized };
  });
}

async function safeCloseConnection(connection: { close: () => Promise<void> | void }): Promise<void> {
  try {
    await connection.close();
  } catch {
    // Ignore close failures during cleanup paths.
  }
}

export async function connectOracleSession(
  options: OracleConnectOptions,
  dbSessionManager: DbSessionManager,
): Promise<OracleDbSession> {
  dbSessionManager.assertCapacity();
  const resolvedConnectString = resolveConnectString(options);

  try {
    const connection = await oracledb.getConnection({
      user: options.username,
      password: options.password,
      connectString: resolvedConnectString,
      transportConnectTimeout: toTransportConnectTimeoutSeconds(options.connectTimeoutMs),
      stmtCacheSize: DEFAULT_DB_STMT_CACHE_SIZE,
      ...(options.configDir ? { configDir: options.configDir } : {}),
      ...(options.walletLocation ? { walletLocation: options.walletLocation } : {}),
      ...(options.walletPassword ? { walletPassword: options.walletPassword } : {}),
      ...(options.httpsProxy ? { httpsProxy: options.httpsProxy } : {}),
      ...(options.httpsProxyPort ? { httpsProxyPort: options.httpsProxyPort } : {}),
    });

    try {
      connection.module = "ssh-mcp-server";
      connection.action = "oracle_connect";
    } catch {
      // Older drivers or restricted accounts may reject these metadata writes.
    }

    const now = Date.now();
    const session: OracleDbSession = {
      id: randomUUID(),
      connection,
      username: options.username,
      connectTarget: toConnectTarget(options, resolvedConnectString),
      createdAt: now,
      lastUsedAt: now,
      label: options.sessionLabel,
      closed: false,
      closing: false,
    };

    normalizeSessionSnapshot(session);
    dbSessionManager.add(session);
    return session;
  } catch (error) {
    const message = getErrorMessage(error);
    if (isOracleAuthError(message)) {
      throw new HandledError(
        "AUTH_FAILED",
        "Oracle DB authentication failed. Verify the username, password, and account status.",
      );
    }

    if (isOracleConnectTimeout(message)) {
      throw new HandledError(
        "DB_CONNECT_TIMEOUT",
        `Oracle DB connection timed out after ${options.connectTimeoutMs}ms.`,
      );
    }

    throw new HandledError(
      "DB_CONNECT_FAILED",
      `Unable to open the Oracle DB connection: ${message}`,
    );
  }
}

export async function closeOracleSession(
  session: OracleDbSession,
  _reason: string,
): Promise<void> {
  await safeCloseConnection(session.connection);
}

export async function executeSql(
  session: OracleDbSession,
  options: ExecuteSqlOptions,
): Promise<ExecuteSqlResult> {
  if (session.activeExecution) {
    throw new HandledError(
      "DB_SESSION_BUSY",
      "This Oracle DB session is already running a query. Wait for it to finish or close the session before retrying.",
    );
  }

  session.activeExecution = {
    sql: options.sql,
    startedAt: Date.now(),
    timeoutMs: options.timeoutMs,
  };
  session.lastUsedAt = Date.now();

  const previousTimeout = session.connection.callTimeout;
  session.connection.callTimeout = Math.max(1, options.timeoutMs);

  try {
    const result = await session.connection.execute(
      options.sql,
      options.binds,
      {
        outFormat: oracledb.OUT_FORMAT_OBJECT,
        autoCommit: false,
        maxRows: options.maxRows,
        fetchArraySize: Math.min(options.maxRows, 200),
        prefetchRows: Math.min(options.maxRows, 200),
      },
    );

    normalizeSessionSnapshot(session);
    return {
      rows: normalizeRows(result.rows),
      rowCount: Array.isArray(result.rows) ? result.rows.length : 0,
      rowsAffected:
        typeof result.rowsAffected === "number" ? result.rowsAffected : null,
      metaData: normalizeMetaData(result.metaData),
      executionMs: Date.now() - session.activeExecution.startedAt,
      timedOut: false,
      transactionInProgress: Boolean(session.connection.transactionInProgress),
      ...(result.warning ? { warning: getErrorMessage(result.warning) } : {}),
    };
  } catch (error) {
    normalizeSessionSnapshot(session);
    const message = getErrorMessage(error);
    const executionMs = Date.now() - session.activeExecution.startedAt;

    if (isOracleExecutionTimeout(message)) {
      throw new HandledError(
        "TIMEOUT",
        `SQL execution timed out after ${options.timeoutMs}ms.`,
        {
          executionMs,
          sessionReusable: !isOracleConnectionUnusable(message),
          driverMessage: message,
        },
      );
    }

    throw new HandledError(
      "DB_QUERY_FAILED",
      `Oracle DB query failed: ${message}`,
      {
        executionMs,
      },
    );
  } finally {
    session.connection.callTimeout = previousTimeout;
    session.activeExecution = undefined;
    session.lastUsedAt = Date.now();
  }
}

export async function closeBrokenOracleSession(
  session: OracleDbSession,
  dbSessionManager: DbSessionManager,
  reason: string,
): Promise<void> {
  const detached = dbSessionManager.unregister(session.id, reason);
  if (detached) {
    await closeOracleSession(detached, reason);
  }
}
