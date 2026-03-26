#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import {
  closeBrokenOracleSession,
  closeOracleSession,
  connectOracleSession,
  executeSql,
} from "./db.js";
import {
  DbSessionManager,
  type OracleDbSession,
  type PendingSqlApproval,
} from "./db-session.js";
import { executeCommand, interruptSession } from "./executor.js";
import {
  loadCommandPolicyConfig,
  loadSqlPolicyConfig,
  summarizeCombinedPolicyConfig,
} from "./policy-config.js";
import { reviewCommandPolicy } from "./policy.js";
import {
  SessionManager,
  type PendingApproval,
  type ShellSession,
} from "./session.js";
import { closeShellSession, connectShellSession, type AuthMethod } from "./ssh.js";
import { reviewSqlPolicy } from "./sql-policy.js";
import {
  cleanShellOutput,
  decodeInputEscapes,
  DEFAULT_TERMINAL_COLS,
  DEFAULT_TERMINAL_ROWS,
  getErrorMessage,
  HandledError,
  isRecord,
  parsePositiveInt,
} from "./utils.js";

const SERVER_NAME = "ssh-mcp-server";
const SERVER_VERSION = "1.0.0";
const DEFAULT_IDLE_TIMEOUT_MS = parsePositiveInt(process.env.MCP_SSH_IDLE_TIMEOUT_MS, 1_800_000);
const DEFAULT_COMMAND_TIMEOUT_MS = parsePositiveInt(
  process.env.MCP_SSH_DEFAULT_TIMEOUT_MS,
  30_000,
);
const DEFAULT_DB_IDLE_TIMEOUT_MS = parsePositiveInt(process.env.MCP_DB_IDLE_TIMEOUT_MS, 1_800_000);
const DEFAULT_DB_TIMEOUT_MS = parsePositiveInt(process.env.MCP_DB_DEFAULT_TIMEOUT_MS, 30_000);
const DEFAULT_APPROVAL_TTL_MS = parsePositiveInt(
  process.env.MCP_SSH_APPROVAL_TTL_MS,
  600_000,
);
const DEFAULT_MAX_SESSIONS = parsePositiveInt(process.env.MCP_SSH_MAX_SESSIONS, 10);
const DEFAULT_MAX_DB_SESSIONS = parsePositiveInt(process.env.MCP_DB_MAX_SESSIONS, 5);
const DEFAULT_DB_MAX_ROWS = parsePositiveInt(process.env.MCP_DB_MAX_ROWS, 200);
const DEFAULT_AUDIT_LOG_FILE =
  process.env.MCP_AUDIT_LOG_FILE?.trim() ||
  fileURLToPath(new URL("../mcp-audit.ndjson", import.meta.url));
const DEFAULT_TRANSPORT = (process.env.MCP_TRANSPORT ?? "stdio").toLowerCase();
const DEFAULT_SSE_PORT = parsePositiveInt(process.env.MCP_SSE_PORT, 3000);
const commandPolicyConfig = loadCommandPolicyConfig();
const sqlPolicyConfig = loadSqlPolicyConfig();

const TOOL_DEFINITIONS = [
  {
    name: "ssh_connect",
    description: "Establishes SSH connection and opens a PTY shell session.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["host", "username", "authMethod"],
      properties: {
        host: { type: "string" },
        port: { type: "integer", default: 22 },
        username: { type: "string" },
        authMethod: {
          type: "string",
          enum: ["password", "privateKey", "agent"],
        },
        password: { type: "string" },
        privateKey: { type: "string" },
        passphrase: { type: "string" },
        sessionLabel: { type: "string" },
        connectTimeout: { type: "integer", default: 10000 },
      },
    },
  },
  {
    name: "execute_command",
    description:
      "Executes a shell command in an existing PTY session. Only an explicit safe read-only list auto-runs. Any other command requires user confirmation first unless a deny rule or blocked category forbids it.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId", "command"],
      properties: {
        sessionId: { type: "string" },
        command: { type: "string" },
        timeout: { type: "integer", default: DEFAULT_COMMAND_TIMEOUT_MS },
        sudoPassword: { type: "string" },
        stripAnsi: { type: "boolean", default: true },
        approvalId: { type: "string" },
        userConfirmation: { type: "string" },
      },
    },
  },
  {
    name: "review_command",
    description:
      "Reviews a command before execution and returns whether MCP can auto-run it, must ask the user first, or is blocked by explicit policy.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["command"],
      properties: {
        sessionId: { type: "string" },
        command: { type: "string" },
      },
    },
  },
  {
    name: "write_stdin",
    description:
      "Writes raw input into the PTY session. This is restricted to already-interactive sessions and recovery signals so it cannot bypass command safety policy at a normal shell prompt.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId", "input"],
      properties: {
        sessionId: { type: "string" },
        input: { type: "string" },
      },
    },
  },
  {
    name: "read_output",
    description: "Reads the current PTY output buffer.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
        clear: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "resize_terminal",
    description: "Resizes the PTY window for an existing session.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
        cols: { type: "integer", default: DEFAULT_TERMINAL_COLS },
        rows: { type: "integer", default: DEFAULT_TERMINAL_ROWS },
      },
    },
  },
  {
    name: "list_sessions",
    description: "Lists all active SSH PTY sessions.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
  {
    name: "oracle_connect",
    description:
      "Establishes a cached Oracle DB session for NMS diagnostics and query execution. Provide connectString, or provide host plus either serviceName or sid.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["username", "password"],
      properties: {
        username: { type: "string" },
        password: { type: "string" },
        connectString: { type: "string" },
        host: { type: "string" },
        port: { type: "integer", default: 1521 },
        serviceName: { type: "string" },
        sid: { type: "string" },
        sessionLabel: { type: "string" },
        connectTimeout: { type: "integer", default: 15000 },
        configDir: { type: "string" },
        walletLocation: { type: "string" },
        walletPassword: { type: "string" },
        httpsProxy: { type: "string" },
        httpsProxyPort: { type: "integer" },
      },
    },
  },
  {
    name: "execute_sql",
    description:
      "Executes SQL in an existing cached Oracle DB session. Only explicit safe SELECT queries auto-run. Any other SQL requires user confirmation first unless a deny rule or blocked category forbids it.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["dbSessionId", "sql"],
      properties: {
        dbSessionId: { type: "string" },
        sql: { type: "string" },
        binds: {
          oneOf: [{ type: "object" }, { type: "array" }],
        },
        maxRows: { type: "integer", default: DEFAULT_DB_MAX_ROWS },
        timeout: { type: "integer", default: DEFAULT_DB_TIMEOUT_MS },
        approvalId: { type: "string" },
        userConfirmation: { type: "string" },
      },
    },
  },
  {
    name: "review_sql",
    description:
      "Reviews SQL before execution and returns whether MCP can auto-run it, must ask the user first, or is blocked by explicit policy.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sql"],
      properties: {
        dbSessionId: { type: "string" },
        sql: { type: "string" },
      },
    },
  },
  {
    name: "list_db_sessions",
    description: "Lists all active cached Oracle DB sessions.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
  {
    name: "read_policy",
    description:
      "Returns the active shell-command and SQL safety policies, including blocked categories, approval categories, and any configured allowlist or denylist rules.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
  {
    name: "read_audit_log",
    description:
      "Returns recent audit entries showing SSH and Oracle DB reviews, approvals, blocks, execution starts, completions, timeouts, and interrupts.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        sessionId: { type: "string" },
        limit: { type: "integer", default: 50 },
      },
    },
  },
  {
    name: "close_session",
    description: "Closes a PTY shell session and its SSH connection.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
      },
    },
  },
  {
    name: "close_db_session",
    description: "Closes a cached Oracle DB session.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["dbSessionId"],
      properties: {
        dbSessionId: { type: "string" },
      },
    },
  },
  {
    name: "interrupt_session",
    description:
      "Attempts to recover a stuck PTY shell by sending Ctrl+C, Ctrl+D, or a newline and optionally waiting for the prompt to return.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
        signal: {
          type: "string",
          enum: ["ctrlC", "ctrlD", "newline"],
          default: "ctrlC",
        },
        waitForReadyMs: { type: "integer", default: 5000 },
        clearBuffer: { type: "boolean", default: false },
      },
    },
  },
];

const sessionManager = new SessionManager({
  idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
  maxSessions: DEFAULT_MAX_SESSIONS,
  closeSession: closeShellSession,
  auditLogFilePath: DEFAULT_AUDIT_LOG_FILE,
});

const dbSessionManager = new DbSessionManager({
  idleTimeoutMs: DEFAULT_DB_IDLE_TIMEOUT_MS,
  maxSessions: DEFAULT_MAX_DB_SESSIONS,
  closeSession: closeOracleSession,
});

function createToolResult(structuredContent: Record<string, unknown>, isError = false) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(structuredContent, null, 2),
      },
    ],
    structuredContent,
    isError,
  };
}

function normalizeToolError(error: unknown): Record<string, unknown> {
  if (error instanceof HandledError) {
    return {
      error: error.code,
      message: error.message,
      ...error.details,
    };
  }

  return {
    error: "INTERNAL_ERROR",
    message: getErrorMessage(error),
  };
}

async function safeToolCall(
  action: () => Promise<Record<string, unknown>>,
) {
  try {
    const result = await action();
    return createToolResult(result, Boolean(result.error));
  } catch (error) {
    return createToolResult(normalizeToolError(error), true);
  }
}

function readString(
  args: Record<string, unknown>,
  fieldName: string,
  required = false,
): string | undefined {
  const value = args[fieldName];
  if (value == null || value === "") {
    if (required) {
      throw new HandledError(
        "INVALID_ARGUMENT",
        `${fieldName} is required and must be a non-empty string.`,
      );
    }

    return undefined;
  }

  if (typeof value !== "string") {
    throw new HandledError("INVALID_ARGUMENT", `${fieldName} must be a string.`);
  }

  return value;
}

function readBoolean(
  args: Record<string, unknown>,
  fieldName: string,
  fallback: boolean,
): boolean {
  const value = args[fieldName];
  if (value == null) {
    return fallback;
  }

  if (typeof value !== "boolean") {
    throw new HandledError("INVALID_ARGUMENT", `${fieldName} must be a boolean.`);
  }

  return value;
}

function readPositiveInteger(
  args: Record<string, unknown>,
  fieldName: string,
  fallback: number,
): number {
  const value = args[fieldName];
  if (value == null) {
    return fallback;
  }

  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      `${fieldName} must be a positive integer.`,
    );
  }

  return value;
}

function readBinds(
  args: Record<string, unknown>,
  fieldName: string,
): Record<string, unknown> | unknown[] | undefined {
  const value = args[fieldName];
  if (value == null) {
    return undefined;
  }

  if (isRecord(value) || Array.isArray(value)) {
    return value as Record<string, unknown> | unknown[];
  }

  throw new HandledError(
    "INVALID_ARGUMENT",
    `${fieldName} must be an object or array when provided.`,
  );
}

function readAuthMethod(args: Record<string, unknown>): AuthMethod {
  const authMethod = readString(args, "authMethod", true);
  if (
    authMethod !== "password" &&
    authMethod !== "privateKey" &&
    authMethod !== "agent"
  ) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      'authMethod must be one of "password", "privateKey", or "agent".',
    );
  }

  return authMethod;
}

function sanitizePreview(value: string, maxLength = 140): string {
  const normalized = value
    .replace(/\x03/g, "\\x03")
    .replace(/\x04/g, "\\x04")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .trim();

  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, maxLength - 3)}...`;
}

function createApprovalId(): string {
  return randomUUID().split("-")[0]?.toUpperCase() ?? "APPROVAL";
}

function toPendingApprovalSummary(pendingApproval?: PendingApproval): Record<string, unknown> | null {
  if (!pendingApproval) {
    return null;
  }

  return {
    approvalId: pendingApproval.approvalId,
    riskLevel: pendingApproval.riskLevel,
    requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
    createdAt: pendingApproval.createdAt,
    expiresAt: pendingApproval.expiresAt,
    summary: pendingApproval.summary,
    commandPreview: sanitizePreview(pendingApproval.command, 100),
  };
}

function createOrReusePendingApproval(
  session: ShellSession,
  command: string,
  riskLevel: PendingApproval["riskLevel"],
  requiredConfirmationToken: PendingApproval["requiredConfirmationToken"],
  summary: string,
): PendingApproval {
  const now = Date.now();
  const existing = session.pendingApproval;
  if (
    existing &&
    existing.command === command &&
    existing.riskLevel === riskLevel &&
    existing.requiredConfirmationToken === requiredConfirmationToken &&
    existing.expiresAt > now
  ) {
    return existing;
  }

  const pendingApproval: PendingApproval = {
    approvalId: createApprovalId(),
    command,
    riskLevel,
    requiredConfirmationToken,
    summary,
    createdAt: now,
    expiresAt: now + DEFAULT_APPROVAL_TTL_MS,
  };

  session.pendingApproval = pendingApproval;
  return pendingApproval;
}

function ensureCommandApproval(
  session: ShellSession,
  command: string,
  approvalId: string | undefined,
  userConfirmation: string | undefined,
): {
  riskLevel: "read-only" | "mutating" | "destructive";
  category: string;
  safeForAutoRun: boolean;
} {
  const review = reviewCommandPolicy(command, session, commandPolicyConfig);

  sessionManager.recordAudit({
    level: review.decision === "blocked" || review.requiresConfirmation ? "warning" : "info",
    event: "command_reviewed",
    message: `Reviewed ${review.riskLevel} command with policy decision "${review.decision}".`,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    command,
    riskLevel: review.riskLevel,
    details: {
      category: review.category,
      summary: review.summary,
      decision: review.decision,
      decisionReason: review.decisionReason,
      matchedRule: review.matchedRule ?? null,
      reasons: review.reasons,
      safeForAutoRun: review.safeForAutoRun,
    },
  });

  if (review.decision === "blocked") {
    session.pendingApproval = undefined;

    sessionManager.recordAudit({
      level: "warning",
      event: "command_blocked",
      message: "Blocked command by safety policy.",
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command,
      riskLevel: review.riskLevel,
      details: {
        category: review.category,
        summary: review.summary,
        decisionReason: review.decisionReason,
        matchedRule: review.matchedRule ?? null,
        reasons: review.reasons,
      },
    });

    throw new HandledError(
      "POLICY_BLOCKED",
      "The active MCP policy blocked this command from running.",
      {
        commandReview: review,
        instructions:
          "Use read_policy or review_command to inspect the policy, then change the policy only if you intentionally want MCP to keep refusing or specially handle this command class.",
      },
    );
  }

  if (!review.requiresConfirmation || !review.requiredConfirmationToken) {
    if (session.pendingApproval?.command === command) {
      session.pendingApproval = undefined;
    }

    return {
      riskLevel: review.riskLevel,
      category: review.category,
      safeForAutoRun: review.safeForAutoRun,
    };
  }

  const pendingApproval = createOrReusePendingApproval(
    session,
    command,
    review.riskLevel,
    review.requiredConfirmationToken,
    review.summary,
  );

  const confirmationAccepted =
    approvalId === pendingApproval.approvalId &&
    userConfirmation === pendingApproval.requiredConfirmationToken &&
    pendingApproval.expiresAt > Date.now();

  if (confirmationAccepted) {
    session.pendingApproval = undefined;
    return {
      riskLevel: review.riskLevel,
      category: review.category,
      safeForAutoRun: review.safeForAutoRun,
    };
  }

  const errorCode = "CONFIRMATION_REQUIRED";
  const message =
    "User confirmation is required before MCP runs this command because it is outside the explicit safe auto-run list.";

  sessionManager.recordAudit({
    level: "warning",
    event: "command_blocked",
    message,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    command,
    riskLevel: review.riskLevel,
    details: {
      approvalId: pendingApproval.approvalId,
      requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
      expiresAt: pendingApproval.expiresAt,
      providedApprovalId: approvalId ?? null,
      providedConfirmation: userConfirmation ?? null,
      category: review.category,
      summary: review.summary,
      reasons: review.reasons,
    },
  });

  throw new HandledError(errorCode, message, {
    approvalId: pendingApproval.approvalId,
    requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
    expiresAt: pendingApproval.expiresAt,
    commandReview: review,
    confirmationPrompt: `Command: ${command}\nConsequence: ${review.summary}\nReply with exact CONFIRM before MCP runs it.`,
    instructions:
      `Show the exact command and the consequence summary to the user. Only retry execute_command after the user replies with CONFIRM, using approvalId "${pendingApproval.approvalId}" and userConfirmation "CONFIRM".`,
  });
}

function toSessionSummary(session: ShellSession): Record<string, unknown> {
  return {
    sessionId: session.id,
    host: session.host,
    username: session.username,
    label: session.label ?? null,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    isSudo: session.isSudo,
    ready: session.ready,
    pendingApproval: toPendingApprovalSummary(session.pendingApproval),
  };
}

function toPendingSqlApprovalSummary(
  pendingApproval?: PendingSqlApproval,
): Record<string, unknown> | null {
  if (!pendingApproval) {
    return null;
  }

  return {
    approvalId: pendingApproval.approvalId,
    riskLevel: pendingApproval.riskLevel,
    requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
    createdAt: pendingApproval.createdAt,
    expiresAt: pendingApproval.expiresAt,
    summary: pendingApproval.summary,
    sqlPreview: sanitizePreview(pendingApproval.sql, 100),
  };
}

function createOrReusePendingSqlApproval(
  session: OracleDbSession,
  sql: string,
  riskLevel: PendingSqlApproval["riskLevel"],
  requiredConfirmationToken: PendingSqlApproval["requiredConfirmationToken"],
  summary: string,
): PendingSqlApproval {
  const now = Date.now();
  const existing = session.pendingApproval;
  if (
    existing &&
    existing.sql === sql &&
    existing.riskLevel === riskLevel &&
    existing.requiredConfirmationToken === requiredConfirmationToken &&
    existing.expiresAt > now
  ) {
    return existing;
  }

  const pendingApproval: PendingSqlApproval = {
    approvalId: createApprovalId(),
    sql,
    riskLevel,
    requiredConfirmationToken,
    summary,
    createdAt: now,
    expiresAt: now + DEFAULT_APPROVAL_TTL_MS,
  };

  session.pendingApproval = pendingApproval;
  return pendingApproval;
}

function ensureSqlApproval(
  session: OracleDbSession,
  sql: string,
  approvalId: string | undefined,
  userConfirmation: string | undefined,
): {
  riskLevel: "read-only" | "mutating" | "destructive";
  category: string;
  safeForAutoRun: boolean;
  executableSql: string;
} {
  const review = reviewSqlPolicy(sql, session, sqlPolicyConfig);

  sessionManager.recordAudit({
    level: review.decision === "blocked" || review.requiresConfirmation ? "warning" : "info",
    event: "sql_reviewed",
    message: `Reviewed ${review.riskLevel} SQL with policy decision "${review.decision}".`,
    sessionId: session.id,
    host: session.connectTarget,
    username: session.username,
    command: review.normalizedSql,
    riskLevel: review.riskLevel,
    details: {
      category: review.category,
      summary: review.summary,
      decision: review.decision,
      decisionReason: review.decisionReason,
      matchedRule: review.matchedRule ?? null,
      reasons: review.reasons,
      safeForAutoRun: review.safeForAutoRun,
      sql: review.normalizedSql,
    },
  });

  if (review.decision === "blocked") {
    session.pendingApproval = undefined;

    sessionManager.recordAudit({
      level: "warning",
      event: "sql_blocked",
      message: "Blocked SQL statement by safety policy.",
      sessionId: session.id,
      host: session.connectTarget,
      username: session.username,
      command: review.normalizedSql,
      riskLevel: review.riskLevel,
      details: {
        category: review.category,
        summary: review.summary,
        decisionReason: review.decisionReason,
        matchedRule: review.matchedRule ?? null,
        reasons: review.reasons,
      },
    });

    throw new HandledError(
      "POLICY_BLOCKED",
      "The active MCP policy blocked this SQL from running.",
      {
        sqlReview: review,
        instructions:
          "Use read_policy or review_sql to inspect the SQL policy, then change the policy only if you intentionally want MCP to keep refusing or specially handle this SQL class.",
      },
    );
  }

  if (!review.requiresConfirmation || !review.requiredConfirmationToken) {
    if (session.pendingApproval?.sql === sql) {
      session.pendingApproval = undefined;
    }

    return {
      riskLevel: review.riskLevel,
      category: review.category,
      safeForAutoRun: review.safeForAutoRun,
      executableSql: review.executableSql,
    };
  }

  const pendingApproval = createOrReusePendingSqlApproval(
    session,
    sql,
    review.riskLevel,
    review.requiredConfirmationToken,
    review.summary,
  );

  const confirmationAccepted =
    approvalId === pendingApproval.approvalId &&
    userConfirmation === pendingApproval.requiredConfirmationToken &&
    pendingApproval.expiresAt > Date.now();

  if (confirmationAccepted) {
    session.pendingApproval = undefined;
    return {
      riskLevel: review.riskLevel,
      category: review.category,
      safeForAutoRun: review.safeForAutoRun,
      executableSql: review.executableSql,
    };
  }

  const errorCode = "CONFIRMATION_REQUIRED";
  const message =
    "User confirmation is required before MCP runs this SQL because it is outside the explicit safe auto-run SQL list.";

  sessionManager.recordAudit({
    level: "warning",
    event: "sql_blocked",
    message,
    sessionId: session.id,
    host: session.connectTarget,
    username: session.username,
    command: review.normalizedSql,
    riskLevel: review.riskLevel,
    details: {
      approvalId: pendingApproval.approvalId,
      requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
      expiresAt: pendingApproval.expiresAt,
      providedApprovalId: approvalId ?? null,
      providedConfirmation: userConfirmation ?? null,
      category: review.category,
      summary: review.summary,
      reasons: review.reasons,
    },
  });

  throw new HandledError(errorCode, message, {
    approvalId: pendingApproval.approvalId,
    requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
    expiresAt: pendingApproval.expiresAt,
    sqlReview: review,
    confirmationPrompt: `SQL: ${review.normalizedSql}\nConsequence: ${review.summary}\nReply with exact CONFIRM before MCP runs it.`,
    instructions:
      `Show the exact SQL and the consequence summary to the user. Only retry execute_sql after the user replies with CONFIRM, using approvalId "${pendingApproval.approvalId}" and userConfirmation "CONFIRM".`,
  });
}

function toDbSessionSummary(session: OracleDbSession): Record<string, unknown> {
  return {
    dbSessionId: session.id,
    username: session.username,
    target: session.connectTarget,
    label: session.label ?? null,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    currentSchema: session.currentSchema ?? null,
    dbName: session.dbName ?? null,
    dbDomain: session.dbDomain ?? null,
    serviceName: session.serviceName ?? null,
    serverVersion: session.serverVersion ?? null,
    busy: Boolean(session.activeExecution),
    transactionInProgress: Boolean(session.connection.transactionInProgress),
    pendingApproval: toPendingSqlApprovalSummary(session.pendingApproval),
  };
}

async function callSshConnect(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const host = readString(args, "host", true) ?? "";
  const port = readPositiveInteger(args, "port", 22);
  const username = readString(args, "username", true) ?? "";
  const authMethod = readAuthMethod(args);
  const password = readString(args, "password");
  const privateKey = readString(args, "privateKey");
  const passphrase = readString(args, "passphrase");
  const sessionLabel = readString(args, "sessionLabel");
  const connectTimeout = readPositiveInteger(args, "connectTimeout", 10_000);

  const session = await connectShellSession({
    host,
    port,
    username,
    authMethod,
    password,
    privateKey,
    passphrase,
    sessionLabel,
    connectTimeout,
    sessionManager,
  });

  return {
    sessionId: session.id,
    host: session.host,
    username: session.username,
    connected: true,
    ...(session.serverBanner ? { serverBanner: session.serverBanner } : {}),
  };
}

async function callExecuteCommand(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const command = readString(args, "command", true) ?? "";
  const timeoutMs = readPositiveInteger(args, "timeout", DEFAULT_COMMAND_TIMEOUT_MS);
  const sudoPassword = readString(args, "sudoPassword");
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const approvalId = readString(args, "approvalId");
  const userConfirmation = readString(args, "userConfirmation");
  const session = sessionManager.require(sessionId);
  const policy = ensureCommandApproval(session, command, approvalId, userConfirmation);

  sessionManager.recordAudit({
    level: "info",
    event: "command_started",
    message: `Started ${policy.riskLevel} command execution.`,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    command,
    riskLevel: policy.riskLevel,
    details: {
      category: policy.category,
      timeoutMs,
      confirmationUsed: Boolean(userConfirmation),
    },
  });

  try {
    const result = await executeCommand(session, command, {
      timeoutMs,
      sudoPassword,
      stripAnsiOutput: stripAnsi,
    });

    sessionManager.recordAudit({
      level: "info",
      event: "command_completed",
      message: `Completed command with exit code ${result.exitCode}.`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command,
      riskLevel: policy.riskLevel,
      details: {
        category: policy.category,
        exitCode: result.exitCode,
        executionMs: result.executionMs,
      },
    });

    return {
      ...result,
      policy: {
        riskLevel: policy.riskLevel,
        category: policy.category,
      },
    };
  } catch (error) {
    if (error instanceof HandledError) {
      sessionManager.recordAudit({
        level: error.code === "TIMEOUT" ? "warning" : "error",
        event: error.code === "TIMEOUT" ? "command_timed_out" : "command_failed",
        message: error.message,
        sessionId: session.id,
        host: session.host,
        username: session.username,
        command,
        riskLevel: policy.riskLevel,
        details: {
          category: policy.category,
          ...error.details,
        },
      });
    }

    throw error;
  }
}

async function callWriteStdin(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const input = readString(args, "input", true) ?? "";
  const session = sessionManager.require(sessionId);
  const decodedInput = decodeInputEscapes(input);
  const controlOnly = /^[\x03\x04\r\n]+$/.test(decodedInput);

  if (session.ready && !session.manualMode && !session.activeCommand && !controlOnly) {
    sessionManager.recordAudit({
      level: "warning",
      event: "stdin_blocked",
      message: "Blocked raw stdin while the shell was at a normal prompt.",
      sessionId: session.id,
      host: session.host,
      username: session.username,
      details: {
        inputPreview: sanitizePreview(decodedInput),
      },
    });

    throw new HandledError(
      "WRITE_STDIN_RESTRICTED",
      "Raw stdin is only allowed while an interactive program is already running or when sending recovery control keys. Use execute_command so the safety policy and approval flow are enforced.",
    );
  }

  if (decodedInput.includes("\x03") && session.activeCommand && !session.activeCommand.completed) {
    // Treat manual Ctrl+C as an explicit interrupt so the session can recover
    // even if the original command never reaches its sentinel line.
    session.activeCommand.timedOutReported = true;
  }

  session.shell.write(decodedInput);
  session.lastUsedAt = Date.now();

  if (!session.activeCommand) {
    session.manualMode = true;
    if (decodedInput.includes("\n") || decodedInput.includes("\r")) {
      session.ready = false;
    }
  }

  sessionManager.recordAudit({
    level: "info",
    event: "stdin_written",
    message: controlOnly
      ? "Sent recovery control input to the PTY session."
      : "Sent raw stdin to an active interactive PTY session.",
    sessionId: session.id,
    host: session.host,
    username: session.username,
    details: {
      controlOnly,
      inputPreview: sanitizePreview(decodedInput),
    },
  });

  return { written: true };
}

async function callReviewCommand(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId");
  const command = readString(args, "command", true) ?? "";
  const session = sessionId ? sessionManager.require(sessionId) : undefined;
  const review = reviewCommandPolicy(command, session, commandPolicyConfig);
  const pendingApproval =
    session &&
    review.decision === "approval_required" &&
    review.requiresConfirmation &&
    review.requiredConfirmationToken
      ? createOrReusePendingApproval(
          session,
          command,
          review.riskLevel,
          review.requiredConfirmationToken,
          review.summary,
        )
      : undefined;

  sessionManager.recordAudit({
    level: review.decision === "blocked" || review.requiresConfirmation ? "warning" : "info",
    event: review.decision === "blocked" ? "command_blocked" : "command_reviewed",
    message:
      review.decision === "blocked"
        ? `Blocked ${review.riskLevel} command during review.`
        : `Reviewed ${review.riskLevel} command without executing it.`,
    sessionId: session?.id,
    host: session?.host,
    username: session?.username,
    command,
    riskLevel: review.riskLevel,
    details: {
      category: review.category,
      summary: review.summary,
      decision: review.decision,
      decisionReason: review.decisionReason,
      matchedRule: review.matchedRule ?? null,
      reasons: review.reasons,
      approvalId: pendingApproval?.approvalId ?? null,
      requiredConfirmationToken: pendingApproval?.requiredConfirmationToken ?? null,
      expiresAt: pendingApproval?.expiresAt ?? null,
    },
  });

  return {
    ...review,
    sessionId: session?.id ?? null,
    pendingApproval: toPendingApprovalSummary(pendingApproval),
  };
}

async function callInterruptSession(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const signalValue = readString(args, "signal") ?? "ctrlC";
  const waitForReadyMs = readPositiveInteger(args, "waitForReadyMs", 5000);
  const clearBuffer = readBoolean(args, "clearBuffer", false);
  const session = sessionManager.require(sessionId);

  if (!["ctrlC", "ctrlD", "newline"].includes(signalValue)) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      'signal must be one of "ctrlC", "ctrlD", or "newline".',
    );
  }

  const result = await interruptSession(session, {
    signal: signalValue as "ctrlC" | "ctrlD" | "newline",
    waitForReadyMs,
    clearBuffer,
  });

  sessionManager.recordAudit({
    level: "warning",
    event: "session_interrupted",
    message: `Sent ${signalValue} to recover the PTY session.`,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    details: {
      signal: signalValue,
      waitForReadyMs,
      clearBuffer,
      sessionReady: result.sessionReady,
      clearedActiveCommand: result.clearedActiveCommand,
    },
  });

  return {
    interrupted: true,
    sessionReady: result.sessionReady,
    clearedActiveCommand: result.clearedActiveCommand,
    bufferLength: session.buffer.length,
  };
}

async function callReadOutput(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const clear = readBoolean(args, "clear", false);
  const session = sessionManager.require(sessionId);
  const output = cleanShellOutput(session.buffer, true);

  if (clear) {
    sessionManager.clearBuffer(session);
  } else {
    sessionManager.touch(session);
  }

  return {
    output,
    bufferLength: session.buffer.length,
    sessionReady: session.ready,
  };
}

async function callResizeTerminal(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const cols = readPositiveInteger(args, "cols", DEFAULT_TERMINAL_COLS);
  const rows = readPositiveInteger(args, "rows", DEFAULT_TERMINAL_ROWS);
  const session = sessionManager.require(sessionId);

  session.shell.setWindow(rows, cols, 0, 0);
  session.cols = cols;
  session.rows = rows;
  session.lastUsedAt = Date.now();

  return { resized: true };
}

async function callListSessions(): Promise<Record<string, unknown>> {
  return {
    sessions: sessionManager.list().map((session) => toSessionSummary(session)),
  };
}

async function callOracleConnect(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const username = readString(args, "username", true) ?? "";
  const password = readString(args, "password", true) ?? "";
  const connectString = readString(args, "connectString");
  const host = readString(args, "host");
  const port = readPositiveInteger(args, "port", 1521);
  const serviceName = readString(args, "serviceName");
  const sid = readString(args, "sid");
  const sessionLabel = readString(args, "sessionLabel");
  const connectTimeout = readPositiveInteger(args, "connectTimeout", 15_000);
  const configDir = readString(args, "configDir") ?? process.env.MCP_DB_CONFIG_DIR?.trim();
  const walletLocation =
    readString(args, "walletLocation") ?? process.env.MCP_DB_WALLET_LOCATION?.trim();
  const walletPassword =
    readString(args, "walletPassword") ?? process.env.MCP_DB_WALLET_PASSWORD?.trim();
  const httpsProxy = readString(args, "httpsProxy") ?? process.env.MCP_DB_HTTPS_PROXY?.trim();
  const httpsProxyPort =
    args["httpsProxyPort"] == null
      ? (() => {
          const envPort = parsePositiveInt(process.env.MCP_DB_HTTPS_PROXY_PORT, 0);
          return envPort > 0 ? envPort : undefined;
        })()
      : readPositiveInteger(args, "httpsProxyPort", 1);

  const session = await connectOracleSession(
    {
      username,
      password,
      connectString,
      host,
      port,
      serviceName,
      sid,
      sessionLabel,
      connectTimeoutMs: connectTimeout,
      configDir,
      walletLocation,
      walletPassword,
      httpsProxy,
      httpsProxyPort,
    },
    dbSessionManager,
  );

  sessionManager.recordAudit({
    level: "info",
    event: "db_session_opened",
    message: `Opened Oracle DB session for ${session.username}@${session.connectTarget}.`,
    sessionId: session.id,
    host: session.connectTarget,
    username: session.username,
    details: {
      currentSchema: session.currentSchema ?? null,
      serviceName: session.serviceName ?? null,
      dbName: session.dbName ?? null,
      dbDomain: session.dbDomain ?? null,
      label: session.label ?? null,
    },
  });

  return {
    dbSessionId: session.id,
    username: session.username,
    target: session.connectTarget,
    connected: true,
    currentSchema: session.currentSchema ?? null,
    serviceName: session.serviceName ?? null,
    dbName: session.dbName ?? null,
    dbDomain: session.dbDomain ?? null,
    serverVersion: session.serverVersion ?? null,
  };
}

async function callExecuteSql(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const dbSessionId = readString(args, "dbSessionId", true) ?? "";
  const sql = readString(args, "sql", true) ?? "";
  const binds = readBinds(args, "binds");
  const timeoutMs = readPositiveInteger(args, "timeout", DEFAULT_DB_TIMEOUT_MS);
  const maxRows = readPositiveInteger(args, "maxRows", DEFAULT_DB_MAX_ROWS);
  const approvalId = readString(args, "approvalId");
  const userConfirmation = readString(args, "userConfirmation");
  const session = dbSessionManager.require(dbSessionId);

  if (maxRows > DEFAULT_DB_MAX_ROWS) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      `maxRows exceeds the configured server limit of ${DEFAULT_DB_MAX_ROWS}.`,
    );
  }

  const policy = ensureSqlApproval(session, sql, approvalId, userConfirmation);

  sessionManager.recordAudit({
    level: "info",
    event: "sql_started",
    message: `Started ${policy.riskLevel} SQL execution.`,
    sessionId: session.id,
    host: session.connectTarget,
    username: session.username,
    command: sanitizePreview(policy.executableSql, 300),
    riskLevel: policy.riskLevel,
    details: {
      category: policy.category,
      timeoutMs,
      maxRows,
      confirmationUsed: Boolean(userConfirmation),
    },
  });

  try {
    const result = await executeSql(session, {
      sql: policy.executableSql,
      binds,
      timeoutMs,
      maxRows,
    });

    sessionManager.recordAudit({
      level: "info",
      event: "sql_completed",
      message: "Completed SQL execution.",
      sessionId: session.id,
      host: session.connectTarget,
      username: session.username,
      command: sanitizePreview(policy.executableSql, 300),
      riskLevel: policy.riskLevel,
      details: {
        category: policy.category,
        executionMs: result.executionMs,
        rowCount: result.rowCount,
        rowsAffected: result.rowsAffected,
        transactionInProgress: result.transactionInProgress,
      },
    });

    return {
      ...result,
      sqlPolicy: {
        riskLevel: policy.riskLevel,
        category: policy.category,
      },
      currentSchema: session.currentSchema ?? null,
      serviceName: session.serviceName ?? null,
    };
  } catch (error) {
    if (error instanceof HandledError) {
      let dbSessionClosed = false;
      if (error.code === "TIMEOUT" && error.details["sessionReusable"] === false) {
        await closeBrokenOracleSession(
          session,
          dbSessionManager,
          "Closed after SQL timeout left the Oracle DB connection unusable.",
        );
        dbSessionClosed = true;
        error.details["dbSessionClosed"] = true;

        sessionManager.recordAudit({
          level: "warning",
          event: "db_session_closed",
          message: "Closed Oracle DB session after an unrecoverable SQL timeout.",
          sessionId: session.id,
          host: session.connectTarget,
          username: session.username,
          details: {
            reason: "Closed after SQL timeout left the Oracle DB connection unusable.",
          },
        });
      }

      sessionManager.recordAudit({
        level: error.code === "TIMEOUT" ? "warning" : "error",
        event: error.code === "TIMEOUT" ? "sql_timed_out" : "sql_failed",
        message: error.message,
        sessionId: session.id,
        host: session.connectTarget,
        username: session.username,
        command: sanitizePreview(policy.executableSql, 300),
        riskLevel: policy.riskLevel,
        details: {
          category: policy.category,
          dbSessionClosed,
          ...error.details,
        },
      });
    }

    throw error;
  }
}

async function callReviewSql(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const dbSessionId = readString(args, "dbSessionId");
  const sql = readString(args, "sql", true) ?? "";
  const session = dbSessionId ? dbSessionManager.require(dbSessionId) : undefined;
  const review = reviewSqlPolicy(sql, session, sqlPolicyConfig);
  const pendingApproval =
    session &&
    review.decision === "approval_required" &&
    review.requiresConfirmation &&
    review.requiredConfirmationToken
      ? createOrReusePendingSqlApproval(
          session,
          sql,
          review.riskLevel,
          review.requiredConfirmationToken,
          review.summary,
        )
      : undefined;

  sessionManager.recordAudit({
    level: review.decision === "blocked" || review.requiresConfirmation ? "warning" : "info",
    event: review.decision === "blocked" ? "sql_blocked" : "sql_reviewed",
    message:
      review.decision === "blocked"
        ? `Blocked ${review.riskLevel} SQL during review.`
        : `Reviewed ${review.riskLevel} SQL without executing it.`,
    sessionId: session?.id,
    host: session?.connectTarget,
    username: session?.username,
    command: review.normalizedSql,
    riskLevel: review.riskLevel,
    details: {
      category: review.category,
      summary: review.summary,
      decision: review.decision,
      decisionReason: review.decisionReason,
      matchedRule: review.matchedRule ?? null,
      reasons: review.reasons,
      approvalId: pendingApproval?.approvalId ?? null,
      requiredConfirmationToken: pendingApproval?.requiredConfirmationToken ?? null,
      expiresAt: pendingApproval?.expiresAt ?? null,
    },
  });

  return {
    ...review,
    dbSessionId: session?.id ?? null,
    pendingApproval: toPendingSqlApprovalSummary(pendingApproval),
  };
}

async function callListDbSessions(): Promise<Record<string, unknown>> {
  return {
    sessions: dbSessionManager.list().map((session) => toDbSessionSummary(session)),
  };
}

async function callReadPolicy(): Promise<Record<string, unknown>> {
  return {
    ...summarizeCombinedPolicyConfig(commandPolicyConfig, sqlPolicyConfig),
    auditLogFile: DEFAULT_AUDIT_LOG_FILE,
  };
}

async function callReadAuditLog(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId");
  const limit = readPositiveInteger(args, "limit", 50);

  return {
    logFilePath: DEFAULT_AUDIT_LOG_FILE,
    entries: sessionManager.listAudit({
      sessionId,
      limit,
    }),
  };
}

async function callCloseSession(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const session = sessionManager.close(sessionId, "Closed by close_session.");

  return {
    closed: true,
    sessionId: session.id,
  };
}

async function callCloseDbSession(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const dbSessionId = readString(args, "dbSessionId", true) ?? "";
  const session = dbSessionManager.require(dbSessionId);

  if (session.activeExecution) {
    throw new HandledError(
      "DB_SESSION_BUSY",
      "This Oracle DB session is still running a query. Wait for it to finish before closing the session.",
    );
  }

  const closedSession = await dbSessionManager.close(
    dbSessionId,
    "Closed by close_db_session.",
  );

  sessionManager.recordAudit({
    level: "info",
    event: "db_session_closed",
    message: `Closed Oracle DB session for ${closedSession.username}@${closedSession.connectTarget}.`,
    sessionId: closedSession.id,
    host: closedSession.connectTarget,
    username: closedSession.username,
    details: {
      reason: "Closed by close_db_session.",
    },
  });

  return {
    closed: true,
    dbSessionId: closedSession.id,
  };
}

function buildServer() {
  const server = new McpServer(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: TOOL_DEFINITIONS,
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const params: Record<string, unknown> = isRecord(request.params) ? request.params : {};
    const toolName = typeof params["name"] === "string" ? String(params["name"]) : "";
    const args: Record<string, unknown> = isRecord(params["arguments"])
      ? (params["arguments"] as Record<string, unknown>)
      : {};

    switch (toolName) {
      case "ssh_connect":
        return await safeToolCall(() => callSshConnect(args));
      case "execute_command":
        return await safeToolCall(() => callExecuteCommand(args));
      case "review_command":
        return await safeToolCall(() => callReviewCommand(args));
      case "write_stdin":
        return await safeToolCall(() => callWriteStdin(args));
      case "read_output":
        return await safeToolCall(() => callReadOutput(args));
      case "resize_terminal":
        return await safeToolCall(() => callResizeTerminal(args));
      case "list_sessions":
        return await safeToolCall(() => callListSessions());
      case "oracle_connect":
        return await safeToolCall(() => callOracleConnect(args));
      case "execute_sql":
        return await safeToolCall(() => callExecuteSql(args));
      case "review_sql":
        return await safeToolCall(() => callReviewSql(args));
      case "list_db_sessions":
        return await safeToolCall(() => callListDbSessions());
      case "read_policy":
        return await safeToolCall(() => callReadPolicy());
      case "read_audit_log":
        return await safeToolCall(() => callReadAuditLog(args));
      case "close_session":
        return await safeToolCall(() => callCloseSession(args));
      case "close_db_session":
        return await safeToolCall(() => callCloseDbSession(args));
      case "interrupt_session":
        return await safeToolCall(() => callInterruptSession(args));
      default:
        return createToolResult(
          {
            error: "UNKNOWN_TOOL",
            message: `Unsupported tool "${toolName}".`,
          },
          true,
        );
    }
  });

  return server;
}

async function closeMcpServer(server: unknown): Promise<void> {
  const closable = server as { close?: () => Promise<void> | void };
  if (typeof closable.close === "function") {
    await closable.close();
  }
}

function registerCleanup(cleanup: () => Promise<void> | void): void {
  let shuttingDown = false;

  const runCleanup = async (): Promise<void> => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    try {
      await cleanup();
    } finally {
      await dbSessionManager.closeAll("Process shutdown.");
      sessionManager.dispose();
      dbSessionManager.dispose();
    }
  };

  process.on("SIGINT", () => {
    void runCleanup().finally(() => {
      process.exit(0);
    });
  });

  process.on("SIGTERM", () => {
    void runCleanup().finally(() => {
      process.exit(0);
    });
  });

  process.on("exit", () => {
    if (!shuttingDown) {
      sessionManager.closeAll("Process exit.");
      void dbSessionManager.closeAll("Process exit.");
      sessionManager.dispose();
      dbSessionManager.dispose();
    }
  });
}

async function startStdioTransport(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();

  registerCleanup(async () => {
    sessionManager.closeAll("Process shutdown.");
    await closeMcpServer(server);
  });

  await server.connect(transport);
}

async function startSseTransport(): Promise<void> {
  const activeTransports = new Map<
    string,
    {
      transport: SSEServerTransport;
      server: ReturnType<typeof buildServer>;
    }
  >();

  const disposeTransport = async (sessionId: string): Promise<void> => {
    const entry = activeTransports.get(sessionId);
    if (!entry) {
      return;
    }

    activeTransports.delete(sessionId);
    await closeMcpServer(entry.server);
  };

  const httpServer = createHttpServer(async (request, response) => {
    try {
      if (!request.url) {
        response.statusCode = 400;
        response.end("Missing request URL.");
        return;
      }

      const url = new URL(
        request.url,
        `http://${request.headers.host ?? `127.0.0.1:${DEFAULT_SSE_PORT}`}`,
      );

      if (request.method === "GET" && url.pathname === "/sse") {
        const transport = new SSEServerTransport("/messages", response);
        const server = buildServer();
        activeTransports.set(transport.sessionId, { transport, server });
        transport.onclose = () => {
          void disposeTransport(transport.sessionId);
        };
        response.on("close", () => {
          void disposeTransport(transport.sessionId);
        });
        await server.connect(transport);
        return;
      }

      if (request.method === "POST" && url.pathname === "/messages") {
        const sessionId = url.searchParams.get("sessionId");
        if (!sessionId) {
          response.statusCode = 400;
          response.end("Missing sessionId query parameter.");
          return;
        }

        const entry = activeTransports.get(sessionId);
        if (!entry) {
          response.statusCode = 404;
          response.end("Unknown SSE transport session.");
          return;
        }

        await entry.transport.handlePostMessage(request, response);
        return;
      }

      response.statusCode = 404;
      response.end("Not found.");
    } catch (error) {
      response.statusCode = 500;
      response.end(getErrorMessage(error));
    }
  });

  registerCleanup(async () => {
    for (const sessionId of Array.from(activeTransports.keys())) {
      await disposeTransport(sessionId);
    }

    sessionManager.closeAll("Process shutdown.");

    await new Promise<void>((resolve, reject) => {
      httpServer.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(DEFAULT_SSE_PORT, resolve);
  });
}

async function main(): Promise<void> {
  if (DEFAULT_TRANSPORT === "stdio") {
    await startStdioTransport();
    return;
  }

  if (DEFAULT_TRANSPORT === "sse") {
    await startSseTransport();
    return;
  }

  throw new Error(
    `Unsupported MCP transport "${DEFAULT_TRANSPORT}". Use "stdio" or "sse".`,
  );
}

main().catch((error) => {
  console.error(getErrorMessage(error));
  process.exit(1);
});
