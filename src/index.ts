#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { summarizeCommandBatchReviews } from "./command-batch.js";
import {
  closeBrokenOracleSession,
  closeOracleSession,
  connectOracleSession,
  executeSql,
  interruptOracleExecution,
} from "./db.js";
import {
  resolveOracleCredentials,
  resolveSshCredentials,
  resolveSudoPassword,
} from "./credentials.js";
import {
  DbSessionManager,
  type OracleDbSession,
  type PendingSqlApproval,
} from "./db-session.js";
import {
  executeCommand,
  getVisibleInteractionBuffers,
  handleShellData,
  interruptSession,
  startInteractiveCommand,
  waitForCommandActivity,
} from "./executor.js";
import {
  listNmsGuides,
  resolveNmsGuidePdf,
} from "./nms-docs.js";
import {
  loadCommandPolicyConfig,
  loadSqlPolicyConfig,
  summarizeCombinedPolicyConfig,
} from "./policy-config.js";
import { reviewCommandPolicy } from "./policy.js";
import {
  SessionManager,
  runExclusiveShellOperation,
  type PendingApproval,
  type ShellSession,
} from "./session.js";
import { maybeAdoptInteractiveShell } from "./shell-state.js";
import { closeShellSession, connectShellSession, type AuthMethod } from "./ssh.js";
import { reviewSqlPolicy } from "./sql-policy.js";
import { inferShellIdentityTransition } from "./sudo.js";
import { getUsageGuide } from "./usage-guide.js";
import {
  analyzeInteractionPrompt,
  cleanShellOutput,
  cleanCommandOutput,
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

const SHARED_CREDENTIAL_INPUTS = {
  ldapUser: { type: "string" },
  ldapPassword: { type: "string" },
  ldapPasswordEncoded: { type: "string" },
  hostUser: { type: "string" },
  hostPassword: { type: "string" },
  hostPasswordEncoded: { type: "string" },
  dbUser: { type: "string" },
  dbPassword: { type: "string" },
  dbPasswordEncoded: { type: "string" },
  passwordEncoded: { type: "string" },
  sudoPasswordEncoded: { type: "string" },
} as const;

const TOOL_DEFINITIONS = [
  {
    name: "ssh_connect",
    description: "Establishes SSH connection and opens a PTY shell session.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["host", "authMethod"],
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
        ...SHARED_CREDENTIAL_INPUTS,
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
        ...SHARED_CREDENTIAL_INPUTS,
      },
    },
  },
  {
    name: "start_interactive_command",
    description:
      "Starts a command inside the PTY session and keeps the interaction open so the agent can inspect prompts and send follow-up input safely.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId", "command"],
      properties: {
        sessionId: { type: "string" },
        command: { type: "string" },
        timeout: { type: "integer", default: DEFAULT_COMMAND_TIMEOUT_MS },
        waitForOutputMs: { type: "integer", default: 1500 },
        sudoPassword: { type: "string" },
        stripAnsi: { type: "boolean", default: true },
        approvalId: { type: "string" },
        userConfirmation: { type: "string" },
        ...SHARED_CREDENTIAL_INPUTS,
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
    name: "review_command_batch",
    description:
      "Reviews a related set of shell commands together and reports whether the whole batch can auto-run, needs one confirmation, or contains blocked commands.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["commands"],
      properties: {
        sessionId: { type: "string" },
        commands: {
          type: "array",
          minItems: 1,
          items: { type: "string" },
        },
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
        redactInput: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "send_interaction_input",
    description:
      "Sends follow-up input to an active interactive PTY command, optionally waits for fresh output, and returns a classified interaction snapshot.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId", "input"],
      properties: {
        sessionId: { type: "string" },
        input: { type: "string" },
        waitForOutputMs: { type: "integer", default: 1500 },
        stripAnsi: { type: "boolean", default: true },
        redactInput: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "execute_command_batch",
    description:
      "Executes a related set of shell commands sequentially in one session. MCP reviews them together so one confirmation can cover the whole batch when needed.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId", "commands"],
      properties: {
        sessionId: { type: "string" },
        commands: {
          type: "array",
          minItems: 1,
          items: { type: "string" },
        },
        timeout: { type: "integer", default: DEFAULT_COMMAND_TIMEOUT_MS },
        sudoPassword: { type: "string" },
        stripAnsi: { type: "boolean", default: true },
        approvalId: { type: "string" },
        userConfirmation: { type: "string" },
        stopOnError: { type: "boolean", default: true },
        ...SHARED_CREDENTIAL_INPUTS,
      },
    },
  },
  {
    name: "read_output",
    description: "Reads the current PTY output buffer and returns the current interaction classification.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
        clear: { type: "boolean", default: false },
        stripAnsi: { type: "boolean", default: true },
      },
    },
  },
  {
    name: "read_interaction_state",
    description:
      "Returns the active PTY interaction state, including prompt classification, command mode, and the latest output from the running command or shell.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sessionId"],
      properties: {
        sessionId: { type: "string" },
        clear: { type: "boolean", default: false },
        stripAnsi: { type: "boolean", default: true },
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
      required: [],
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
        ...SHARED_CREDENTIAL_INPUTS,
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
          oneOf: [{ type: "object" }, { type: "array", items: {} }],
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
    name: "list_nms_guides",
    description:
      "Lists Oracle Utilities Network Management System documentation versions and guides from the live Oracle docs site, including cached local PDF paths when present.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        version: { type: "string" },
      },
    },
  },
  {
    name: "get_nms_guide_pdf",
    description:
      "Finds one Oracle Utilities Network Management System guide, downloads its PDF into the local cache when needed, and returns the absolute local file path.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["version", "guide"],
      properties: {
        version: { type: "string" },
        guide: { type: "string" },
        refresh: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "read_usage_guide",
    description:
      "Returns MCP-specific usage guidance, preferred tool-selection style, anti-patterns, and operator-style recommendations for this server.",
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
    name: "interrupt_db_session",
    description:
      "Attempts to interrupt the currently running SQL statement on a cached Oracle DB session and optionally waits for the session to become idle again.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["dbSessionId"],
      properties: {
        dbSessionId: { type: "string" },
        waitForIdleMs: { type: "integer", default: 5000 },
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

function readStringArray(
  args: Record<string, unknown>,
  fieldName: string,
  required = false,
): string[] {
  const value = args[fieldName];
  if (value == null) {
    if (required) {
      throw new HandledError(
        "INVALID_ARGUMENT",
        `${fieldName} is required and must be a non-empty array of strings.`,
      );
    }

    return [];
  }

  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || entry === "")) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      `${fieldName} must be a non-empty array of non-empty strings.`,
    );
  }

  return value;
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

function normalizeApprovalText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
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
  const normalizedCommand = normalizeApprovalText(command);
  const existing = session.pendingApproval;
  if (
    existing &&
    existing.command === normalizedCommand &&
    existing.riskLevel === riskLevel &&
    existing.requiredConfirmationToken === requiredConfirmationToken &&
    existing.expiresAt > now
  ) {
    return existing;
  }

  const pendingApproval: PendingApproval = {
    approvalId: createApprovalId(),
    command: normalizedCommand,
    riskLevel,
    requiredConfirmationToken,
    summary,
    createdAt: now,
    expiresAt: now + DEFAULT_APPROVAL_TTL_MS,
  };

  session.pendingApproval = pendingApproval;
  return pendingApproval;
}

function summarizeBatchCommands(commands: string[]): string {
  return commands.map((command, index) => `${index + 1}. ${command}`).join("\n");
}

function toCommandReviewSummary(review: {
  command: string;
  riskLevel: string;
  category: string;
  summary: string;
  decision: string;
  safeForAutoRun: boolean;
}): Record<string, unknown> {
  return {
    command: review.command,
    riskLevel: review.riskLevel,
    category: review.category,
    summary: review.summary,
    decision: review.decision,
    safeForAutoRun: review.safeForAutoRun,
  };
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
    if (session.pendingApproval?.command === review.normalizedCommand) {
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
    review.normalizedCommand,
    review.riskLevel,
    review.requiredConfirmationToken,
    review.summary,
  );

  const normalizedConfirmation = userConfirmation ? normalizeApprovalText(userConfirmation) : undefined;
  const confirmationAccepted =
    approvalId === pendingApproval.approvalId &&
    normalizedConfirmation === pendingApproval.requiredConfirmationToken &&
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
      `Show the exact command and the consequence summary to the user. Only retry execute_command or start_interactive_command after the user replies with CONFIRM, using approvalId "${pendingApproval.approvalId}" and userConfirmation "CONFIRM".`,
  });
}

function ensureCommandBatchApproval(
  session: ShellSession,
  commands: string[],
  approvalId: string | undefined,
  userConfirmation: string | undefined,
): {
  riskLevel: "read-only" | "mutating" | "destructive";
  category: string;
  safeForAutoRun: boolean;
  reviews: ReturnType<typeof summarizeCommandBatchReviews>["reviews"];
} {
  const batchReview = summarizeCommandBatchReviews(commands, session, commandPolicyConfig);

  sessionManager.recordAudit({
    level: batchReview.decision === "blocked" || batchReview.requiresConfirmation ? "warning" : "info",
    event: "command_reviewed",
    message: `Reviewed ${batchReview.commandCount} command(s) as one batch with policy decision "${batchReview.decision}".`,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    command: `batch(${batchReview.commandCount})`,
    riskLevel: batchReview.riskLevel,
    details: {
      category: batchReview.category,
      summary: batchReview.summary,
      decision: batchReview.decision,
      blockedCount: batchReview.blockedCount,
      approvalRequiredCount: batchReview.approvalRequiredCount,
      safeForAutoRun: batchReview.safeForAutoRun,
      commands: batchReview.reviews.map((review) => toCommandReviewSummary(review)),
    },
  });

  if (batchReview.decision === "blocked") {
    session.pendingApproval = undefined;

    sessionManager.recordAudit({
      level: "warning",
      event: "command_blocked",
      message: "Blocked command batch by safety policy.",
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command: `batch(${batchReview.commandCount})`,
      riskLevel: batchReview.riskLevel,
      details: {
        category: batchReview.category,
        summary: batchReview.summary,
        blockedCount: batchReview.blockedCount,
        approvalRequiredCount: batchReview.approvalRequiredCount,
        commands: batchReview.reviews.map((review) => toCommandReviewSummary(review)),
      },
    });

    throw new HandledError(
      "POLICY_BLOCKED",
      "The active MCP policy blocked one or more commands in this batch.",
      {
        commandBatchReview: batchReview,
        instructions:
          "Use review_command_batch or review_command to inspect the batch, then remove or change the blocked command before retrying.",
      },
    );
  }

  if (!batchReview.requiresConfirmation) {
    if (session.pendingApproval?.command === batchReview.normalizedBatch) {
      session.pendingApproval = undefined;
    }

    return {
      riskLevel: batchReview.riskLevel,
      category: batchReview.category,
      safeForAutoRun: batchReview.safeForAutoRun,
      reviews: batchReview.reviews,
    };
  }

  const pendingApproval = createOrReusePendingApproval(
    session,
    batchReview.normalizedBatch,
    batchReview.riskLevel,
    "CONFIRM",
    batchReview.summary,
  );

  const normalizedConfirmation = userConfirmation ? normalizeApprovalText(userConfirmation) : undefined;
  const confirmationAccepted =
    approvalId === pendingApproval.approvalId &&
    normalizedConfirmation === pendingApproval.requiredConfirmationToken &&
    pendingApproval.expiresAt > Date.now();

  if (confirmationAccepted) {
    session.pendingApproval = undefined;
    return {
      riskLevel: batchReview.riskLevel,
      category: batchReview.category,
      safeForAutoRun: batchReview.safeForAutoRun,
      reviews: batchReview.reviews,
    };
  }

  const message =
    "User confirmation is required before MCP runs this related command batch because at least one command is outside the explicit safe auto-run list.";

  sessionManager.recordAudit({
    level: "warning",
    event: "command_blocked",
    message,
    sessionId: session.id,
    host: session.host,
    username: session.username,
    command: `batch(${batchReview.commandCount})`,
    riskLevel: batchReview.riskLevel,
    details: {
      approvalId: pendingApproval.approvalId,
      requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
      expiresAt: pendingApproval.expiresAt,
      providedApprovalId: approvalId ?? null,
      providedConfirmation: userConfirmation ?? null,
      category: batchReview.category,
      summary: batchReview.summary,
      commands: batchReview.reviews.map((review) => toCommandReviewSummary(review)),
    },
  });

  throw new HandledError("CONFIRMATION_REQUIRED", message, {
    approvalId: pendingApproval.approvalId,
    requiredConfirmationToken: pendingApproval.requiredConfirmationToken,
    expiresAt: pendingApproval.expiresAt,
    commandBatchReview: batchReview,
    confirmationPrompt:
      `Commands:\n${summarizeBatchCommands(commands)}\nConsequence: ${batchReview.summary}\nReply with exact CONFIRM before MCP runs this batch.`,
    instructions:
      `Show the exact command list and the consequence summary to the user. Only retry execute_command_batch after the user replies with CONFIRM, using approvalId "${pendingApproval.approvalId}" and userConfirmation "CONFIRM".`,
  });
}

function guessForegroundCommand(command: string | undefined): string | null {
  if (!command) {
    return null;
  }

  let normalized = normalizeApprovalText(command);
  normalized = normalized.replace(
    /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)\s+)*/,
    "",
  );
  normalized = normalized.replace(/^sudo(?:\s+-[^\s]+(?:\s+[^\s]+)?)?\s+/i, "");

  const match = normalized.match(/^\s*([A-Za-z_][A-Za-z0-9._-]*)\b/);
  return match?.[1] ?? null;
}

function buildInteractionState(
  session: ShellSession,
  stripAnsi = true,
): Record<string, unknown> {
  const activeCommand = session.activeCommand;
  const { outputBuffer, promptBuffer } = getVisibleInteractionBuffers(session);
  const output = activeCommand
    ? cleanCommandOutput(outputBuffer, activeCommand.submittedCommand, stripAnsi)
    : cleanShellOutput(outputBuffer, stripAnsi);
  const prompt = analyzeInteractionPrompt(promptBuffer, {
    commandHint: activeCommand?.command,
    sessionReady: session.ready,
  });
  const suggestedInputs = [...prompt.suggestions];

  let safeToAutoRespond = prompt.safeToAutoRespond;
  const autoResponseSent =
    prompt.promptType === "sudo_password" &&
    Boolean(activeCommand?.sudoPassword) &&
    (activeCommand?.sudoPromptAttempts ?? 0) > 0;

  if (prompt.promptType === "sudo_password" && activeCommand?.sudoPassword) {
    if (autoResponseSent) {
      safeToAutoRespond = false;
      suggestedInputs.unshift({
        input: "",
        description: "The server already submitted the provided sudo password. Wait for more output before sending anything else.",
      });
    } else {
      safeToAutoRespond = true;
      suggestedInputs.unshift({
        input: "<provided sudo password>\\n",
        description: "Submit the sudo password supplied with the active command.",
        sensitive: true,
      });
    }
  }

  return {
    sessionMode: activeCommand
      ? activeCommand.executionMode
      : session.manualMode
        ? "manual"
        : "idle",
    activeCommand: activeCommand?.command ?? null,
    foregroundCommand: guessForegroundCommand(activeCommand?.command),
    running: Boolean(activeCommand && !activeCommand.completed),
    completed: Boolean(activeCommand?.completed),
    exitCode: activeCommand?.completed ? (activeCommand.exitCode ?? 0) : null,
    startedAt: activeCommand?.startedAt ?? null,
    executionMs: activeCommand ? Date.now() - activeCommand.startedAt : null,
    promptType: prompt.promptType,
    promptText: prompt.promptText,
    confidence: prompt.confidence,
    expectsInput: prompt.expectsInput,
    safeToAutoRespond,
    autoResponseSent,
    suggestedInputs,
    output,
    bufferLength: outputBuffer.length,
    sessionReady: session.ready,
    isSudo: session.isSudo,
    sessionIdentity: {
      loginUser: session.identity.loginUser,
      effectiveUser: session.identity.effectiveUser,
      privilegeMode: session.identity.privilegeMode,
      promptMarkerActive: session.identity.promptMarkerActive,
      source: session.identity.source,
      lastDetectedAt: session.identity.lastDetectedAt,
    },
    bootstrap: {
      successful: session.bootstrap.successful,
      lastBootstrapAt: session.bootstrap.lastBootstrapAt ?? null,
      lastBootstrapReason: session.bootstrap.lastBootstrapReason ?? null,
      lastBootstrapError: session.bootstrap.lastBootstrapError ?? null,
      lastReadyMarker: session.bootstrap.lastReadyMarker ?? null,
      recoveryCount: session.bootstrap.recoveryCount,
      adoptedShellCount: session.bootstrap.adoptedShellCount,
    },
    operation: {
      activeLabel: session.operationState.activeLabel ?? null,
      activeSince: session.operationState.activeSince ?? null,
      queuedCount: session.operationState.queuedCount,
    },
  };
}

async function waitForPotentialShellAdoption(
  session: ShellSession,
  waitWindowMs: number,
) {
  handleShellData(session);

  let adoption = await maybeAdoptInteractiveShell(session, Math.max(waitWindowMs, 1500));
  if (adoption.adopted || !session.activeCommand) {
    return adoption;
  }

  if (!inferShellIdentityTransition(session.activeCommand.command)) {
    return adoption;
  }

  const deadline = Date.now() + Math.max(waitWindowMs, 0);
  let previousLength = session.activeCommand.buffer.length;

  while (Date.now() < deadline && session.activeCommand && !session.activeCommand.completed) {
    const remainingMs = deadline - Date.now();
    await waitForCommandActivity(session, previousLength, Math.min(remainingMs, 300));
    previousLength = session.activeCommand?.buffer.length ?? previousLength;
    adoption = await maybeAdoptInteractiveShell(session, Math.min(Math.max(remainingMs, 1), 1500));
    if (adoption.adopted) {
      return adoption;
    }
  }

  return adoption;
}

function toSessionSummary(session: ShellSession): Record<string, unknown> {
  const interaction = buildInteractionState(session, true);

  return {
    sessionId: session.id,
    host: session.host,
    username: session.username,
    label: session.label ?? null,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    isSudo: session.isSudo,
    ready: session.ready,
    sessionIdentity: interaction["sessionIdentity"],
    bootstrap: interaction["bootstrap"],
    operation: interaction["operation"],
    pendingApproval: toPendingApprovalSummary(session.pendingApproval),
    interaction: {
      sessionMode: interaction["sessionMode"],
      foregroundCommand: interaction["foregroundCommand"],
      running: interaction["running"],
      promptType: interaction["promptType"],
      expectsInput: interaction["expectsInput"],
    },
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
  const normalizedSql = normalizeApprovalText(sql);
  const existing = session.pendingApproval;
  if (
    existing &&
    existing.sql === normalizedSql &&
    existing.riskLevel === riskLevel &&
    existing.requiredConfirmationToken === requiredConfirmationToken &&
    existing.expiresAt > now
  ) {
    return existing;
  }

  const pendingApproval: PendingSqlApproval = {
    approvalId: createApprovalId(),
    sql: normalizedSql,
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
    if (session.pendingApproval?.sql === review.normalizedSql) {
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
    review.normalizedSql,
    review.riskLevel,
    review.requiredConfirmationToken,
    review.summary,
  );

  const normalizedConfirmation = userConfirmation ? normalizeApprovalText(userConfirmation) : undefined;
  const confirmationAccepted =
    approvalId === pendingApproval.approvalId &&
    normalizedConfirmation === pendingApproval.requiredConfirmationToken &&
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
  const authMethod = readAuthMethod(args);
  const credentials = resolveSshCredentials(args, authMethod);
  const sessionLabel = readString(args, "sessionLabel");
  const connectTimeout = readPositiveInteger(args, "connectTimeout", 10_000);

  const session = await connectShellSession({
    host,
    port,
    username: credentials.username,
    authMethod,
    password: credentials.password,
    privateKey: credentials.privateKey,
    passphrase: credentials.passphrase,
    sessionLabel,
    connectTimeout,
    sessionManager,
  });

  return {
    sessionId: session.id,
    host: session.host,
    username: session.username,
    connected: true,
    sessionIdentity: {
      loginUser: session.identity.loginUser,
      effectiveUser: session.identity.effectiveUser,
      privilegeMode: session.identity.privilegeMode,
      promptMarkerActive: session.identity.promptMarkerActive,
      source: session.identity.source,
    },
    bootstrap: {
      successful: session.bootstrap.successful,
      lastBootstrapAt: session.bootstrap.lastBootstrapAt ?? null,
      lastBootstrapReason: session.bootstrap.lastBootstrapReason ?? null,
      recoveryCount: session.bootstrap.recoveryCount,
      adoptedShellCount: session.bootstrap.adoptedShellCount,
    },
    ...(session.serverBanner ? { serverBanner: session.serverBanner } : {}),
  };
}

async function callExecuteCommand(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const command = readString(args, "command", true) ?? "";
  const timeoutMs = readPositiveInteger(args, "timeout", DEFAULT_COMMAND_TIMEOUT_MS);
  const sudoPassword = resolveSudoPassword(args);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const approvalId = readString(args, "approvalId");
  const userConfirmation = readString(args, "userConfirmation");
  const session = sessionManager.require(sessionId);
  return await runExclusiveShellOperation(session, "execute_command", async () => {
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
        executionMode: "oneshot",
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
          executionMode: "oneshot",
        },
      });

      return {
        ...result,
        interaction: buildInteractionState(session, stripAnsi),
        policy: {
          riskLevel: policy.riskLevel,
          category: policy.category,
        },
      };
    } catch (error) {
      if (error instanceof HandledError) {
        if (error.code === "TIMEOUT") {
          error.details["interaction"] = buildInteractionState(session, stripAnsi);
        }

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
            executionMode: "oneshot",
            ...error.details,
          },
        });
      }

      throw error;
    }
  });
}

async function callStartInteractiveCommand(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const command = readString(args, "command", true) ?? "";
  const timeoutMs = readPositiveInteger(args, "timeout", DEFAULT_COMMAND_TIMEOUT_MS);
  const waitForOutputMs = readPositiveInteger(args, "waitForOutputMs", 1500);
  const sudoPassword = resolveSudoPassword(args);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const approvalId = readString(args, "approvalId");
  const userConfirmation = readString(args, "userConfirmation");
  const session = sessionManager.require(sessionId);
  return await runExclusiveShellOperation(session, "start_interactive_command", async () => {
    const policy = ensureCommandApproval(session, command, approvalId, userConfirmation);

    sessionManager.recordAudit({
      level: "info",
      event: "command_started",
      message: `Started ${policy.riskLevel} interactive command execution.`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command,
      riskLevel: policy.riskLevel,
      details: {
        category: policy.category,
        timeoutMs,
        waitForOutputMs,
        confirmationUsed: Boolean(userConfirmation),
        executionMode: "interactive",
      },
    });

    try {
      const result = await startInteractiveCommand(session, command, {
        timeoutMs,
        waitForOutputMs,
        sudoPassword,
        stripAnsiOutput: stripAnsi,
      });
      const interaction = buildInteractionState(session, stripAnsi);

      if (result.completed) {
        sessionManager.recordAudit({
          level: "info",
          event: "command_completed",
          message: `Completed interactive command with exit code ${result.exitCode ?? 0}.`,
          sessionId: session.id,
          host: session.host,
          username: session.username,
          command,
          riskLevel: policy.riskLevel,
          details: {
            category: policy.category,
            exitCode: result.exitCode ?? 0,
            executionMs: result.executionMs,
            executionMode: "interactive",
          },
        });
      }

      return {
        ...result,
        shellAdopted: !result.completed && !session.activeCommand && session.ready,
        interaction,
        policy: {
          riskLevel: policy.riskLevel,
          category: policy.category,
        },
      };
    } catch (error) {
      if (error instanceof HandledError) {
        error.details["interaction"] = buildInteractionState(session, stripAnsi);

        sessionManager.recordAudit({
          level: "error",
          event: "command_failed",
          message: error.message,
          sessionId: session.id,
          host: session.host,
          username: session.username,
          command,
          riskLevel: policy.riskLevel,
          details: {
            category: policy.category,
            executionMode: "interactive",
            ...error.details,
          },
        });
      }

      throw error;
    }
  });
}

function writeInputToSession(
  session: ShellSession,
  decodedInput: string,
  options: {
    redactInput?: boolean;
  } = {},
): { controlOnly: boolean } {
  const controlOnly = /^[\x03\x04\r\n]+$/.test(decodedInput);
  const prompt = analyzeInteractionPrompt(
    session.activeCommand ? session.activeCommand.buffer : session.buffer,
    {
      commandHint: session.activeCommand?.command,
      sessionReady: session.ready,
    },
  );
  const shouldRedactInput =
    options.redactInput ||
    prompt.promptType === "password" ||
    prompt.promptType === "sudo_password";

  if (session.ready && !session.manualMode && !session.activeCommand && !controlOnly) {
    sessionManager.recordAudit({
      level: "warning",
      event: "stdin_blocked",
      message: "Blocked raw stdin while the shell was at a normal prompt.",
      sessionId: session.id,
      host: session.host,
      username: session.username,
      details: {
        inputPreview: shouldRedactInput ? "<redacted>" : sanitizePreview(decodedInput),
      },
    });

    throw new HandledError(
      "WRITE_STDIN_RESTRICTED",
      "Raw stdin is only allowed while an interactive program is already running or when sending recovery control keys. Use execute_command or start_interactive_command so the safety policy and approval flow are enforced.",
    );
  }

  if (decodedInput.includes("\x03") && session.activeCommand && !session.activeCommand.completed) {
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
      inputPreview: shouldRedactInput ? "<redacted>" : sanitizePreview(decodedInput),
    },
  });

  return { controlOnly };
}

async function callWriteStdin(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const input = readString(args, "input", true) ?? "";
  const redactInput = readBoolean(args, "redactInput", false);
  const session = sessionManager.require(sessionId);
  const decodedInput = decodeInputEscapes(input);
  return await runExclusiveShellOperation(session, "write_stdin", async () => {
    writeInputToSession(session, decodedInput, {
      redactInput,
    });

    return { written: true };
  });
}

async function callReviewCommandBatch(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId");
  const commands = readStringArray(args, "commands", true);
  const session = sessionId ? sessionManager.require(sessionId) : undefined;
  const batchReview = summarizeCommandBatchReviews(commands, session, commandPolicyConfig);
  const pendingApproval =
    session && batchReview.requiresConfirmation
      ? createOrReusePendingApproval(
          session,
          batchReview.normalizedBatch,
          batchReview.riskLevel,
          "CONFIRM",
          batchReview.summary,
        )
      : undefined;

  sessionManager.recordAudit({
    level: batchReview.decision === "blocked" || batchReview.requiresConfirmation ? "warning" : "info",
    event: batchReview.decision === "blocked" ? "command_blocked" : "command_reviewed",
    message:
      batchReview.decision === "blocked"
        ? `Blocked ${batchReview.commandCount} command(s) during batch review.`
        : `Reviewed ${batchReview.commandCount} command(s) without executing them.`,
    sessionId: session?.id,
    host: session?.host,
    username: session?.username,
    command: `batch(${batchReview.commandCount})`,
    riskLevel: batchReview.riskLevel,
    details: {
      category: batchReview.category,
      summary: batchReview.summary,
      decision: batchReview.decision,
      blockedCount: batchReview.blockedCount,
      approvalRequiredCount: batchReview.approvalRequiredCount,
      approvalId: pendingApproval?.approvalId ?? null,
      requiredConfirmationToken: pendingApproval?.requiredConfirmationToken ?? null,
      expiresAt: pendingApproval?.expiresAt ?? null,
      commands: batchReview.reviews.map((review) => toCommandReviewSummary(review)),
    },
  });

  return {
    sessionId: session?.id ?? null,
    commandCount: batchReview.commandCount,
    riskLevel: batchReview.riskLevel,
    category: batchReview.category,
    decision: batchReview.decision,
    summary: batchReview.summary,
    requiresConfirmation: batchReview.requiresConfirmation,
    safeForAutoRun: batchReview.safeForAutoRun,
    blockedCount: batchReview.blockedCount,
    approvalRequiredCount: batchReview.approvalRequiredCount,
    commands: batchReview.reviews.map((review) => ({
      ...review,
    })),
    pendingApproval: toPendingApprovalSummary(pendingApproval),
  };
}

async function callSendInteractionInput(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const input = readString(args, "input", true) ?? "";
  const waitForOutputMs = readPositiveInteger(args, "waitForOutputMs", 1500);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const redactInput = readBoolean(args, "redactInput", false);
  const session = sessionManager.require(sessionId);

  return await runExclusiveShellOperation(session, "send_interaction_input", async () => {
    if ((session.activeCommand && session.activeCommand.completed) || (!session.activeCommand && !session.manualMode)) {
      throw new HandledError(
        "NO_ACTIVE_INTERACTION",
        "There is no active interactive PTY command to receive follow-up input.",
      );
    }

    const decodedInput = decodeInputEscapes(input);
    const previousLength = session.activeCommand?.buffer.length ?? session.buffer.length;
    writeInputToSession(session, decodedInput, {
      redactInput,
    });

    if (waitForOutputMs > 0) {
      await waitForCommandActivity(session, previousLength, waitForOutputMs);
    }

    const adoption = await waitForPotentialShellAdoption(session, waitForOutputMs);

    return {
      written: true,
      shellAdopted: adoption.adopted,
      adoptedEffectiveUser: adoption.effectiveUser,
      ...(adoption.adoptionError ? { adoptionError: adoption.adoptionError } : {}),
      interaction: buildInteractionState(session, stripAnsi),
    };
  });
}

async function callExecuteCommandBatch(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const commands = readStringArray(args, "commands", true);
  const timeoutMs = readPositiveInteger(args, "timeout", DEFAULT_COMMAND_TIMEOUT_MS);
  const sudoPassword = resolveSudoPassword(args);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const approvalId = readString(args, "approvalId");
  const userConfirmation = readString(args, "userConfirmation");
  const stopOnError = readBoolean(args, "stopOnError", true);
  const session = sessionManager.require(sessionId);

  return await runExclusiveShellOperation(session, "execute_command_batch", async () => {
    const policy = ensureCommandBatchApproval(session, commands, approvalId, userConfirmation);
    const results: Array<Record<string, unknown>> = [];

    sessionManager.recordAudit({
      level: "info",
      event: "command_started",
      message: `Started execution of a ${policy.riskLevel} command batch with ${commands.length} command(s).`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command: `batch(${commands.length})`,
      riskLevel: policy.riskLevel,
      details: {
        category: policy.category,
        timeoutMs,
        confirmationUsed: Boolean(userConfirmation),
        executionMode: "batch",
        stopOnError,
      },
    });

    for (let index = 0; index < commands.length; index += 1) {
      const command = commands[index] ?? "";
      const commandPolicy = policy.reviews[index];

      sessionManager.recordAudit({
        level: "info",
        event: "command_started",
        message: `Started batch command ${index + 1} of ${commands.length}.`,
        sessionId: session.id,
        host: session.host,
        username: session.username,
        command,
        riskLevel: commandPolicy?.riskLevel ?? policy.riskLevel,
        details: {
          category: commandPolicy?.category ?? policy.category,
          timeoutMs,
          executionMode: "batch",
          batchIndex: index + 1,
          batchSize: commands.length,
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
          message: `Completed batch command ${index + 1} of ${commands.length} with exit code ${result.exitCode}.`,
          sessionId: session.id,
          host: session.host,
          username: session.username,
          command,
          riskLevel: commandPolicy?.riskLevel ?? policy.riskLevel,
          details: {
            category: commandPolicy?.category ?? policy.category,
            exitCode: result.exitCode,
            executionMs: result.executionMs,
            executionMode: "batch",
            batchIndex: index + 1,
            batchSize: commands.length,
          },
        });

        results.push({
          command,
          index,
          ...result,
          policy: {
            riskLevel: commandPolicy?.riskLevel ?? policy.riskLevel,
            category: commandPolicy?.category ?? policy.category,
          },
          interaction: buildInteractionState(session, stripAnsi),
        });
      } catch (error) {
        if (error instanceof HandledError) {
          error.details["batchResults"] = results;
          error.details["failedCommand"] = command;
          error.details["failedCommandIndex"] = index;
          error.details["batchSize"] = commands.length;

          sessionManager.recordAudit({
            level: error.code === "TIMEOUT" ? "warning" : "error",
            event: error.code === "TIMEOUT" ? "command_timed_out" : "command_failed",
            message: `Batch command ${index + 1} of ${commands.length} failed: ${error.message}`,
            sessionId: session.id,
            host: session.host,
            username: session.username,
            command,
            riskLevel: commandPolicy?.riskLevel ?? policy.riskLevel,
            details: {
              category: commandPolicy?.category ?? policy.category,
              executionMode: "batch",
              batchIndex: index + 1,
              batchSize: commands.length,
              ...error.details,
            },
          });
        }

        if (stopOnError) {
          throw error;
        }

        results.push({
          command,
          index,
          error: normalizeToolError(error),
          policy: {
            riskLevel: commandPolicy?.riskLevel ?? policy.riskLevel,
            category: commandPolicy?.category ?? policy.category,
          },
          interaction: buildInteractionState(session, stripAnsi),
        });
      }
    }

    sessionManager.recordAudit({
      level: "info",
      event: "command_completed",
      message: `Completed execution of a command batch with ${commands.length} command(s).`,
      sessionId: session.id,
      host: session.host,
      username: session.username,
      command: `batch(${commands.length})`,
      riskLevel: policy.riskLevel,
      details: {
        category: policy.category,
        executionMode: "batch",
        completedCount: results.length,
        stopOnError,
      },
    });

    return {
      executed: true,
      commandCount: commands.length,
      completedCount: results.length,
      stopOnError,
      policy: {
        riskLevel: policy.riskLevel,
        category: policy.category,
      },
      results,
    };
  });
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

  return await runExclusiveShellOperation(session, "interrupt_session", async () => {
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
      interaction: buildInteractionState(session, true),
    };
  });
}

async function callReadOutput(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const clear = readBoolean(args, "clear", false);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const session = sessionManager.require(sessionId);
  await waitForPotentialShellAdoption(session, 500);
  const interaction = buildInteractionState(session, stripAnsi);

  if (clear) {
    sessionManager.clearBuffer(session, true);
  } else {
    sessionManager.touch(session);
  }

  return {
    output: interaction["output"],
    bufferLength: interaction["bufferLength"],
    sessionReady: session.ready,
    interaction,
  };
}

async function callReadInteractionState(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const clear = readBoolean(args, "clear", false);
  const stripAnsi = readBoolean(args, "stripAnsi", true);
  const session = sessionManager.require(sessionId);
  await waitForPotentialShellAdoption(session, 500);
  const interaction = buildInteractionState(session, stripAnsi);

  if (clear) {
    sessionManager.clearBuffer(session, true);
  } else {
    sessionManager.touch(session);
  }

  return interaction;
}

async function callResizeTerminal(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const sessionId = readString(args, "sessionId", true) ?? "";
  const cols = readPositiveInteger(args, "cols", DEFAULT_TERMINAL_COLS);
  const rows = readPositiveInteger(args, "rows", DEFAULT_TERMINAL_ROWS);
  const session = sessionManager.require(sessionId);

  return await runExclusiveShellOperation(session, "resize_terminal", async () => {
    session.shell.setWindow(rows, cols, 0, 0);
    session.cols = cols;
    session.rows = rows;
    session.lastUsedAt = Date.now();

    return { resized: true };
  });
}

async function callListSessions(): Promise<Record<string, unknown>> {
  return {
    sessions: sessionManager.list().map((session) => toSessionSummary(session)),
  };
}

async function callOracleConnect(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const credentials = resolveOracleCredentials(args);
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
      username: credentials.username,
      password: credentials.password,
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
      if (
        (error.code === "TIMEOUT" || error.code === "INTERRUPTED") &&
        error.details["sessionReusable"] === false
      ) {
        const closeReason =
          error.code === "TIMEOUT"
            ? "Closed after SQL timeout left the Oracle DB connection unusable."
            : "Closed after SQL interruption left the Oracle DB connection unusable.";
        await closeBrokenOracleSession(
          session,
          dbSessionManager,
          closeReason,
        );
        dbSessionClosed = true;
        error.details["dbSessionClosed"] = true;

        sessionManager.recordAudit({
          level: "warning",
          event: "db_session_closed",
          message:
            error.code === "TIMEOUT"
              ? "Closed Oracle DB session after an unrecoverable SQL timeout."
              : "Closed Oracle DB session after an unrecoverable SQL interruption.",
          sessionId: session.id,
          host: session.connectTarget,
          username: session.username,
          details: {
            reason: closeReason,
          },
        });
      }

      sessionManager.recordAudit({
        level:
          error.code === "TIMEOUT" || error.code === "INTERRUPTED" ? "warning" : "error",
        event:
          error.code === "TIMEOUT"
            ? "sql_timed_out"
            : error.code === "INTERRUPTED"
              ? "sql_interrupted"
              : "sql_failed",
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

async function callListNmsGuides(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const version = readString(args, "version");
  const result = await listNmsGuides({
    versionQuery: version,
  });
  return {
    ...result,
  };
}

async function callGetNmsGuidePdf(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const version = readString(args, "version", true) ?? "";
  const guide = readString(args, "guide", true) ?? "";
  const refresh = readBoolean(args, "refresh", false);

  const result = await resolveNmsGuidePdf({
    versionQuery: version,
    guideQuery: guide,
    refresh,
  });
  return {
    ...result,
  };
}

async function callReadPolicy(): Promise<Record<string, unknown>> {
  return {
    ...summarizeCombinedPolicyConfig(commandPolicyConfig, sqlPolicyConfig),
    auditLogFile: DEFAULT_AUDIT_LOG_FILE,
  };
}

async function callReadUsageGuide(): Promise<Record<string, unknown>> {
  return {
    usageGuide: getUsageGuide(),
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

async function callInterruptDbSession(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const dbSessionId = readString(args, "dbSessionId", true) ?? "";
  const waitForIdleMs = readPositiveInteger(args, "waitForIdleMs", 5000);
  const session = dbSessionManager.require(dbSessionId);

  const result = await interruptOracleExecution(session, {
    waitForIdleMs,
  });

  let dbSessionClosed = false;
  if (
    result.interruptedExecution &&
    !result.sessionBusy &&
    result.sessionReusable === false
  ) {
    await closeBrokenOracleSession(
      session,
      dbSessionManager,
      "Closed after SQL interruption left the Oracle DB connection unusable.",
    );
    dbSessionClosed = true;
  }

  sessionManager.recordAudit({
    level: "warning",
    event: "db_session_interrupted",
    message: result.interruptedExecution
      ? "Requested interruption of the active Oracle DB statement."
      : "Interrupt requested for an idle Oracle DB session.",
    sessionId: session.id,
    host: session.connectTarget,
    username: session.username,
    details: {
      waitForIdleMs,
      interruptedExecution: result.interruptedExecution,
      sessionBusy: result.sessionBusy,
      waitTimedOut: result.waitTimedOut,
      sessionReusable: result.sessionReusable,
      dbSessionClosed,
      sql: result.sql,
      driverMessage: result.driverMessage ?? null,
    },
  });

  return {
    interrupted: result.interruptedExecution,
    sessionBusy: result.sessionBusy,
    waitTimedOut: result.waitTimedOut,
    sessionReusable: result.sessionReusable,
    dbSessionClosed,
    dbSessionId: session.id,
    sql: result.sql,
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
      case "start_interactive_command":
        return await safeToolCall(() => callStartInteractiveCommand(args));
      case "execute_command_batch":
        return await safeToolCall(() => callExecuteCommandBatch(args));
      case "review_command":
        return await safeToolCall(() => callReviewCommand(args));
      case "review_command_batch":
        return await safeToolCall(() => callReviewCommandBatch(args));
      case "write_stdin":
        return await safeToolCall(() => callWriteStdin(args));
      case "send_interaction_input":
        return await safeToolCall(() => callSendInteractionInput(args));
      case "read_output":
        return await safeToolCall(() => callReadOutput(args));
      case "read_interaction_state":
        return await safeToolCall(() => callReadInteractionState(args));
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
      case "list_nms_guides":
        return await safeToolCall(() => callListNmsGuides(args));
      case "get_nms_guide_pdf":
        return await safeToolCall(() => callGetNmsGuidePdf(args));
      case "read_usage_guide":
        return await safeToolCall(() => callReadUsageGuide());
      case "read_policy":
        return await safeToolCall(() => callReadPolicy());
      case "read_audit_log":
        return await safeToolCall(() => callReadAuditLog(args));
      case "close_session":
        return await safeToolCall(() => callCloseSession(args));
      case "close_db_session":
        return await safeToolCall(() => callCloseDbSession(args));
      case "interrupt_db_session":
        return await safeToolCall(() => callInterruptDbSession(args));
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
