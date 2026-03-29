import type { ShellSession } from "./session.js";

import { maybeInjectSudoPassword, updateSessionSudoState } from "./sudo.js";
import {
  cleanCommandOutput,
  detectShellPrompt,
  escapeRegExp,
  generateSentinel,
  HandledError,
  SHELL_PROMPT_MARKER,
  sleep,
} from "./utils.js";

export interface ExecuteCommandOptions {
  timeoutMs: number;
  sudoPassword?: string;
  stripAnsiOutput: boolean;
}

export interface ExecuteCommandResult {
  stdout: string;
  exitCode: number;
  timedOut: false;
  executionMs: number;
}

export interface StartInteractiveCommandOptions {
  timeoutMs: number;
  sudoPassword?: string;
  stripAnsiOutput: boolean;
  waitForOutputMs: number;
}

export interface StartInteractiveCommandResult {
  stdout: string;
  started: true;
  completed: boolean;
  exitCode: number | null;
  executionMs: number;
}

export interface InterruptSessionOptions {
  signal: "ctrlC" | "ctrlD" | "newline";
  waitForReadyMs: number;
  clearBuffer: boolean;
}

function buildWrappedCommand(command: string, sentinelId: string): string {
  const escapedCommand = command
    .replace(/\\/g, "\\\\")
    .replace(/'/g, `'\\''`)
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");

  return (
    `__mcp_cmd='${escapedCommand}'; ` +
    `eval "$(printf '%b' "$__mcp_cmd")"; ` +
    `__mcp_exit_code=$?; ` +
    `export PS1='${SHELL_PROMPT_MARKER} '; ` +
    `PROMPT_COMMAND=; ` +
    `echo "${sentinelId}_$__mcp_exit_code"\n`
  );
}

function ensureSessionCanStartCommand(session: ShellSession): void {
  handleShellData(session);

  if (session.activeCommand?.completed) {
    session.activeCommand = undefined;
  }

  if (session.activeCommand || !session.ready) {
    throw new HandledError(
      "SHELL_BUSY",
      "The PTY shell is still busy with a previous command or interactive program.",
    );
  }

  if (session.closed) {
    throw new HandledError(
      "SESSION_NOT_FOUND",
      `Session "${session.id}" is no longer available.`,
    );
  }
}

function beginCommand(
  session: ShellSession,
  command: string,
  options: {
    timeoutMs: number;
    sudoPassword?: string;
    stripAnsiOutput: boolean;
    executionMode: "oneshot" | "interactive";
  },
): { sentinelId: string; startedAt: number } {
  const sentinelId = generateSentinel();
  const startedAt = Date.now();
  const submittedCommand = buildWrappedCommand(command, sentinelId);

  session.activeCommand = {
    command,
    submittedCommand,
    executionMode: options.executionMode,
    sentinelId,
    startedAt,
    timeoutMs: options.timeoutMs,
    buffer: "",
    sudoPassword: options.sudoPassword,
    sudoPromptAttempts: 0,
    lastSudoPromptBufferLength: 0,
    completed: false,
    timedOutReported: false,
    stripAnsiOutput: options.stripAnsiOutput,
  };
  session.ready = false;
  session.manualMode = options.executionMode === "interactive";
  session.lastUsedAt = startedAt;

  session.shell.write(submittedCommand);

  return {
    sentinelId,
    startedAt,
  };
}

function cleanActiveCommandOutput(session: ShellSession): string {
  const activeCommand = session.activeCommand;
  if (!activeCommand) {
    return "";
  }

  return cleanCommandOutput(
    activeCommand.buffer,
    activeCommand.submittedCommand,
    activeCommand.stripAnsiOutput,
  );
}

function maybeFinalizeActiveCommand(session: ShellSession): void {
  const activeCommand = session.activeCommand;
  if (!activeCommand || activeCommand.completed) {
    return;
  }

  maybeInjectSudoPassword(session, activeCommand);

  const sentinelPattern = new RegExp(`${escapeRegExp(activeCommand.sentinelId)}_(\\d+)`);
  const match = activeCommand.buffer.match(sentinelPattern);
  if (!match) {
    if (activeCommand.timedOutReported && detectShellPrompt(session.buffer)) {
      session.activeCommand = undefined;
      session.ready = true;
      session.manualMode = false;
    }

    return;
  }

  const exitCode = Number.parseInt(match[1] ?? "0", 10);
  activeCommand.completed = true;
  activeCommand.completedAt = Date.now();
  activeCommand.exitCode = Number.isFinite(exitCode) ? exitCode : 0;
  activeCommand.output = cleanCommandOutput(
    activeCommand.buffer,
    activeCommand.submittedCommand,
    activeCommand.stripAnsiOutput,
  );

  session.ready = true;
  session.manualMode = false;
  updateSessionSudoState(session, activeCommand.command, activeCommand.exitCode);

  if (activeCommand.timedOutReported) {
    session.activeCommand = undefined;
  }
}

export function handleShellData(session: ShellSession): void {
  const activeCommand = session.activeCommand;
  if (activeCommand) {
    maybeFinalizeActiveCommand(session);
    return;
  }

  if (!session.ready && detectShellPrompt(session.buffer)) {
    session.ready = true;
    session.manualMode = false;
  }
}

export function markSessionInterrupted(session: ShellSession): boolean {
  const activeCommand = session.activeCommand;
  if (!activeCommand || activeCommand.completed) {
    return false;
  }

  // When a client interrupts a running PTY command, the queued sentinel may
  // never be emitted. Marking the command this way lets prompt detection clear
  // the stuck busy state as soon as the shell comes back.
  activeCommand.timedOutReported = true;
  activeCommand.closedReason = undefined;
  return true;
}

export async function waitForSessionReady(
  session: ShellSession,
  timeoutMs: number,
): Promise<boolean> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (session.closed) {
      return false;
    }

    if (session.ready) {
      return true;
    }

    if (!session.activeCommand && detectShellPrompt(session.buffer)) {
      session.ready = true;
      session.manualMode = false;
      return true;
    }

    await sleep(50);
  }

  return session.ready;
}

export async function waitForCommandActivity(
  session: ShellSession,
  previousOutputLength: number,
  timeoutMs: number,
): Promise<{ observedOutput: boolean; commandCompleted: boolean; sessionReady: boolean }> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (session.closed) {
      return {
        observedOutput: false,
        commandCompleted: false,
        sessionReady: false,
      };
    }

    handleShellData(session);
    const activeCommand = session.activeCommand;
    if (!activeCommand) {
      return {
        observedOutput: session.buffer.length > previousOutputLength,
        commandCompleted: true,
        sessionReady: session.ready,
      };
    }

    if (activeCommand.completed || activeCommand.buffer.length > previousOutputLength) {
      return {
        observedOutput: activeCommand.buffer.length > previousOutputLength,
        commandCompleted: activeCommand.completed,
        sessionReady: session.ready,
      };
    }

    await sleep(50);
  }

  const activeCommand = session.activeCommand;
  return {
    observedOutput: Boolean(activeCommand && activeCommand.buffer.length > previousOutputLength),
    commandCompleted: Boolean(activeCommand?.completed),
    sessionReady: session.ready,
  };
}

export async function interruptSession(
  session: ShellSession,
  options: InterruptSessionOptions,
): Promise<{ sessionReady: boolean; clearedActiveCommand: boolean }> {
  const signalText =
    options.signal === "ctrlD"
      ? "\x04"
      : options.signal === "newline"
        ? "\n"
        : "\x03";

  const clearedActiveCommand = markSessionInterrupted(session);

  if (options.clearBuffer) {
    session.buffer = "";
  }

  session.shell.write(signalText);
  session.lastUsedAt = Date.now();

  const sessionReady =
    options.waitForReadyMs > 0 ? await waitForSessionReady(session, options.waitForReadyMs) : session.ready;

  return {
    sessionReady,
    clearedActiveCommand,
  };
}

export async function executeCommand(
  session: ShellSession,
  command: string,
  options: ExecuteCommandOptions,
): Promise<ExecuteCommandResult> {
  ensureSessionCanStartCommand(session);
  const { startedAt } = beginCommand(session, command, {
    timeoutMs: options.timeoutMs,
    sudoPassword: options.sudoPassword,
    stripAnsiOutput: options.stripAnsiOutput,
    executionMode: "oneshot",
  });

  while (true) {
    const activeCommand = session.activeCommand;
    if (!activeCommand) {
      throw new HandledError(
        "SESSION_NOT_FOUND",
        `Session "${session.id}" closed before the command completed.`,
      );
    }

    if (activeCommand.closedReason) {
      session.activeCommand = undefined;
      throw new HandledError("SESSION_NOT_FOUND", activeCommand.closedReason);
    }

    if (activeCommand.completed) {
      const executionMs = (activeCommand.completedAt ?? Date.now()) - startedAt;
      if (session.activeCommand === activeCommand) {
        session.activeCommand = undefined;
      }

      session.lastUsedAt = Date.now();
      return {
        stdout: activeCommand.output ?? "",
        exitCode: activeCommand.exitCode ?? 0,
        timedOut: false,
        executionMs,
      };
    }

    const executionMs = Date.now() - startedAt;
    if (executionMs >= options.timeoutMs) {
      activeCommand.timedOutReported = true;
      session.lastUsedAt = Date.now();

      throw new HandledError(
        "TIMEOUT",
        `Command timed out after ${options.timeoutMs}ms. The shell is still attached; use read_output or read_interaction_state to inspect it, then send_interaction_input or write_stdin to continue managing it.`,
        {
          partialOutput: cleanActiveCommandOutput(session),
          executionMs,
          timedOut: true,
        },
      );
    }

    await sleep(50);
  }
}

export async function startInteractiveCommand(
  session: ShellSession,
  command: string,
  options: StartInteractiveCommandOptions,
): Promise<StartInteractiveCommandResult> {
  ensureSessionCanStartCommand(session);
  const { startedAt } = beginCommand(session, command, {
    timeoutMs: options.timeoutMs,
    sudoPassword: options.sudoPassword,
    stripAnsiOutput: options.stripAnsiOutput,
    executionMode: "interactive",
  });

  const baselineOutputLength = session.activeCommand?.buffer.length ?? 0;
  if (options.waitForOutputMs > 0) {
    await waitForCommandActivity(session, baselineOutputLength, options.waitForOutputMs);
  }

  const activeCommand = session.activeCommand;
  const completed = Boolean(activeCommand?.completed);
  const executionMs = Date.now() - startedAt;

  if (completed && activeCommand) {
    const stdout = activeCommand.output ?? cleanActiveCommandOutput(session);
    return {
      stdout,
      started: true,
      completed: true,
      exitCode: activeCommand.exitCode ?? 0,
      executionMs,
    };
  }

  return {
    stdout: cleanActiveCommandOutput(session),
    started: true,
    completed: false,
    exitCode: null,
    executionMs,
  };
}
