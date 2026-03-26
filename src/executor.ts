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

export interface InterruptSessionOptions {
  signal: "ctrlC" | "ctrlD" | "newline";
  waitForReadyMs: number;
  clearBuffer: boolean;
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
    activeCommand.command,
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

  const sentinelId = generateSentinel();
  const startedAt = Date.now();
  const completionLine =
    `__mcp_exit_code=$?; export PS1='${SHELL_PROMPT_MARKER} '; ` +
    `PROMPT_COMMAND=; echo "${sentinelId}_\${__mcp_exit_code}"`;

  session.activeCommand = {
    command,
    sentinelId,
    startedAt,
    timeoutMs: options.timeoutMs,
    buffer: "",
    sudoPassword: options.sudoPassword,
    sudoPromptAttempts: 0,
    completed: false,
    timedOutReported: false,
    stripAnsiOutput: options.stripAnsiOutput,
  };
  session.ready = false;
  session.manualMode = false;
  session.lastUsedAt = startedAt;

  // The sentinel line is queued after the user's command in the same PTY so we
  // can wait for real shell completion instead of guessing with fixed sleeps.
  session.shell.write(`${command}\n${completionLine}\n`);

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
        `Command timed out after ${options.timeoutMs}ms. The shell is still attached; use read_output or write_stdin to continue managing it.`,
        {
          partialOutput: cleanCommandOutput(
            activeCommand.buffer,
            activeCommand.command,
            activeCommand.stripAnsiOutput,
          ),
          executionMs,
          timedOut: true,
        },
      );
    }

    await sleep(50);
  }
}
