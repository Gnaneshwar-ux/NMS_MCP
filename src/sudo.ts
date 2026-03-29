import type { ActiveCommandState, ShellSession } from "./session.js";

const SUDO_PROMPT_PATTERNS = [/\[sudo\] password/i, /password for .+:/i];
const MAX_SUDO_PROMPT_ATTEMPTS = 3;
const SUDO_LOGIN_SHELL_PATTERNS = [
  /^\s*sudo\b(?:(?!\n).)*\s-s(?:\s|$)/i,
  /^\s*sudo\b(?:(?!\n).)*\s-i(?:\s|$)/i,
  /^\s*sudo\b(?:(?!\n).)*\bsu\b/i,
];
const SHELL_EXIT_PATTERN = /^\s*(?:exit|logout)\s*$/i;

export function maybeInjectSudoPassword(
  session: ShellSession,
  activeCommand: ActiveCommandState,
): void {
  if (!activeCommand.sudoPassword || activeCommand.sudoPromptAttempts >= MAX_SUDO_PROMPT_ATTEMPTS) {
    return;
  }

  const tail = activeCommand.buffer.slice(-256);
  if (
    activeCommand.buffer.length === activeCommand.lastSudoPromptBufferLength ||
    !SUDO_PROMPT_PATTERNS.some((pattern) => pattern.test(tail))
  ) {
    return;
  }

  // PTY shells expose one merged stream, so the simplest reliable place to
  // answer sudo is directly in the active channel the moment the prompt appears.
  activeCommand.sudoPromptAttempts += 1;
  activeCommand.lastSudoPromptBufferLength = activeCommand.buffer.length;
  session.shell.write(`${activeCommand.sudoPassword}\n`);
}

export function updateSessionSudoState(
  session: ShellSession,
  command: string,
  exitCode: number,
): void {
  if (exitCode !== 0) {
    return;
  }

  if (SUDO_LOGIN_SHELL_PATTERNS.some((pattern) => pattern.test(command))) {
    session.isSudo = true;
    return;
  }

  if (session.isSudo && SHELL_EXIT_PATTERN.test(command)) {
    session.isSudo = false;
  }
}
