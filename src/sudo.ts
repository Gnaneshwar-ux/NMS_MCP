import {
  setSessionIdentity,
  type ActiveCommandState,
  type ShellPrivilegeMode,
  type ShellSession,
} from "./session.js";

const SUDO_PROMPT_PATTERNS = [/\[sudo\] password/i, /password for .+:/i];
const MAX_SUDO_PROMPT_ATTEMPTS = 3;
const SHELL_EXIT_PATTERN = /^\s*(?:exit|logout)\s*$/i;

export interface ShellIdentityTransition {
  adoptsShell: boolean;
  expectedUser: string;
  privilegeMode: ShellPrivilegeMode;
  viaSudo: boolean;
  sourceCommand: string;
}

function normalizeCommand(command: string): string {
  return command.replace(/\s+/g, " ").trim();
}

function tokenize(command: string): string[] {
  return normalizeCommand(command)
    .split(" ")
    .map((token) => token.trim())
    .filter(Boolean);
}

function inferSuTransition(command: string): ShellIdentityTransition | null {
  const tokens = tokenize(command);
  if (tokens[0]?.toLowerCase() !== "su") {
    return null;
  }

  const expectedUser =
    tokens
      .slice(1)
      .find((token) => token !== "-" && !token.startsWith("-")) ?? "root";
  return {
    adoptsShell: true,
    expectedUser,
    privilegeMode: expectedUser === "root" ? "root" : "su",
    viaSudo: false,
    sourceCommand: normalizeCommand(command),
  };
}

function inferSudoTransition(command: string): ShellIdentityTransition | null {
  const normalized = normalizeCommand(command);
  const tokens = tokenize(command);
  if (tokens[0]?.toLowerCase() !== "sudo") {
    return null;
  }

  let explicitUser: string | undefined;
  let launchesShell = false;

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index] ?? "";
    const lowerToken = token.toLowerCase();

    if (lowerToken === "su") {
      const suTransition = inferSuTransition(tokens.slice(index).join(" "));
      const expectedUser = suTransition?.expectedUser ?? explicitUser ?? "root";
      return {
        adoptsShell: true,
        expectedUser,
        privilegeMode: expectedUser === "root" ? "root" : "sudo",
        viaSudo: true,
        sourceCommand: normalized,
      };
    }

    if (lowerToken === "-u" || token === "-U") {
      explicitUser = tokens[index + 1] ?? explicitUser;
      index += 1;
      continue;
    }

    if (!token.startsWith("-")) {
      continue;
    }

    const shortFlags = token.slice(1);
    const normalizedFlags = shortFlags.toLowerCase();
    if (normalizedFlags.includes("s") || normalizedFlags.includes("i")) {
      launchesShell = true;
    }

    const uIndex = normalizedFlags.indexOf("u");
    if (uIndex >= 0) {
      if (shortFlags.length > uIndex + 1) {
        explicitUser = shortFlags.slice(uIndex + 1);
      } else {
        explicitUser = tokens[index + 1] ?? explicitUser;
        index += 1;
      }
    }
  }

  if (launchesShell) {
    const expectedUser = explicitUser ?? "root";
    return {
      adoptsShell: true,
      expectedUser,
      privilegeMode: expectedUser === "root" ? "root" : "sudo",
      viaSudo: true,
      sourceCommand: normalized,
    };
  }

  return null;
}

export function inferShellIdentityTransition(command: string): ShellIdentityTransition | null {
  return inferSuTransition(command) ?? inferSudoTransition(command);
}

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

export function applyInteractiveShellIdentityTransition(
  session: ShellSession,
  transition: ShellIdentityTransition,
  effectiveUserOverride?: string,
): void {
  const effectiveUser = effectiveUserOverride?.trim() || transition.expectedUser;
  setSessionIdentity(session, {
    effectiveUser,
    privilegeMode:
      effectiveUser === session.identity.loginUser
        ? "standard"
        : effectiveUser === "root"
          ? "root"
          : transition.privilegeMode,
    promptMarkerActive: true,
    source: "bootstrap",
  });
}

export function updateSessionSudoState(
  session: ShellSession,
  command: string,
  exitCode: number,
): void {
  if (exitCode !== 0) {
    return;
  }

  const transition = inferShellIdentityTransition(command);
  if (transition) {
    applyInteractiveShellIdentityTransition(session, transition);
    return;
  }

  if (session.identity.effectiveUser !== session.identity.loginUser && SHELL_EXIT_PATTERN.test(command)) {
    setSessionIdentity(session, {
      effectiveUser: session.identity.loginUser,
      privilegeMode: "standard",
      promptMarkerActive: session.identity.promptMarkerActive,
      source: "inferred",
    });
  }
}
