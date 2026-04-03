import {
  setSessionIdentity,
  type ActiveCommandState,
  type ShellPrivilegeMode,
  type ShellSession,
} from "./session.js";
import { stripAnsiPreserveWhitespace } from "./utils.js";

const MAX_SUDO_PROMPT_ATTEMPTS = 3;
const SHELL_EXIT_PATTERN = /^\s*(?:exit|logout)\s*$/i;
const SUDO_PROMPT_AT_END_PATTERNS = [
  /\[sudo\] password(?: for [^:\n]+)?:\s*$/i,
  /password for [^:\n]+:\s*$/i,
];

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

function chooseHereDocDelimiter(value: string): string {
  let delimiter = "__MCP_SUDO_PASSWORD__";
  while (
    value === delimiter ||
    value.startsWith(`${delimiter}\n`) ||
    value.endsWith(`\n${delimiter}`) ||
    value.includes(`\n${delimiter}\n`)
  ) {
    delimiter = `${delimiter}_X`;
  }

  return delimiter;
}

const SUDO_OPTIONS_WITH_VALUE = new Set([
  "-g",
  "-h",
  "-p",
  "-r",
  "-t",
  "-u",
  "-C",
  "-T",
  "--chdir",
  "--close-from",
  "--group",
  "--host",
  "--prompt",
  "--role",
  "--type",
  "--user",
]);

function stripNonInteractiveSudoFlags(commandRemainder: string): string {
  const tokens = normalizeCommand(commandRemainder)
    .split(" ")
    .map((token) => token.trim())
    .filter(Boolean);
  const rewrittenTokens: string[] = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] ?? "";
    const lowerToken = token.toLowerCase();

    if (token === "-n" || lowerToken === "--non-interactive") {
      continue;
    }

    if (token === "--") {
      rewrittenTokens.push(...tokens.slice(index));
      break;
    }

    if (!token.startsWith("-")) {
      rewrittenTokens.push(...tokens.slice(index));
      break;
    }

    rewrittenTokens.push(token);
    if (SUDO_OPTIONS_WITH_VALUE.has(token) || SUDO_OPTIONS_WITH_VALUE.has(lowerToken)) {
      const nextToken = tokens[index + 1];
      if (nextToken) {
        rewrittenTokens.push(nextToken);
        index += 1;
      }
    }
  }

  return rewrittenTokens.join(" ");
}

function tokenize(command: string): string[] {
  return normalizeCommand(command)
    .split(" ")
    .map((token) => token.trim())
    .filter(Boolean);
}

function isShellProgram(token: string): boolean {
  const program = token.split("/").at(-1)?.toLowerCase() ?? token.toLowerCase();
  return ["sh", "bash", "ksh", "zsh", "csh", "tcsh"].includes(program);
}

function isShellCommandInvocation(commandTokens: string[]): boolean {
  if (commandTokens.length === 0) {
    return false;
  }

  const [program, ...args] = commandTokens;
  if (!isShellProgram(program)) {
    return false;
  }

  return !args.some((arg) => /^-[A-Za-z]*c[A-Za-z]*$/.test(arg) || arg === "--command");
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
  let explicitCommandTokens: string[] = [];

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

    if (token === "--") {
      explicitCommandTokens = tokens.slice(index + 1);
      break;
    }

    if (lowerToken === "-u" || token === "-U") {
      explicitUser = tokens[index + 1] ?? explicitUser;
      index += 1;
      continue;
    }

    if (!token.startsWith("-")) {
      explicitCommandTokens = tokens.slice(index);
      break;
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
    if (
      explicitCommandTokens.length > 0 &&
      !isShellCommandInvocation(explicitCommandTokens)
    ) {
      return null;
    }

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

export function rewriteSudoCommandWithPassword(
  command: string,
  sudoPassword?: string,
): {
  rewrittenCommand: string;
  usesPromptInjection: boolean;
} {
  if (!sudoPassword || inferShellIdentityTransition(command)) {
    return {
      rewrittenCommand: command,
      usesPromptInjection: Boolean(sudoPassword),
    };
  }

  const sudoPrefixPattern =
    /^\s*((?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)\s+)*)sudo\b/i;
  const sudoPrefixMatch = command.match(sudoPrefixPattern);
  if (!sudoPrefixMatch) {
    return {
      rewrittenCommand: command,
      usesPromptInjection: Boolean(sudoPassword),
    };
  }

  const envPrefix = sudoPrefixMatch[1] ?? "";
  const rest = stripNonInteractiveSudoFlags(command.slice(sudoPrefixMatch[0].length));
  const delimiter = chooseHereDocDelimiter(sudoPassword);

  return {
    rewrittenCommand: `cat <<'${delimiter}' | ${envPrefix}sudo -S -p '' ${rest}\n${sudoPassword}\n${delimiter}`,
    usesPromptInjection: false,
  };
}

export function maybeInjectSudoPassword(
  session: ShellSession,
  activeCommand: ActiveCommandState,
): void {
  if (!activeCommand.sudoPassword || activeCommand.sudoPromptAttempts >= MAX_SUDO_PROMPT_ATTEMPTS) {
    return;
  }

  const strippedTail = stripAnsiPreserveWhitespace(activeCommand.buffer).slice(-256);
  const promptMatch = SUDO_PROMPT_AT_END_PATTERNS.map((pattern) => strippedTail.match(pattern)).find(Boolean);
  const promptSignature = promptMatch?.[0]?.trim();

  if (!promptSignature) {
    return;
  }

  if (
    activeCommand.buffer.length === activeCommand.lastSudoPromptBufferLength &&
    activeCommand.lastSudoPromptSignature === promptSignature
  ) {
    return;
  }

  // PTY shells expose one merged stream, so the simplest reliable place to
  // answer sudo is directly in the active channel the moment the prompt appears.
  activeCommand.sudoPromptAttempts += 1;
  activeCommand.lastSudoPromptBufferLength = activeCommand.buffer.length;
  activeCommand.lastSudoPromptSignature = promptSignature;
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
