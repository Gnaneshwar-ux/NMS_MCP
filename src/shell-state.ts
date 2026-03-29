import {
  recordShellAdoption,
  recordShellBootstrap,
  recordShellBootstrapFailure,
  setSessionIdentity,
  type ShellPrivilegeMode,
  type ShellSession,
} from "./session.js";
import {
  applyInteractiveShellIdentityTransition,
  inferShellIdentityTransition,
  type ShellIdentityTransition,
} from "./sudo.js";
import {
  cleanCommandOutput,
  detectShellPrompt,
  escapeRegExp,
  getErrorMessage,
  HandledError,
  SHELL_PROMPT_MARKER,
  SHELL_READY_MARKER_PREFIX,
  sleep,
} from "./utils.js";

export interface ShellBootstrapResult {
  readyMarker: string;
  effectiveUser: string | null;
}

export interface ShellAdoptionResult {
  adopted: boolean;
  effectiveUser: string | null;
  stdout: string;
  adoptionError?: string;
}

function createReadyMarker(): string {
  return `${SHELL_READY_MARKER_PREFIX}${Date.now()}_${Math.floor(Math.random() * 1000)}`;
}

function buildBootstrapCommand(readyMarker: string): string {
  return (
    `__mcp_user="$(id -un 2>/dev/null || whoami 2>/dev/null || printf unknown)"; ` +
    `stty -echo 2>/dev/null || true; ` +
    `bind 'set enable-bracketed-paste off' 2>/dev/null || true; ` +
    `export PS1='${SHELL_PROMPT_MARKER} '; ` +
    `export PS2=''; ` +
    `PROMPT_COMMAND=; ` +
    `printf '${readyMarker}|%s\\n' "$__mcp_user"`
  );
}

function parseBootstrapResult(buffer: string, readyMarker: string): ShellBootstrapResult | null {
  const pattern = new RegExp(`(?:^|[\\r\\n])${escapeRegExp(readyMarker)}\\|([^\\r\\n]+)`);
  const match = buffer.match(pattern);
  if (!match) {
    return null;
  }

  return {
    readyMarker,
    effectiveUser: match[1]?.trim() || null,
  };
}

function resolvePrivilegeMode(
  session: ShellSession,
  effectiveUser: string | null,
  transition?: ShellIdentityTransition | null,
): ShellPrivilegeMode {
  if (!effectiveUser || effectiveUser === session.identity.loginUser) {
    return "standard";
  }

  if (effectiveUser === "root") {
    return "root";
  }

  if (transition?.privilegeMode) {
    return transition.privilegeMode;
  }

  return session.identity.privilegeMode === "sudo" ? "sudo" : "su";
}

export async function bootstrapShell(
  session: ShellSession,
  timeoutMs: number,
  reason: string,
  transition?: ShellIdentityTransition | null,
): Promise<ShellBootstrapResult> {
  const readyMarker = createReadyMarker();
  const setupLine = buildBootstrapCommand(readyMarker);
  const startedAt = Date.now();

  session.shell.write(`${setupLine}\n`);

  while (Date.now() - startedAt < timeoutMs) {
    if (session.closed) {
      throw new HandledError(
        "CONNECT_TIMEOUT",
        session.closeReason ?? "The remote shell closed before bootstrap completed.",
      );
    }

    const result = parseBootstrapResult(session.buffer, readyMarker);
    if (result) {
      const privilegeMode = resolvePrivilegeMode(session, result.effectiveUser, transition);
      setSessionIdentity(session, {
        effectiveUser: result.effectiveUser ?? session.identity.effectiveUser,
        privilegeMode,
        promptMarkerActive: true,
        source: "bootstrap",
      });
      recordShellBootstrap(session, reason, readyMarker, reason !== "initial-connect");
      session.ready = true;
      session.lastUsedAt = Date.now();
      return result;
    }

    await sleep(50);
  }

  const error = new HandledError(
    "CONNECT_TIMEOUT",
    `Timed out waiting for the remote PTY shell to finish bootstrap after ${timeoutMs}ms.`,
  );
  recordShellBootstrapFailure(session, reason, error.message);
  throw error;
}

export async function maybeAdoptInteractiveShell(
  session: ShellSession,
  timeoutMs: number,
): Promise<ShellAdoptionResult> {
  const activeCommand = session.activeCommand;
  if (!activeCommand || activeCommand.completed || activeCommand.executionMode !== "interactive") {
    return {
      adopted: false,
      effectiveUser: null,
      stdout: "",
    };
  }

  const transition = inferShellIdentityTransition(activeCommand.command);
  if (!transition) {
    return {
      adopted: false,
      effectiveUser: null,
      stdout: "",
    };
  }

  const promptBuffer = activeCommand.buffer || session.buffer;
  if (!detectShellPrompt(promptBuffer)) {
    return {
      adopted: false,
      effectiveUser: null,
      stdout: cleanCommandOutput(
        activeCommand.buffer,
        activeCommand.submittedCommand,
        activeCommand.stripAnsiOutput,
      ),
    };
  }

  const stdout = cleanCommandOutput(
    activeCommand.buffer,
    activeCommand.submittedCommand,
    activeCommand.stripAnsiOutput,
  );

  try {
    const result = await bootstrapShell(
      session,
      Math.max(500, Math.min(timeoutMs, 5_000)),
      `interactive shell adoption for ${transition.sourceCommand}`,
      transition,
    );
    applyInteractiveShellIdentityTransition(session, transition, result.effectiveUser ?? undefined);
    recordShellAdoption(session);
    session.activeCommand = undefined;
    session.manualMode = false;
    session.ready = true;

    return {
      adopted: true,
      effectiveUser: result.effectiveUser,
      stdout,
    };
  } catch (error) {
    return {
      adopted: false,
      effectiveUser: null,
      stdout,
      adoptionError: getErrorMessage(error),
    };
  }
}
