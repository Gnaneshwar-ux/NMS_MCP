import { promises as fs } from "node:fs";
import process from "node:process";

import {
  Client,
  type Algorithms,
  type CipherAlgorithm,
  type ClientChannel,
  type CompressionAlgorithm,
  type ConnectConfig,
  type KexAlgorithm,
  type MacAlgorithm,
  type ServerHostKeyAlgorithm,
} from "ssh2";
import { v4 as uuidv4 } from "uuid";

import { handleShellData } from "./executor.js";
import { bootstrapShell } from "./shell-state.js";
import {
  createInitialShellIdentity,
  type SessionManager,
  type ShellSession,
} from "./session.js";
import {
  appendRollingBuffer,
  cleanInitialBanner,
  DEFAULT_BUFFER_LIMIT,
  DEFAULT_TERMINAL_COLS,
  DEFAULT_TERMINAL_ROWS,
  getErrorMessage,
  HandledError,
} from "./utils.js";

export type AuthMethod = "password" | "privateKey" | "agent";

const COMPAT_CIPHERS: CipherAlgorithm[] = [
  "aes128-ctr",
  "aes192-ctr",
  "aes256-ctr",
  "aes128-gcm",
  "aes128-gcm@openssh.com",
  "aes256-gcm",
  "aes256-gcm@openssh.com",
];

const COMPAT_HMACS: MacAlgorithm[] = [
  "hmac-sha2-256",
  "hmac-sha2-512",
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512-etm@openssh.com",
  "hmac-sha1",
];

const COMPAT_KEX: KexAlgorithm[] = [
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
  "ecdh-sha2-nistp256",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp521",
  "diffie-hellman-group14-sha256",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group-exchange-sha256",
];

const COMPAT_HOST_KEYS: ServerHostKeyAlgorithm[] = [
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "rsa-sha2-256",
  "rsa-sha2-512",
  "ssh-rsa",
];

const COMPAT_COMPRESSION: CompressionAlgorithm[] = [
  "none",
  "zlib@openssh.com",
  "zlib",
];

type AlgorithmProfile = "compat" | "default";

interface ConnectShellOptions {
  host: string;
  port: number;
  username: string;
  authMethod: AuthMethod;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  sessionLabel?: string;
  connectTimeout: number;
  sessionManager: SessionManager;
}

interface ReadyConnection {
  client: Client;
  shell: ClientChannel;
  serverBanner?: string;
}

function normalizeConnectError(error: unknown): Error {
  const message = getErrorMessage(error);
  const errorLevel =
    typeof error === "object" && error && "level" in error
      ? String((error as { level?: string }).level ?? "")
      : "";

  if (
    errorLevel === "client-authentication" ||
    /all configured authentication methods failed|authentication failed|permission denied|failed to retrieve identities from agent/i.test(
      message,
    )
  ) {
    return new HandledError("AUTH_FAILED", message || "SSH authentication failed.");
  }

  return error instanceof Error ? error : new Error(message);
}

export function resolveClientAlgorithms(profile = process.env.MCP_SSH_ALGORITHM_PROFILE?.trim().toLowerCase() ?? "compat"): Algorithms | undefined {
  switch (profile) {
    case "":
    case "compat":
      // Prefer CTR + SHA-2 MACs first because that combination has been the
      // most reliable over flaky VPN/private routes in our NMS environments.
      return {
        cipher: COMPAT_CIPHERS,
        hmac: COMPAT_HMACS,
        kex: COMPAT_KEX,
        serverHostKey: COMPAT_HOST_KEYS,
        compress: COMPAT_COMPRESSION,
      };
    case "default":
      return undefined;
    default:
      throw new HandledError(
        "INVALID_ARGUMENT",
        `Unsupported MCP_SSH_ALGORITHM_PROFILE "${profile}". Use "compat" or "default".`,
      );
  }
}

async function resolvePrivateKey(privateKey?: string): Promise<string | Buffer | undefined> {
  if (!privateKey) {
    return undefined;
  }

  try {
    const stats = await fs.stat(privateKey);
    if (stats.isFile()) {
      return await fs.readFile(privateKey);
    }
  } catch {
    return privateKey;
  }

  return privateKey;
}

async function buildConnectConfig(options: ConnectShellOptions): Promise<ConnectConfig> {
  const algorithms = resolveClientAlgorithms();
  const config: ConnectConfig = {
    host: options.host,
    port: options.port,
    username: options.username,
    readyTimeout: options.connectTimeout,
    keepaliveInterval: 10_000,
    keepaliveCountMax: 3,
    ...(algorithms ? { algorithms } : {}),
  };

  switch (options.authMethod) {
    case "password":
      if (!options.password) {
        throw new HandledError(
          "AUTH_FAILED",
          "Password authentication was requested, but no password was provided.",
        );
      }

      config.password = options.password;
      config.tryKeyboard = true;
      break;
    case "privateKey": {
      const privateKey = await resolvePrivateKey(options.privateKey);
      if (!privateKey) {
        throw new HandledError(
          "AUTH_FAILED",
          "Private key authentication was requested, but no private key was provided.",
        );
      }

      config.privateKey = privateKey;
      if (options.passphrase) {
        config.passphrase = options.passphrase;
      }
      break;
    }
    case "agent": {
      const agent = process.env.SSH_AUTH_SOCK ?? (process.platform === "win32" ? "pageant" : undefined);
      if (!agent) {
        throw new HandledError(
          "AUTH_FAILED",
          "SSH agent authentication was requested, but SSH_AUTH_SOCK is not set.",
        );
      }

      config.agent = agent;
      break;
    }
    default:
      throw new HandledError(
        "AUTH_FAILED",
        `Unsupported authentication method "${String(options.authMethod)}".`,
      );
  }

  return config;
}

async function connectClient(options: ConnectShellOptions): Promise<{ client: Client; serverBanner?: string }> {
  const connectConfig = await buildConnectConfig(options);

  return await new Promise((resolve, reject) => {
    const client = new Client();
    // ssh2 can emit a late auth error after the setup listeners are cleaned up.
    // Keep a baseline listener attached so the process does not crash.
    client.on("error", () => {});
    let serverBanner: string | undefined;
    let settled = false;

    const cleanup = (): void => {
      client.off("ready", onReady);
      client.off("banner", onBanner);
      client.off("error", onError);
      client.off("close", onClose);
      client.off("end", onEnd);
      client.off("keyboard-interactive", onKeyboardInteractive);
    };

    const fail = (error: unknown): void => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      try {
        client.end();
      } catch {
        // Ignore best-effort cleanup failures during connection setup.
      }
      reject(normalizeConnectError(error));
    };

    const onBanner = (message: string): void => {
      serverBanner = serverBanner ? `${serverBanner}\n${message}` : message;
    };

    const onReady = (): void => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      (client as Client & { setKeepAliveInterval?: (interval: number) => void }).setKeepAliveInterval?.(
        10_000,
      );
      resolve({ client, serverBanner });
    };

    const onError = (error: Error): void => {
      fail(error);
    };

    const onClose = (): void => {
      fail(new Error("SSH connection closed before the PTY shell was ready."));
    };

    const onEnd = (): void => {
      fail(new Error("SSH connection ended before the PTY shell was ready."));
    };

    const onKeyboardInteractive = (
      _name: string,
      _instructions: string,
      _language: string,
      prompts: Array<{ prompt: string }>,
      finish: (responses: string[]) => void,
    ): void => {
      if (options.authMethod === "password" && options.password) {
        finish(prompts.map(() => options.password ?? ""));
        return;
      }

      finish([]);
    };

    client.on("ready", onReady);
    client.on("banner", onBanner);
    client.on("error", onError);
    client.on("close", onClose);
    client.on("end", onEnd);
    client.on("keyboard-interactive", onKeyboardInteractive);
    client.connect(connectConfig);
  });
}

async function openPtyShell(client: Client): Promise<ClientChannel> {
  return await new Promise((resolve, reject) => {
    client.shell(
      {
        term: "xterm-256color",
        cols: DEFAULT_TERMINAL_COLS,
        rows: DEFAULT_TERMINAL_ROWS,
      },
      (error, shell) => {
        if (error) {
          reject(error);
          return;
        }

        shell.setEncoding("utf8");
        resolve(shell);
      },
    );
  });
}

function handleUnexpectedClosure(
  session: ShellSession,
  sessionManager: SessionManager,
  reason: string,
): void {
  if (session.closed) {
    return;
  }

  if (session.activeCommand && !session.activeCommand.completed) {
    session.activeCommand.closedReason = reason;
  }

  sessionManager.unregister(session.id, reason);
}

function attachSessionListeners(session: ShellSession, sessionManager: SessionManager): void {
  const onData = (chunk: Buffer | string): void => {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    session.buffer = appendRollingBuffer(session.buffer, text, DEFAULT_BUFFER_LIMIT);
    session.recentBuffer = appendRollingBuffer(session.recentBuffer, text, DEFAULT_BUFFER_LIMIT);

    if (session.activeCommand) {
      session.activeCommand.buffer = appendRollingBuffer(
        session.activeCommand.buffer,
        text,
        DEFAULT_BUFFER_LIMIT,
      );
    }

    session.lastUsedAt = Date.now();
    handleShellData(session);
  };

  session.shell.on("data", onData);
  session.shell.on("close", () => {
    handleUnexpectedClosure(session, sessionManager, `Session "${session.id}" shell channel closed.`);
  });
  session.shell.on("end", () => {
    handleUnexpectedClosure(session, sessionManager, `Session "${session.id}" shell channel ended.`);
  });
  session.shell.on("error", (error: unknown) => {
    handleUnexpectedClosure(
      session,
      sessionManager,
      `Session "${session.id}" shell error: ${getErrorMessage(error)}`,
    );
  });

  session.client.on("close", () => {
    handleUnexpectedClosure(session, sessionManager, `Session "${session.id}" SSH connection closed.`);
  });
  session.client.on("end", () => {
    handleUnexpectedClosure(session, sessionManager, `Session "${session.id}" SSH connection ended.`);
  });
  session.client.on("error", (error: unknown) => {
    if (session.closing) {
      return;
    }

    handleUnexpectedClosure(
      session,
      sessionManager,
      `Session "${session.id}" SSH client error: ${getErrorMessage(error)}`,
    );
  });
}

async function createReadyConnection(options: ConnectShellOptions): Promise<ReadyConnection> {
  const { client, serverBanner } = await connectClient(options);

  try {
    const shell = await openPtyShell(client);
    return { client, shell, serverBanner };
  } catch (error) {
    try {
      client.end();
    } catch {
      // Ignore cleanup errors when the PTY channel fails to open.
    }
    throw error;
  }
}

export async function connectShellSession(options: ConnectShellOptions): Promise<ShellSession> {
  options.sessionManager.assertCapacity();

  const readyConnection = await createReadyConnection(options);
  const createdAt = Date.now();
  const session: ShellSession = {
    id: uuidv4(),
    client: readyConnection.client,
    shell: readyConnection.shell,
    buffer: "",
    recentBuffer: "",
    ready: false,
    host: options.host,
    username: options.username,
    createdAt,
    lastUsedAt: createdAt,
    label: options.sessionLabel,
    serverBanner: readyConnection.serverBanner,
    isSudo: false,
    cols: DEFAULT_TERMINAL_COLS,
    rows: DEFAULT_TERMINAL_ROWS,
    closed: false,
    closing: false,
    manualMode: false,
    identity: createInitialShellIdentity(options.username),
    bootstrap: {
      successful: false,
      recoveryCount: 0,
      adoptedShellCount: 0,
    },
    operationState: {
      queuedCount: 0,
    },
  };

  attachSessionListeners(session, options.sessionManager);

  try {
    await bootstrapShell(session, options.connectTimeout, "initial-connect");
    const startupOutput = session.buffer;
    const initialBanner = cleanInitialBanner(startupOutput);
    const combinedBanner = [readyConnection.serverBanner, initialBanner]
      .filter((value) => Boolean(value && value.trim()))
      .join("\n\n")
      .trim();

    session.serverBanner = combinedBanner || undefined;
    session.buffer = "";
    session.recentBuffer = "";
    session.ready = true;
    session.lastUsedAt = Date.now();
    options.sessionManager.add(session);
    return session;
  } catch (error) {
    closeShellSession(session, "Failed during remote shell initialization.");
    throw error;
  }
}

export function closeShellSession(session: ShellSession, reason: string): void {
  session.closing = true;
  session.closed = true;
  session.closeReason = reason;

  if (session.activeCommand && !session.activeCommand.completed) {
    session.activeCommand.closedReason = reason;
  }

  try {
    session.shell.end("exit\n");
  } catch {
    // Ignore best-effort channel shutdown errors.
  }

  try {
    session.shell.destroy();
  } catch {
    // Ignore best-effort channel destroy errors.
  }

  try {
    session.client.end();
  } catch {
    // Ignore best-effort client shutdown errors.
  }

  try {
    session.client.destroy();
  } catch {
    // Ignore best-effort client destroy errors.
  }
}
