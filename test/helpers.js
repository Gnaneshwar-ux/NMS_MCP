import { createInitialShellIdentity } from "../dist/session.js";

export function createFakeSession(options = {}) {
  const now = Date.now();
  const writes = [];
  const username = options.username ?? "test";
  const session = {
    id: options.id ?? "session-1",
    client: options.client ?? {},
    shell: {
      write(input) {
        writes.push(input);
        options.onWrite?.(input, session, writes);
      },
      setWindow() {},
    },
    buffer: options.buffer ?? "",
    ready: options.ready ?? true,
    host: options.host ?? "nms-host",
    username,
    createdAt: now,
    lastUsedAt: now,
    label: options.label,
    serverBanner: options.serverBanner,
    isSudo: options.isSudo ?? false,
    cols: options.cols ?? 220,
    rows: options.rows ?? 50,
    closed: options.closed ?? false,
    closing: options.closing ?? false,
    closeReason: options.closeReason,
    manualMode: options.manualMode ?? false,
    identity: options.identity ?? createInitialShellIdentity(username),
    bootstrap: options.bootstrap ?? {
      successful: false,
      recoveryCount: 0,
      adoptedShellCount: 0,
    },
    operationState: options.operationState ?? {
      queuedCount: 0,
    },
    activeCommand: options.activeCommand,
    pendingApproval: options.pendingApproval,
  };

  return {
    session,
    writes,
  };
}
