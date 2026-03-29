import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import { HandledError } from "../dist/utils.js";
import { SessionManager } from "../dist/session.js";

function createActiveCommand() {
  return {
    command: "sleep 10",
    submittedCommand: "sleep 10\n",
    executionMode: "interactive",
    sentinelId: "sentinel",
    startedAt: Date.now(),
    timeoutMs: 10_000,
    buffer: "partial output",
    sudoPromptAttempts: 0,
    lastSudoPromptBufferLength: 0,
    completed: false,
    timedOutReported: false,
    stripAnsiOutput: true,
  };
}

test("session manager adds, audits, clears, and closes sessions", () => {
  const closed = [];
  const manager = new SessionManager({
    idleTimeoutMs: 60_000,
    maxSessions: 2,
    closeSession(session, reason) {
      closed.push({ sessionId: session.id, reason });
    },
  });

  try {
    const { session } = createFakeSession({
      id: "session-a",
      buffer: "stale",
      activeCommand: createActiveCommand(),
    });

    manager.add(session);
    assert.equal(manager.require("session-a"), session);
    assert.equal(manager.list()[0]?.id, "session-a");
    assert.equal(manager.listAudit({ limit: 1 })[0]?.event, "session_opened");

    manager.clearBuffer(session, true);
    assert.equal(session.buffer, "");
    assert.equal(session.activeCommand?.buffer, "");

    const closedSession = manager.close("session-a", "unit test close");
    assert.equal(closedSession.closed, true);
    assert.equal(closedSession.closeReason, "unit test close");
    assert.equal(closedSession.identity.promptMarkerActive, false);
    assert.deepEqual(closed, [{ sessionId: "session-a", reason: "unit test close" }]);
  } finally {
    manager.dispose();
  }
});

test("session manager enforces max session capacity", () => {
  const manager = new SessionManager({
    idleTimeoutMs: 60_000,
    maxSessions: 1,
    closeSession() {},
  });

  try {
    const first = createFakeSession({ id: "session-1" }).session;
    const second = createFakeSession({ id: "session-2" }).session;

    manager.add(first);

    assert.throws(() => manager.add(second), (error) => {
      assert.ok(error instanceof HandledError);
      assert.equal(error.code, "MAX_SESSIONS_REACHED");
      return true;
    });
  } finally {
    manager.dispose();
  }
});
