import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import { handleShellData } from "../dist/executor.js";

test("clears a timed-out active command when the shell prompt is already back", () => {
  const { session } = createFakeSession({
    ready: false,
    buffer: "output line\n__MCP_PROMPT__ ",
    activeCommand: {
      command: "sudo -k ls /root | head -n 5",
      submittedCommand: "sudo -k ls /root | head -n 5\n",
      executionMode: "oneshot",
      sentinelId: "sentinel",
      startedAt: Date.now(),
      timeoutMs: 30_000,
      buffer: "output line\n",
      sudoPromptAttempts: 1,
      lastSudoPromptBufferLength: 12,
      lastSudoPromptSignature: "[sudo] password for nmsadmin:",
      completed: false,
      timedOutReported: true,
      stripAnsiOutput: true,
    },
  });

  handleShellData(session);

  assert.equal(session.activeCommand, undefined);
  assert.equal(session.ready, true);
  assert.equal(session.manualMode, false);
  assert.equal(session.identity.promptMarkerActive, true);
});
