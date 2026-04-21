import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  getVisibleInteractionBuffers,
  handleShellData,
  startInteractiveCommand,
} from "../dist/executor.js";

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

test("does not clear a timed-out active command from a stale prompt marker", () => {
  const { session } = createFakeSession({
    ready: false,
    buffer: "output line\n__MCP_PROMPT__ \n127.0.0.1 localhost",
    activeCommand: {
      command: "tail -n 3 -f /etc/hosts",
      submittedCommand: "tail -n 3 -f /etc/hosts\n",
      executionMode: "oneshot",
      sentinelId: "sentinel",
      startedAt: Date.now(),
      timeoutMs: 1_500,
      buffer: "127.0.0.1 localhost\n",
      sudoPromptAttempts: 0,
      lastSudoPromptBufferLength: 0,
      lastSudoPromptSignature: undefined,
      completed: false,
      timedOutReported: true,
      stripAnsiOutput: true,
    },
  });

  handleShellData(session);

  assert.notEqual(session.activeCommand, undefined);
  assert.equal(session.activeCommand?.command, "tail -n 3 -f /etc/hosts");
  assert.equal(session.ready, false);
  assert.equal(session.manualMode, false);
  assert.equal(session.identity.promptMarkerActive, false);
});

test("prefers the fresh session buffer for one-shot output while keeping prompt state from the rolling buffer", () => {
  const { session } = createFakeSession({
    buffer: "older output\n__MCP_PROMPT__ ",
    recentBuffer: "fresh output only\n__MCP_PROMPT__ ",
  });

  const buffers = getVisibleInteractionBuffers(session);

  assert.equal(buffers.outputBuffer, "fresh output only\n__MCP_PROMPT__ ");
  assert.equal(buffers.promptBuffer, "fresh output only\n__MCP_PROMPT__ ");
});

test("reuses the session preferred sudo password when a prompt appears later", () => {
  const { session, writes } = createFakeSession({
    ready: false,
    preferredSudoPassword: "Oracle1234",
    activeCommand: {
      command: "sudo -u oracle whoami",
      submittedCommand: "sudo -u oracle whoami\n",
      executionMode: "oneshot",
      sentinelId: "sentinel",
      startedAt: Date.now(),
      timeoutMs: 30_000,
      buffer: "[sudo] password for test: ",
      sudoPromptAttempts: 0,
      lastSudoPromptBufferLength: 0,
      lastSudoPromptSignature: undefined,
      completed: false,
      timedOutReported: false,
      stripAnsiOutput: true,
    },
  });

  handleShellData(session);

  assert.deepEqual(writes, ["Oracle1234\n"]);
  assert.equal(session.activeCommand?.sudoPassword, "Oracle1234");
  assert.equal(session.activeCommand?.sudoPromptAttempts, 1);
});

test("submits shell-adopting interactive commands without the sentinel wrapper", async () => {
  const { session, writes } = createFakeSession({
    ready: true,
  });

  await startInteractiveCommand(session, "sudo -iu oracle", {
    timeoutMs: 5_000,
    waitForOutputMs: 0,
    sudoPassword: "Oracle1234",
    stripAnsiOutput: true,
  });

  assert.equal(writes.length, 1);
  assert.equal(writes[0], "sudo -iu oracle\n");
  assert.equal(session.activeCommand?.submissionMode, "raw");
});
