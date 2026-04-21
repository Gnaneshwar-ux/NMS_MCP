import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  bootstrapShell,
  maybeAdoptInteractiveShell,
  reconcileShellIdentity,
} from "../dist/shell-state.js";

function extractReadyMarker(input) {
  return input.match(/printf '([^']+)\|%s\\n'/)?.[1] ?? null;
}

test("bootstraps a shell and records the detected effective user", async () => {
  const { session, writes } = createFakeSession({
    ready: false,
    onWrite(input, activeSession) {
      const readyMarker = extractReadyMarker(input);
      if (!readyMarker) {
        return;
      }

      setTimeout(() => {
        activeSession.buffer += `\n${readyMarker}|nmsadmin\n__MCP_PROMPT__ `;
      }, 0);
    },
  });

  const result = await bootstrapShell(session, 1_000, "unit-test");

  assert.equal(result.effectiveUser, "nmsadmin");
  assert.equal(session.identity.effectiveUser, "nmsadmin");
  assert.equal(session.identity.promptMarkerActive, true);
  assert.equal(session.bootstrap.successful, true);
  assert.equal(session.bootstrap.lastBootstrapReason, "unit-test");
  assert.equal(writes.length, 1);
});

test("adopts an interactive su shell into the managed session", async () => {
  const { session } = createFakeSession({
    ready: false,
    manualMode: true,
    buffer: "Password:\nuser@nms-host$ ",
    activeCommand: {
      command: "su - nmsadmin",
      submittedCommand: "su - nmsadmin\n",
      executionMode: "interactive",
      sentinelId: "sentinel",
      startedAt: Date.now(),
      timeoutMs: 30_000,
      buffer: "Password:\nuser@nms-host$ ",
      completed: false,
      timedOutReported: false,
      sudoPromptAttempts: 0,
      lastSudoPromptBufferLength: 0,
      stripAnsiOutput: true,
    },
    onWrite(input, activeSession) {
      const readyMarker = extractReadyMarker(input);
      if (!readyMarker) {
        return;
      }

      setTimeout(() => {
        activeSession.buffer += `\n${readyMarker}|nmsadmin\n__MCP_PROMPT__ `;
      }, 0);
    },
  });

  const result = await maybeAdoptInteractiveShell(session, 1_500);

  assert.equal(result.adopted, true);
  assert.equal(result.effectiveUser, "nmsadmin");
  assert.equal(session.activeCommand, undefined);
  assert.equal(session.ready, true);
  assert.equal(session.manualMode, false);
  assert.equal(session.identity.effectiveUser, "nmsadmin");
  assert.equal(session.identity.privilegeMode, "su");
  assert.equal(session.bootstrap.adoptedShellCount, 1);
});

test("does not adopt when the interactive shell has not reached a prompt yet", async () => {
  const { session } = createFakeSession({
    ready: false,
    manualMode: true,
    activeCommand: {
      command: "su - nmsadmin",
      submittedCommand: "su - nmsadmin\n",
      executionMode: "interactive",
      sentinelId: "sentinel",
      startedAt: Date.now(),
      timeoutMs: 30_000,
      buffer: "Password: ",
      completed: false,
      timedOutReported: false,
      sudoPromptAttempts: 0,
      lastSudoPromptBufferLength: 0,
      stripAnsiOutput: true,
    },
  });

  const result = await maybeAdoptInteractiveShell(session, 1_000);

  assert.equal(result.adopted, false);
  assert.equal(session.activeCommand?.command, "su - nmsadmin");
  assert.equal(session.identity.effectiveUser, "test");
});

test("reconciles shell identity after the prompt is already back", async () => {
  const { session, writes } = createFakeSession({
    ready: true,
    buffer: "Last login: Tue Apr 21 13:58:55 UTC 2026 on pts/1\n$ ",
    identity: {
      loginUser: "gnagurra",
      effectiveUser: "gnagurra",
      privilegeMode: "standard",
      promptMarkerActive: false,
      source: "login",
      lastDetectedAt: Date.now(),
    },
    onWrite(input, activeSession) {
      const readyMarker = extractReadyMarker(input);
      if (!readyMarker) {
        return;
      }

      setTimeout(() => {
        activeSession.buffer += `\n${readyMarker}|gbuora\n__MCP_PROMPT__ `;
      }, 0);
    },
  });

  const result = await reconcileShellIdentity(
    session,
    1_000,
    "target-session reconciliation",
    {
      adoptsShell: true,
      expectedUser: "gbuora",
      privilegeMode: "sudo",
      viaSudo: true,
      sourceCommand: "sudo su - gbuora",
    },
  );

  assert.ok(result);
  assert.equal(result.effectiveUser, "gbuora");
  assert.equal(session.identity.effectiveUser, "gbuora");
  assert.equal(session.identity.privilegeMode, "sudo");
  assert.equal(writes.length, 1);
});
