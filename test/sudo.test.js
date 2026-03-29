import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  inferShellIdentityTransition,
  maybeInjectSudoPassword,
  rewriteSudoCommandWithPassword,
  updateSessionSudoState,
} from "../dist/sudo.js";

test("infers su shell transitions", () => {
  const transition = inferShellIdentityTransition("su - nmsadmin");

  assert.ok(transition);
  assert.equal(transition.expectedUser, "nmsadmin");
  assert.equal(transition.privilegeMode, "su");
  assert.equal(transition.viaSudo, false);
});

test("infers sudo login-shell transitions with explicit target user", () => {
  const transition = inferShellIdentityTransition("sudo -iu oracle");

  assert.ok(transition);
  assert.equal(transition.expectedUser, "oracle");
  assert.equal(transition.privilegeMode, "sudo");
  assert.equal(transition.viaSudo, true);
});

test("infers root shell transitions for plain sudo -i", () => {
  const transition = inferShellIdentityTransition("sudo -i");

  assert.ok(transition);
  assert.equal(transition.expectedUser, "root");
  assert.equal(transition.privilegeMode, "root");
});

test("tracks shell identity on exit back to the login user", () => {
  const { session } = createFakeSession({
    username: "test",
  });

  updateSessionSudoState(session, "su - nmsadmin", 0);
  assert.equal(session.identity.effectiveUser, "nmsadmin");
  assert.equal(session.identity.privilegeMode, "su");
  assert.equal(session.isSudo, true);

  updateSessionSudoState(session, "exit", 0);
  assert.equal(session.identity.effectiveUser, "test");
  assert.equal(session.identity.privilegeMode, "standard");
  assert.equal(session.isSudo, false);
});

test("injects the sudo password only once for the same visible prompt", () => {
  const { session, writes } = createFakeSession();
  const activeCommand = {
    command: "sudo -k ls /root",
    submittedCommand: "sudo -k ls /root\n",
    executionMode: "oneshot",
    sentinelId: "sentinel",
    startedAt: Date.now(),
    timeoutMs: 30_000,
    buffer: "[sudo] password for test: ",
    sudoPassword: "Oracle1234",
    sudoPromptAttempts: 0,
    lastSudoPromptBufferLength: 0,
    lastSudoPromptSignature: undefined,
    completed: false,
    timedOutReported: false,
    stripAnsiOutput: true,
  };

  maybeInjectSudoPassword(session, activeCommand);
  assert.deepEqual(writes, ["Oracle1234\n"]);

  activeCommand.buffer += "\nOracle1234";
  maybeInjectSudoPassword(session, activeCommand);
  assert.deepEqual(writes, ["Oracle1234\n"]);
  assert.equal(activeCommand.sudoPromptAttempts, 1);
});

test("rewrites direct sudo commands to use sudo -S when a password is supplied", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -k ls /root | head -n 5",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, false);
  assert.match(
    result.rewrittenCommand,
    /^cat <<'__MCP_SUDO_PASSWORD__' \| sudo -S -p '' -k ls \/root \| head -n 5\nOracle1234\n__MCP_SUDO_PASSWORD__$/,
  );
  assert.doesNotMatch(result.rewrittenCommand, /printf '%s\\n'/);
});

test("keeps shell-elevating sudo flows on prompt injection", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -iu oracle",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, true);
  assert.equal(result.rewrittenCommand, "sudo -iu oracle");
});
