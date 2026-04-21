import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  buildTargetShellSwitchCommand,
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

test("builds a sudo-based target shell switch command", () => {
  assert.equal(buildTargetShellSwitchCommand("oracle"), "sudo su - oracle");
  assert.equal(buildTargetShellSwitchCommand("oracle", "sudo-iu"), "sudo -iu oracle");
});

test("infers root shell transitions for plain sudo -i", () => {
  const transition = inferShellIdentityTransition("sudo -i");

  assert.ok(transition);
  assert.equal(transition.expectedUser, "root");
  assert.equal(transition.privilegeMode, "root");
});

test("does not infer shell adoption for one-shot sudo bash -lc commands", () => {
  const transition = inferShellIdentityTransition(
    "sudo -iu oracle bash -lc 'whoami'",
  );

  assert.equal(transition, null);
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

test("does not switch session identity for one-shot sudo shell commands", () => {
  const { session } = createFakeSession({
    username: "test",
  });

  updateSessionSudoState(session, "sudo -iu oracle bash -lc 'whoami'", 0);
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

test("re-injects only after the previous visible prompt cycle has cleared", () => {
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
  maybeInjectSudoPassword(session, activeCommand);

  activeCommand.buffer = "sorry, try again.\n";
  maybeInjectSudoPassword(session, activeCommand);

  activeCommand.buffer += "[sudo] password for test: ";
  maybeInjectSudoPassword(session, activeCommand);

  assert.deepEqual(writes, ["Oracle1234\n", "Oracle1234\n"]);
  assert.equal(activeCommand.sudoPromptAttempts, 2);
});

test("injects a stored password for generic password prompts too", () => {
  const { session, writes } = createFakeSession();
  const activeCommand = {
    command: "su - oracle",
    submittedCommand: "su - oracle\n",
    executionMode: "interactive",
    sentinelId: "sentinel",
    startedAt: Date.now(),
    timeoutMs: 30_000,
    buffer: "Password: ",
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
  assert.equal(activeCommand.sudoPromptAttempts, 1);
});

test("keeps direct sudo commands intact and uses prompt injection when a password is supplied", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -k ls /root | head -n 5",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, true);
  assert.equal(result.rewrittenCommand, "sudo -k ls /root | head -n 5");
});

test("keeps shell-elevating sudo flows on prompt injection", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -iu oracle",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, true);
  assert.equal(result.rewrittenCommand, "sudo -iu oracle");
});

test("keeps one-shot sudo bash -lc commands intact and uses prompt injection", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -iu oracle bash -lc 'whoami'",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, true);
  assert.equal(result.rewrittenCommand, "sudo -iu oracle bash -lc 'whoami'");
});
