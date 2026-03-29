import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  inferShellIdentityTransition,
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
