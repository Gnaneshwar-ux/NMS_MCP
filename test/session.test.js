import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  runExclusiveShellOperation,
  setSessionIdentity,
} from "../dist/session.js";

test("serializes shell operations per session", async () => {
  const { session } = createFakeSession();
  const order = [];
  let releaseFirst;

  const first = runExclusiveShellOperation(session, "first", async () => {
    order.push("first:start");
    await new Promise((resolve) => {
      releaseFirst = resolve;
    });
    order.push("first:end");
  });

  const second = runExclusiveShellOperation(session, "second", async () => {
    order.push("second:start");
    order.push("second:end");
  });

  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(session.operationState.activeLabel, "first");
  assert.equal(session.operationState.queuedCount, 1);

  releaseFirst();
  await Promise.all([first, second]);

  assert.deepEqual(order, [
    "first:start",
    "first:end",
    "second:start",
    "second:end",
  ]);
  assert.equal(session.operationState.activeLabel, undefined);
  assert.equal(session.operationState.queuedCount, 0);
});

test("updating session identity keeps privilege flags in sync", () => {
  const { session } = createFakeSession();

  setSessionIdentity(session, {
    effectiveUser: "root",
    privilegeMode: "root",
    promptMarkerActive: true,
    source: "bootstrap",
  });

  assert.equal(session.identity.effectiveUser, "root");
  assert.equal(session.identity.privilegeMode, "root");
  assert.equal(session.isSudo, true);
});
