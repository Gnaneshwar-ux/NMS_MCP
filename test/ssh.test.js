import test from "node:test";
import assert from "node:assert/strict";

import { resolveClientAlgorithms } from "../dist/ssh.js";

test("compat ssh algorithm profile prefers ctr ciphers and sha2 hmac", () => {
  const algorithms = resolveClientAlgorithms("compat");

  assert.ok(algorithms);
  assert.deepEqual(algorithms.cipher.slice(0, 3), [
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
  ]);
  assert.equal(algorithms.hmac[0], "hmac-sha2-256");
  assert.equal(algorithms.compress[0], "none");
});

test("default ssh algorithm profile keeps ssh2 defaults", () => {
  assert.equal(resolveClientAlgorithms("default"), undefined);
});

test("unknown ssh algorithm profile throws a handled error", () => {
  assert.throws(
    () => resolveClientAlgorithms("unexpected"),
    /Unsupported MCP_SSH_ALGORITHM_PROFILE/,
  );
});
