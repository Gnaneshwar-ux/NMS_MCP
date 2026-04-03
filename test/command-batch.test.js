import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import { summarizeCommandBatchReviews } from "../dist/command-batch.js";

const TEST_POLICY = {
  loadedFrom: null,
  blockedCategories: [],
  approvalCategories: ["session-state"],
  allowRules: [],
  denyRules: [],
};

test("allows a read-only standalone command batch", () => {
  const batch = summarizeCommandBatchReviews(
    [
      "sudo -u esb8 smsReport 2>&1 | head -n 40",
      "sudo -u esb8 grep -i -n ERROR ~/logs/DDService.log | head -n 20",
      "sudo -u esb8 find ~/logs -maxdepth 1 -type f | sort | tail -n 10",
    ],
    undefined,
    TEST_POLICY,
  );

  assert.equal(batch.decision, "allow");
  assert.equal(batch.requiresConfirmation, false);
  assert.equal(batch.safeForAutoRun, true);
  assert.equal(batch.riskLevel, "read-only");
  assert.equal(batch.commandCount, 3);
});

test("requires one shared confirmation when any batch command needs approval", () => {
  const batch = summarizeCommandBatchReviews(
    [
      "ps -ef | grep weblogic | head -n 20",
      "systemctl status nms",
    ],
    undefined,
    TEST_POLICY,
  );

  assert.equal(batch.decision, "approval_required");
  assert.equal(batch.requiresConfirmation, true);
  assert.equal(batch.approvalRequiredCount, 1);
  assert.equal(batch.blockedCount, 0);
});

test("preserves blocked decisions inside a batch", () => {
  const blockedPolicy = {
    ...TEST_POLICY,
    denyRules: [
      {
        name: "block-rm",
        pattern: "\\brm\\b",
        flags: "i",
        reason: "Hard block rm in test policy.",
        regex: /\brm\b/i,
      },
    ],
  };

  const batch = summarizeCommandBatchReviews(
    [
      "ps -ef | grep weblogic | head -n 20",
      "rm -rf /tmp/bad",
    ],
    undefined,
    blockedPolicy,
  );

  assert.equal(batch.decision, "blocked");
  assert.equal(batch.blockedCount, 1);
  assert.equal(batch.riskLevel, "destructive");
});

test("allows already-elevated sessions to batch known-safe read-only checks", () => {
  const { session } = createFakeSession({
    isSudo: true,
  });

  const batch = summarizeCommandBatchReviews(
    [
      "whoami",
      "smsReport 2>&1 | head -n 40",
      "grep -i -n ERROR ~/logs/JMService.log | head -n 20",
    ],
    session,
    TEST_POLICY,
  );

  assert.equal(batch.decision, "allow");
  assert.equal(batch.requiresConfirmation, false);
  assert.equal(batch.safeForAutoRun, true);
});
