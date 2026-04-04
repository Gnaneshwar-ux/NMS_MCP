import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import {
  shouldStopBatchOnExitCode,
  summarizeCommandBatchReviews,
} from "../dist/command-batch.js";

const TEST_POLICY = {
  loadedFrom: null,
  blockedCategories: [
    "privilege-escalation",
    "password-change",
    "sudoers-change",
    "account-change",
    "service-change",
    "data-delete",
  ],
  approvalCategories: [
    "session-state",
    "privileged-command",
    "shell-wrapper",
    "interactive-terminal",
    "file-write",
    "scratch-write",
    "opaque-script",
  ],
  allowRules: [],
  denyRules: [],
  approvedScratchPaths: ["/tmp", "/var/tmp"],
  diagnosticsProfiles: ["oracle-nms-readonly"],
};

test("allows a read-only standalone command batch", () => {
  const batch = summarizeCommandBatchReviews(
    [
      "hostname",
      "grep -i -n ERROR ~/logs/DDService.log | head -n 20",
      "find ~/logs -maxdepth 1 -type f | sort | tail -n 10",
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

test("allows exact sudo read-only target-user checks in a batch", () => {
  const batch = summarizeCommandBatchReviews(
    [
      "sudo -u esb8 whoami",
      "grep -i -n ERROR ~/logs/DDService.log | head -n 20",
    ],
    undefined,
    TEST_POLICY,
  );

  assert.equal(batch.decision, "allow");
  assert.equal(batch.requiresConfirmation, false);
  assert.equal(batch.approvalRequiredCount, 0);
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

test("stopOnError treats non-zero exit codes as a batch stop signal", () => {
  assert.equal(shouldStopBatchOnExitCode(1, true), true);
  assert.equal(shouldStopBatchOnExitCode(0, true), false);
  assert.equal(shouldStopBatchOnExitCode(2, false), false);
});
