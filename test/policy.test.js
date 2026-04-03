import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import { reviewCommandPolicy } from "../dist/policy.js";
import { rewriteSudoCommandWithPassword } from "../dist/sudo.js";

const TEST_POLICY = {
  loadedFrom: null,
  blockedCategories: [],
  approvalCategories: ["session-state"],
  allowRules: [],
  denyRules: [],
};

test("allows read-only sudo diagnostics for one-shot target-user commands", () => {
  const review = reviewCommandPolicy(
    "sudo -u esb8 ps -ef | egrep 'isis|JMS' | grep -v grep | head -n 20",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.riskLevel, "read-only");
});

test("allows read-only sudo diagnostic bundles wrapped in bash -lc", () => {
  const review = reviewCommandPolicy(
    `sudo -u esb8 bash -lc 'source ~/.nmsrc >/dev/null 2>&1; echo "=== host ==="; hostname; echo "=== user ==="; whoami; echo "=== smsReport ==="; smsReport 2>&1 | head -n 120; echo "=== key processes ==="; ps -ef | egrep "isis|JMS|genpublisher|ddservice|jmservice" | grep -v grep | head -n 80; echo "=== recent logs ==="; find ~/logs -maxdepth 1 -type f \\( -name "*.log" -o -name "*.out" \\) -printf "%TY-%Tm-%Td %TT %p\\n" 2>/dev/null | sort | tail -n 10'`,
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "diagnostic-bundle");
});

test("keeps shell-elevating sudo flows behind confirmation", () => {
  const review = reviewCommandPolicy("sudo -iu oracle", undefined, TEST_POLICY);

  assert.equal(review.decision, "approval_required");
  assert.equal(review.requiresConfirmation, true);
});

test("allows known-safe read-only commands inside an already elevated session", () => {
  const { session } = createFakeSession({
    isSudo: true,
  });

  const review = reviewCommandPolicy(
    "ps -ef | grep weblogic | head -n 20",
    session,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
});

test("drops sudo non-interactive flags when a password is supplied", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -n -u esb8 bash -lc 'whoami'",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, false);
  assert.doesNotMatch(result.rewrittenCommand, /\s-n(?=\s|$)/);
  assert.match(
    result.rewrittenCommand,
    /^cat <<'__MCP_SUDO_PASSWORD__' \| sudo -S -p '' -u esb8 bash -lc 'whoami'\nOracle1234\n__MCP_SUDO_PASSWORD__$/,
  );
});
