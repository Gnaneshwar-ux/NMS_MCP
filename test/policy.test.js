import test from "node:test";
import assert from "node:assert/strict";

import { createFakeSession } from "./helpers.js";
import { reviewCommandPolicy } from "../dist/policy.js";
import { rewriteSudoCommandWithPassword } from "../dist/sudo.js";

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

test("requires confirmation for read-only sudo diagnostics", () => {
  const review = reviewCommandPolicy(
    "sudo -u esb8 ps -ef | egrep 'isis|JMS' | grep -v grep | head -n 20",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "approval_required");
  assert.equal(review.requiresConfirmation, true);
  assert.equal(review.safeForAutoRun, false);
  assert.equal(review.category, "privileged-command");
  assert.equal(review.riskLevel, "read-only");
});

test("allows exact read-only diagnostics bundles wrapped in bash -lc", () => {
  const review = reviewCommandPolicy(
    `bash -lc 'source ~/.nmsrc >/dev/null 2>&1; echo "=== host ==="; hostname; echo "=== user ==="; whoami; echo "=== smsReport ==="; smsReport 2>&1 | head -n 120; echo "=== key processes ==="; ps -ef | egrep "isis|JMS|genpublisher|ddservice|jmservice" | grep -v grep | head -n 80; echo "=== recent logs ==="; find ~/logs -maxdepth 1 -type f \\( -name "*.log" -o -name "*.out" \\) -printf "%TY-%Tm-%Td %TT %p\\n" 2>/dev/null | sort | tail -n 10'`,
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "diagnostic-bundle");
});

test("blocks shell-elevating sudo flows", () => {
  const review = reviewCommandPolicy("sudo -iu oracle", undefined, TEST_POLICY);

  assert.equal(review.decision, "blocked");
  assert.equal(review.category, "privilege-escalation");
});

test("allows known-safe read-only commands inside an already elevated session", () => {
  const { session } = createFakeSession({
    isSudo: true,
  });

  const review = reviewCommandPolicy(
    "ps -ef | grep weblogic | grep -v grep | head -n 20",
    session,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
});

test("blocks piped sudo password changes even when the leading command looks harmless", () => {
  const review = reviewCommandPolicy(
    "echo 'test:Oracle1234' | sudo chpasswd",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "blocked");
  assert.equal(review.category, "password-change");
});

test("blocks piped sudoers writes even when the leading command looks harmless", () => {
  const review = reviewCommandPolicy(
    "echo 'test ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/test",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "blocked");
  assert.equal(review.category, "sudoers-change");
});

test("blocks wrapped sudoers writes inside bash -lc", () => {
  const review = reviewCommandPolicy(
    "bash -lc 'echo \"test ALL=(ALL) NOPASSWD:ALL\" | sudo tee /etc/sudoers.d/test'",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "blocked");
  assert.equal(review.category, "sudoers-change");
});

test("requires confirmation for heredoc-wrapped inline scripts", () => {
  const review = reviewCommandPolicy(
    "cat <<'EOF' | bash\nhostname\nEOF",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "approval_required");
  assert.equal(review.safeForAutoRun, false);
  assert.equal(review.knownSafeAutoRun, false);
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
