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

test("allows exact read-only sudo diagnostics for target-user execution", () => {
  const review = reviewCommandPolicy(
    "sudo -u esb8 ps -ef | egrep 'isis|JMS' | grep -v grep | head -n 20",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "privileged-command");
  assert.equal(review.riskLevel, "read-only");
});

test("allows exact sudo target-user directory discovery find diagnostics", () => {
  const review = reviewCommandPolicy(
    "sudo -u gbuora find /scratch/wls -maxdepth 5 -type d \\( -name nmsdomain -o -name servers -o -name logs \\)",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "privileged-command");
});

test("allows exact sudo target-user log-path discovery bundles wrapped in bash -lc", () => {
  const review = reviewCommandPolicy(
    "sudo -u gbuora bash -lc 'find /scratch/wls -maxdepth 7 -type f \\( -name \"*.log\" -o -name \"*.out\" \\) | grep \"/servers/.*/logs/\" | tail -40'",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "privileged-command");
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

test("allows exact non-root sudo-based shell adoption flows", () => {
  const review = reviewCommandPolicy("sudo -iu oracle", undefined, TEST_POLICY);

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "privileged-session-switch");
  assert.equal(review.riskLevel, "mutating");
});

test("allows sudo su target-user handoff flows", () => {
  const review = reviewCommandPolicy("sudo su - nmsadmin", undefined, TEST_POLICY);

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "privileged-session-switch");
});

test("blocks root sudo handoff flows from auto-running", () => {
  const review = reviewCommandPolicy("sudo su - root", undefined, TEST_POLICY);

  assert.equal(review.decision, "blocked");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, false);
  assert.equal(review.category, "privilege-escalation");
});

test("blocks implicit root login-shell sudo flows from auto-running", () => {
  const review = reviewCommandPolicy("sudo -i", undefined, TEST_POLICY);

  assert.equal(review.decision, "blocked");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, false);
  assert.equal(review.category, "privilege-escalation");
});

test("blocks NMS service control commands as service changes", () => {
  const review = reviewCommandPolicy("sms-stop -ais", undefined, TEST_POLICY);

  assert.equal(review.decision, "blocked");
  assert.equal(review.category, "service-change");
  assert.equal(review.riskLevel, "mutating");
});

test("allows bare smsReport as an exact read-only NMS diagnostic", () => {
  const review = reviewCommandPolicy("smsReport", undefined, TEST_POLICY);

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "server-state");
  assert.equal(review.riskLevel, "read-only");
});

test("allows bare pwd as an exact read-only diagnostic", () => {
  const review = reviewCommandPolicy("pwd", undefined, TEST_POLICY);

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "identity-read");
  assert.equal(review.riskLevel, "read-only");
});

test("allows command -v lookups as exact read-only diagnostics", () => {
  const review = reviewCommandPolicy("command -v sqlplus", undefined, TEST_POLICY);

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "identity-read");
  assert.equal(review.riskLevel, "read-only");
});

test("allows exact find and sort file-discovery diagnostics", () => {
  const review = reviewCommandPolicy(
    "find /scratch/wls -maxdepth 7 -type f \\( -name \"*.log\" -o -name \"*.out\" \\) | sort | tail -n 10",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "log-read");
  assert.equal(review.riskLevel, "read-only");
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

test("allows exact getent passwd lookups without treating them as password changes", () => {
  const review = reviewCommandPolicy(
    "getent passwd oracle",
    undefined,
    TEST_POLICY,
  );

  assert.equal(review.decision, "allow");
  assert.equal(review.requiresConfirmation, false);
  assert.equal(review.safeForAutoRun, true);
  assert.equal(review.category, "account-read");
  assert.equal(review.riskLevel, "read-only");
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

test("keeps sudo commands intact and uses prompt injection when a password is supplied", () => {
  const result = rewriteSudoCommandWithPassword(
    "sudo -n -u esb8 bash -lc 'whoami'",
    "Oracle1234",
  );

  assert.equal(result.usesPromptInjection, true);
  assert.equal(result.rewrittenCommand, "sudo -n -u esb8 bash -lc 'whoami'");
});
