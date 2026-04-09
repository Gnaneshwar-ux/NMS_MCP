import test from "node:test";
import assert from "node:assert/strict";

import { getUsageGuide } from "../dist/usage-guide.js";

test("usage guide exposes preferred style and tool guidance", () => {
  const guide = getUsageGuide();

  assert.equal(typeof guide.summary, "string");
  assert.ok(guide.summary.length > 0);
  assert.ok(guide.preferredStyle.some((entry) => entry.includes("standalone")));
  assert.ok(guide.confirmationStyle.some((entry) => entry.includes("one shared confirmation")));
  assert.ok(guide.sudoStyle.some((entry) => entry.includes("sudo -u")));
  assert.ok(guide.sudoStyle.some((entry) => entry.includes("LDAP login first")));
  assert.ok(guide.sudoStyle.some((entry) => entry.includes("sudo su -")));
  assert.ok(guide.preferredStyle.some((entry) => entry.includes("list_nms_guides")));
  assert.equal(guide.livePolicyReference.tool, "read_policy");

  const toolNames = new Set(guide.toolGuidance.map((entry) => entry.tool));
  assert.ok(toolNames.has("read_usage_guide"));
  assert.ok(toolNames.has("ssh_connect_target_session"));
  assert.ok(toolNames.has("execute_command"));
  assert.ok(toolNames.has("execute_command_batch"));
  assert.ok(toolNames.has("list_nms_guides"));
  assert.ok(toolNames.has("get_nms_guide_pdf"));
  assert.ok(toolNames.has("read_policy"));
});
