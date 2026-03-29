import test from "node:test";
import assert from "node:assert/strict";

import {
  appendRollingBuffer,
  analyzeInteractionPrompt,
  cleanCommandOutput,
  decodeInputEscapes,
  detectShellPrompt,
  hasPromptMarker,
  parsePositiveInt,
  SHELL_PROMPT_MARKER,
} from "../dist/utils.js";

test("classifies generic text prompts more precisely", () => {
  const result = analyzeInteractionPrompt("Name: ");

  assert.equal(result.promptType, "text_prompt");
  assert.equal(result.expectsInput, true);
  assert.equal(result.suggestions[0]?.input, "<text>\\n");
});

test("classifies SQL prompts using the command hint", () => {
  const result = analyzeInteractionPrompt("SQL> ", {
    commandHint: "sqlplus / as sysdba",
  });

  assert.equal(result.promptType, "sqlplus_prompt");
  assert.equal(result.expectsInput, true);
});

test("detects managed shell prompts distinctly from fallback prompts", () => {
  const managedPrompt = `welcome\n${SHELL_PROMPT_MARKER} `;
  const fallbackPrompt = "user@nms-host$ ";
  const anglePrompt = "nmsadmin@nms-host> ";

  assert.equal(hasPromptMarker(managedPrompt), true);
  assert.equal(detectShellPrompt(managedPrompt), true);
  assert.equal(hasPromptMarker(fallbackPrompt), false);
  assert.equal(detectShellPrompt(fallbackPrompt), true);
  assert.equal(detectShellPrompt(anglePrompt), true);
});

test("does not treat stale managed prompt markers as an active shell prompt", () => {
  const staleManagedPrompt = `welcome\n${SHELL_PROMPT_MARKER} \n127.0.0.1 localhost`;
  const prompt = analyzeInteractionPrompt(staleManagedPrompt, {
    sessionReady: true,
  });

  assert.equal(hasPromptMarker(staleManagedPrompt), false);
  assert.equal(detectShellPrompt(staleManagedPrompt), false);
  assert.equal(prompt.promptType, "none");
  assert.equal(prompt.expectsInput, false);
});

test("handles yes-no and press-enter prompt families", () => {
  const yesNo = analyzeInteractionPrompt("Proceed with restart? yes/no");
  const pressEnter = analyzeInteractionPrompt("Press Enter to continue");

  assert.equal(yesNo.promptType, "yes_no");
  assert.equal(pressEnter.promptType, "press_enter");
  assert.equal(pressEnter.safeToAutoRespond, true);
});

test("cleans echoed commands and decodes escaped input", () => {
  const output = `echo hi\nhi\n${SHELL_PROMPT_MARKER} `;
  const cleaned = cleanCommandOutput(output, "echo hi");

  assert.equal(cleaned, "hi");
  assert.equal(decodeInputEscapes("line\\nnext\\x21"), "line\nnext!");
});

test("parses integers and maintains rolling buffers", () => {
  assert.equal(parsePositiveInt("42", 5), 42);
  assert.equal(parsePositiveInt("0", 5), 5);
  assert.equal(appendRollingBuffer("abcdef", "ghijkl", 5), "hijkl");
});
