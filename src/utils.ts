export const DEFAULT_TERMINAL_COLS = 220;
export const DEFAULT_TERMINAL_ROWS = 50;
export const DEFAULT_BUFFER_LIMIT = 200_000;
export const SHELL_PROMPT_MARKER = "__MCP_PROMPT__";
export const SHELL_READY_MARKER_PREFIX = "__MCP_READY__";

export type InteractionPromptType =
  | "none"
  | "shell_prompt"
  | "sudo_password"
  | "password"
  | "yes_no"
  | "press_enter"
  | "python_repl"
  | "sql_prompt"
  | "isql_prompt"
  | "sqlplus_prompt"
  | "pager"
  | "command_continuation"
  | "unknown_interactive";

export interface InteractionSuggestion {
  input: string;
  description: string;
  sensitive?: boolean;
}

export interface InteractionPromptAnalysis {
  promptType: InteractionPromptType;
  promptText: string | null;
  confidence: "low" | "medium" | "high";
  expectsInput: boolean;
  safeToAutoRespond: boolean;
  suggestions: InteractionSuggestion[];
}

let sentinelCounter = 0;

export class HandledError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "HandledError";
  }
}

export function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export function normalizeNewlines(output: string): string {
  return output.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

export function stripAnsiPreserveWhitespace(output: string): string {
  return normalizeNewlines(
    output
      .replace(/\x1B\][^\x07]*(\x07|\x1B\\)/g, "")
      .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, ""),
  ).replace(/[\x00-\x08\x0B-\x1A\x1C-\x1F\x7F]/g, "");
}

export function stripAnsi(output: string): string {
  return stripAnsiPreserveWhitespace(output).trim();
}

export function appendRollingBuffer(
  buffer: string,
  chunk: string,
  maxChars = DEFAULT_BUFFER_LIMIT,
): string {
  const combined = buffer + chunk;
  if (combined.length <= maxChars) {
    return combined;
  }

  return combined.slice(combined.length - maxChars);
}

export function generateSentinel(): string {
  sentinelCounter = (sentinelCounter + 1) % 1000;
  return `MCP_EOF_${Date.now()}${String(sentinelCounter).padStart(3, "0")}`;
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function decodeInputEscapes(input: string): string {
  return input
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_match, value: string) =>
      String.fromCharCode(Number.parseInt(value, 16)),
    )
    .replace(/\\r/g, "\r")
    .replace(/\\n/g, "\n");
}

function getTailLines(buffer: string, maxChars = 4000): string[] {
  return stripAnsiPreserveWhitespace(buffer)
    .slice(-maxChars)
    .split("\n");
}

function getLastMeaningfulLine(buffer: string): string {
  return (
    getTailLines(buffer)
      .map((line) => line.replace(/\s+$/, ""))
      .filter((line) => line.length > 0)
      .at(-1) ?? ""
  );
}

export function analyzeInteractionPrompt(
  buffer: string,
  options: {
    commandHint?: string;
    sessionReady?: boolean;
  } = {},
): InteractionPromptAnalysis {
  const strippedTail = stripAnsiPreserveWhitespace(buffer).slice(-4000);
  const lastLine = getLastMeaningfulLine(buffer);
  const commandHint = String(options.commandHint ?? "").toLowerCase();
  const suggestions: InteractionSuggestion[] = [];

  if (
    /\[sudo\] password(?: for [^:\n]+)?:\s*$/i.test(strippedTail) ||
    /\[sudo\] password(?: for [^:\n]+)?:\s*$/i.test(lastLine)
  ) {
    suggestions.push({
      input: "<sudo password>\\n",
      description: "Provide the sudo password followed by Enter.",
      sensitive: true,
    });
    return {
      promptType: "sudo_password",
      promptText: lastLine || "[sudo] password:",
      confidence: "high",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (
    /\bpassword(?: for [^:\n]+)?:\s*$/i.test(strippedTail) ||
    /\bpassphrase(?: for [^:\n]+)?:\s*$/i.test(strippedTail)
  ) {
    suggestions.push({
      input: "<secret>\\n",
      description: "Provide the requested password or passphrase followed by Enter.",
      sensitive: true,
    });
    return {
      promptType: "password",
      promptText: lastLine || "password:",
      confidence: "high",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (
    /\b(?:\[y\/n\]|\[yes\/no\]|\[y\/N\]|\[Y\/n\]|\(y\/n\)|\(yes\/no\)|yes\/no)\b/i.test(
      strippedTail,
    ) ||
    /\?\s*$/.test(lastLine) && /\b(?:proceed|continue|overwrite|replace|confirm|retry)\b/i.test(lastLine)
  ) {
    suggestions.push(
      {
        input: "yes\\n",
        description: "Affirm the prompt.",
      },
      {
        input: "no\\n",
        description: "Decline the prompt.",
      },
    );
    return {
      promptType: "yes_no",
      promptText: lastLine || "yes/no prompt",
      confidence: "medium",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (/\b(?:press|hit)\s+(?:enter|return)\b|\bpress any key\b|\bcontinue\b.*\benter\b/i.test(strippedTail)) {
    suggestions.push({
      input: "\\n",
      description: "Press Enter to continue.",
    });
    return {
      promptType: "press_enter",
      promptText: lastLine || "Press Enter to continue",
      confidence: "high",
      expectsInput: true,
      safeToAutoRespond: true,
      suggestions,
    };
  }

  if (/(?:^|\n)>>> $/.test(strippedTail) || /(?:^|\n)\.\.\. $/.test(strippedTail)) {
    return {
      promptType: "python_repl",
      promptText: lastLine || ">>>",
      confidence: "high",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (/(?:^|\n)SQL>\s*$/.test(strippedTail)) {
    const promptType =
      commandHint.includes("isql") ? "isql_prompt" : commandHint.includes("sqlplus") ? "sqlplus_prompt" : "sql_prompt";
    return {
      promptType,
      promptText: "SQL>",
      confidence: "high",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (/--More--|\(END\)\s*$|:\s*$/.test(lastLine) && /\b(?:more|less)\b/i.test(strippedTail)) {
    suggestions.push(
      {
        input: " ",
        description: "Advance one pager page.",
      },
      {
        input: "q",
        description: "Quit the pager.",
      },
      {
        input: "\\n",
        description: "Advance one line in the pager.",
      },
    );
    return {
      promptType: "pager",
      promptText: lastLine || "pager prompt",
      confidence: "medium",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (/(?:^|\n)> $/.test(strippedTail) && !detectShellPrompt(strippedTail)) {
    return {
      promptType: "command_continuation",
      promptText: lastLine || ">",
      confidence: "medium",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (detectShellPrompt(buffer)) {
    return {
      promptType: "shell_prompt",
      promptText: lastLine || SHELL_PROMPT_MARKER,
      confidence: options.sessionReady ? "high" : "medium",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  if (/[>:] ?$/.test(lastLine) && lastLine.length > 0) {
    return {
      promptType: "unknown_interactive",
      promptText: lastLine,
      confidence: "low",
      expectsInput: true,
      safeToAutoRespond: false,
      suggestions,
    };
  }

  return {
    promptType: "none",
    promptText: null,
    confidence: "low",
    expectsInput: false,
    safeToAutoRespond: false,
    suggestions,
  };
}

export function detectShellPrompt(buffer: string): boolean {
  const tail = stripAnsiPreserveWhitespace(buffer).slice(-200);
  return tail.includes(`${SHELL_PROMPT_MARKER} `) || /(?:^|\n)[^\n]*[#$] ?$/.test(tail);
}

function removeInternalLines(output: string): string {
  return normalizeNewlines(output)
    .split("\n")
    .filter(
      (line) =>
        !/MCP_EOF_\d+_/.test(line) && !/__MCP_READY__[A-Za-z0-9_-]*/.test(line),
    )
    .join("\n");
}

function removePromptMarkers(output: string): string {
  return removeInternalLines(output).replaceAll(SHELL_PROMPT_MARKER, "");
}

export function cleanShellOutput(output: string, stripOutput = true): string {
  const cleaned = removePromptMarkers(output);
  return stripOutput ? stripAnsi(cleaned) : stripAnsiPreserveWhitespace(cleaned).trim();
}

function stripEchoedCommandPrefix(output: string, command: string): string {
  const raw = normalizeNewlines(output);
  const expected = command.trim();
  if (!expected) {
    return raw;
  }

  let rawIndex = 0;
  let commandIndex = 0;

  while (rawIndex < raw.length && commandIndex < expected.length) {
    if (raw.startsWith("> ", rawIndex)) {
      rawIndex += 2;
      continue;
    }

    const rawChar = raw[rawIndex];
    if (rawChar === "\n") {
      rawIndex += 1;
      continue;
    }

    if (rawChar !== expected[commandIndex]) {
      return raw;
    }

    rawIndex += 1;
    commandIndex += 1;
  }

  if (commandIndex !== expected.length) {
    return raw;
  }

  while (rawIndex < raw.length && (raw[rawIndex] === "\n" || raw.startsWith("> ", rawIndex))) {
    if (raw.startsWith("> ", rawIndex)) {
      rawIndex += 2;
      continue;
    }

    rawIndex += 1;
  }

  return raw.slice(rawIndex);
}

export function cleanCommandOutput(
  output: string,
  command: string,
  stripOutput = true,
): string {
  const withoutPrompts = cleanShellOutput(output, false);
  const joined = stripEchoedCommandPrefix(withoutPrompts, command);
  return stripOutput ? stripAnsi(joined) : stripAnsiPreserveWhitespace(joined).trim();
}

export function cleanInitialBanner(output: string): string {
  return cleanShellOutput(output, true);
}

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
