export const DEFAULT_TERMINAL_COLS = 220;
export const DEFAULT_TERMINAL_ROWS = 50;
export const DEFAULT_BUFFER_LIMIT = 200_000;
export const SHELL_PROMPT_MARKER = "__MCP_PROMPT__";
export const SHELL_READY_MARKER_PREFIX = "__MCP_READY__";

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
      .replace(/\x1B\[[0-9;]*[mGKHF]/g, ""),
  );
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
  return stripOutput ? stripAnsi(cleaned) : normalizeNewlines(cleaned).trim();
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
  return stripOutput ? stripAnsi(joined) : normalizeNewlines(joined).trim();
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
