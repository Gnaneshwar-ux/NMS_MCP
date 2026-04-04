import type { CommandPolicyConfig, PolicyDecision } from "./policy-config.js";
import type { CommandRiskLevel, ShellSession } from "./session.js";
import { inferShellIdentityTransition } from "./sudo.js";

export interface MatchedPolicyRule {
  source: "allow" | "deny";
  name: string;
  pattern: string;
  flags: string;
  reason: string;
  decision: PolicyDecision;
}

export interface CommandReview {
  command: string;
  normalizedCommand: string;
  riskLevel: CommandRiskLevel;
  category: string;
  summary: string;
  reasons: string[];
  decision: PolicyDecision;
  decisionReason: string;
  matchedRule?: MatchedPolicyRule;
  requiresConfirmation: boolean;
  requiredConfirmationToken?: "CONFIRM" | "EXEC";
  safeForAutoRun: boolean;
  needsManualReview: boolean;
  knownSafeAutoRun: boolean;
}

interface MatchRule {
  riskLevel: CommandRiskLevel;
  category: string;
  summary: string;
  reason: string;
  regex: RegExp;
}

interface RedirectionInspection {
  operator: string;
  target: string | null;
  writes: boolean;
  targetIsSafeSink: boolean;
  targetIsScratch: boolean;
  heredoc: boolean;
}

interface EffectiveCommand {
  command: string;
  leadingCommand?: string;
}

interface CommandInspection {
  effectiveCommands: EffectiveCommand[];
  usesSudo: boolean;
  elevatesShell: boolean;
  hasPipeline: boolean;
  hasShellWrapper: boolean;
  hasOpaqueInlineScript: boolean;
  hasHeredoc: boolean;
  hasWritableRedirection: boolean;
  writesOutsideScratch: boolean;
  interactiveCommand: boolean;
  hasCommandSubstitution: boolean;
}

interface KnownSafeMatch {
  category: string;
  summary: string;
}

const SUDO_OPTIONS_WITH_VALUE = new Set([
  "-g",
  "-h",
  "-p",
  "-r",
  "-t",
  "-u",
  "-C",
  "-T",
  "--chdir",
  "--close-from",
  "--group",
  "--host",
  "--prompt",
  "--role",
  "--type",
  "--user",
]);

const SAFE_DIRECT_SEGMENT_PATTERNS: Array<{
  regex: RegExp;
  category: string;
  summary: string;
}> = [
  { regex: /^hostname$/i, category: "server-state", summary: "Exact hostname diagnostic." },
  { regex: /^whoami$/i, category: "identity-read", summary: "Exact current-user diagnostic." },
  { regex: /^id$/i, category: "identity-read", summary: "Exact user and group identity diagnostic." },
  { regex: /^getent\s+passwd\s+[A-Za-z0-9._-]+$/i, category: "account-read", summary: "Exact getent passwd lookup." },
  { regex: /^getent\s+group\s+[A-Za-z0-9._-]+$/i, category: "account-read", summary: "Exact getent group lookup." },
  { regex: /^ss\s+-ltn$/i, category: "network-read", summary: "Exact listening TCP socket diagnostic." },
  { regex: /^head(?:\s+-n\s+\d+)?\s+.+$/i, category: "log-read", summary: "Exact head file preview." },
  { regex: /^tail\s+-n\s+\d+\s+.+$/i, category: "log-read", summary: "Exact tail file preview." },
  { regex: /^smsReport(?:\s+2>&1)?$/i, category: "server-state", summary: "Exact smsReport diagnostic." },
  { regex: /^smsReport(?:\s+2>&1)?\s*\|\s*head\s+-n\s+\d+$/i, category: "server-state", summary: "Exact smsReport preview pipeline." },
  {
    regex:
      /^ps\s+-ef\s*\|\s*(?:grep|egrep)\s+.+\s+\|\s+grep\s+-v\s+grep(?:\s*\|\s*head\s+-n\s+\d+)?$/i,
    category: "server-state",
    summary: "Exact process-filter diagnostic pipeline.",
  },
  {
    regex: /^(?:grep|egrep|fgrep)\b(?=.*(?:^|\s)-n(?:\s|$)).+(?:\s*\|\s*head\s+-n\s+\d+)?$/i,
    category: "search-and-read",
    summary: "Exact grep-with-line-numbers diagnostic.",
  },
  {
    regex: /^find\s+.+\s+\|\s+sort(?:\s+.+)?\s+\|\s+tail\s+-n\s+\d+$/i,
    category: "search-and-read",
    summary: "Exact find/sort/tail diagnostic pipeline.",
  },
];

const SAFE_BUNDLE_SEGMENT_PATTERNS: RegExp[] = [
  /^(?:source|\.)\s+(?:~\/)?\.nmsrc(?:\s+>\s*\/dev\/null(?:\s+2>&1)?)?$/i,
  /^echo\s+(['"]).*\1$/i,
  /^printf\s+(['"]).*\1$/i,
];

const DESTRUCTIVE_RULES: MatchRule[] = [
  {
    riskLevel: "destructive",
    category: "server-shutdown",
    summary: "This command can shut down, reboot, or power off the host.",
    reason: "Matches a shutdown, reboot, halt, or poweroff operation.",
    regex:
      /(?:^|[;&|]\s*)(?:shutdown|reboot|poweroff|halt|init\s+[06]|telinit\s+[06]|systemctl\s+(?:reboot|poweroff|halt|kexec))/i,
  },
  {
    riskLevel: "destructive",
    category: "data-delete",
    summary: "This command can delete files or recursively remove directories.",
    reason: "Matches file or directory deletion commands such as rm, rmdir, or shred.",
    regex:
      /(?:^|[;&|]\s*)(?:rm\b|rmdir\b|unlink\b|shred\b|wipefs\b|mkfs(?:\.[A-Za-z0-9_-]+)?\b|fdisk\b|parted\b|pvremove\b|lvremove\b|vgremove\b)/i,
  },
  {
    riskLevel: "destructive",
    category: "package-remove",
    summary: "This command can uninstall packages or remove deployed components.",
    reason: "Matches package removal or uninstall operations.",
    regex:
      /\b(?:apt(?:-get)?|yum|dnf|rpm|zypper|pip(?:3)?|npm|pnpm|yarn)\s+(?:remove|purge|erase|uninstall)\b/i,
  },
  {
    riskLevel: "destructive",
    category: "database-destructive",
    summary: "This command can delete or drop database objects or records.",
    reason: "Matches destructive SQL keywords executed through a database client.",
    regex:
      /\b(?:sqlplus|isql|psql|mysql|mariadb|sqlite3|sqlcmd)\b[\s\S]*\b(?:drop|truncate|delete)\b/i,
  },
  {
    riskLevel: "destructive",
    category: "container-delete",
    summary: "This command can delete containers, volumes, or Kubernetes resources.",
    reason: "Matches docker or kubectl delete/remove operations.",
    regex:
      /\b(?:docker\s+(?:rm|rmi|volume\s+rm|container\s+rm)|kubectl\s+delete)\b/i,
  },
  {
    riskLevel: "destructive",
    category: "git-destructive",
    summary: "This command can discard or permanently clean repository content.",
    reason: "Matches destructive git operations such as reset --hard or clean -fd.",
    regex:
      /\bgit\s+(?:reset\s+--hard|clean\s+-[A-Za-z]*f|checkout\s+--)\b/i,
  },
];

const MUTATING_RULES: MatchRule[] = [
  {
    riskLevel: "mutating",
    category: "session-state",
    summary: "This command changes persistent shell session state.",
    reason: "Matches shell state changes such as cd, source, export, or alias.",
    regex:
      /(?:^|[;&|]\s*)(?:cd\b|pushd\b|popd\b|source\b|\. [^\n]+|export\b|unset\b|alias\b|unalias\b|umask\b|set\b|declare\b|typeset\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "sudoers-change",
    summary: "This command can change sudoers policy or sudo access.",
    reason: "Matches visudo or writes to /etc/sudoers or /etc/sudoers.d.",
    regex:
      /\bvisudo\b|(?:\b(?:tee|cp|mv|install|chmod|chown|sed\s+-i|perl\s+-pi)\b[\s\S]*\/etc\/sudoers(?:\.d(?:\/|\b)|\b))|(?:[>]{1,2}\s*\/etc\/sudoers(?:\.d(?:\/|\b)|\b))/i,
  },
  {
    riskLevel: "mutating",
    category: "password-change",
    summary: "This command can change passwords or password-aging state.",
    reason: "Matches passwd, chpasswd, gpasswd, chage, or usermod password changes.",
    regex:
      /^(?:\S+\/)?(?:passwd|chpasswd|gpasswd|chage)\b|\busermod\b[\s\S]*\b(?:-p|--password)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "account-change",
    summary: "This command can create, modify, or remove operating-system users and groups.",
    reason: "Matches local account-management commands such as useradd, usermod, or groupadd.",
    regex:
      /(?:^|[;&|]\s*)(?:useradd\b|adduser\b|usermod\b|userdel\b|groupadd\b|groupmod\b|groupdel\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "service-change",
    summary: "This command can change service or process availability.",
    reason: "Matches service control actions such as start, stop, restart, or kill.",
    regex:
      /(?:systemctl|service)\s+[^\n]*(?:start|stop|restart|reload|enable|disable|mask|unmask)\b|\b(?:kill|pkill|killall)\b|(?:^|[;&|]\s*)(?:sms-(?:start|stop)\b|nms-all-(?:start|stop)\b|nms-wls-control\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "file-write",
    summary: "This command can create, edit, copy, move, or rewrite files.",
    reason: "Matches common file mutation commands such as touch, cp, mv, chmod, or tee.",
    regex:
      /(?:^|[;&|]\s*)(?:touch\b|mkdir\b|install\b|cp\b|mv\b|ln\b|chmod\b|chown\b|chgrp\b|sed\s+-i\b|perl\s+-pi\b|tee\b|truncate\b|dd\b|tar\b\s+(?:-[A-Za-z]*[crux]|--(?:create|update|append)))/i,
  },
  {
    riskLevel: "mutating",
    category: "package-install",
    summary: "This command can install or upgrade packages or runtime dependencies.",
    reason: "Matches package installation or upgrade operations.",
    regex:
      /\b(?:apt(?:-get)?|yum|dnf|rpm|zypper|pip(?:3)?|npm|pnpm|yarn)\s+(?:install|update|upgrade|add)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "database-change",
    summary: "This command can change database structure or data.",
    reason: "Matches non-destructive SQL mutation keywords executed through a database client.",
    regex:
      /\b(?:sqlplus|isql|psql|mysql|mariadb|sqlite3|sqlcmd)\b[\s\S]*\b(?:insert|update|alter|create|grant|revoke)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "deploy-change",
    summary: "This command can change deployed application or infrastructure state.",
    reason: "Matches docker or kubectl apply/patch/run/scale style operations.",
    regex:
      /\b(?:docker\s+(?:run|start|stop|restart|compose\s+up)|kubectl\s+(?:apply|patch|edit|scale|rollout\s+restart|set)\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "git-change",
    summary: "This command changes repository files or branch state.",
    reason: "Matches git write operations such as commit, merge, checkout, or restore.",
    regex:
      /\bgit\s+(?:commit|merge|rebase|checkout\b(?!\s+--)|restore\b|switch\b|cherry-pick\b|revert\b|stash\b)/i,
  },
];

const INTERACTIVE_COMMAND_PATTERNS = [
  /(?:^|[;&|]\s*)(?:python(?:3)?\b|sqlplus\b|ISQL\b|isql\b|psql\b|mysql\b|sqlite3\b|rlwrap\b\s+\w+|less\b|more\b|man\b|vi\b|vim\b|nano\b|top\b|htop\b|watch\b|sftp\b|ftp\b|telnet\b|ssh\b|read\b)/i,
  /(?:^|[;&|]\s*)tail\b[^\n]*\s-f(?:\s|$)/i,
];

function normalizeCommand(command: string): string {
  return command.replace(/\s+/g, " ").trim();
}

function stripLeadingEnvAssignments(command: string): string {
  return command.replace(
    /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)\s+)*/,
    "",
  );
}

function basenameToken(token: string): string {
  return token.replace(/^['"]|['"]$/g, "").split("/").at(-1)?.toLowerCase() ?? "";
}

function isShellProgram(token: string): boolean {
  return ["sh", "bash", "ksh", "zsh", "csh", "tcsh"].includes(basenameToken(token));
}

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";

    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      current += character;
      escaped = true;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      current += character;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      current += character;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote && /\s/.test(character)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += character;
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

function isShellCommandInvocation(commandTokens: string[]): boolean {
  if (commandTokens.length === 0) {
    return false;
  }

  const [program, ...args] = commandTokens;
  if (!isShellProgram(program)) {
    return false;
  }

  return !args.some((arg) => /^-[A-Za-z]*c[A-Za-z]*$/.test(arg) || arg === "--command");
}

function shortOptionNeedsSeparateValue(shortFlags: string): boolean {
  const valueFlags = ["u", "g", "h", "p", "r", "t", "C", "T"];
  return valueFlags.some((flag) => {
    const index = shortFlags.indexOf(flag.toLowerCase());
    return index >= 0 && index === shortFlags.length - 1;
  });
}

function parseLeadingPrivilegeWrapper(command: string): {
  analysisTarget: string;
  usesSudo: boolean;
  elevatesShell: boolean;
} {
  const normalized = normalizeCommand(command);
  const tokens = tokenizeCommand(normalized);
  const firstToken = basenameToken(tokens[0] ?? "");

  if (firstToken === "su") {
    return {
      analysisTarget: normalized,
      usesSudo: false,
      elevatesShell: true,
    };
  }

  if (firstToken !== "sudo") {
    return {
      analysisTarget: normalized,
      usesSudo: false,
      elevatesShell: false,
    };
  }

  let launchesShell = false;
  let commandStartIndex = -1;

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index] ?? "";
    const lowerToken = token.toLowerCase();

    if (lowerToken === "su") {
      return {
        analysisTarget: tokens.slice(index).join(" "),
        usesSudo: true,
        elevatesShell: true,
      };
    }

    if (token === "--") {
      commandStartIndex = index + 1;
      break;
    }

    if (!token.startsWith("-")) {
      commandStartIndex = index;
      break;
    }

    if (
      lowerToken.startsWith("--user=") ||
      lowerToken.startsWith("--group=") ||
      lowerToken.startsWith("--host=") ||
      lowerToken.startsWith("--prompt=") ||
      lowerToken.startsWith("--role=") ||
      lowerToken.startsWith("--type=") ||
      lowerToken.startsWith("--chdir=") ||
      lowerToken.startsWith("--close-from=")
    ) {
      continue;
    }

    const shortFlags = token.slice(1).toLowerCase();
    if (shortFlags.includes("s") || shortFlags.includes("i")) {
      launchesShell = true;
    }

    if (
      SUDO_OPTIONS_WITH_VALUE.has(token) ||
      SUDO_OPTIONS_WITH_VALUE.has(lowerToken) ||
      shortOptionNeedsSeparateValue(shortFlags)
    ) {
      index += 1;
    }
  }

  const commandTokens = commandStartIndex >= 0 ? tokens.slice(commandStartIndex) : [];
  const elevatesShell =
    launchesShell && (commandTokens.length === 0 || isShellCommandInvocation(commandTokens));

  return {
    analysisTarget: commandTokens.length > 0 ? commandTokens.join(" ") : normalized,
    usesSudo: true,
    elevatesShell,
  };
}

function unwrapOneShotShellWrapper(command: string): {
  analysisTarget: string;
  wrappedInOneShotShell: boolean;
} {
  const patterns = [
    /^\s*(?:\S*\/)?(?:bash|sh|ksh|zsh)\s+-lc\s+(['"])([\s\S]*)\1\s*$/i,
    /^\s*(?:\S*\/)?(?:bash|sh|ksh|zsh)\s+-cl\s+(['"])([\s\S]*)\1\s*$/i,
    /^\s*(?:\S*\/)?(?:bash|sh|ksh|zsh)\s+-c\s+(['"])([\s\S]*)\1\s*$/i,
    /^\s*(?:\S*\/)?(?:bash|sh|ksh|zsh)\s+--login\s+-c\s+(['"])([\s\S]*)\1\s*$/i,
    /^\s*(?:\S*\/)?(?:bash|sh|ksh|zsh)\s+-l\s+-c\s+(['"])([\s\S]*)\1\s*$/i,
  ];

  for (const pattern of patterns) {
    const match = command.match(pattern);
    if (!match) {
      continue;
    }

    return {
      analysisTarget: normalizeCommand(match[2] ?? command),
      wrappedInOneShotShell: true,
    };
  }

  return {
    analysisTarget: command,
    wrappedInOneShotShell: false,
  };
}

function containsCommandSubstitution(command: string): boolean {
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";
    const nextCharacter = command[index + 1] ?? "";

    if (escaped) {
      escaped = false;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      escaped = true;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote) {
      if (character === "`" || (character === "$" && nextCharacter === "(")) {
        return true;
      }
    }
  }

  return false;
}

function containsOpaqueInlineScript(command: string): boolean {
  return (
    /\b(?:python(?:3)?|perl|ruby|node)\s+-[ce]\b/i.test(command) ||
    /<<-?\s*['"]?[A-Za-z0-9_-]+['"]?/i.test(command)
  );
}

function splitTopLevelCommands(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";
    const nextCharacter = command[index + 1] ?? "";

    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      current += character;
      escaped = true;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      current += character;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      current += character;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote) {
      const isSeparator =
        character === ";" ||
        character === "\n" ||
        (character === "&" && nextCharacter === "&") ||
        (character === "|" && nextCharacter === "|");

      if (isSeparator) {
        const trimmed = normalizeCommand(current);
        if (trimmed) {
          segments.push(trimmed);
        }

        current = "";
        if ((character === "&" || character === "|") && nextCharacter === character) {
          index += 1;
        }
        continue;
      }
    }

    current += character;
  }

  const trailing = normalizeCommand(current);
  if (trailing) {
    segments.push(trailing);
  }

  return segments;
}

function splitPipelineSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";
    const nextCharacter = command[index + 1] ?? "";

    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      current += character;
      escaped = true;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      current += character;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      current += character;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote && character === "|" && nextCharacter !== "|") {
      const trimmed = normalizeCommand(current);
      if (trimmed) {
        segments.push(trimmed);
      }
      current = "";
      if (nextCharacter === "&") {
        index += 1;
      }
      continue;
    }

    current += character;
  }

  const trailing = normalizeCommand(current);
  if (trailing) {
    segments.push(trailing);
  }

  return segments;
}

function readShellWord(command: string, startIndex: number): { word: string; endIndex: number } {
  let word = "";
  let index = startIndex;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  while (index < command.length) {
    const character = command[index] ?? "";

    if (escaped) {
      word += character;
      escaped = false;
      index += 1;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      word += character;
      escaped = true;
      index += 1;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      word += character;
      index += 1;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      word += character;
      index += 1;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote && /[\s;|&()<>]/.test(character)) {
      break;
    }

    word += character;
    index += 1;
  }

  return {
    word,
    endIndex: index,
  };
}

function stripQuotedShellWord(word: string): string {
  return word.replace(/^['"]|['"]$/g, "");
}

function isSafeSink(target: string | null): boolean {
  const normalizedTarget = String(target ?? "").trim().toLowerCase();
  return normalizedTarget === "/dev/null" || normalizedTarget === "nul" || normalizedTarget === "&1" || normalizedTarget === "&2";
}

function normalizeScratchPath(path: string): string {
  const normalized = path.replace(/\\/g, "/").replace(/\/+$/, "");
  return normalized || "/";
}

function isScratchPath(target: string | null, scratchPaths: string[]): boolean {
  if (!target) {
    return false;
  }

  const normalizedTarget = stripQuotedShellWord(target).replace(/\\/g, "/");
  if (!normalizedTarget.startsWith("/")) {
    return false;
  }

  return scratchPaths.some((path) => {
    const normalizedPath = normalizeScratchPath(path);
    return normalizedTarget === normalizedPath || normalizedTarget.startsWith(`${normalizedPath}/`);
  });
}

function inspectRedirections(
  command: string,
  scratchPaths: string[],
): RedirectionInspection[] {
  const redirections: RedirectionInspection[] = [];
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";
    const nextCharacter = command[index + 1] ?? "";

    if (escaped) {
      escaped = false;
      continue;
    }

    if (character === "\\" && !inSingleQuote) {
      escaped = true;
      continue;
    }

    if (character === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }

    if (character === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    if (inSingleQuote || inDoubleQuote) {
      continue;
    }

    if (
      character === ">" ||
      character === "<" ||
      (/\d/.test(character) && (nextCharacter === ">" || nextCharacter === "<"))
    ) {
      let operator = "";
      if (/\d/.test(character) && (nextCharacter === ">" || nextCharacter === "<")) {
        operator += character;
        index += 1;
      }

      operator += command[index] ?? "";
      if (command[index + 1] === ">" || command[index + 1] === "<") {
        operator += command[index + 1] ?? "";
        index += 1;
      }
      if (command[index + 1] === "-") {
        operator += command[index + 1] ?? "";
        index += 1;
      }

      let cursor = index + 1;
      while (cursor < command.length && /\s/.test(command[cursor] ?? "")) {
        cursor += 1;
      }

      if (operator.startsWith("<<")) {
        const token = readShellWord(command, cursor);
        redirections.push({
          operator,
          target: token.word || null,
          writes: false,
          targetIsSafeSink: false,
          targetIsScratch: false,
          heredoc: true,
        });
        index = Math.max(index, token.endIndex - 1);
        continue;
      }

      let target: string | null = null;
      let endIndex = cursor;
      if (command[cursor] === "&" && /\d/.test(command[cursor + 1] ?? "")) {
        target = `&${command[cursor + 1] ?? ""}`;
        endIndex = cursor + 2;
      } else {
        const token = readShellWord(command, cursor);
        target = token.word || null;
        endIndex = token.endIndex;
      }
      const writes = operator.includes(">");
      redirections.push({
        operator,
        target,
        writes,
        targetIsSafeSink: isSafeSink(target),
        targetIsScratch: writes && isScratchPath(target, scratchPaths),
        heredoc: false,
      });
      index = Math.max(index, endIndex - 1);
    }
  }

  return redirections;
}

function getLeadingCommandName(command: string): string | undefined {
  const match = stripLeadingEnvAssignments(command).match(/^\s*([A-Za-z_][A-Za-z0-9._/-]*)\b/);
  return match?.[1] ? basenameToken(match[1]) : undefined;
}

function looksInteractiveCommand(command: string): boolean {
  return INTERACTIVE_COMMAND_PATTERNS.some((pattern) => pattern.test(command));
}

function inspectCommandStructure(
  command: string,
  config: CommandPolicyConfig,
  depth = 0,
): CommandInspection {
  const normalized = normalizeCommand(command);
  const inspection: CommandInspection = {
    effectiveCommands: [],
    usesSudo: false,
    elevatesShell: false,
    hasPipeline: false,
    hasShellWrapper: false,
    hasOpaqueInlineScript: false,
    hasHeredoc: false,
    hasWritableRedirection: false,
    writesOutsideScratch: false,
    interactiveCommand: false,
    hasCommandSubstitution: false,
  };

  if (!normalized || depth > 4) {
    inspection.hasOpaqueInlineScript = depth > 4;
    return inspection;
  }

  if (containsCommandSubstitution(normalized)) {
    inspection.hasCommandSubstitution = true;
    inspection.hasOpaqueInlineScript = true;
  }

  for (const segment of splitTopLevelCommands(normalized)) {
    const pipelineSegments = splitPipelineSegments(segment);
    if (pipelineSegments.length > 1) {
      inspection.hasPipeline = true;
    }

    for (const pipelineSegment of pipelineSegments) {
      const redirections = inspectRedirections(pipelineSegment, config.approvedScratchPaths);
      if (redirections.some((entry) => entry.heredoc)) {
        inspection.hasHeredoc = true;
      }

      const writableRedirections = redirections.filter(
        (entry) => entry.writes && !entry.targetIsSafeSink,
      );
      if (writableRedirections.length > 0) {
        inspection.hasWritableRedirection = true;
        if (writableRedirections.some((entry) => !entry.targetIsScratch)) {
          inspection.writesOutsideScratch = true;
        }
      }

      if (containsOpaqueInlineScript(pipelineSegment)) {
        inspection.hasOpaqueInlineScript = true;
      }

      const withoutAssignments = stripLeadingEnvAssignments(pipelineSegment);
      const privilegeWrapper = parseLeadingPrivilegeWrapper(withoutAssignments);
      inspection.usesSudo = inspection.usesSudo || privilegeWrapper.usesSudo;
      inspection.elevatesShell = inspection.elevatesShell || privilegeWrapper.elevatesShell;

      const wrapper = unwrapOneShotShellWrapper(privilegeWrapper.analysisTarget);
      if (wrapper.wrappedInOneShotShell) {
        inspection.hasShellWrapper = true;
        const nested = inspectCommandStructure(wrapper.analysisTarget, config, depth + 1);
        inspection.effectiveCommands.push(...nested.effectiveCommands);
        inspection.usesSudo = inspection.usesSudo || nested.usesSudo;
        inspection.elevatesShell = inspection.elevatesShell || nested.elevatesShell;
        inspection.hasPipeline = inspection.hasPipeline || nested.hasPipeline;
        inspection.hasShellWrapper = inspection.hasShellWrapper || nested.hasShellWrapper;
        inspection.hasOpaqueInlineScript =
          inspection.hasOpaqueInlineScript || nested.hasOpaqueInlineScript;
        inspection.hasHeredoc = inspection.hasHeredoc || nested.hasHeredoc;
        inspection.hasWritableRedirection =
          inspection.hasWritableRedirection || nested.hasWritableRedirection;
        inspection.writesOutsideScratch =
          inspection.writesOutsideScratch || nested.writesOutsideScratch;
        inspection.interactiveCommand =
          inspection.interactiveCommand || nested.interactiveCommand;
        inspection.hasCommandSubstitution =
          inspection.hasCommandSubstitution || nested.hasCommandSubstitution;
        continue;
      }

      const effectiveCommand = normalizeCommand(privilegeWrapper.analysisTarget);
      inspection.effectiveCommands.push({
        command: effectiveCommand,
        leadingCommand: getLeadingCommandName(effectiveCommand),
      });
      inspection.interactiveCommand =
        inspection.interactiveCommand || looksInteractiveCommand(effectiveCommand);
    }
  }

  return inspection;
}

function matchRules(texts: string[], rules: MatchRule[]): MatchRule[] {
  const matches: MatchRule[] = [];
  const seen = new Set<string>();

  for (const rule of rules) {
    if (!texts.some((text) => rule.regex.test(text))) {
      continue;
    }

    const key = `${rule.category}:${rule.reason}`;
    if (!seen.has(key)) {
      matches.push(rule);
      seen.add(key);
    }
  }

  return matches;
}

function buildMatchedRule(
  source: "allow" | "deny",
  rule:
    | CommandPolicyConfig["allowRules"][number]
    | CommandPolicyConfig["denyRules"][number],
): MatchedPolicyRule {
  return {
    source,
    name: rule.name,
    pattern: rule.pattern,
    flags: rule.flags,
    reason: rule.reason,
    decision: source === "deny" ? "blocked" : "decision" in rule ? rule.decision : "blocked",
  };
}

function findAllowRule(command: string, config: CommandPolicyConfig): MatchedPolicyRule | undefined {
  const rule = config.allowRules.find((candidate) => candidate.regex.test(command));
  return rule ? buildMatchedRule("allow", rule) : undefined;
}

function findDenyRule(command: string, config: CommandPolicyConfig): MatchedPolicyRule | undefined {
  const rule = config.denyRules.find((candidate) => candidate.regex.test(command));
  return rule ? buildMatchedRule("deny", rule) : undefined;
}

function isReadOnlyIsqlCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!/^ISQL\b/i.test(trimmed)) {
    return false;
  }

  const hasSelect = /\bselect\b/i.test(trimmed);
  const hasUnsafeSql =
    /\b(?:insert|update|delete|merge|drop|truncate|alter|create|grant|revoke|begin|declare|commit|rollback|lock|call|exec(?:ute)?)\b/i.test(
      trimmed,
    );

  return hasSelect && !hasUnsafeSql;
}

function matchSafeDiagnosticSegment(segment: string): KnownSafeMatch | null {
  const normalized = normalizeCommand(segment);
  for (const entry of SAFE_DIRECT_SEGMENT_PATTERNS) {
    if (entry.regex.test(normalized)) {
      return {
        category: entry.category,
        summary: entry.summary,
      };
    }
  }

  if (SAFE_BUNDLE_SEGMENT_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return {
      category: "diagnostic-bundle",
      summary: "Exact Oracle NMS wrapper setup or banner segment.",
    };
  }

  if (isReadOnlyIsqlCommand(normalized)) {
    return {
      category: "database-read",
      summary: "Exact read-only ISQL SELECT command.",
    };
  }

  return null;
}

function matchDiagnosticsProfile(
  command: string,
  config: CommandPolicyConfig,
): KnownSafeMatch | null {
  if (!config.diagnosticsProfiles.includes("oracle-nms-readonly")) {
    return null;
  }

  const normalized = normalizeCommand(command);
  const inspection = inspectCommandStructure(normalized, config);
  if (
    inspection.usesSudo ||
    inspection.elevatesShell ||
    inspection.hasHeredoc ||
    inspection.hasOpaqueInlineScript ||
    inspection.hasWritableRedirection ||
    inspection.hasCommandSubstitution ||
    inspection.interactiveCommand
  ) {
    return null;
  }

  const directMatch = matchSafeDiagnosticSegment(normalized);
  if (directMatch) {
    return directMatch;
  }

  const wrapper = unwrapOneShotShellWrapper(stripLeadingEnvAssignments(normalized));
  if (!wrapper.wrappedInOneShotShell) {
    return null;
  }

  const segments = splitTopLevelCommands(wrapper.analysisTarget);
  if (segments.length === 0) {
    return null;
  }

  let meaningfulSegments = 0;
  for (const segment of segments) {
    const matched = matchSafeDiagnosticSegment(segment);
    if (!matched) {
      return null;
    }

    if (matched.category !== "diagnostic-bundle") {
      meaningfulSegments += 1;
    }
  }

  if (meaningfulSegments === 0) {
    return null;
  }

  return {
    category: "diagnostic-bundle",
    summary: "Exact Oracle NMS read-only diagnostics bundle.",
  };
}

function buildReadOnlySummary(
  command: string,
  config: CommandPolicyConfig,
): {
  category: string;
  summary: string;
  knownSafeAutoRun: boolean;
} {
  const safeProfileMatch = matchDiagnosticsProfile(command, config);
  if (safeProfileMatch) {
    return {
      category: safeProfileMatch.category,
      summary: safeProfileMatch.summary,
      knownSafeAutoRun: true,
    };
  }

  if (isReadOnlyIsqlCommand(command)) {
    return {
      category: "database-read",
      summary: "Explicitly allowed ISQL read-only SELECT command.",
      knownSafeAutoRun: true,
    };
  }

  return {
    category: "general-shell",
    summary:
      "This command does not match an exact safe diagnostics profile, so MCP requires review before running it automatically.",
    knownSafeAutoRun: false,
  };
}

function decideCommandPolicy(
  input: {
    riskLevel: CommandRiskLevel;
    category: string;
    usesSudo: boolean;
    elevatesShell: boolean;
    opaqueInlineScript: boolean;
    hasHeredoc: boolean;
    hasWritableRedirection: boolean;
    knownSafeAutoRun: boolean;
    safeSudoReadOnlyAutoRun: boolean;
    safePrivilegeTransitionAutoRun: boolean;
  },
  config: CommandPolicyConfig,
  matchedAllowRule?: MatchedPolicyRule,
  matchedDenyRule?: MatchedPolicyRule,
): {
  decision: PolicyDecision;
  decisionReason: string;
  matchedRule?: MatchedPolicyRule;
} {
  const autoAllowPermitted =
    input.safeSudoReadOnlyAutoRun ||
    input.safePrivilegeTransitionAutoRun ||
    input.knownSafeAutoRun &&
    !input.usesSudo &&
    !input.elevatesShell &&
    !input.opaqueInlineScript &&
    !input.hasHeredoc &&
    !input.hasWritableRedirection;

  if (matchedDenyRule) {
    return {
      decision: "blocked",
      decisionReason: matchedDenyRule.reason,
      matchedRule: matchedDenyRule,
    };
  }

  if (config.blockedCategories.includes(input.category)) {
    return {
      decision: "blocked",
      decisionReason: "Active policy blocks this command category from running through MCP.",
    };
  }

  if (matchedAllowRule) {
    if (
      (input.riskLevel === "read-only" || input.safePrivilegeTransitionAutoRun) &&
      matchedAllowRule.decision === "allow" &&
      autoAllowPermitted
    ) {
      return {
        decision: "allow",
        decisionReason: matchedAllowRule.reason,
        matchedRule: matchedAllowRule,
      };
    }

    return {
      decision: "approval_required",
      decisionReason:
        matchedAllowRule.decision === "allow"
          ? `${matchedAllowRule.reason} MCP still requires explicit confirmation because this command uses a high-scrutiny shell structure or privilege boundary.`
          : matchedAllowRule.reason,
      matchedRule: matchedAllowRule,
    };
  }

  if (
    !input.safeSudoReadOnlyAutoRun &&
    !input.safePrivilegeTransitionAutoRun &&
    config.approvalCategories.includes(input.category)
  ) {
    return {
      decision: "approval_required",
      decisionReason: "Active policy requires confirmation for this command category before MCP can run it.",
    };
  }

  if (autoAllowPermitted) {
    return {
      decision: "allow",
      decisionReason: "Built-in policy allows this exact known-safe read-only diagnostic command without confirmation.",
    };
  }

  return {
    decision: "approval_required",
    decisionReason:
      input.riskLevel === "read-only"
        ? "This command is not on the exact safe auto-run list, or it uses sudo, wrappers, redirections, or other high-scrutiny shell structure, so user confirmation is required."
        : "This command can change shell state or broader system state, so MCP requires explicit user confirmation before running it.",
  };
}

export function reviewCommandPolicy(
  command: string,
  session: ShellSession | undefined,
  config: CommandPolicyConfig,
): CommandReview {
  const normalizedCommand = normalizeCommand(command);
  const inspection = inspectCommandStructure(normalizedCommand, config);
  const textsForRules = Array.from(
    new Set([
      normalizedCommand,
      ...inspection.effectiveCommands.map((entry) => entry.command),
    ]),
  );
  const reasons = new Set<string>();

  const destructiveMatches = matchRules(textsForRules, DESTRUCTIVE_RULES);
  const mutatingMatches = matchRules(textsForRules, MUTATING_RULES);
  const readOnlySummary = buildReadOnlySummary(normalizedCommand, config);
  const leadingPrivilegeWrapper = parseLeadingPrivilegeWrapper(
    stripLeadingEnvAssignments(normalizedCommand),
  );
  const sudoReadOnlySummary =
    leadingPrivilegeWrapper.usesSudo && !leadingPrivilegeWrapper.elevatesShell
      ? buildReadOnlySummary(leadingPrivilegeWrapper.analysisTarget, config)
      : undefined;
  const privilegeTransition = inferShellIdentityTransition(normalizedCommand);
  const safePrivilegeTransitionAutoRun =
    Boolean(privilegeTransition?.viaSudo) &&
    privilegeTransition?.expectedUser !== "root" &&
    !inspection.hasPipeline &&
    !inspection.hasShellWrapper &&
    !inspection.hasOpaqueInlineScript &&
    !inspection.hasHeredoc &&
    !inspection.hasWritableRedirection &&
    !inspection.hasCommandSubstitution &&
    !inspection.interactiveCommand;
  const safeSudoReadOnlyAutoRun =
    inspection.usesSudo &&
    !inspection.elevatesShell &&
    Boolean(sudoReadOnlySummary?.knownSafeAutoRun) &&
    !inspection.hasShellWrapper &&
    !inspection.hasOpaqueInlineScript &&
    !inspection.hasHeredoc &&
    !inspection.hasWritableRedirection &&
    !inspection.hasCommandSubstitution &&
    !inspection.interactiveCommand;

  for (const match of destructiveMatches) {
    reasons.add(match.reason);
  }

  for (const match of mutatingMatches) {
    reasons.add(match.reason);
  }

  if (inspection.usesSudo) {
    reasons.add(
      safePrivilegeTransitionAutoRun || safeSudoReadOnlyAutoRun
        ? "Matches an exact built-in sudo pattern that MCP can auto-run for LDAP-to-target-user handoff."
        : "Contains sudo in the effective command path, so MCP must not auto-run it.",
    );
  }

  if (inspection.elevatesShell) {
    reasons.add(
      safePrivilegeTransitionAutoRun && privilegeTransition
        ? `Adopts the managed shell as ${privilegeTransition.expectedUser}.`
        : "Changes the active shell identity or privilege boundary.",
    );
  }

  if (inspection.hasPipeline) {
    reasons.add("Uses a shell pipeline, so MCP inspected every pipeline segment before deciding.");
  }

  if (inspection.hasShellWrapper) {
    reasons.add("Uses a shell wrapper such as bash -lc, which receives higher scrutiny.");
  }

  if (inspection.hasWritableRedirection) {
    reasons.add(
      inspection.writesOutsideScratch
        ? "Contains shell redirection that can write outside the approved scratch paths."
        : "Contains shell redirection that can write to an approved scratch path.",
    );
  }

  if (inspection.hasHeredoc) {
    reasons.add("Contains a heredoc, which MCP treats as a high-scrutiny inline script structure.");
  }

  if (inspection.hasCommandSubstitution) {
    reasons.add("Contains command substitution, which MCP treats as a high-scrutiny shell structure.");
  }

  if (inspection.hasOpaqueInlineScript) {
    reasons.add("Contains an inline script or opaque shell wrapper body whose behavior is harder to verify safely.");
  }

  if (inspection.interactiveCommand) {
    reasons.add("Starts an interactive or long-running terminal program that may require follow-up input.");
  }

  let riskLevel: CommandRiskLevel = "read-only";
  let category = readOnlySummary.category;
  let summary = readOnlySummary.summary;
  let knownSafeAutoRun = readOnlySummary.knownSafeAutoRun;

  if (destructiveMatches.length > 0) {
    riskLevel = "destructive";
    category = destructiveMatches[0]?.category ?? category;
    summary = destructiveMatches[0]?.summary ?? summary;
    knownSafeAutoRun = false;
  } else if (safePrivilegeTransitionAutoRun && privilegeTransition) {
    riskLevel = "mutating";
    category = "privileged-session-switch";
    summary = `This exact sudo-based shell switch adopts the ${privilegeTransition.expectedUser} user for subsequent commands.`;
    knownSafeAutoRun = true;
  } else if (
    knownSafeAutoRun &&
    mutatingMatches.every((match) => match.category === "session-state") &&
    !inspection.usesSudo &&
    !inspection.hasWritableRedirection &&
    !inspection.hasHeredoc &&
    !inspection.hasOpaqueInlineScript &&
    !inspection.interactiveCommand
  ) {
    riskLevel = "read-only";
  } else if (inspection.elevatesShell) {
    riskLevel = "mutating";
    category = "privilege-escalation";
    summary = "This command elevates or replaces the active shell identity.";
    knownSafeAutoRun = false;
  } else if (
    inspection.usesSudo &&
    mutatingMatches.length === 0 &&
    !inspection.hasWritableRedirection &&
    !inspection.hasHeredoc &&
    !inspection.hasOpaqueInlineScript &&
    !inspection.interactiveCommand
  ) {
    riskLevel = "read-only";
    category = "privileged-command";
    summary = safeSudoReadOnlyAutoRun
      ? "This exact read-only diagnostic runs under sudo as the requested target user."
      : "This command runs under sudo and therefore still needs explicit review.";
    knownSafeAutoRun = safeSudoReadOnlyAutoRun;
  } else if (
    mutatingMatches.length > 0 ||
    inspection.hasWritableRedirection ||
    inspection.hasHeredoc ||
    inspection.hasOpaqueInlineScript
  ) {
    riskLevel = "mutating";
    category =
      mutatingMatches[0]?.category ??
      (inspection.hasWritableRedirection
        ? inspection.writesOutsideScratch
          ? "file-write"
          : "scratch-write"
        : "opaque-script");
    summary =
      mutatingMatches[0]?.summary ??
      (inspection.hasWritableRedirection
        ? inspection.writesOutsideScratch
          ? "This command can write or overwrite files outside the approved scratch paths."
          : "This command writes to an approved scratch path and still requires confirmation."
        : inspection.hasHeredoc
          ? "This command uses a heredoc, so its behavior is harder to verify safely."
          : "This command includes an inline script or opaque shell wrapper, so its behavior is harder to verify safely.");
    knownSafeAutoRun = false;
  } else if (inspection.interactiveCommand) {
    riskLevel = "read-only";
    category = "interactive-terminal";
    summary = "This command starts an interactive or long-running terminal program.";
    knownSafeAutoRun = false;
  }

  if (session?.isSudo && riskLevel !== "read-only") {
    reasons.add("The session is already elevated with sudo privileges.");
  }

  if (session?.isSudo && riskLevel === "read-only") {
    reasons.add("The session is already elevated with sudo privileges, even though the command itself looks read-only.");
  }

  const matchedDenyRule = findDenyRule(normalizedCommand, config);
  const matchedAllowRule = findAllowRule(normalizedCommand, config);
  const decisionState = decideCommandPolicy(
    {
      riskLevel,
      category,
      usesSudo: inspection.usesSudo,
      elevatesShell: inspection.elevatesShell,
      opaqueInlineScript: inspection.hasOpaqueInlineScript,
      hasHeredoc: inspection.hasHeredoc,
      hasWritableRedirection: inspection.hasWritableRedirection,
      knownSafeAutoRun,
      safeSudoReadOnlyAutoRun,
      safePrivilegeTransitionAutoRun,
    },
    config,
    matchedAllowRule,
    matchedDenyRule,
  );

  const requiresConfirmation = decisionState.decision === "approval_required";
  const requiredConfirmationToken = requiresConfirmation ? "CONFIRM" : undefined;

  if (reasons.size === 0) {
    reasons.add(
      knownSafeAutoRun
        ? "This command matches an exact built-in safe diagnostics profile."
        : "This command was not recognized as one of the exact safe auto-run commands.",
    );
  }

  if (decisionState.decision === "blocked") {
    reasons.add(decisionState.decisionReason);
  }

  return {
    command,
    normalizedCommand,
    riskLevel,
    category,
    summary,
    reasons: Array.from(reasons),
    decision: decisionState.decision,
    decisionReason: decisionState.decisionReason,
    matchedRule: decisionState.matchedRule,
    requiresConfirmation,
    requiredConfirmationToken,
    safeForAutoRun: decisionState.decision === "allow",
    needsManualReview:
      decisionState.decision !== "allow" ||
      inspection.hasOpaqueInlineScript ||
      inspection.hasHeredoc ||
      (inspection.usesSudo && !safeSudoReadOnlyAutoRun && !safePrivilegeTransitionAutoRun) ||
      inspection.hasWritableRedirection,
    knownSafeAutoRun,
  };
}
