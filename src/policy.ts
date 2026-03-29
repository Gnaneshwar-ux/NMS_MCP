import type { CommandPolicyConfig, PolicyDecision } from "./policy-config.js";
import type { CommandRiskLevel, ShellSession } from "./session.js";

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

const SAFE_AUTO_RUN_COMMANDS = new Set([
  "ls",
  "pwd",
  "cd",
  "grep",
  "find",
  "locate",
  "cat",
  "ps",
  "tail",
]);

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
    category: "privilege-escalation",
    summary: "This command elevates the shell or changes the active user context.",
    reason: "Matches sudo -s, sudo su, or su style shell elevation.",
    regex:
      /(?:^|[;&|]\s*)(?:sudo(?:\s+-[^\s]+)*\s+(?:-s\b|su\b)|su(?:\s+-\w*)?\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "file-write",
    summary: "This command can create, edit, copy, move, or rewrite files.",
    reason: "Matches common file mutation commands such as touch, cp, mv, chmod, or sed -i.",
    regex:
      /(?:^|[;&|]\s*)(?:touch\b|mkdir\b|install\b|cp\b|mv\b|ln\b|chmod\b|chown\b|chgrp\b|sed\s+-i\b|perl\s+-pi\b|tee\b|truncate\b|dd\b|tar\b\s+(?:-[A-Za-z]*[crux]|--(?:create|update|append)))/i,
  },
  {
    riskLevel: "mutating",
    category: "account-change",
    summary: "This command can create, modify, lock, unlock, or remove operating-system users and groups.",
    reason: "Matches local account-management commands such as useradd, usermod, passwd, or chpasswd.",
    regex:
      /(?:^|[;&|]\s*)(?:useradd\b|adduser\b|usermod\b|userdel\b|groupadd\b|groupmod\b|groupdel\b|passwd\b|chpasswd\b|gpasswd\b|chage\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "service-change",
    summary: "This command can change service or process availability.",
    reason: "Matches service control actions such as start, stop, restart, or kill.",
    regex:
      /(?:systemctl|service)\s+[^\n]*(?:start|stop|restart|reload|enable|disable|mask|unmask)\b|\b(?:kill|pkill|killall)\b/i,
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

function unwrapLeadingSudo(command: string): {
  analysisTarget: string;
  usesSudo: boolean;
  elevatesShell: boolean;
} {
  const trimmed = command.trim();
  if (
    /^sudo(?:\s+-[^\s]+)*\s+(?:-s\b|su\b)/i.test(trimmed) ||
    /^su(?:\s+-\w*)?\b/i.test(trimmed)
  ) {
    return {
      analysisTarget: trimmed,
      usesSudo: true,
      elevatesShell: true,
    };
  }

  const sudoMatch = trimmed.match(/^sudo(?:\s+-[^\s]+(?:\s+[^\s]+)?)?\s+([\s\S]+)$/i);
  if (!sudoMatch) {
    return {
      analysisTarget: trimmed,
      usesSudo: false,
      elevatesShell: false,
    };
  }

  return {
    analysisTarget: sudoMatch[1] ?? trimmed,
    usesSudo: true,
    elevatesShell: false,
  };
}

function containsOpaqueInlineScript(command: string): boolean {
  return (
    /\b(?:bash|sh|python(?:3)?|perl|ruby|node)\s+-[ce]\b/i.test(command) ||
    /<<-?\s*['"]?[A-Za-z0-9_-]+['"]?/i.test(command)
  );
}

function containsFileRedirection(command: string): boolean {
  const matches = command.matchAll(/(^|[^<])(\d?>>?|>>?)\s*([^\s;|&]+)/g);

  for (const match of matches) {
    const target = String(match[3] ?? "").replace(/^['"]|['"]$/g, "").toLowerCase();
    if (target === "/dev/null" || target === "nul" || target === "&1" || target === "&2") {
      continue;
    }

    return true;
  }

  return false;
}

function looksInteractiveCommand(command: string): boolean {
  return INTERACTIVE_COMMAND_PATTERNS.some((pattern) => pattern.test(command));
}

function matchRules(command: string, rules: MatchRule[]): MatchRule[] {
  return rules.filter((rule) => rule.regex.test(command));
}

function getLeadingCommandName(command: string): string | undefined {
  const match = command.match(/^\s*([A-Za-z_][A-Za-z0-9._-]*)\b/);
  return match?.[1]?.toLowerCase();
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

function buildReadOnlySummary(command: string): {
  category: string;
  summary: string;
  knownSafeAutoRun: boolean;
} {
  const leadingCommand = getLeadingCommandName(command);
  if (leadingCommand && SAFE_AUTO_RUN_COMMANDS.has(leadingCommand)) {
    return {
      category: leadingCommand === "ps" ? "server-state" : "search-and-read",
      summary: "Explicitly allowed read-only or low-impact shell command.",
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
      "The command does not match the explicit safe auto-run list, even though it does not currently look destructive.",
    knownSafeAutoRun: false,
  };
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

function decideCommandPolicy(
  input: {
    riskLevel: CommandRiskLevel;
    category: string;
    usesSudo: boolean;
    opaqueInlineScript: boolean;
    sessionIsSudo: boolean;
    knownSafeAutoRun: boolean;
  },
  config: CommandPolicyConfig,
  matchedAllowRule?: MatchedPolicyRule,
  matchedDenyRule?: MatchedPolicyRule,
): {
  decision: PolicyDecision;
  decisionReason: string;
  matchedRule?: MatchedPolicyRule;
} {
  if (matchedDenyRule) {
    return {
      decision: "blocked",
      decisionReason: matchedDenyRule.reason,
      matchedRule: matchedDenyRule,
    };
  }

  if (matchedAllowRule) {
    if (
      (input.riskLevel === "read-only" || input.category === "session-state") &&
      !input.usesSudo &&
      !input.sessionIsSudo
    ) {
      return {
        decision: matchedAllowRule.decision,
        decisionReason: matchedAllowRule.reason,
        matchedRule: matchedAllowRule,
      };
    }

    return {
      decision: "approval_required",
      decisionReason:
        matchedAllowRule.decision === "allow"
          ? `${matchedAllowRule.reason} MCP still requires explicit confirmation for commands outside the safe auto-run path.`
          : matchedAllowRule.reason,
      matchedRule: matchedAllowRule,
    };
  }

  if (config.blockedCategories.includes(input.category)) {
    return {
      decision: "blocked",
      decisionReason: "Active policy blocks this command category from running through MCP.",
    };
  }

  if (
    input.knownSafeAutoRun &&
    !input.usesSudo &&
    !input.sessionIsSudo &&
    !input.opaqueInlineScript
  ) {
    return {
      decision: "allow",
      decisionReason: "Built-in policy allows this explicit safe shell command without confirmation.",
    };
  }

  return {
    decision: "approval_required",
    decisionReason:
      input.riskLevel === "read-only"
        ? "This command is not on the explicit safe auto-run list, so user confirmation is required before MCP runs it."
        : "This command can change shell state or broader system state, so MCP requires explicit user confirmation before running it.",
  };
}

export function reviewCommandPolicy(
  command: string,
  session: ShellSession | undefined,
  config: CommandPolicyConfig,
): CommandReview {
  const normalizedCommand = normalizeCommand(command);
  const withoutAssignments = stripLeadingEnvAssignments(normalizedCommand);
  const sudoState = unwrapLeadingSudo(withoutAssignments);
  const analysisTarget = sudoState.analysisTarget;
  const leadingCommand = getLeadingCommandName(analysisTarget);
  const reasons = new Set<string>();

  const destructiveMatches = matchRules(analysisTarget, DESTRUCTIVE_RULES);
  const mutatingMatches = matchRules(analysisTarget, MUTATING_RULES);
  const opaqueInlineScript = containsOpaqueInlineScript(analysisTarget);
  const fileRedirection = containsFileRedirection(analysisTarget);
  const interactiveCommand = looksInteractiveCommand(analysisTarget);

  for (const match of destructiveMatches) {
    reasons.add(match.reason);
  }

  for (const match of mutatingMatches) {
    reasons.add(match.reason);
  }

  if (sudoState.usesSudo && !sudoState.elevatesShell) {
    reasons.add("Uses sudo for this command; elevated reads or writes must be treated more carefully.");
  }

  if (fileRedirection) {
    reasons.add("Contains shell output redirection, which can write or overwrite files.");
  }

  if (opaqueInlineScript) {
    reasons.add("Contains an inline script or heredoc, so the exact behavior is harder to verify quickly.");
  }

  if (interactiveCommand) {
    reasons.add("Starts an interactive or long-running terminal program that may require follow-up input.");
  }

  let riskLevel: CommandRiskLevel = "read-only";
  let category = "general-shell";
  let summary = "";
  let knownSafeAutoRun = false;

  if (destructiveMatches.length > 0) {
    riskLevel = "destructive";
    category = destructiveMatches[0]?.category ?? category;
    summary = destructiveMatches[0]?.summary ?? summary;
  } else if (
    leadingCommand === "cd" &&
    mutatingMatches.every((match) => match.category === "session-state") &&
    !fileRedirection &&
    !opaqueInlineScript &&
    !interactiveCommand
  ) {
    riskLevel = "mutating";
    category = "session-state";
    summary = "Explicitly allowed low-impact shell directory change.";
    knownSafeAutoRun = true;
  } else if (mutatingMatches.length > 0 || fileRedirection || opaqueInlineScript) {
    riskLevel = "mutating";
    category = mutatingMatches[0]?.category ?? (fileRedirection ? "file-write" : "opaque-script");
    summary =
      mutatingMatches[0]?.summary ??
      (fileRedirection
        ? "This command can write or overwrite files through shell redirection."
        : "This command includes an inline script or heredoc, so its behavior is harder to verify safely.");
  } else if (interactiveCommand) {
    riskLevel = "read-only";
    category = "interactive-terminal";
    summary = "This command starts an interactive or long-running terminal program.";
  } else {
    const readOnlySummary = buildReadOnlySummary(analysisTarget);
    category = readOnlySummary.category;
    summary = readOnlySummary.summary;
    knownSafeAutoRun = readOnlySummary.knownSafeAutoRun;
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
      usesSudo: sudoState.usesSudo,
      opaqueInlineScript,
      sessionIsSudo: Boolean(session?.isSudo),
      knownSafeAutoRun,
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
        ? "This command matches the explicit safe auto-run list."
        : "This command was not recognized as one of the explicitly safe auto-run commands.",
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
    needsManualReview: decisionState.decision !== "allow" || opaqueInlineScript,
    knownSafeAutoRun,
  };
}
