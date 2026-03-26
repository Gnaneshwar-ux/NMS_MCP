import type { OracleDbSession, SqlRiskLevel } from "./db-session.js";
import type { PolicyDecision, SqlPolicyConfig } from "./policy-config.js";
import type { MatchedPolicyRule } from "./policy.js";

export interface SqlReview {
  sql: string;
  normalizedSql: string;
  executableSql: string;
  riskLevel: SqlRiskLevel;
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

interface SqlMatchRule {
  riskLevel: SqlRiskLevel;
  category: string;
  summary: string;
  reason: string;
  regex: RegExp;
}

const DESTRUCTIVE_SQL_RULES: SqlMatchRule[] = [
  {
    riskLevel: "destructive",
    category: "ddl-destructive",
    summary: "This SQL can drop, truncate, purge, or otherwise permanently remove database objects or data.",
    reason: "Matches destructive DDL such as DROP, TRUNCATE, PURGE, or destructive FLASHBACK forms.",
    regex: /^\s*(?:drop|truncate|purge|flashback\s+\w+\s+to\s+before\s+drop)\b/i,
  },
  {
    riskLevel: "destructive",
    category: "db-admin",
    summary: "This SQL changes database-wide or account-level state.",
    reason: "Matches administrative statements such as ALTER SYSTEM, CREATE USER, DROP USER, STARTUP, or SHUTDOWN.",
    regex:
      /^\s*(?:alter\s+system|alter\s+database|create\s+user|alter\s+user|drop\s+user|startup|shutdown)\b/i,
  },
];

const MUTATING_SQL_RULES: SqlMatchRule[] = [
  {
    riskLevel: "mutating",
    category: "session-state",
    summary: "This SQL changes the current database session state.",
    reason: "Matches session-scoped statements such as ALTER SESSION or SET ROLE.",
    regex: /^\s*(?:alter\s+session|set\s+role|set\s+transaction)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "dml-change",
    summary: "This SQL can change rows in application tables or views.",
    reason: "Matches DML such as INSERT, UPDATE, DELETE, or MERGE.",
    regex: /^(?:\s*with\b[\s\S]*\b(?:insert|update|delete|merge)\b|\s*(?:insert|update|delete|merge)\b)/i,
  },
  {
    riskLevel: "mutating",
    category: "ddl-change",
    summary: "This SQL can create or alter database objects.",
    reason: "Matches DDL such as CREATE, ALTER, RENAME, COMMENT, ANALYZE, or FLASHBACK.",
    regex: /^\s*(?:create|alter(?!\s+session\b)|rename|comment|analyze|flashback)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "transaction-control",
    summary: "This SQL changes transaction state.",
    reason: "Matches COMMIT, ROLLBACK, SAVEPOINT, or SET TRANSACTION.",
    regex: /^\s*(?:commit|rollback|savepoint|set\s+transaction)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "privilege-change",
    summary: "This SQL changes privileges or grants.",
    reason: "Matches GRANT or REVOKE statements.",
    regex: /^\s*(?:grant|revoke)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "lock-control",
    summary: "This SQL can lock rows or tables and affect concurrent application activity.",
    reason: "Matches LOCK TABLE or SELECT ... FOR UPDATE.",
    regex: /^\s*lock\s+table\b|\bfor\s+update\b/i,
  },
  {
    riskLevel: "mutating",
    category: "plsql-exec",
    summary: "This SQL executes PL/SQL or procedural logic whose side effects may be difficult to verify safely.",
    reason: "Matches BEGIN, DECLARE, CALL, EXEC, or EXECUTE forms.",
    regex: /^\s*(?:begin|declare|call|exec(?:ute)?)\b/i,
  },
  {
    riskLevel: "mutating",
    category: "package-call",
    summary: "This SQL invokes a schema-qualified or packaged routine, which can hide side effects.",
    reason: "Matches a package or schema-qualified routine call such as pkg.proc(...).",
    regex: /(?:\b[A-Za-z_][A-Za-z0-9_$#]*\.){1,2}[A-Za-z_][A-Za-z0-9_$#]*\s*\(/i,
  },
];

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function stripSqlCommentsAndQuotedText(sql: string): string {
  let index = 0;
  let output = "";

  while (index < sql.length) {
    const current = sql[index];
    const next = sql[index + 1];

    if (current === "-" && next === "-") {
      index += 2;
      while (index < sql.length && sql[index] !== "\n") {
        index += 1;
      }
      output += " ";
      continue;
    }

    if (current === "/" && next === "*") {
      index += 2;
      while (index < sql.length && !(sql[index] === "*" && sql[index + 1] === "/")) {
        index += 1;
      }
      index += 2;
      output += " ";
      continue;
    }

    if (current === "'" || current === '"') {
      const quote = current;
      index += 1;
      while (index < sql.length) {
        if (sql[index] === quote) {
          if (sql[index + 1] === quote) {
            index += 2;
            continue;
          }

          index += 1;
          break;
        }

        index += 1;
      }
      output += " ";
      continue;
    }

    output += current;
    index += 1;
  }

  return output;
}

function trimTrailingSqlTerminators(sql: string): string {
  return sql.trim().replace(/;+$/g, "").trim();
}

export function normalizeExecutableSql(sql: string): string {
  return trimTrailingSqlTerminators(sql);
}

function containsMultipleStatements(sql: string): boolean {
  const withoutTrailingTerminator = trimTrailingSqlTerminators(sql);
  return withoutTrailingTerminator.includes(";");
}

function matchRules(sql: string, rules: SqlMatchRule[]): SqlMatchRule[] {
  return rules.filter((rule) => rule.regex.test(sql));
}

function buildMatchedRule(
  source: "allow" | "deny",
  rule:
    | SqlPolicyConfig["allowRules"][number]
    | SqlPolicyConfig["denyRules"][number],
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

function findAllowRule(sql: string, config: SqlPolicyConfig): MatchedPolicyRule | undefined {
  const rule = config.allowRules.find((candidate) => candidate.regex.test(sql));
  return rule ? buildMatchedRule("allow", rule) : undefined;
}

function findDenyRule(sql: string, config: SqlPolicyConfig): MatchedPolicyRule | undefined {
  const rule = config.denyRules.find((candidate) => candidate.regex.test(sql));
  return rule ? buildMatchedRule("deny", rule) : undefined;
}

function isKnownSafeReadOnlySelect(sql: string): boolean {
  return /^\s*(?:select|with)\b/i.test(sql);
}

function buildReadOnlySummary(sql: string): {
  category: string;
  summary: string;
  knownSafeAutoRun: boolean;
} {
  if (isKnownSafeReadOnlySelect(sql)) {
    return {
      category: "query-read",
      summary: "Explicitly allowed read-only SELECT query.",
      knownSafeAutoRun: true,
    };
  }

  return {
    category: "unknown-sql",
    summary: "This statement does not match the explicit safe auto-run SQL list.",
    knownSafeAutoRun: false,
  };
}

function decideSqlPolicy(
  input: {
    riskLevel: SqlRiskLevel;
    category: string;
    multipleStatements: boolean;
    knownSafeAutoRun: boolean;
  },
  config: SqlPolicyConfig,
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
    if (input.riskLevel === "read-only") {
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
          ? `${matchedAllowRule.reason} MCP still requires explicit confirmation for non-read-only SQL.`
          : matchedAllowRule.reason,
      matchedRule: matchedAllowRule,
    };
  }

  if (config.blockedCategories.includes(input.category)) {
    return {
      decision: "blocked",
      decisionReason: "Active policy blocks this SQL category from running through MCP.",
    };
  }

  if (input.knownSafeAutoRun && !input.multipleStatements) {
    return {
      decision: "allow",
      decisionReason: "Built-in SQL policy allows this explicit safe SELECT query without confirmation.",
    };
  }

  return {
    decision: "approval_required",
    decisionReason:
      input.riskLevel === "read-only"
        ? "This SQL is not on the explicit safe auto-run list, so user confirmation is required before MCP runs it."
        : "This SQL can change session state, rows, schema, locks, privileges, or procedural behavior, so MCP requires explicit user confirmation before running it.",
  };
}

export function reviewSqlPolicy(
  sql: string,
  session: OracleDbSession | undefined,
  config: SqlPolicyConfig,
): SqlReview {
  const executableSql = normalizeExecutableSql(sql);
  const normalizedSql = normalizeWhitespace(executableSql);
  const analysisTarget = normalizeWhitespace(stripSqlCommentsAndQuotedText(executableSql));
  const reasons = new Set<string>();
  const multipleStatements = containsMultipleStatements(stripSqlCommentsAndQuotedText(executableSql));

  const destructiveMatches = matchRules(analysisTarget, DESTRUCTIVE_SQL_RULES);
  const mutatingMatches = matchRules(analysisTarget, MUTATING_SQL_RULES);

  for (const match of destructiveMatches) {
    reasons.add(match.reason);
  }

  for (const match of mutatingMatches) {
    reasons.add(match.reason);
  }

  if (multipleStatements) {
    reasons.add("Contains multiple SQL statements separated by semicolons.");
  }

  let riskLevel: SqlRiskLevel = "read-only";
  let category = "query-read";
  let summary = "";
  let knownSafeAutoRun = false;

  if (destructiveMatches.length > 0) {
    riskLevel = "destructive";
    category = destructiveMatches[0]?.category ?? category;
    summary = destructiveMatches[0]?.summary ?? summary;
  } else if (mutatingMatches.length > 0 || multipleStatements) {
    riskLevel = mutatingMatches.length > 0 ? mutatingMatches[0]?.riskLevel ?? "mutating" : "mutating";
    category = mutatingMatches[0]?.category ?? "plsql-exec";
    summary =
      mutatingMatches[0]?.summary ??
      "This SQL request contains multiple statements and needs explicit confirmation.";
  } else {
    const readOnlySummary = buildReadOnlySummary(analysisTarget);
    category = readOnlySummary.category;
    summary = readOnlySummary.summary;
    knownSafeAutoRun = readOnlySummary.knownSafeAutoRun;
    if (!knownSafeAutoRun) {
      riskLevel = "mutating";
      reasons.add("The statement was not recognized as one of the explicitly safe SELECT queries.");
    }
  }

  if (session?.connection.transactionInProgress) {
    reasons.add("This DB session already has an active transaction in progress.");
  }

  const matchedDenyRule = findDenyRule(normalizedSql, config);
  const matchedAllowRule = findAllowRule(normalizedSql, config);
  const decisionState = decideSqlPolicy(
    {
      riskLevel,
      category,
      multipleStatements,
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
        ? "This SQL matches the explicit safe auto-run SELECT list."
        : "This SQL was not recognized as one of the explicitly safe auto-run statements.",
    );
  }

  if (decisionState.decision === "blocked") {
    reasons.add(decisionState.decisionReason);
  }

  return {
    sql,
    normalizedSql,
    executableSql,
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
    needsManualReview: decisionState.decision !== "allow" || multipleStatements,
    knownSafeAutoRun,
  };
}
