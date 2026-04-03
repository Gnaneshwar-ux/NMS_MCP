import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export type PolicyDecision = "allow" | "approval_required" | "blocked";

export interface PolicyRuleSummary {
  name: string;
  pattern: string;
  flags: string;
  reason: string;
}

export interface CompiledAllowRule extends PolicyRuleSummary {
  decision: "allow" | "approval_required";
  regex: RegExp;
}

export interface CompiledDenyRule extends PolicyRuleSummary {
  regex: RegExp;
}

export interface PolicySectionConfig {
  blockedCategories: string[];
  approvalCategories: string[];
  allowRules: CompiledAllowRule[];
  denyRules: CompiledDenyRule[];
}

export interface CommandPolicyConfig extends PolicySectionConfig {
  approvedScratchPaths: string[];
  diagnosticsProfiles: string[];
  loadedFrom: string | null;
}

export interface SqlPolicyConfig extends PolicySectionConfig {
  loadedFrom: string | null;
}

interface PolicyRuleInput {
  name?: string;
  regex: string;
  flags?: string;
  decision?: PolicyDecision;
  reason?: string;
}

interface PolicySectionInput {
  blockedCategories?: string[];
  approvalCategories?: string[];
  allowRules?: PolicyRuleInput[];
  denyRules?: PolicyRuleInput[];
}

interface CommandPolicySectionInput extends PolicySectionInput {
  approvedScratchPaths?: string[];
  diagnosticsProfiles?: string[];
}

interface PolicyFileConfig extends CommandPolicySectionInput {
  commandPolicy?: CommandPolicySectionInput;
  sqlPolicy?: PolicySectionInput;
}

export const DEFAULT_BLOCKED_CATEGORIES = [
  "privilege-escalation",
  "password-change",
  "sudoers-change",
  "account-change",
  "service-change",
  "data-delete",
  "package-remove",
  "package-install",
  "database-destructive",
  "deploy-change",
  "container-delete",
  "git-destructive",
] as const;

export const DEFAULT_APPROVAL_CATEGORIES = [
  "session-state",
  "privileged-command",
  "shell-wrapper",
  "interactive-terminal",
  "file-write",
  "scratch-write",
  "opaque-script",
] as const;

export const DEFAULT_APPROVED_SCRATCH_PATHS = ["/tmp", "/var/tmp"] as const;

export const DEFAULT_DIAGNOSTICS_PROFILES = ["oracle-nms-readonly"] as const;

export const DEFAULT_SQL_BLOCKED_CATEGORIES = [
  "ddl-destructive",
  "db-admin",
  "lock-control",
] as const;

export const DEFAULT_SQL_APPROVAL_CATEGORIES = ["session-state"] as const;

export function defaultPolicyFilePath(): string {
  return fileURLToPath(new URL("../ssh-mcp-policy.json", import.meta.url));
}

function readPolicyFile(filePath: string): PolicyFileConfig {
  const raw = readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as unknown;

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Policy file "${filePath}" must contain a JSON object.`);
  }

  return parsed as PolicyFileConfig;
}

function readStringArray(value: unknown, fieldName: string, fallback: readonly string[]): string[] {
  if (value == null) {
    return [...fallback];
  }

  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Policy field "${fieldName}" must be an array of strings.`);
  }

  return Array.from(new Set(value.map((entry) => String(entry).trim()).filter(Boolean)));
}

function compileAllowRules(value: unknown, fieldName = "allowRules"): CompiledAllowRule[] {
  if (value == null) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`Policy field "${fieldName}" must be an array.`);
  }

  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object.`);
    }

    const rule = entry as PolicyRuleInput;
    if (!rule.regex || typeof rule.regex !== "string") {
      throw new Error(`${fieldName}[${index}].regex must be a non-empty string.`);
    }

    const decision =
      rule.decision === "allow" || rule.decision === "approval_required"
        ? rule.decision
        : "approval_required";

    return {
      name: rule.name?.trim() || `allow_rule_${index + 1}`,
      pattern: rule.regex,
      flags: rule.flags ?? "",
      reason: rule.reason?.trim() || "Matched an explicit allow rule.",
      decision,
      regex: new RegExp(rule.regex, rule.flags ?? ""),
    };
  });
}

function compileDenyRules(value: unknown, fieldName = "denyRules"): CompiledDenyRule[] {
  if (value == null) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`Policy field "${fieldName}" must be an array.`);
  }

  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object.`);
    }

    const rule = entry as PolicyRuleInput;
    if (!rule.regex || typeof rule.regex !== "string") {
      throw new Error(`${fieldName}[${index}].regex must be a non-empty string.`);
    }

    return {
      name: rule.name?.trim() || `deny_rule_${index + 1}`,
      pattern: rule.regex,
      flags: rule.flags ?? "",
      reason: rule.reason?.trim() || "Matched an explicit deny rule.",
      regex: new RegExp(rule.regex, rule.flags ?? ""),
    };
  });
}

function loadPolicyFileConfig(): {
  loadedFrom: string | null;
  fileConfig: PolicyFileConfig | null;
} {
  const configuredPath = process.env.MCP_SSH_POLICY_FILE?.trim();
  const fallbackPath = defaultPolicyFilePath();
  const candidatePath = configuredPath || fallbackPath;
  const hasPolicyFile = existsSync(candidatePath);

  if (!configuredPath && !hasPolicyFile) {
    return {
      loadedFrom: null,
      fileConfig: null,
    };
  }

  if (configuredPath && !hasPolicyFile) {
    throw new Error(`Configured policy file "${configuredPath}" was not found.`);
  }

  return {
    loadedFrom: candidatePath,
    fileConfig: readPolicyFile(candidatePath),
  };
}

function compilePolicySection(
  section: PolicySectionInput | null | undefined,
  fieldPrefix: string,
  defaultBlockedCategories: readonly string[],
  defaultApprovalCategories: readonly string[],
): PolicySectionConfig {
  return {
    blockedCategories: readStringArray(
      section?.blockedCategories,
      `${fieldPrefix}.blockedCategories`,
      defaultBlockedCategories,
    ),
    approvalCategories: readStringArray(
      section?.approvalCategories,
      `${fieldPrefix}.approvalCategories`,
      defaultApprovalCategories,
    ),
    allowRules: compileAllowRules(section?.allowRules, `${fieldPrefix}.allowRules`),
    denyRules: compileDenyRules(section?.denyRules, `${fieldPrefix}.denyRules`),
  };
}

function compileCommandPolicySection(
  section: CommandPolicySectionInput | null | undefined,
  fieldPrefix: string,
): Omit<CommandPolicyConfig, "loadedFrom"> {
  const base = compilePolicySection(
    section,
    fieldPrefix,
    DEFAULT_BLOCKED_CATEGORIES,
    DEFAULT_APPROVAL_CATEGORIES,
  );

  return {
    ...base,
    approvedScratchPaths: readStringArray(
      section?.approvedScratchPaths,
      `${fieldPrefix}.approvedScratchPaths`,
      DEFAULT_APPROVED_SCRATCH_PATHS,
    ),
    diagnosticsProfiles: readStringArray(
      section?.diagnosticsProfiles,
      `${fieldPrefix}.diagnosticsProfiles`,
      DEFAULT_DIAGNOSTICS_PROFILES,
    ),
  };
}

function summarizePolicySection(config: PolicySectionConfig): Record<string, unknown> {
  return {
    blockedCategories: config.blockedCategories,
    approvalCategories: config.approvalCategories,
    allowRules: config.allowRules.map((rule) => ({
      name: rule.name,
      pattern: rule.pattern,
      flags: rule.flags,
      decision: rule.decision,
      reason: rule.reason,
    })),
    denyRules: config.denyRules.map((rule) => ({
      name: rule.name,
      pattern: rule.pattern,
      flags: rule.flags,
      reason: rule.reason,
    })),
  };
}

export function loadCommandPolicyConfig(): CommandPolicyConfig {
  const { loadedFrom, fileConfig } = loadPolicyFileConfig();
  const section = compileCommandPolicySection(
    fileConfig?.commandPolicy ?? fileConfig,
    "commandPolicy",
  );

  return {
    loadedFrom,
    ...section,
  };
}

export function loadSqlPolicyConfig(): SqlPolicyConfig {
  const { loadedFrom, fileConfig } = loadPolicyFileConfig();
  const section = compilePolicySection(
    fileConfig?.sqlPolicy,
    "sqlPolicy",
    DEFAULT_SQL_BLOCKED_CATEGORIES,
    DEFAULT_SQL_APPROVAL_CATEGORIES,
  );

  return {
    loadedFrom,
    ...section,
  };
}

export function summarizePolicyConfig(config: CommandPolicyConfig): Record<string, unknown> {
  return {
    loadedFrom: config.loadedFrom,
    ...summarizePolicySection(config),
    approvedScratchPaths: config.approvedScratchPaths,
    diagnosticsProfiles: config.diagnosticsProfiles,
  };
}

export function summarizeSqlPolicyConfig(config: SqlPolicyConfig): Record<string, unknown> {
  return {
    loadedFrom: config.loadedFrom,
    ...summarizePolicySection(config),
  };
}

export function summarizeCombinedPolicyConfig(
  commandPolicy: CommandPolicyConfig,
  sqlPolicy: SqlPolicyConfig,
): Record<string, unknown> {
  return {
    loadedFrom: commandPolicy.loadedFrom ?? sqlPolicy.loadedFrom,
    commandPolicy: summarizePolicyConfig(commandPolicy),
    sqlPolicy: summarizePolicySection(sqlPolicy),
  };
}
