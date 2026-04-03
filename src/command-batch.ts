import type { PolicyDecision, CommandPolicyConfig } from "./policy-config.js";
import { reviewCommandPolicy, type CommandReview } from "./policy.js";
import type { CommandRiskLevel, ShellSession } from "./session.js";

export interface CommandBatchReview {
  reviews: CommandReview[];
  commandCount: number;
  normalizedBatch: string;
  riskLevel: CommandRiskLevel;
  category: string;
  decision: PolicyDecision;
  requiresConfirmation: boolean;
  safeForAutoRun: boolean;
  summary: string;
  blockedCount: number;
  approvalRequiredCount: number;
}

const BATCH_SEPARATOR = "\n--MCP-COMMAND-BATCH--\n";

function pickHighestRiskLevel(reviews: CommandReview[]): CommandRiskLevel {
  if (reviews.some((review) => review.riskLevel === "destructive")) {
    return "destructive";
  }

  if (reviews.some((review) => review.riskLevel === "mutating")) {
    return "mutating";
  }

  return "read-only";
}

function summarizeBatchReview(
  reviews: CommandReview[],
  riskLevel: CommandRiskLevel,
  blockedCount: number,
  approvalRequiredCount: number,
): string {
  if (blockedCount > 0) {
    return blockedCount === 1
      ? "One command in this batch is blocked by policy."
      : `${blockedCount} commands in this batch are blocked by policy.`;
  }

  if (approvalRequiredCount > 0) {
    return approvalRequiredCount === 1
      ? "One command in this batch requires confirmation before execution."
      : `${approvalRequiredCount} commands in this batch require one shared confirmation before execution.`;
  }

  if (riskLevel === "read-only") {
    return "This standalone read-only command batch can auto-run without extra confirmation.";
  }

  return "This command batch can auto-run.";
}

export function summarizeCommandBatchReviews(
  commands: string[],
  session: ShellSession | undefined,
  config: CommandPolicyConfig,
): CommandBatchReview {
  const reviews = commands.map((command) => reviewCommandPolicy(command, session, config));
  const blockedCount = reviews.filter((review) => review.decision === "blocked").length;
  const approvalRequiredCount = reviews.filter(
    (review) => review.decision === "approval_required",
  ).length;
  const riskLevel = pickHighestRiskLevel(reviews);
  const uniqueCategories = Array.from(new Set(reviews.map((review) => review.category)));
  const decision: PolicyDecision =
    blockedCount > 0
      ? "blocked"
      : approvalRequiredCount > 0
        ? "approval_required"
        : "allow";

  return {
    reviews,
    commandCount: reviews.length,
    normalizedBatch: reviews.map((review) => review.normalizedCommand).join(BATCH_SEPARATOR),
    riskLevel,
    category: uniqueCategories.length === 1 ? uniqueCategories[0] ?? "batch" : "batch",
    decision,
    requiresConfirmation: decision === "approval_required",
    safeForAutoRun: reviews.every((review) => review.safeForAutoRun),
    summary: summarizeBatchReview(reviews, riskLevel, blockedCount, approvalRequiredCount),
    blockedCount,
    approvalRequiredCount,
  };
}
