import { and, eq } from "drizzle-orm";
import { issueExecutionDecisions, type Db } from "@paperclipai/db";

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

/**
 * Whether this still-owning native run saved the approval that selected the
 * issue's current pending stage. Finalization may hand that stage off after the
 * run ends; an unrelated pending stage remains a governance hold.
 */
export async function executionStageHandoffApprovedByRun(
  db: Db,
  run: { id: string; companyId: string; agentId: string },
  issue: { id: string; executionRunId: string | null; assigneeAgentId: string | null; assigneeUserId: string | null; executionState?: unknown },
): Promise<string | null> {
  const state = record(issue.executionState);
  if (issue.executionRunId !== run.id || issue.assigneeAgentId !== run.agentId || issue.assigneeUserId ||
      state.status !== "pending" || state.lastDecisionOutcome !== "approved" || typeof state.lastDecisionId !== "string" ||
      typeof state.currentStageId !== "string") return null;
  const completedStageIds = Array.isArray(state.completedStageIds) ? state.completedStageIds : [];
  const [decision] = await db.select({ id: issueExecutionDecisions.id, stageId: issueExecutionDecisions.stageId })
    .from(issueExecutionDecisions).where(and(
      eq(issueExecutionDecisions.id, state.lastDecisionId),
      eq(issueExecutionDecisions.companyId, run.companyId),
      eq(issueExecutionDecisions.issueId, issue.id),
      eq(issueExecutionDecisions.outcome, "approved"),
      eq(issueExecutionDecisions.actorAgentId, run.agentId),
      eq(issueExecutionDecisions.createdByRunId, run.id),
    )).limit(1);
  return decision && decision.stageId !== state.currentStageId && completedStageIds.includes(decision.stageId)
    ? decision.id : null;
}
