// Shared helpers. Import the wrappers from the subpaths:
//   @glinr/theauth-agent-frameworks/langchain
//   @glinr/theauth-agent-frameworks/mastra
// The Vercel AI SDK and OpenAI Agents SDK need no wrapper: use guardTool from core with
// createApprovalGrants and resumeAfterApproval below.

export {
	guardTool,
	guardTools,
	ToolApprovalRequiredError,
	ToolDeniedError,
	ToolGuardError,
	ToolGuardFailedError,
} from "@glinr/theauth";
export type {
	ApprovalGrants,
	ApprovalHost,
	ApprovalInterruptPayload,
	NormalizedDecision,
	ResumeAfterApprovalOptions,
	ResumeDecision,
	ResumeResult,
} from "./shared.js";
export {
	createApprovalGrants,
	isApprovalRequired,
	normalizeDecision,
	resumeAfterApproval,
	toInterruptPayload,
} from "./shared.js";
