export { classifyRow, compactPermissions, covers, splitPermission } from "./permissions.js";
export { readDecisionRows } from "./rows.js";
export { suggestShrink } from "./shrink.js";
export type {
	AnalyzeOptions,
	BlastRadiusReport,
	DecisionResult,
	DecisionRow,
	Grant,
	GrantMatchCount,
	GrantSource,
	PreviewOptions,
	PreviewReport,
	RowRef,
	ShrinkOptions,
	ShrinkRewrite,
	ShrinkSuggestion,
	UncoveredAllow,
	UsageAnalysis,
	UsageEvidence,
	UsedPermission,
	VerifyOptions,
} from "./types.js";
export { analyzeUsage, createUsageAccumulator, loadGrants } from "./usage.js";
export { createReplay, previewPolicyChange, verifyShrink } from "./verify.js";
