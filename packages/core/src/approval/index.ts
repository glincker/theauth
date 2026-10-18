export type {
	ApprovalConfig,
	ApprovalDeps,
	ApprovalModule,
	ApprovalRequest,
	DecideInput,
} from "./approval.js";
export { createApprovalModule } from "./approval.js";
export type {
	ApprovalDenialCode,
	ConsumeApprovalInput,
	ConsumeApprovalResult,
} from "./consume.js";
export { APPROVAL_CODES, consumeApproval, decisionCodeOfApproval } from "./consume.js";
