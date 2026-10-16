export type { ApprovalConfig, ApprovalModule, ApprovalRequest } from "./approval.js";
export { createApprovalModule } from "./approval.js";
export type {
	ApprovalDenialCode,
	ConsumeApprovalInput,
	ConsumeApprovalResult,
} from "./consume.js";
export { APPROVAL_CODES, consumeApproval } from "./consume.js";
