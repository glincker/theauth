// Entry bundled by benchmarks/micro-build.mjs. It re-exports the internals the micro benchmarks time,
// so a before and after run can bundle the same file from two source states.

export { default as Database } from "better-sqlite3";
export { exportJWK, generateKeyPair, SignJWT } from "jose";
export { listPendingApprovals } from "../../packages/core/src/admin-api/approval-decisions.js";
export { delegationImpact } from "../../packages/core/src/admin-api/revocations.js";
export { canonicalApprovalJson } from "../../packages/core/src/approval/canonical.js";
export {
	evaluateDeviceBundle,
	signDeviceBundle,
	verifyDeviceBundle,
} from "../../packages/core/src/device/bundle.js";
export { verifyDpopProofWith } from "../../packages/core/src/mcp/dpop.js";
export { attachFreshnessDeps } from "../../packages/core/src/mcp/freshness.js";
export { validateAccessToken } from "../../packages/core/src/mcp/validate.js";
export { findMatchingPermission, matchResource } from "../../packages/core/src/policy/abac.js";
export { createStatelessSessions } from "../../packages/core/src/session/stateless.js";
export { memoryStorage } from "../../packages/core/src/storage/memory.js";
export { createTheAuth } from "../../packages/core/src/theauth.js";
