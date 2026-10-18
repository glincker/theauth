export type { ExternalGuard, GuardCheckInput } from "./guard.js";
export { composeBeforeAuthorize, guardHook } from "./guard.js";
export type {
	GuardWireRequest,
	GuardWireVerdict,
	HttpGuardOptions,
	VerifyGuardOptions,
	VerifyGuardResult,
} from "./http-guard.js";
export {
	GUARD_DEFAULT_TOLERANCE_SEC,
	GUARD_PROTOCOL_VERSION,
	GUARD_SIGNATURE_HEADER,
	GUARD_TIMESTAMP_HEADER,
	guardVerdictSchema,
	httpGuard,
	httpGuardHook,
	signGuardBody,
	verifyGuardRequest,
} from "./http-guard.js";
export type {
	AuthHooks,
	AuthorizeSource,
	BeforeAuthorizeContext,
	BeforeAuthorizeResult,
	DelegationLink as HookDelegationLink,
	HookDelegationChain,
	HookVerdict,
	LegacyHookVerdict,
	TheAuthHooks,
} from "./lifecycle.js";
export { classifyViolation } from "./lifecycle.js";
export type {
	EnvReader,
	HookErrorInfo,
	HookFailMode,
	HookGuardOptions,
	HookName,
	HookSafetyConfig,
	ResolvedHookGuard,
	ResolvedHookSafety,
} from "./safety.js";
export { HookBlockedError, HookTimeoutError, resolveHookSafety } from "./safety.js";
