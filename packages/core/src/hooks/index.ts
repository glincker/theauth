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
