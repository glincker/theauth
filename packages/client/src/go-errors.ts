import type { GoAuthError } from "./go-types.js";

export const GO_CODE_RECENT_AUTH_REQUIRED = "auth.recent_auth_required";
export const GO_CODE_RATE_LIMITED = "rate_limited";
export const GO_CODE_ACCOUNT_LOCKED = "account_locked";

export type GoThrottleError = GoAuthError & {
	code: typeof GO_CODE_RATE_LIMITED | typeof GO_CODE_ACCOUNT_LOCKED;
};

/** True when the action needs a fresh step-up; run client.stepUp then retry. */
export function isRecentAuthRequired(error: GoAuthError): boolean {
	return error.code === GO_CODE_RECENT_AUTH_REQUIRED;
}

/** Narrows to a 429 throttle; `retryAfter` is seconds from the Retry-After header. */
export function isThrottleError(error: GoAuthError): error is GoThrottleError {
	return error.code === GO_CODE_RATE_LIMITED || error.code === GO_CODE_ACCOUNT_LOCKED;
}
