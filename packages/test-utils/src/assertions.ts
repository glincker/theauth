/**
 * Typed assertion helpers for TheAuth `ActionResult` values.
 *
 * These narrow the result type so subsequent code can access `.data` or
 * `.error` without an extra type guard.  They throw descriptive errors on
 * failure so test output is readable.
 */

import type { ActionResult } from "@glinr/theauth-react";

// ─── Assertion helpers ────────────────────────────────────────────────────────

/**
 * Asserts that an `ActionResult` succeeded.
 *
 * @throws if `result.success` is `false`
 *
 * @example
 * const result = await signIn("alice@example.com", "password");
 * expectAuthenticated(result);
 */
export function expectAuthenticated<T>(
	result: ActionResult<T>,
): asserts result is { success: true; data: T } {
	if (!result.success) {
		throw new Error(`Expected authenticated result but got failure: ${result.error}`);
	}
}

/**
 * Asserts that an `ActionResult` failed with any error.
 *
 * @throws if `result.success` is `true`
 *
 * @example
 * const result = await signIn("bad@example.com", "wrong");
 * expectUnauthenticated(result);
 */
export function expectUnauthenticated<T>(
	result: ActionResult<T>,
): asserts result is { success: false; error: string } {
	if (result.success) {
		throw new Error("Expected unauthenticated (failure) result but got success");
	}
}

/**
 * Asserts that an `ActionResult` failed with a message containing the word
 * "permission" or a custom substring you provide.
 *
 * Useful for testing authorization failures separately from authentication
 * failures.
 *
 * @param match - substring to look for in `result.error`. Defaults to "permission".
 * @throws if the result succeeded, or if the error message does not contain `match`
 *
 * @example
 * const result = await createAgent(unauthorizedInput);
 * expectPermissionDenied(result);
 *
 * // Custom match:
 * expectPermissionDenied(result, "not allowed");
 */
export function expectPermissionDenied<T>(
	result: ActionResult<T>,
	match = "permission",
): asserts result is { success: false; error: string } {
	if (result.success) {
		throw new Error("Expected permission-denied failure but got success");
	}
	const lower = result.error.toLowerCase();
	if (!lower.includes(match.toLowerCase())) {
		throw new Error(`Expected error to contain "${match}" but got: "${result.error}"`);
	}
}
