/** Typed helpers that narrow `ActionResult` and throw readable errors on mismatch. */

import type { ActionResult } from "@glinr/theauth-react";

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
 * Asserts failure with an error containing "permission" (or a custom `match`) for authorization checks.
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
