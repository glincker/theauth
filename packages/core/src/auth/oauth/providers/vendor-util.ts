/**
 * Small helpers shared by the vendor provider files that sit on top of
 * `genericOIDC` (Linear, Kick, Vercel, PayPal, Kakao).
 */

/** Non-empty string, or undefined. */
export function str(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** String or finite number rendered as a string, or undefined. */
export function idString(value: unknown): string | undefined {
	if (typeof value === "string" && value.length > 0) return value;
	if (typeof value === "number" && Number.isFinite(value)) return String(value);
	return undefined;
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}
