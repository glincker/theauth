/**
 * Keys the SDK itself writes into audit `parameters`. Caller supplied tool arguments are merged into the same object, so a tool argument named `theauthHook` or `approvalId` would otherwise read as a guard verdict or a consumed approval. Every key starting with `theauth` (any case) is reserved for the SDK, plus `approvalId` and `inputProvenance`. Input provenance is captured only from the trusted request context (`context.inputs`), never from tool arguments, so an argument cannot plant or forge a source.
 */

const RESERVED_EXACT = new Set(["approvalId", "inputProvenance"]);
const RESERVED_PREFIX = "theauth";

export function isReservedAuditKey(key: string): boolean {
	return RESERVED_EXACT.has(key) || key.toLowerCase().startsWith(RESERVED_PREFIX);
}

/** Copy of caller supplied arguments without the reserved keys. Undefined stays undefined. */
export function stripReservedAuditKeys(
	args: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
	if (!args) return args;
	// fromEntries defines own properties, so a `__proto__` argument stays plain data.
	return Object.fromEntries(Object.entries(args).filter(([key]) => !isReservedAuditKey(key)));
}
