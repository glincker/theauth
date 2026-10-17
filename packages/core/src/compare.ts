/**
 * Compare two strings by UTF-16 code unit order.
 * It is deliberately not `localeCompare`: the audit hash chain, SigV4 canonical headers and permission fingerprints all depend on a locale-independent, stable order.
 */
export function compareCodeUnits(a: string, b: string): number {
	if (a < b) return -1;
	return a > b ? 1 : 0;
}
