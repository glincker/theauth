/**
 * Code unit order string comparator. Matches the default `Array#sort` order (UTF-16 code units) but is explicit, so it is locale independent and reads clearly at call sites. Internal only, not exported from the package root.
 */
export function compareStrings(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}
