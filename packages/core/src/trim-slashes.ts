/**
 * Remove trailing slashes with a scan. `value.replace(/\/+$/, "")` is
 * quadratic on a long run of slashes that does not end the string, because the
 * engine retries the pattern from every slash.
 */
export function trimTrailingSlashes(value: string): string {
	let end = value.length;
	while (end > 0 && value.charCodeAt(end - 1) === 47) end -= 1;
	return end === value.length ? value : value.slice(0, end);
}
