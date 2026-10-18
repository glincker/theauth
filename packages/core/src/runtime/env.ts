/**
 * Edge-safe environment lookup. Cloudflare Workers and Deno (without node compat) have no `process`,
 * and a bare `process.env` there throws a ReferenceError. This returns undefined instead, and
 * treats an empty string as unset.
 */
export function getEnv(name: string): string | undefined {
	try {
		const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
		const value = proc?.env?.[name];
		return value === undefined || value === "" ? undefined : value;
	} catch {
		return undefined;
	}
}

/** `getEnv` parsed as a finite number, or undefined. */
export function getEnvNumber(name: string): number | undefined {
	const raw = getEnv(name);
	if (raw === undefined) return undefined;
	const n = Number(raw);
	return Number.isFinite(n) ? n : undefined;
}
