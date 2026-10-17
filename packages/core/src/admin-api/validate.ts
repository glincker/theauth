/** Small input validators for the admin API. Each returns undefined when the value is invalid. */

const ID_RE = /^[A-Za-z0-9_.:@-]{1,200}$/;
const ADMIN_ACTION_RE = /^admin:[a-z][a-z0-9_]{0,63}$/;
const AUDIT_ACTION_RE = /^admin_mcp\.[a-z][a-z0-9_]{0,63}$/;
const RESOURCE_RE = /^[\x21-\x7e]{1,200}$/;
const SECRET_KEY_RE = /token|secret|password|passwd|authorization|api[_-]?key|credential|cookie/i;
const MAX_PARAMS_BYTES = 8192;

export const AUDIT_MODES = ["read", "write"] as const;
export const AUDIT_RESULTS = [
	"ok",
	"error",
	"requested",
	"pending",
	"denied",
	"executed",
	"failed",
] as const;

export type AuditMode = (typeof AUDIT_MODES)[number];
export type AuditResult = (typeof AUDIT_RESULTS)[number];

export function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function asId(v: unknown): string | undefined {
	return typeof v === "string" && ID_RE.test(v) ? v : undefined;
}

export function asAdminAction(v: unknown): string | undefined {
	return typeof v === "string" && ADMIN_ACTION_RE.test(v) ? v : undefined;
}

export function asAuditAction(v: unknown): string | undefined {
	return typeof v === "string" && AUDIT_ACTION_RE.test(v) ? v : undefined;
}

export function asResource(v: unknown): string | undefined {
	return typeof v === "string" && RESOURCE_RE.test(v) ? v : undefined;
}

export function asEnum<T extends string>(v: unknown, allowed: readonly T[]): T | undefined {
	return typeof v === "string" ? allowed.find((a) => a === v) : undefined;
}

export function asReason(v: unknown): string | undefined {
	return typeof v === "string" && v.length <= 500 ? v : undefined;
}

/** Drop secret-looking keys at any depth so token material never reaches the audit log. */
export function scrub(value: unknown, depth = 0): unknown {
	if (depth > 5) return "[truncated]";
	if (Array.isArray(value)) return value.slice(0, 50).map((v) => scrub(v, depth + 1));
	if (isRecord(value)) {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value)) {
			out[k] = SECRET_KEY_RE.test(k) ? "[redacted]" : scrub(v, depth + 1);
		}
		return out;
	}
	return value;
}

/** Audit params must be a plain object no larger than 8 KiB once serialised. */
export function asParams(v: unknown): Record<string, unknown> | undefined {
	if (v === undefined) return {};
	if (!isRecord(v)) return undefined;
	if (JSON.stringify(v).length > MAX_PARAMS_BYTES) return undefined;
	const scrubbed = scrub(v);
	return isRecord(scrubbed) ? scrubbed : undefined;
}

export function asLimit(raw: string | null, fallback: number, max: number): number {
	if (raw === null) return fallback;
	const n = Number(raw);
	return Number.isInteger(n) && n >= 1 ? Math.min(n, max) : fallback;
}
