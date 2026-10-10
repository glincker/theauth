const SENSITIVE_KEY =
	/token|secret|password|authorization|api[-_]?key|credential|private|signature/i;
const MAX_DEPTH = 8;

/** Deep copy that replaces values under secret-looking keys with "[redacted]". */
export function redact(value: unknown, depth = 0): unknown {
	if (depth > MAX_DEPTH) return "[truncated]";
	if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
	if (typeof value === "object" && value !== null) {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value)) {
			out[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : redact(v, depth + 1);
		}
		return out;
	}
	return value;
}
