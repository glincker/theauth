import type { PermissionConstraints } from "../types.js";

function hhmm(value: string): number {
	const [h, m] = value.split(":");
	return Number(h) * 60 + Number(m);
}

/**
 * Combine a parent's constraints with the ones requested for a child so the
 * result is never looser than the parent's. A child can only add restrictions.
 */
export function narrowConstraints(
	parent: PermissionConstraints | undefined,
	child: PermissionConstraints | undefined,
): PermissionConstraints | undefined {
	if (!parent && !child) return undefined;
	const a = parent ?? {};
	const b = child ?? {};
	const out: PermissionConstraints = {};

	if (a.requireApproval || b.requireApproval) out.requireApproval = true;

	if (a.maxCallsPerHour !== undefined && b.maxCallsPerHour !== undefined) {
		out.maxCallsPerHour = Math.min(a.maxCallsPerHour, b.maxCallsPerHour);
	} else if (a.maxCallsPerHour !== undefined || b.maxCallsPerHour !== undefined) {
		out.maxCallsPerHour = a.maxCallsPerHour ?? b.maxCallsPerHour;
	}

	// Patterns: both sides present means the common ones; if nothing is common
	// the parent's list stays, since an empty list would read as "no restriction".
	if (a.allowedArgPatterns && b.allowedArgPatterns) {
		const common = b.allowedArgPatterns.filter((p) => a.allowedArgPatterns?.includes(p));
		out.allowedArgPatterns = common.length > 0 ? common : a.allowedArgPatterns;
	} else if (a.allowedArgPatterns || b.allowedArgPatterns) {
		out.allowedArgPatterns = a.allowedArgPatterns ?? b.allowedArgPatterns;
	}

	if (a.ipAllowlist && a.ipAllowlist.length > 0 && b.ipAllowlist && b.ipAllowlist.length > 0) {
		const common = b.ipAllowlist.filter((ip) => a.ipAllowlist?.includes(ip));
		out.ipAllowlist = common.length > 0 ? common : a.ipAllowlist;
	} else if (a.ipAllowlist?.length || b.ipAllowlist?.length) {
		out.ipAllowlist = a.ipAllowlist?.length ? a.ipAllowlist : b.ipAllowlist;
	}

	if (a.timeWindow && b.timeWindow) {
		const aw = a.timeWindow;
		const bw = b.timeWindow;
		const sameDay = hhmm(aw.start) <= hhmm(aw.end) && hhmm(bw.start) <= hhmm(bw.end);
		const start = hhmm(aw.start) >= hhmm(bw.start) ? aw.start : bw.start;
		const end = hhmm(aw.end) <= hhmm(bw.end) ? aw.end : bw.end;
		// Only same-day windows intersect cleanly; otherwise keep the parent's.
		out.timeWindow = sameDay && hhmm(start) < hhmm(end) ? { start, end } : aw;
	} else if (a.timeWindow || b.timeWindow) {
		out.timeWindow = a.timeWindow ?? b.timeWindow;
	}

	return Object.keys(out).length > 0 ? out : undefined;
}
