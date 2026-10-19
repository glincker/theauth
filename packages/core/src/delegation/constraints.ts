import { narrowAttestationConstraint } from "../policy/attestation-constraint.js";
import type { PermissionConstraints } from "../types.js";

// Deny-all representations. abac.ts reads an empty list as "no constraint", so
// an empty intersection has to be a non-empty value that can never match.
// A regex that matches nothing: every string argument fails it.
const DENY_ALL_ARG_PATTERN = "(?!)";
// An out-of-range prefix never matches any IP, and a missing IP is denied too.
const DENY_ALL_IP_ENTRY = "0.0.0.0/33";
// parseClock in abac.ts rejects "24:00", so the window never contains any time.
const DENY_ALL_WINDOW = { start: "24:00", end: "24:00" };

function hhmm(value: string): number {
	const [h, m] = value.split(":");
	return Number(h) * 60 + Number(m);
}

/** Combine a parent's constraints with the ones requested for a child so the result is never looser than the parent's. A child can only add restrictions. */
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
	// the result denies everything (an empty list would read as "no restriction").
	if (a.allowedArgPatterns && b.allowedArgPatterns) {
		const common = b.allowedArgPatterns.filter((p) => a.allowedArgPatterns?.includes(p));
		out.allowedArgPatterns = common.length > 0 ? common : [DENY_ALL_ARG_PATTERN];
	} else if (a.allowedArgPatterns || b.allowedArgPatterns) {
		out.allowedArgPatterns = a.allowedArgPatterns ?? b.allowedArgPatterns;
	}

	if (a.ipAllowlist && a.ipAllowlist.length > 0 && b.ipAllowlist && b.ipAllowlist.length > 0) {
		const common = b.ipAllowlist.filter((ip) => a.ipAllowlist?.includes(ip));
		out.ipAllowlist = common.length > 0 ? common : [DENY_ALL_IP_ENTRY];
	} else if (a.ipAllowlist?.length || b.ipAllowlist?.length) {
		out.ipAllowlist = a.ipAllowlist?.length ? a.ipAllowlist : b.ipAllowlist;
	}

	if (a.timeWindow && b.timeWindow) {
		const aw = a.timeWindow;
		const bw = b.timeWindow;
		const sameDay = hhmm(aw.start) <= hhmm(aw.end) && hhmm(bw.start) <= hhmm(bw.end);
		const start = hhmm(aw.start) >= hhmm(bw.start) ? aw.start : bw.start;
		const end = hhmm(aw.end) <= hhmm(bw.end) ? aw.end : bw.end;
		// Only same-day windows intersect cleanly. Identical overnight windows are
		// kept as is. Anything else has no representable overlap and denies.
		if (sameDay) {
			out.timeWindow = hhmm(start) <= hhmm(end) ? { start, end } : { ...DENY_ALL_WINDOW };
		} else if (aw.start === bw.start && aw.end === bw.end) {
			out.timeWindow = { start: aw.start, end: aw.end };
		} else {
			out.timeWindow = { ...DENY_ALL_WINDOW };
		}
	} else if (a.timeWindow || b.timeWindow) {
		out.timeWindow = a.timeWindow ?? b.timeWindow;
	}

	const attestation = narrowAttestationConstraint(a.attestation, b.attestation);
	if (attestation) out.attestation = attestation;

	return Object.keys(out).length > 0 ? out : undefined;
}
