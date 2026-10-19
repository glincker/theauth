/**
 * Security rules for API key scoping, IoT devices, approvals and sender constrained agent tokens.
 * They read the same loaded config object as the rules in security-doctor.ts and never open a database.
 */
import type { SecurityConfig, SecurityFinding, SecuritySeverity } from "./security-doctor.js";

/** Longest device bundle lifetime the linter accepts without a finding, in seconds. */
export const DEVICE_BUNDLE_TTL_LIMIT_SECONDS = 3600;

const WRITE_ACTIONS = new Set([
	"*",
	"write",
	"create",
	"update",
	"delete",
	"admin",
	"manage",
	"publish",
	"execute",
	"send",
]);

function finding(
	id: string,
	severity: SecuritySeverity,
	message: string,
	fix: string,
): SecurityFinding {
	return { id, severity, message, fix, docs: `/security-doctor#${id.replace(/[._]/g, "-")}` };
}

function resourceSegments(resource: string): string[] {
	return resource.split(/[:/]/);
}

function hasWildcardBeforeLast(resource: string, wildcards: readonly string[]): boolean {
	return resourceSegments(resource)
		.slice(0, -1)
		.some((s) => wildcards.includes(s));
}

function apiKeyFindings(c: SecurityConfig): SecurityFinding[] {
	if (c.apiKeys === undefined || c.apiKeys.trustedServerUse === true) return [];
	if (c.apiKeys.grantablePermissions !== undefined || c.org !== undefined) return [];
	return [
		finding(
			"sec.api_keys.no_scope_resolver",
			"low",
			"apiKeys has no grantablePermissions resolver and no org module to derive one from, so self service creation can only mint keys with an empty permission list",
			"Add grantablePermissions to apiKeys, or enable the org module so the creator's org roles cap the key.",
		),
	];
}

function deviceFindings(c: SecurityConfig): SecurityFinding[] {
	const devices = c.devices;
	if (devices === undefined) return [];
	const out: SecurityFinding[] = [];
	const resources = Object.keys(c.permissions ?? {});
	const pathMode = c.resourceMatching === "path";

	const slashWild = resources.filter(
		(r) => r.includes("/") && resourceSegments(r).some((s) => ["*", "**", "+", "#"].includes(s)),
	);
	if (!pathMode && slashWild.length > 0) {
		out.push(
			finding(
				"sec.device.path_matching_off",
				"medium",
				`resourceMatching is not "path", so wildcards in ${slashWild.map((r) => `"${r}"`).join(", ")} are compared as plain text and never match a topic below them`,
				'Set resourceMatching to "path" so "/" separates segments, or write the resources with ":" separators.',
			),
		);
	}

	const wildcards = pathMode ? ["#"] : ["*", "**", "#"];
	const mid = resources.filter((r) => hasWildcardBeforeLast(r, wildcards));
	if (mid.length > 0) {
		out.push(
			finding(
				"sec.device.mid_wildcard",
				"medium",
				`Device resources ${mid.map((r) => `"${r}"`).join(", ")} put a wildcard before the last segment${pathMode ? " (# must be last, MQTT 5 section 4.7.1.2)" : ", which grants more than it reads in the default matching mode"}`,
				"Keep wildcards in the final segment, and list the fixed prefix before it.",
			),
		);
	}

	const ttl = devices.bundleTtlSeconds;
	if (typeof ttl === "number" && ttl > DEVICE_BUNDLE_TTL_LIMIT_SECONDS) {
		out.push(
			finding(
				"sec.device.bundle_ttl_long",
				"medium",
				`devices.bundleTtlSeconds is ${ttl}, so a revoked device keeps working offline for up to ${Math.round(ttl / 3600)} hour(s)`,
				"Set devices.bundleTtlSeconds to 3600 or less, and let devices refresh bundles while online.",
			),
		);
	}

	if (devices.attestation?.verify === undefined) {
		out.push(
			finding(
				"sec.device.no_attestation",
				"medium",
				"devices is set, so enrollment tokens can be issued, but no attestation.verify hook checks what enrolls with them, and anyone holding a token can register any hardware",
				"Add devices.attestation.verify (for example an EAT verifier, RFC 9711) and set attestation.required.",
			),
		);
	}
	return out;
}

function approvalFindings(c: SecurityConfig): SecurityFinding[] {
	const a = c.approval;
	if (a === undefined) return [];
	if (a.requireAcr !== undefined || a.maxAuthAge !== undefined || a.stepUp !== undefined) return [];
	return [
		finding(
			"sec.approval.no_step_up",
			"medium",
			"approval is configured with no requireAcr, maxAuthAge or stepUp rule, so any signed in session can approve a requireApproval permission",
			"Set approval.requireAcr (and maxAuthAge), or an approval.stepUp function for high risk requests.",
		),
	];
}

function isWriteLike(entry: string): boolean {
	const last = entry.split(":").pop() ?? "";
	return WRITE_ACTIONS.has(entry) || WRITE_ACTIONS.has(last);
}

function dpopFindings(c: SecurityConfig): SecurityFinding[] {
	if (c.agents?.enabled !== true || c.agents.confirmation?.required === true) return [];
	const catalogWrites = Object.entries(c.permissions ?? {}).some(([, actions]) =>
		actions.some((a) => WRITE_ACTIONS.has(a)),
	);
	const defaultWrites = (c.agents.defaultPermissions ?? []).some(isWriteLike);
	if (!catalogWrites && !defaultWrites) return [];
	return [
		finding(
			"sec.agent.dpop_not_required",
			"medium",
			"agents.confirmation.required is off while permissions include write actions, so a stolen agent token works as a plain bearer token",
			"Set agents.confirmation.required to true and configure agents.confirmation.dpop (RFC 9449) or an mTLS method (RFC 8705).",
		),
	];
}

export function fleetFindings(c: SecurityConfig): SecurityFinding[] {
	return [...apiKeyFindings(c), ...deviceFindings(c), ...approvalFindings(c), ...dpopFindings(c)];
}

/** Ids of the rules in this file, for docs and tests. */
export const FLEET_FINDING_IDS = [
	"sec.api_keys.no_scope_resolver",
	"sec.device.path_matching_off",
	"sec.device.mid_wildcard",
	"sec.device.bundle_ttl_long",
	"sec.device.no_attestation",
	"sec.approval.no_step_up",
	"sec.agent.dpop_not_required",
] as const;
