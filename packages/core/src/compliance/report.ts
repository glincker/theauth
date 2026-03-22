import { and, eq, gte, lte } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, auditLogs, delegationChains, permissions } from "../db/schema.js";

export interface ComplianceReportOptions {
	framework: "eu-ai-act" | "nist-ai-rmf" | "soc2" | "iso-42001";
	since?: Date;
	until?: Date;
}

export interface ComplianceReport {
	framework: string;
	generatedAt: string;
	period: { from: string; to: string };
	summary: {
		totalAgents: number;
		activeAgents: number;
		revokedAgents: number;
		totalAuditEvents: number;
		deniedEvents: number;
		rateLimitedEvents: number;
		delegationChains: number;
	};
	controls: ComplianceControl[];
	recommendations: string[];
}

export interface ComplianceControl {
	id: string;
	name: string;
	description: string;
	status: "compliant" | "partial" | "non-compliant" | "not-applicable";
	evidence: string[];
	gaps: string[];
}

interface ReportStats {
	totalAgents: number;
	activeAgents: number;
	revokedAgents: number;
	totalAuditEvents: number;
	deniedEvents: number;
	rateLimitedEvents: number;
	delegationChainCount: number;
	agentsWithExpiry: number;
	agentsWithRequireApproval: number;
	agentsWithNonWildcardPerms: number;
	agentsWithType: number;
	hasAuditEvents: boolean;
	hasRateLimitedEvents: boolean;
	hasDeniedTracking: boolean;
}

async function gatherStats(db: Database, since: Date, until: Date): Promise<ReportStats> {
	const timeConditions = [gte(auditLogs.timestamp, since), lte(auditLogs.timestamp, until)];

	const [allAgents, auditStats, chainCount] = await Promise.all([
		db.select().from(agents),
		db
			.select()
			.from(auditLogs)
			.where(and(...timeConditions)),
		db
			.select({ id: delegationChains.id })
			.from(delegationChains)
			.where(eq(delegationChains.status, "active")),
	]);

	const totalAgents = allAgents.length;
	const activeAgents = allAgents.filter((a) => a.status === "active").length;
	const revokedAgents = allAgents.filter((a) => a.status === "revoked").length;

	const totalAuditEvents = auditStats.length;
	const deniedEvents = auditStats.filter((e) => e.result === "denied").length;
	const rateLimitedEvents = auditStats.filter((e) => e.result === "rate_limited").length;

	const agentsWithExpiry = allAgents.filter((a) => a.expiresAt !== null).length;

	// Fetch all agent permissions to inspect constraints
	const allPerms = await db.select().from(permissions);

	const agentIdsWithRequireApproval = new Set<string>();
	for (const perm of allPerms) {
		const constraints = perm.constraints as {
			requireApproval?: boolean;
			maxCallsPerHour?: number;
		} | null;
		if (constraints?.requireApproval === true) {
			agentIdsWithRequireApproval.add(perm.agentId);
		}
	}

	const agentIdsWithNonWildcard = new Set<string>();
	for (const perm of allPerms) {
		if (perm.resource !== "*") {
			agentIdsWithNonWildcard.add(perm.agentId);
		}
	}

	const agentsWithType = allAgents.filter((a) => a.type !== null && a.type !== undefined).length;

	return {
		totalAgents,
		activeAgents,
		revokedAgents,
		totalAuditEvents,
		deniedEvents,
		rateLimitedEvents,
		delegationChainCount: chainCount.length,
		agentsWithExpiry,
		agentsWithRequireApproval: agentIdsWithRequireApproval.size,
		agentsWithNonWildcardPerms: agentIdsWithNonWildcard.size,
		agentsWithType,
		hasAuditEvents: totalAuditEvents > 0,
		hasRateLimitedEvents: rateLimitedEvents > 0,
		hasDeniedTracking: deniedEvents > 0 || totalAuditEvents > 0,
	};
}

function buildEuAiActControls(stats: ReportStats): ComplianceControl[] {
	const controls: ComplianceControl[] = [];

	// Art 12 — Record keeping
	{
		const evidence: string[] = [];
		const gaps: string[] = [];
		if (stats.hasAuditEvents) {
			evidence.push(`${stats.totalAuditEvents} audit events recorded in period`);
		} else {
			gaps.push("No audit events recorded — verify audit logging is enabled");
		}
		controls.push({
			id: "EU-AI-12",
			name: "Record keeping (Art. 12)",
			description: "High-risk AI systems must keep logs of their operation to the extent possible",
			status: stats.hasAuditEvents ? "compliant" : "non-compliant",
			evidence,
			gaps,
		});
	}

	// Art 14 — Human oversight
	{
		const evidence: string[] = [];
		const gaps: string[] = [];
		if (stats.agentsWithRequireApproval > 0) {
			evidence.push(
				`${stats.agentsWithRequireApproval} agent(s) have requireApproval constraint configured`,
			);
		} else {
			gaps.push(
				"No agents have requireApproval constraints — consider requiring human approval for sensitive operations",
			);
		}
		controls.push({
			id: "EU-AI-14",
			name: "Human oversight (Art. 14)",
			description: "High-risk AI systems must allow effective human oversight",
			status: stats.agentsWithRequireApproval > 0 ? "compliant" : "partial",
			evidence,
			gaps,
		});
	}

	// Art 15 — Accuracy, robustness and security
	{
		const evidence: string[] = [];
		const gaps: string[] = [];
		if (stats.agentsWithExpiry > 0) {
			evidence.push(`${stats.agentsWithExpiry} agent(s) have token expiry configured`);
		} else {
			gaps.push("No agents have expiry dates — token rotation and expiry improve security posture");
		}
		const status =
			stats.agentsWithExpiry > 0 && stats.activeAgents > 0
				? stats.agentsWithExpiry >= stats.activeAgents
					? "compliant"
					: "partial"
				: stats.agentsWithExpiry > 0
					? "compliant"
					: "non-compliant";
		controls.push({
			id: "EU-AI-15",
			name: "Accuracy, robustness and security (Art. 15)",
			description:
				"High-risk AI systems must be designed to achieve appropriate levels of accuracy and resilience",
			status,
			evidence,
			gaps,
		});
	}

	// Art 9 — Risk management
	{
		const evidence: string[] = [];
		const gaps: string[] = [];
		if (stats.agentsWithNonWildcardPerms > 0) {
			evidence.push(
				`${stats.agentsWithNonWildcardPerms} agent(s) use scoped (non-wildcard) permissions`,
			);
		}
		if (stats.hasDeniedTracking) {
			evidence.push("Denied access events are tracked in the audit log");
		}
		const wildcardOnlyAgents = stats.activeAgents - stats.agentsWithNonWildcardPerms;
		if (wildcardOnlyAgents > 0) {
			gaps.push(
				`${wildcardOnlyAgents} active agent(s) may have only wildcard permissions — apply least-privilege scoping`,
			);
		}
		controls.push({
			id: "EU-AI-9",
			name: "Risk management system (Art. 9)",
			description: "Providers must establish a risk management system for high-risk AI systems",
			status:
				stats.agentsWithNonWildcardPerms > 0 && wildcardOnlyAgents === 0
					? "compliant"
					: stats.agentsWithNonWildcardPerms > 0
						? "partial"
						: "non-compliant",
			evidence,
			gaps,
		});
	}

	// Art 50 — Transparency obligations
	{
		const evidence: string[] = [];
		const gaps: string[] = [];
		if (stats.agentsWithType > 0) {
			evidence.push(
				`${stats.agentsWithType} agent(s) have type classification set (autonomous/delegated/service)`,
			);
		} else {
			gaps.push("No agent types set — classify agents for transparency reporting");
		}
		const untyped = stats.totalAgents - stats.agentsWithType;
		if (untyped > 0) {
			gaps.push(`${untyped} agent(s) lack type classification`);
		}
		controls.push({
			id: "EU-AI-50",
			name: "Transparency obligations (Art. 50)",
			description: "Providers must ensure AI systems are sufficiently transparent",
			status:
				stats.agentsWithType >= stats.totalAgents && stats.totalAgents > 0
					? "compliant"
					: stats.agentsWithType > 0
						? "partial"
						: stats.totalAgents === 0
							? "not-applicable"
							: "non-compliant",
			evidence,
			gaps,
		});
	}

	return controls;
}

function buildNistAiRmfControls(stats: ReportStats): ComplianceControl[] {
	return [
		{
			id: "NIST-GOVERN-1.7",
			name: "Accountability documentation (GOVERN 1.7)",
			description: "Processes and procedures are in place for transparency and accountability",
			status: stats.hasAuditEvents ? "compliant" : "partial",
			evidence: stats.hasAuditEvents
				? [
						`Audit trail contains ${stats.totalAuditEvents} events`,
						"Agent identity tracked per audit entry",
					]
				: [],
			gaps: stats.hasAuditEvents
				? []
				: ["No audit events found — confirm audit logging is active and capturing events"],
		},
		{
			id: "NIST-MANAGE-4.2",
			name: "Action traceability (MANAGE 4.2)",
			description: "AI system actions can be traced back to the agent that performed them",
			status: stats.hasAuditEvents ? "compliant" : "non-compliant",
			evidence: stats.hasAuditEvents
				? [
						`${stats.totalAuditEvents} agent actions recorded with agentId, action, resource, and timestamp`,
					]
				: [],
			gaps: stats.hasAuditEvents
				? []
				: ["Audit log is empty — cannot establish action traceability without records"],
		},
		{
			id: "NIST-MAP-1.5",
			name: "Risk identification (MAP 1.5)",
			description: "AI risks are identified and prioritised",
			status: stats.hasDeniedTracking ? "compliant" : "partial",
			evidence: stats.hasDeniedTracking
				? [
						`${stats.deniedEvents} denied events tracked`,
						`${stats.rateLimitedEvents} rate-limited events tracked`,
					]
				: [],
			gaps: stats.hasDeniedTracking
				? []
				: [
						"No denied events recorded — this may indicate insufficient activity or that access controls are not being exercised",
					],
		},
	];
}

function buildSoc2Controls(stats: ReportStats): ComplianceControl[] {
	const wildcardOnlyAgents = stats.activeAgents - stats.agentsWithNonWildcardPerms;

	return [
		{
			id: "CC6.1",
			name: "Logical access controls (CC6.1)",
			description:
				"The entity implements logical access security software, infrastructure, and architectures",
			status: stats.totalAgents > 0 ? "compliant" : "not-applicable",
			evidence:
				stats.totalAgents > 0
					? [
							`Permission engine active with ${stats.totalAgents} registered agent(s)`,
							"Every agent has explicit permission grants before access is allowed",
						]
					: [],
			gaps:
				stats.totalAgents === 0
					? ["No agents registered — permission engine has no subjects to enforce against"]
					: [],
		},
		{
			id: "CC6.3",
			name: "Least privilege (CC6.3)",
			description: "The entity authorises access based on role and need-to-know principles",
			status:
				wildcardOnlyAgents === 0 && stats.activeAgents > 0
					? "compliant"
					: wildcardOnlyAgents < stats.activeAgents
						? "partial"
						: "non-compliant",
			evidence:
				stats.agentsWithNonWildcardPerms > 0
					? [`${stats.agentsWithNonWildcardPerms} agent(s) use scoped resource permissions`]
					: [],
			gaps:
				wildcardOnlyAgents > 0
					? [
							`${wildcardOnlyAgents} active agent(s) may hold wildcard (*) permissions — review and narrow scope`,
						]
					: [],
		},
		{
			id: "CC7.1",
			name: "System monitoring (CC7.1)",
			description:
				"The entity uses detection and monitoring procedures to identify changes to configurations",
			status: stats.hasAuditEvents ? "compliant" : "partial",
			evidence: stats.hasAuditEvents
				? [`Audit log active — ${stats.totalAuditEvents} events captured in period`]
				: [],
			gaps: stats.hasAuditEvents ? [] : ["No audit events in period — verify monitoring coverage"],
		},
		{
			id: "CC7.2",
			name: "Anomaly detection (CC7.2)",
			description:
				"The entity monitors system components and detects anomalies indicating malicious acts",
			status: stats.hasRateLimitedEvents ? "compliant" : "partial",
			evidence: stats.hasRateLimitedEvents
				? [
						`${stats.rateLimitedEvents} rate-limited events detected — rate limiting is active and enforced`,
					]
				: [],
			gaps: stats.hasRateLimitedEvents
				? []
				: [
						"No rate-limited events detected — consider enabling anomaly detection (kavach.anomaly.scan())",
					],
		},
	];
}

function buildIso42001Controls(stats: ReportStats): ComplianceControl[] {
	return [
		{
			id: "ISO42001-A.3",
			name: "Human oversight controls (A.3)",
			description: "The organisation implements measures to maintain human oversight of AI systems",
			status: stats.agentsWithRequireApproval > 0 ? "compliant" : "partial",
			evidence:
				stats.agentsWithRequireApproval > 0
					? [
							`${stats.agentsWithRequireApproval} agent(s) require human approval for sensitive operations`,
						]
					: [],
			gaps:
				stats.agentsWithRequireApproval === 0
					? [
							"No agents configured with requireApproval — add approval gates for high-risk agent operations",
						]
					: [],
		},
		{
			id: "ISO42001-A.7",
			name: "Access control (A.7)",
			description: "Access to AI systems and data is appropriately restricted",
			status:
				stats.agentsWithNonWildcardPerms > 0
					? "compliant"
					: stats.totalAgents === 0
						? "not-applicable"
						: "non-compliant",
			evidence:
				stats.agentsWithNonWildcardPerms > 0
					? [
							`${stats.agentsWithNonWildcardPerms} agent(s) have resource-scoped permissions`,
							`${stats.revokedAgents} agent(s) have been revoked (access removal working)`,
						]
					: [],
			gaps:
				stats.agentsWithNonWildcardPerms === 0 && stats.totalAgents > 0
					? ["All agents have wildcard permissions — apply explicit resource scoping"]
					: [],
		},
		{
			id: "ISO42001-A.8",
			name: "Documentation of AI behaviour (A.8)",
			description: "AI system behaviour is documented and traceable",
			status: stats.hasAuditEvents && stats.agentsWithType > 0 ? "compliant" : "partial",
			evidence: [
				...(stats.hasAuditEvents
					? [`${stats.totalAuditEvents} behaviour events logged with action, resource, result`]
					: []),
				...(stats.agentsWithType > 0
					? [`${stats.agentsWithType} agent(s) classified by type`]
					: []),
			],
			gaps: [
				...(!stats.hasAuditEvents ? ["No audit events — AI behaviour cannot be documented"] : []),
				...(stats.agentsWithType === 0
					? ["Agent types not set — classify agents for documentation completeness"]
					: []),
			],
		},
	];
}

function buildRecommendations(
	framework: ComplianceReportOptions["framework"],
	controls: ComplianceControl[],
	stats: ReportStats,
): string[] {
	const recommendations: string[] = [];

	const nonCompliant = controls.filter((c) => c.status === "non-compliant");
	const partial = controls.filter((c) => c.status === "partial");

	for (const control of nonCompliant) {
		for (const gap of control.gaps) {
			recommendations.push(`[${control.id}] ${gap}`);
		}
	}

	for (const control of partial) {
		for (const gap of control.gaps) {
			recommendations.push(`[${control.id}] ${gap}`);
		}
	}

	if (stats.totalAgents === 0) {
		recommendations.push(
			"Register agents using kavach.agent.create() to begin tracking compliance",
		);
	}

	if (!stats.hasAuditEvents) {
		recommendations.push(
			"Enable auditAll in KavachConfig to capture all authorization decisions automatically",
		);
	}

	if (framework === "eu-ai-act" && stats.agentsWithExpiry < stats.activeAgents) {
		recommendations.push(
			"Set expiresAt on agent creation to enforce automatic token rotation (EU AI Act Art. 15)",
		);
	}

	// Deduplicate while preserving order
	return [...new Set(recommendations)];
}

/**
 * Generate a compliance report for the specified framework.
 *
 * Queries the database for agent, permission, audit, and delegation data,
 * then maps findings to framework-specific controls and generates recommendations.
 */
export async function generateComplianceReport(
	db: Database,
	options: ComplianceReportOptions,
): Promise<ComplianceReport> {
	const until = options.until ?? new Date();
	const since = options.since ?? new Date(until.getTime() - 30 * 24 * 60 * 60 * 1000);

	const stats = await gatherStats(db, since, until);

	let controls: ComplianceControl[];

	switch (options.framework) {
		case "eu-ai-act":
			controls = buildEuAiActControls(stats);
			break;
		case "nist-ai-rmf":
			controls = buildNistAiRmfControls(stats);
			break;
		case "soc2":
			controls = buildSoc2Controls(stats);
			break;
		case "iso-42001":
			controls = buildIso42001Controls(stats);
			break;
	}

	const recommendations = buildRecommendations(options.framework, controls, stats);

	return {
		framework: options.framework,
		generatedAt: new Date().toISOString(),
		period: {
			from: since.toISOString(),
			to: until.toISOString(),
		},
		summary: {
			totalAgents: stats.totalAgents,
			activeAgents: stats.activeAgents,
			revokedAgents: stats.revokedAgents,
			totalAuditEvents: stats.totalAuditEvents,
			deniedEvents: stats.deniedEvents,
			rateLimitedEvents: stats.rateLimitedEvents,
			delegationChains: stats.delegationChainCount,
		},
		controls,
		recommendations,
	};
}
