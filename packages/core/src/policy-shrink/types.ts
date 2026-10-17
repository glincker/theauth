import type { Permission } from "../types.js";

/** Result values the audit log can hold. */
export type DecisionResult = "allowed" | "denied" | "rate_limited" | "escalated";

/** The slice of an audit row the shrink tools need. Plain data, so the pure functions can be driven by rows from a test, an export file or the database. */
export interface DecisionRow {
	id: string;
	action: string;
	resource: string;
	result: DecisionResult;
	reason: string | null;
	timestamp: Date;
	/** Delegation chain ids recorded on the row, when the writer set them. */
	delegationChain?: string[] | null;
}

/** Why a row was classified the way it was. */
export type RowClass =
	/** Bookkeeping row (checkpoint, erasure, write failure, revoke cascade). Ignored. */
	| "internal"
	/** The call was allowed. */
	| "allow"
	/** Denied because no permission covered it. Evidence the agent never had the grant. */
	| "deny_no_grant"
	/** Denied, rate limited or escalated for another cause (rate limit, time window, approval, revoked agent). */
	| "deny_other";

export interface GrantSource {
	kind: "own" | "delegation";
	/** Delegation chain id when kind is "delegation". */
	chainId?: string;
}

/** One single-action permission together with where it came from. */
export interface Grant {
	permission: Permission;
	source: GrantSource;
}

export interface UsedPermission {
	/** A single-action permission (resource pattern plus one action). */
	permission: Permission;
	count: number;
	firstSeen: Date;
	lastSeen: Date;
	/** Delegation chain ids that supplied the grant or appear on the matching rows. Empty for own grants. */
	via: string[];
}

export interface UsageEvidence {
	rowsScanned: number;
	allowedRows: number;
	/** Denials that say no permission covered the call. */
	noGrantDenials: number;
	/** Denials for other causes. Never counted as evidence of non-use. */
	otherDenials: number;
	/** Checkpoint, erasure and similar rows that were skipped. */
	internalRows: number;
	/** Allowed rows that no current grant covers (expired delegation, removed permission). */
	uncoveredAllows: number;
}

export interface UncoveredAllow {
	action: string;
	resource: string;
	count: number;
}

export interface UsageAnalysis {
	agentId: string;
	window: { since: Date | null; until: Date | null };
	/** Effective permissions split to one action each: own first, then delegated. */
	granted: Permission[];
	/** Where each entry of `granted` came from, same order. */
	grants: Grant[];
	used: UsedPermission[];
	/** Granted permissions with no allowed call in the window and no attempt either. */
	unused: Permission[];
	/** Granted permissions that matched only denied calls for other causes (for example a rate limit). Treated as in use: removing them would hide the attempt. */
	attemptedOnly: Permission[];
	/** Distinct (action, resource) pairs denied for lack of a grant. Capped. */
	deniedNoGrant: Array<{ action: string; resource: string }>;
	/** Allowed calls no current grant covers. Capped. */
	uncovered: UncoveredAllow[];
	evidence: UsageEvidence;
}

export interface AnalyzeOptions {
	since?: Date;
	until?: Date;
	/** Rows read per query. Default 1000. Memory use is bounded by this and the distinct pairs seen. */
	pageSize?: number;
}

export interface ShrinkOptions {
	/** A permission needs at least this many allowed calls to be kept. Default 1. */
	minObservations?: number;
	/**
	 * Merge sibling resources into a parent wildcard. Off by default. A merge happens only when every merged resource was observed in use, the wildcard is already covered by an existing grant, and it matches no resource that was denied for lack of a grant.
	 */
	generalize?: boolean;
	/** Distinct observed siblings needed before they merge. Default 3. */
	generalizeMin?: number;
}

export interface ShrinkRewrite {
	from: Permission[];
	to: Permission;
}

export interface ShrinkSuggestion {
	keep: Permission[];
	remove: Permission[];
	rewrites: ShrinkRewrite[];
}

export interface RowRef {
	id: string;
	action: string;
	resource: string;
	timestamp: Date;
}

export interface GrantMatchCount {
	permission: Permission;
	allows: number;
}

export interface BlastRadiusReport {
	/** Historical allowed calls replayed. */
	replayedAllows: number;
	stillAllowed: number;
	/** Count of allowed calls the proposal would deny. `newlyDenied` may be capped. */
	newlyDeniedCount: number;
	newlyDenied: RowRef[];
	/** Calls denied for lack of a grant that the proposal would allow. */
	wouldAlsoAllowCount: number;
	wouldAlsoAllowPreviouslyDenied: RowRef[];
	/** Denials for other causes and bookkeeping rows, left out of the comparison. */
	ignoredRows: number;
	/** Allows per proposed permission, same order as the proposal. Proof data. */
	perPermission: GrantMatchCount[];
	/** True when a list above was cut at `maxExamples`. Counts are always exact. */
	truncated: boolean;
}

export interface VerifyOptions {
	/** Most rows listed in each example list. Default 1000. */
	maxExamples?: number;
}

export interface PreviewOptions extends VerifyOptions {
	since?: Date;
	until?: Date;
	pageSize?: number;
}

export interface PreviewReport extends BlastRadiusReport {
	agentId: string;
	window: { since: Date | null; until: Date | null };
	rowsScanned: number;
}
