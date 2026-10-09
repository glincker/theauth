import { sha256Raw } from "../crypto/web-crypto.js";

export type System = "incumbent" | "theauth";

export interface RolloutUser {
	id: string;
	email?: string;
	tenantId?: string;
	attributes?: Record<string, unknown>;
}

export interface RolloutRule {
	name: string;
	match: (user: RolloutUser) => boolean;
	/** Where matching users go. Default "theauth". */
	target?: System;
}

export interface RolloutConfig {
	/** 0 to 100. 0 is the rollback switch: everyone goes to the incumbent, allowlist included. */
	percent: number;
	/** Keep it stable. Changing it reshuffles who is in the percentage. */
	salt: string;
	allowlist?: { userIds?: string[]; emails?: string[]; tenants?: string[] };
	rules?: RolloutRule[];
}

export interface CohortAssignment {
	system: System;
	/** A label with no user data: "killswitch", "allowlist", "rule:<name>", "percent", "holdout". */
	cohort: string;
}

const BUCKETS = 10_000;

/** Stable bucket in [0, 10000) from SHA-256 of salt and user id. No randomness. */
export async function bucketFor(salt: string, userId: string): Promise<number> {
	const digest = await sha256Raw(`${salt}\u0000${userId}`);
	const n =
		((digest[0] as number) << 24) |
		((digest[1] as number) << 16) |
		((digest[2] as number) << 8) |
		(digest[3] as number);
	return (n >>> 0) % BUCKETS;
}

function clampPercent(p: number): number {
	if (!Number.isFinite(p)) return 0;
	return Math.min(100, Math.max(0, p));
}

/**
 * Decide which system serves a user. Pass an object, or a function that returns the
 * current config, so a flag change takes effect without a redeploy.
 */
export function createRollout(config: RolloutConfig | (() => RolloutConfig)) {
	const current = typeof config === "function" ? config : () => config;

	async function assignCohort(user: RolloutUser): Promise<CohortAssignment> {
		const cfg = current();
		const percent = clampPercent(cfg.percent);
		if (percent === 0) return { system: "incumbent", cohort: "killswitch" };
		const allow = cfg.allowlist;
		if (
			allow?.userIds?.includes(user.id) ||
			(user.email !== undefined &&
				allow?.emails?.some((e) => e.toLowerCase() === user.email?.toLowerCase())) ||
			(user.tenantId !== undefined && allow?.tenants?.includes(user.tenantId))
		) {
			return { system: "theauth", cohort: "allowlist" };
		}
		for (const rule of cfg.rules ?? []) {
			let hit = false;
			try {
				hit = rule.match(user);
			} catch {
				hit = false;
			}
			if (hit) return { system: rule.target ?? "theauth", cohort: `rule:${rule.name}` };
		}
		if (percent === 100) return { system: "theauth", cohort: "percent" };
		const bucket = await bucketFor(cfg.salt, user.id);
		return bucket < percent * 100
			? { system: "theauth", cohort: "percent" }
			: { system: "incumbent", cohort: "holdout" };
	}

	/** Per route or tenant cutover: a route can be fully moved while others stay put. */
	function cutover(
		routes: Record<string, System | "rollout">,
		fallback: System | "rollout" = "incumbent",
	) {
		return async function resolve(route: string, user: RolloutUser): Promise<CohortAssignment> {
			const mode = routes[route] ?? fallback;
			if (mode === "rollout") return assignCohort(user);
			if (current().percent === 0) return { system: "incumbent", cohort: "killswitch" };
			return { system: mode, cohort: `route:${route}` };
		};
	}

	return { assignCohort, cutover };
}

export type Rollout = ReturnType<typeof createRollout>;
