import type { TrustedProxyConfig } from "@glinr/theauth";

/** Tunable limits. Every value can be overridden with an environment variable. */
export interface DemoLimits {
	/** Hard cap on agent rows held at once, across all visitors. */
	maxAgents: number;
	/** Agents one client may hold at once. */
	maxAgentsPerClient: number;
	/** Authorize calls one agent may make before it is cut off. */
	maxActionsPerAgent: number;
	/** API requests per client per minute. */
	requestsPerMinute: number;
	/** Minutes an agent and its audit rows live before cleanup removes them. */
	ttlMinutes: number;
}

export interface DemoEnv {
	DEMO_MAX_AGENTS?: string;
	DEMO_MAX_AGENTS_PER_CLIENT?: string;
	DEMO_MAX_ACTIONS_PER_AGENT?: string;
	DEMO_REQUESTS_PER_MINUTE?: string;
	DEMO_TTL_MINUTES?: string;
	/** Optional secret that keys the client fingerprint. See README. */
	DEMO_CLIENT_SALT?: string;
}

const DEFAULTS: DemoLimits = {
	maxAgents: 200,
	maxAgentsPerClient: 3,
	maxActionsPerAgent: 40,
	requestsPerMinute: 30,
	ttlMinutes: 60,
};

function positiveInt(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const value = Number.parseInt(raw, 10);
	return Number.isFinite(value) && value > 0 ? value : fallback;
}

export function readLimits(env: DemoEnv): DemoLimits {
	return {
		maxAgents: positiveInt(env.DEMO_MAX_AGENTS, DEFAULTS.maxAgents),
		maxAgentsPerClient: positiveInt(env.DEMO_MAX_AGENTS_PER_CLIENT, DEFAULTS.maxAgentsPerClient),
		maxActionsPerAgent: positiveInt(env.DEMO_MAX_ACTIONS_PER_AGENT, DEFAULTS.maxActionsPerAgent),
		requestsPerMinute: positiveInt(env.DEMO_REQUESTS_PER_MINUTE, DEFAULTS.requestsPerMinute),
		ttlMinutes: positiveInt(env.DEMO_TTL_MINUTES, DEFAULTS.ttlMinutes),
	};
}

/**
 * Cloudflare overwrites `cf-connecting-ip` on every request that reaches a
 * Worker, so it is safe to trust as the only client IP source here.
 */
export const CLOUDFLARE_PROXY: TrustedProxyConfig = { trustedHeader: "cf-connecting-ip" };
