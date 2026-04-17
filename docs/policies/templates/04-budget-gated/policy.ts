/**
 * Template 04, Budget-gated agent
 *
 * The agent may call the LLM gateway up to MAX_CALLS_PER_HOUR times per
 * hour. Once the counter reaches the cap the engine denies further calls
 * until the sliding window resets.
 *
 * The rate-limit counter is stored in kavach_rate_limits. Pre-seeding a row
 * with count = MAX_CALLS_PER_HOUR simulates a saturated budget in tests.
 *
 * Note: decisions involving maxCallsPerHour are never cached because the
 * counter changes on every call.
 */

import type { Permission } from "../../../../packages/core/src/types.js";

export const MAX_CALLS_PER_HOUR = 100;

export const budgetGatedPermissions: Permission[] = [
	{
		resource: "llm:gateway",
		actions: ["execute"],
		constraints: {
			maxCallsPerHour: MAX_CALLS_PER_HOUR,
		},
	},
];
