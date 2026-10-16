/**
 * Template 08, Spending limit with human approval above a threshold
 *
 * Payments below the threshold run without a human. Payments at or above it
 * escalate: policy.evaluate() returns decision "escalate" and, with
 * openApproval, opens an approval request. A hard hourly call cap applies to
 * every payment.
 *
 * The threshold is a risk-tier rule keyed on context.risk.amount. It is not a
 * numeric constraint on a permission. Cumulative spend is not tracked.
 *
 *   payments:transfer   execute   maxCallsPerHour
 *   risk tier           minAmount -> require approval
 */

import type { Permission } from "../../../../packages/core/src/index.js";

/** Amounts at or above this escalate. Read it from config. */
export const APPROVAL_THRESHOLD = Number(process.env.PAYMENT_APPROVAL_THRESHOLD ?? "100");
export const MAX_PAYMENTS_PER_HOUR = 50;

export const spendLimitPermissions: Permission[] = [
	{
		resource: "payments:transfer",
		actions: ["execute"],
		constraints: {
			maxCallsPerHour: MAX_PAYMENTS_PER_HOUR,
		},
	},
];

/** Pass as the `policy` option of createTheAuth(). */
export const spendLimitPolicy = {
	policyVersion: "08-spend-limit-v1",
	risk: {
		tiers: [
			{
				tier: "large-payment",
				when: { minAmount: APPROVAL_THRESHOLD },
				require: "approval" as const,
			},
		],
	},
};
