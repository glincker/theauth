import type { Context } from "../context.js";
import type { CheckMeta, CheckOutcome } from "../types.js";

export interface Check extends CheckMeta {
	run(ctx: Context): Promise<CheckOutcome>;
}

export const pass = (summary: string, evidence?: Record<string, unknown>): CheckOutcome => ({
	status: "pass",
	summary,
	...(evidence ? { evidence } : {}),
});

export const fail = (summary: string, evidence?: Record<string, unknown>): CheckOutcome => ({
	status: "fail",
	summary,
	...(evidence ? { evidence } : {}),
});

export const skip = (summary: string, evidence?: Record<string, unknown>): CheckOutcome => ({
	status: "skip",
	summary,
	...(evidence ? { evidence } : {}),
});

export const GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
