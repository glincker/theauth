import { describe, expect, it } from "vitest";
import { uniqueEmail } from "./claim-races.js";
import type { StoreContractTarget } from "./types.js";

type Make = () => Promise<StoreContractTarget>;

const LIMIT = 10;

/**
 * The hourly call budget (`maxCallsPerHour`, table theauth_rate_limits). A read of the counter followed by a write lets every parallel caller see room and spend it, so the budget is overrun. The count must be one guarded statement.
 */
export function defineRateLimitRaces(make: Make, parallel: number): void {
	describe("rate limit races", () => {
		it("never admits more than maxCallsPerHour parallel calls", async () => {
			const t = await make();
			try {
				const { agent, user } = t.auth;
				const owner = await user.create({ email: uniqueEmail("rl") });
				const a = await agent.create({
					ownerId: owner.id,
					name: "contract-rate-limit",
					type: "autonomous",
					permissions: [
						{
							resource: "mcp:rl:*",
							actions: ["execute"],
							constraints: { maxCallsPerHour: LIMIT },
						},
					],
				});
				const call = () => t.auth.authorize(a.id, { action: "execute", resource: "mcp:rl:go" });
				const results = await Promise.all(Array.from({ length: parallel }, call));
				const admitted = results.filter((r) => r.allowed).length;
				expect(admitted).toBeLessThanOrEqual(LIMIT);
				expect(admitted).toBeGreaterThan(0);

				// Refused callers undid their bump, so the counter holds exactly the admitted calls.
				let more = 0;
				for (let i = 0; i < LIMIT + 2; i++) if ((await call()).allowed) more += 1;
				expect(admitted + more).toBe(LIMIT);
			} finally {
				await t.close();
			}
		});
	});
}
