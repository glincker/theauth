import { describe, expect, it } from "vitest";
import { seedAgent, seedUser } from "./seed.js";
import type { MakeTarget, SuiteOptions } from "./target.js";
import { future, past, uid } from "./target.js";

const wins = (results: boolean[]): number => results.filter(Boolean).length;

/** The single-use repositories on the backend's kernel: exactly one winner per claim. */
export function defineSingleUse(make: MakeTarget, options: SuiteOptions): void {
	const parallel = options.parallel ?? 24;
	const race = (fn: () => Promise<boolean>) => Promise.all(Array.from({ length: parallel }, fn));

	describe("single-use repositories", () => {
		it("marks a magic link used once, and refuses an expired or used one", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const token = uid("tok");
				const row = { id: uid("ml"), email: "a@s.test", used: false, createdAt: new Date() };
				await kernel.insert("magicLinks", { ...row, token, expiresAt: future() });
				expect(wins(await race(() => singleUse.magicLinks.markUsed(token, new Date())))).toBe(1);
				expect(await singleUse.magicLinks.markUsed(token, new Date())).toBe(false);
				const stale = uid("tok");
				await kernel.insert("magicLinks", {
					...row,
					id: uid("ml"),
					token: stale,
					expiresAt: past(),
				});
				expect(await singleUse.magicLinks.markUsed(stale, new Date())).toBe(false);
			} finally {
				await t.close();
			}
		});

		it("spends exactly max OTP guesses and deletes once", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const otpId = uid("otp");
				await kernel.insert("emailOtps", {
					id: otpId,
					email: "o@s.test",
					codeHash: "h",
					expiresAt: future(),
					attempts: 0,
					createdAt: new Date(),
				});
				expect(wins(await race(() => singleUse.emailOtps.reserveAttempt(otpId, 5)))).toBe(5);
				expect(wins(await race(() => singleUse.emailOtps.consume(otpId)))).toBe(1);
			} finally {
				await t.close();
			}
		});

		it("flips one-time token and jwt refresh rows once, and deletes a session once", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const user = await seedUser(kernel);
				const ott = uid("ott");
				await kernel.insert("oneTimeTokens", {
					id: ott,
					tokenHash: uid("h"),
					identifier: "i",
					purpose: "p",
					used: false,
					expiresAt: future(),
					createdAt: new Date(),
				});
				expect(wins(await race(() => singleUse.oneTimeTokens.markUsed(ott)))).toBe(1);
				const jwt = uid("jwt");
				await kernel.insert("jwtRefreshTokens", {
					id: jwt,
					userId: user,
					tokenHash: uid("h"),
					used: false,
					expiresAt: future(),
					createdAt: new Date(),
				});
				expect(wins(await race(() => singleUse.jwtRefreshTokens.markUsed(jwt)))).toBe(1);
				const sid = uid("sess");
				await kernel.insert("sessions", {
					id: sid,
					userId: user,
					expiresAt: future(),
					createdAt: new Date(),
				});
				expect(wins(await race(() => singleUse.sessions.deleteOnce(sid)))).toBe(1);
			} finally {
				await t.close();
			}
		});

		it("claims a refresh token from 0 once, and enrollment uses up to the cap", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const user = await seedUser(kernel);
				const family = uid("fam");
				await kernel.insert("refreshTokenFamilies", {
					id: family,
					userId: user,
					revoked: 0,
					absoluteExpiresAt: future(),
					createdAt: new Date(),
				});
				const hash = uid("hash");
				await kernel.insert("refreshTokens", {
					id: uid("rt"),
					familyId: family,
					tokenHash: hash,
					used: 0,
					expiresAt: future(),
					createdAt: new Date(),
				});
				expect(wins(await race(() => singleUse.refreshTokens.claim(hash, 100)))).toBe(1);
				expect(await singleUse.refreshTokens.claim(hash, 200)).toBe(false);

				const nowSec = Math.floor(Date.now() / 1000);
				const enr = uid("enr");
				await kernel.insert("deviceEnrollments", {
					id: enr,
					kind: "claim",
					tokenHash: uid("h"),
					ownerId: user,
					maxUses: 3,
					uses: 0,
					expiresAt: nowSec + 3600,
					createdAt: nowSec,
					template: { groups: [], permissions: [] },
				});
				expect(wins(await race(() => singleUse.deviceEnrollments.spendUse(enr, nowSec)))).toBe(3);
				expect(wins(await race(() => singleUse.deviceEnrollments.revoke(enr, nowSec)))).toBe(1);
				expect(await singleUse.deviceEnrollments.spendUse(enr, nowSec)).toBe(false);
			} finally {
				await t.close();
			}
		});

		it("decides, expires and consumes an approval once", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const { agentId, userId } = await seedAgent(kernel);
				const mk = async (): Promise<string> => {
					const id = uid("apr");
					await kernel.insert("approvalRequests", {
						id,
						agentId,
						userId,
						action: "execute",
						resource: "mcp:x",
						expiresAt: future(),
						createdAt: new Date(),
					});
					return id;
				};
				const id = await mk();
				const decision = { status: "approved", respondedAt: new Date(), respondedBy: userId };
				expect(wins(await race(() => singleUse.approvals.decide(id, decision, new Date())))).toBe(
					1,
				);
				const spend = { id, agentId, action: "execute", resource: "mcp:x" };
				expect(wins(await race(() => singleUse.approvals.consume(spend, new Date())))).toBe(1);
				expect(await singleUse.approvals.consume(spend, new Date())).toBe(false);
				const other = await mk();
				expect(wins(await race(() => singleUse.approvals.expire(other)))).toBe(1);
				expect(await singleUse.approvals.decide(other, decision, new Date())).toBe(false);
			} finally {
				await t.close();
			}
		});

		it("never admits more calls than the hourly budget", async () => {
			const t = await make();
			const { kernel, singleUse } = t.stores;
			try {
				const { agentId } = await seedAgent(kernel);
				const bucket = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000);
				const since = new Date(bucket.getTime() - 3_600_000);
				const results = await race(
					async () =>
						(await singleUse.rateLimits.reserve({ agentId, resource: "r", bucket, since, max: 5 }))
							.allowed,
				);
				expect(wins(results)).toBeLessThanOrEqual(5);
				// Reserving before checking can refuse every caller of a burst, never admit one past max.
				const rows = await kernel.findMany("rateLimits", {
					where: [{ field: "agentId", op: "eq", value: agentId }],
				});
				const stored = rows.reduce((n, r) => n + Number(r.count), 0);
				expect(stored).toBe(wins(results));
				// A sequential call after the burst still fits when the budget is free.
				if (wins(results) < 5) {
					const next = await singleUse.rateLimits.reserve({
						agentId,
						resource: "r",
						bucket,
						since,
						max: 5,
					});
					expect(next.allowed).toBe(true);
				}
			} finally {
				await t.close();
			}
		});
	});
}
