/**
 * The single-use repositories on a store kernel. Every method is one conditional statement
 * (`updateMany`, `deleteMany` or a guarded `increment`) whose row count names the winner. On the
 * Drizzle kernel each one issues the same statement the call site used to build by hand, with
 * the same WHERE clause, so the move changes no behavior.
 */
import type { SingleUseStores, StoreKernel, Where } from "./types.js";

const eqTo = (field: string, value: string | number | boolean): Where => ({
	field,
	op: "eq",
	value,
});

export function createSingleUseStores(kernel: StoreKernel): SingleUseStores {
	const flip = async (
		model: Parameters<StoreKernel["updateMany"]>[0],
		where: readonly Where[],
		set: Record<string, unknown>,
	): Promise<boolean> => (await kernel.updateMany(model, where, set)) > 0;

	const remove = async (
		model: Parameters<StoreKernel["deleteMany"]>[0],
		where: readonly Where[],
	): Promise<boolean> => (await kernel.deleteMany(model, where)) > 0;

	return {
		magicLinks: {
			markUsed: (token, now) =>
				flip(
					"magicLinks",
					[eqTo("token", token), eqTo("used", false), { field: "expiresAt", op: "gt", value: now }],
					{ used: true },
				),
		},
		emailOtps: {
			async reserveAttempt(id, max) {
				const next = await kernel.increment("emailOtps", [eqTo("id", id)], "attempts", 1, {
					field: "attempts",
					op: "lt",
					value: max,
				});
				return next !== null;
			},
			consume: (id) => remove("emailOtps", [eqTo("id", id)]),
		},
		oneTimeTokens: {
			markUsed: (id) =>
				flip("oneTimeTokens", [eqTo("id", id), eqTo("used", false)], { used: true }),
		},
		passkeyChallenges: {
			consume: (id) => remove("passkeyChallenges", [eqTo("id", id)]),
		},
		jwtRefreshTokens: {
			markUsed: (id) =>
				flip("jwtRefreshTokens", [eqTo("id", id), eqTo("used", false)], { used: true }),
		},
		oauthStates: {
			consume: (state) => remove("oauthStates", [eqTo("state", state)]),
		},
		oidcAuthCodes: {
			markUsed: (id) =>
				flip("oidcAuthCodes", [eqTo("id", id), eqTo("used", false)], { used: true }),
		},
		oidcRefreshTokens: {
			rotate: (id) =>
				flip("oidcRefreshTokens", [eqTo("id", id), eqTo("revoked", false)], { revoked: true }),
		},
		orgInvitations: {
			accept: (id) =>
				flip("orgInvitations", [eqTo("id", id), eqTo("status", "pending")], {
					status: "accepted",
				}),
		},
		deviceEnrollments: {
			revoke: (id, atSeconds) =>
				flip("deviceEnrollments", [eqTo("id", id), { field: "revokedAt", op: "isNull" }], {
					revokedAt: atSeconds,
				}),
			async spendUse(id, nowSeconds) {
				const next = await kernel.increment(
					"deviceEnrollments",
					[
						eqTo("id", id),
						{ field: "uses", op: "ltField", other: "maxUses" },
						{ field: "revokedAt", op: "isNull" },
						{ field: "expiresAt", op: "gt", value: nowSeconds },
					],
					"uses",
					1,
				);
				return next !== null;
			},
		},
		approvals: {
			decide: (id, decision, now) =>
				flip(
					"approvalRequests",
					[eqTo("id", id), eqTo("status", "pending"), { field: "expiresAt", op: "gt", value: now }],
					{
						status: decision.status,
						respondedAt: decision.respondedAt,
						respondedBy: decision.respondedBy,
					},
				),
			expire: (id) =>
				flip("approvalRequests", [eqTo("id", id), eqTo("status", "pending")], {
					status: "expired",
				}),
			consume: (spend, now) =>
				flip(
					"approvalRequests",
					[
						eqTo("id", spend.id),
						eqTo("status", "approved"),
						eqTo("agentId", spend.agentId),
						eqTo("action", spend.action),
						eqTo("resource", spend.resource),
						{ field: "expiresAt", op: "gt", value: now },
						{ field: "consumedAt", op: "isNull" },
					],
					{ consumedAt: now },
				),
		},
		sessions: {
			deleteOnce: (id) => remove("sessions", [eqTo("id", id)]),
		},
		refreshTokens: {
			claim: (tokenHash, usedAt) =>
				flip("refreshTokens", [eqTo("tokenHash", tokenHash), eqTo("used", 0)], { used: usedAt }),
		},
	};
}
