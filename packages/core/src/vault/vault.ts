import { and, eq } from "drizzle-orm";
import { insertAuditRow } from "../audit/chain.js";
import { generateId } from "../crypto/web-crypto.js";
import { agents, delegationChains, permissions } from "../db/schema.js";
import { matchAction, matchResource } from "../policy/abac.js";
import { createVaultCipher } from "./cipher.js";
import { refreshTokens } from "./refresh.js";
import { vaultConnections, vaultConsents } from "./schema.js";
import type {
	GetAccessTokenInput,
	StoreConnectionInput,
	TokenVault,
	TokenVaultConfig,
	VaultAccessToken,
	VaultConnectionInfo,
	VaultResult,
} from "./types.js";

type ConnRow = typeof vaultConnections.$inferSelect;

/** Permission resource an agent needs: `vault:<provider>` with action `use`. */
export const VAULT_ACTION = "use";
export function vaultResource(provider: string): string {
	return `vault:${provider}`;
}

function aadFor(
	row: { id: string; userId: string; tenantId: string; provider: string },
	col: string,
) {
	return `${row.id}|${row.userId}|${row.tenantId}|${row.provider}|${col}`;
}

function isSubset(sub: string[], sup: string[]): boolean {
	const set = new Set(sup);
	return sub.every((s) => set.has(s));
}

function fail(
	code: string,
	message: string,
): { success: false; error: { code: string; message: string } } {
	return { success: false, error: { code, message } };
}

export async function createTokenVault(config: TokenVaultConfig): Promise<TokenVault> {
	const { db, storage } = config;
	const cipher = await createVaultCipher(config.keys);
	const now = config.now ?? Date.now;
	const skewMs = (config.expirySkewSeconds ?? 60) * 1000;
	const lockTtl = config.lockTtlSeconds ?? 15;
	const lockWaitMs = config.lockWaitMs ?? 5000;
	const inflight = new Map<string, Promise<ConnRow | null>>();

	function info(r: ConnRow): VaultConnectionInfo {
		return {
			id: r.id,
			userId: r.userId,
			tenantId: r.tenantId === "" ? null : r.tenantId,
			provider: r.provider,
			providerAccountId: r.providerAccountId,
			scopes: r.scopes,
			status: r.status,
			expiresAt: r.expiresAt,
		};
	}

	async function findConn(userId: string, tenant: string, provider: string) {
		const rows = await db
			.select()
			.from(vaultConnections)
			.where(
				and(
					eq(vaultConnections.userId, userId),
					eq(vaultConnections.tenantId, tenant),
					eq(vaultConnections.provider, provider),
				),
			)
			.limit(1);
		return rows[0];
	}

	async function audit(
		input: GetAccessTokenInput,
		result: "allowed" | "denied",
		reason: string | undefined,
		start: number,
	): Promise<void> {
		// Parameters carry provider and scopes only, never a token.
		await insertAuditRow(db, {
			id: generateId(),
			agentId: input.agentId,
			userId: input.userId,
			action: "vault.read",
			resource: vaultResource(input.provider),
			parameters: { provider: input.provider, scopes: input.scopes },
			result,
			reason: reason ?? null,
			durationMs: Math.max(0, Math.round(now() - start)),
			cacheHit: false,
			timestamp: new Date(now()),
		});
	}

	async function agentMayUse(agentId: string, provider: string, at: Date): Promise<boolean> {
		const resource = vaultResource(provider);
		const own = await db.select().from(permissions).where(eq(permissions.agentId, agentId));
		if (
			own.some((p) => matchResource(p.resource, resource) && matchAction(p.actions, VAULT_ACTION))
		) {
			return true;
		}
		const chains = await db
			.select()
			.from(delegationChains)
			.where(and(eq(delegationChains.toAgentId, agentId), eq(delegationChains.status, "active")));
		return chains
			.filter((c) => c.expiresAt > at)
			.some((c) =>
				c.permissions.some(
					(p) => matchResource(p.resource, resource) && matchAction(p.actions, VAULT_ACTION),
				),
			);
	}

	async function consentScopes(
		input: GetAccessTokenInput,
		tenant: string,
		at: Date,
	): Promise<string[] | null> {
		const rows = await db
			.select()
			.from(vaultConsents)
			.where(
				and(
					eq(vaultConsents.userId, input.userId),
					eq(vaultConsents.agentId, input.agentId),
					eq(vaultConsents.tenantId, tenant),
					eq(vaultConsents.provider, input.provider),
				),
			);
		for (const c of rows) {
			if (c.revokedAt) continue;
			if (c.expiresAt && c.expiresAt <= at) continue;
			if (c.delegationChainId) {
				const chain = await db
					.select()
					.from(delegationChains)
					.where(eq(delegationChains.id, c.delegationChainId))
					.limit(1);
				if (!chain[0] || chain[0].status !== "active" || chain[0].expiresAt <= at) continue;
			}
			if (isSubset(input.scopes, c.scopes)) return c.scopes;
		}
		return null;
	}

	async function sleep(ms: number): Promise<void> {
		await new Promise((r) => setTimeout(r, ms));
	}

	function needsRefresh(r: ConnRow): boolean {
		return r.expiresAt !== null && r.expiresAt.getTime() - skewMs <= now();
	}

	async function reload(id: string): Promise<ConnRow | undefined> {
		const rows = await db
			.select()
			.from(vaultConnections)
			.where(eq(vaultConnections.id, id))
			.limit(1);
		return rows[0];
	}

	async function doRefresh(row: ConnRow): Promise<ConnRow | null> {
		const provider = config.providers[row.provider];
		if (!provider || !row.refreshTokenEnc) return null;
		const refreshToken = await cipher.decrypt(row.refreshTokenEnc, aadFor(row, "refresh"));
		const out = await refreshTokens(provider, refreshToken, config.fetch ?? fetch);
		if (!out.ok) {
			if (out.reauth) {
				await db
					.update(vaultConnections)
					.set({ status: "needs_reauth", updatedAt: new Date(now()) })
					.where(eq(vaultConnections.id, row.id));
			}
			return null;
		}
		await db
			.update(vaultConnections)
			.set({
				accessTokenEnc: await cipher.encrypt(out.accessToken, aadFor(row, "access")),
				refreshTokenEnc: out.refreshToken
					? await cipher.encrypt(out.refreshToken, aadFor(row, "refresh"))
					: row.refreshTokenEnc,
				keyId: cipher.activeKeyId,
				scopes: out.scopes ?? row.scopes,
				expiresAt: out.expiresIn ? new Date(now() + out.expiresIn * 1000) : null,
				status: "active",
				updatedAt: new Date(now()),
			})
			.where(eq(vaultConnections.id, row.id));
		return (await reload(row.id)) ?? null;
	}

	/** Single flight: one in-process promise per connection, one storage lock across instances. */
	function refreshOnce(row: ConnRow): Promise<ConnRow | null> {
		const existing = inflight.get(row.id);
		if (existing) return existing;
		const p = (async () => {
			const lockKey = `vault:refresh:${row.id}`;
			const deadline = now() + lockWaitMs;
			try {
				for (;;) {
					const { count } = await storage.incr(lockKey, lockTtl);
					if (count === 1) {
						try {
							const fresh = await reload(row.id);
							if (fresh && !needsRefresh(fresh)) return fresh;
							return await doRefresh(fresh ?? row);
						} finally {
							await storage.delete(lockKey);
						}
					}
					// Someone else holds the lock: wait for their result.
					await sleep(25);
					const fresh = await reload(row.id);
					if (fresh && !needsRefresh(fresh)) return fresh;
					if (fresh && fresh.status !== "active") return null;
					if (now() >= deadline) return null;
				}
			} finally {
				inflight.delete(row.id);
			}
		})();
		inflight.set(row.id, p);
		return p;
	}

	async function getAccessToken(
		input: GetAccessTokenInput,
	): Promise<VaultResult<VaultAccessToken>> {
		const start = now();
		const at = new Date(start);

		async function deny(code: string, message: string) {
			try {
				await audit(input, "denied", code, start);
			} catch {
				// Unknown agent or user can violate the audit FK; the denial still stands.
			}
			return fail(code, message);
		}

		if (input.scopes.length === 0)
			return deny("VAULT_SCOPES_REQUIRED", "Request at least one scope");

		const agentRows = await db.select().from(agents).where(eq(agents.id, input.agentId)).limit(1);
		const agent = agentRows[0];
		if (!agent || agent.status !== "active" || (agent.expiresAt && agent.expiresAt <= at)) {
			return deny("VAULT_AGENT_INACTIVE", "Agent is not active");
		}
		// Tenant comes from the agent, never from the caller.
		const tenant = agent.tenantId ?? "";

		if (!(await agentMayUse(agent.id, input.provider, at))) {
			return deny("VAULT_PERMISSION_DENIED", "Agent has no permission for this provider");
		}
		if ((await consentScopes(input, tenant, at)) === null) {
			return deny(
				"VAULT_CONSENT_REQUIRED",
				"User has not consented to these scopes for this agent",
			);
		}

		let row = await findConn(input.userId, tenant, input.provider);
		if (!row || row.status === "revoked") return deny("VAULT_NOT_CONNECTED", "No connection");
		if (row.status === "needs_reauth") return deny("VAULT_REAUTH_REQUIRED", "User must reconnect");
		if (!isSubset(input.scopes, row.scopes)) {
			return deny("VAULT_SCOPE_NOT_GRANTED", "Connection does not hold the requested scopes");
		}

		if (needsRefresh(row)) {
			const refreshed = await refreshOnce(row);
			if (!refreshed) return deny("VAULT_REFRESH_FAILED", "Could not refresh the token");
			row = refreshed;
		}

		let accessToken: string;
		try {
			accessToken = await cipher.decrypt(row.accessTokenEnc, aadFor(row, "access"));
		} catch {
			return deny("VAULT_DECRYPT_FAILED", "Stored token could not be decrypted");
		}

		// Fail closed: no audit row, no token.
		await audit(input, "allowed", undefined, start);
		return {
			success: true,
			data: {
				accessToken,
				tokenType: "Bearer",
				expiresAt: row.expiresAt ? row.expiresAt.getTime() : null,
				scopes: [...input.scopes],
			},
		};
	}

	async function storeConnection(input: StoreConnectionInput): Promise<VaultConnectionInfo> {
		const tenant = input.tenantId ?? "";
		const existing = await findConn(input.userId, tenant, input.provider);
		const id = existing?.id ?? generateId();
		const base = { id, userId: input.userId, tenantId: tenant, provider: input.provider };
		const values = {
			providerAccountId: input.providerAccountId,
			accessTokenEnc: await cipher.encrypt(input.accessToken, aadFor(base, "access")),
			refreshTokenEnc: input.refreshToken
				? await cipher.encrypt(input.refreshToken, aadFor(base, "refresh"))
				: null,
			keyId: cipher.activeKeyId,
			scopes: input.scopes,
			status: "active" as const,
			expiresAt: input.expiresInSeconds ? new Date(now() + input.expiresInSeconds * 1000) : null,
			updatedAt: new Date(now()),
		};
		if (existing) {
			await db.update(vaultConnections).set(values).where(eq(vaultConnections.id, id));
		} else {
			await db.insert(vaultConnections).values({ ...base, ...values, createdAt: new Date(now()) });
		}
		return info((await reload(id)) as ConnRow);
	}

	async function revokeWhere(cond: ReturnType<typeof eq>): Promise<number> {
		const rows = await db.select().from(vaultConsents).where(cond);
		const live = rows.filter((r) => !r.revokedAt);
		if (live.length > 0) {
			await db
				.update(vaultConsents)
				.set({ revokedAt: new Date(now()) })
				.where(cond);
		}
		return live.length;
	}

	return {
		storeConnection,
		getAccessToken,

		async listConnections(userId, tenantId) {
			const rows = await db
				.select()
				.from(vaultConnections)
				.where(eq(vaultConnections.userId, userId));
			const tenant = tenantId ?? "";
			return rows.filter((r) => r.tenantId === tenant).map(info);
		},

		async disconnect(userId, provider, tenantId) {
			const row = await findConn(userId, tenantId ?? "", provider);
			if (row) await db.delete(vaultConnections).where(eq(vaultConnections.id, row.id));
		},

		async grantConsent(input) {
			const id = generateId();
			await db.insert(vaultConsents).values({
				id,
				userId: input.userId,
				agentId: input.agentId,
				tenantId: input.tenantId ?? "",
				provider: input.provider,
				scopes: [...new Set(input.scopes)],
				delegationChainId: input.delegationChainId ?? null,
				expiresAt: input.expiresAt ?? null,
				createdAt: new Date(now()),
			});
			return { id };
		},

		async revokeConsent(consentId, userId) {
			await db
				.update(vaultConsents)
				.set({ revokedAt: new Date(now()) })
				.where(and(eq(vaultConsents.id, consentId), eq(vaultConsents.userId, userId)));
		},

		revokeForAgent: (agentId) => revokeWhere(eq(vaultConsents.agentId, agentId)),
		revokeForDelegation: (chainId) => revokeWhere(eq(vaultConsents.delegationChainId, chainId)),

		async rotateKeys() {
			const rows = await db.select().from(vaultConnections);
			let rotated = 0;
			for (const r of rows) {
				const needs =
					cipher.keyIdOf(r.accessTokenEnc) !== cipher.activeKeyId ||
					(r.refreshTokenEnc !== null && cipher.keyIdOf(r.refreshTokenEnc) !== cipher.activeKeyId);
				if (!needs) continue;
				const access = await cipher.decrypt(r.accessTokenEnc, aadFor(r, "access"));
				const refresh = r.refreshTokenEnc
					? await cipher.decrypt(r.refreshTokenEnc, aadFor(r, "refresh"))
					: null;
				await db
					.update(vaultConnections)
					.set({
						accessTokenEnc: await cipher.encrypt(access, aadFor(r, "access")),
						refreshTokenEnc: refresh ? await cipher.encrypt(refresh, aadFor(r, "refresh")) : null,
						keyId: cipher.activeKeyId,
						updatedAt: new Date(now()),
					})
					.where(eq(vaultConnections.id, r.id));
				rotated += 1;
			}
			return { rotated };
		},
	};
}
