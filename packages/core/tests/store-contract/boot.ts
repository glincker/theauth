import type {
	ContractMailbox,
	StoreContractTarget,
} from "../../../test-utils/src/store-contract/index.js";
import { decideApproval } from "../../src/admin-api/approval-decisions.js";
import { oauth } from "../../src/auth/oauth/plugin.js";
import type { Database, DatabaseConfig } from "../../src/db/database.js";
import { users } from "../../src/db/schema.js";
import { toStoreConflict } from "../../src/db/store-conflict.js";
import { createTokenFamilyStore } from "../../src/session/token-family.js";
import { createTheAuth } from "../../src/theauth.js";

const SECRET = "contract-session-secret-that-is-at-least-32-chars!!";
const HMAC_KEY = "contract-audit-hmac-key";
const HOUR = 3_600_000;

type Closable = { $client?: { end?: () => Promise<void>; close?: () => void } };

/** Ends the driver behind a Drizzle handle, when it has a close method. */
export async function closeDatabase(db: Database): Promise<void> {
	const client = (db as unknown as Closable).$client;
	if (client?.end) await client.end();
	else client?.close?.();
}

const systemAgents = new WeakMap<object, Promise<string>>();

/** An agent the admin decision path writes its audit rows under, made once per instance. */
function systemAgent(auth: Awaited<ReturnType<typeof createTheAuth>>): Promise<string> {
	let id = systemAgents.get(auth);
	if (!id) {
		id = (async () => {
			const owner = await auth.user.create({
				email: `sys-${Math.random().toString(36).slice(2)}@contract.test`,
			});
			const a = await auth.agent.create({
				ownerId: owner.id,
				name: "contract-admin-system",
				type: "autonomous",
				permissions: [],
			});
			return a.id;
		})();
		systemAgents.set(auth, id);
	}
	return id;
}

/**
 * Boots createTheAuth on one database config. `makeConfig` is called for every boot, so a peer gets
 * its own driver handle. `shared` says whether a second boot sees the same data.
 */
export async function bootTarget(
	makeConfig: () => DatabaseConfig,
	shared: boolean,
): Promise<StoreContractTarget> {
	const mail: ContractMailbox = { magicTokens: [], otpCodes: [] };
	const auth = await createTheAuth({
		database: makeConfig(),
		baseUrl: "https://auth.contract.test",
		secret: SECRET,
		agents: { enabled: true, maxPerUser: 500, auditAll: true, tokenExpiry: "24h" },
		audit: { tamperEvident: true, hmacKey: HMAC_KEY },
		auth: { session: { secret: SECRET } },
		magicLink: {
			appUrl: "https://app.contract.test",
			sendMagicLink: async (_email, token) => {
				mail.magicTokens.push(token);
			},
		},
		emailOtp: {
			sendOtp: async (_email, code) => {
				mail.otpCodes.push(code);
			},
		},
		plugins: [oauth({ providers: {} })],
	});

	return {
		auth: auth as unknown as StoreContractTarget["auth"],
		mail,
		peer: shared ? () => bootTarget(makeConfig, shared) : undefined,
		duplicateInsert: async () => {
			const now = new Date();
			const row = {
				id: `dup-${Math.random().toString(36).slice(2)}`,
				email: `dup-${Math.random().toString(36).slice(2)}@contract.test`,
				name: null,
				metadata: null,
				createdAt: now,
				updatedAt: now,
			};
			await auth.db.insert(users).values(row);
			try {
				await auth.db.insert(users).values({ ...row, id: `${row.id}-b` });
			} catch (err) {
				return toStoreConflict(err, "users") ? "typed" : "untyped";
			}
			return "none";
		},
		tokenFamilies: {
			rotateOnce: async (userId, parallel) => {
				const store = createTokenFamilyStore(auth.db, { reuseGraceMs: 0 });
				const family = await store.createFamily(userId, new Date(Date.now() + 24 * HOUR));
				const token = await store.issueToken(family.id, HOUR);
				const results = await Promise.all(
					Array.from({ length: parallel }, () => store.consumeToken(token.rawToken)),
				);
				return {
					ok: results.filter((r) => r.status === "ok").length,
					others: results.filter((r) => r.status !== "ok").map((r) => r.status),
				};
			},
		},
		adminDecisions: {
			decide: async (approvalId, approverId, decision) => {
				const result = await decideApproval(auth.db, {
					id: approvalId,
					decision,
					approverId,
					systemAgentId: await systemAgent(auth),
					allowSelfApproval: false,
				});
				return result.ok;
			},
		},
		close: () => closeDatabase(auth.db),
	};
}
