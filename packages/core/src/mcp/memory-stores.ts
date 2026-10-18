import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type {
	McpRevocationEntry,
	McpRevocationHit,
	McpRevocationQuery,
	McpRevocationStore,
} from "./revocation-types.js";
import { normalizeBlockValue, normalizeHosts } from "./stores-db-blocks.js";
import type { McpClientStore } from "./stores-db-clients.js";
import type { McpClient, McpJtiDenylist, McpTokenFamilyStore } from "./types.js";
import type { McpClientBlock, McpClientBlockStore } from "./types-cimd.js";

/**
 * In-process refresh token family store.
 * This is the default when `config.tokenFamilies` is not set. State is lost on restart and not shared across instances, so production deployments with more than one instance should pass `createTokenFamilyStore(db)` instead.
 */
export function createInMemoryTokenFamilyStore(): McpTokenFamilyStore {
	interface FamilyRow {
		id: string;
		absoluteExpiresAt: Date;
		revoked: boolean;
	}
	interface TokenRow {
		familyId: string;
		used: boolean;
		expiresAt: Date;
	}
	const families = new Map<string, FamilyRow>();
	const tokens = new Map<string, TokenRow>();

	function prune(now: Date): void {
		for (const [hash, t] of tokens) {
			const fam = families.get(t.familyId);
			if (t.expiresAt <= now && (!fam || fam.absoluteExpiresAt <= now)) tokens.delete(hash);
		}
	}

	return {
		async createFamily(_userId, absoluteExpiresAt) {
			const id = generateId();
			families.set(id, { id, absoluteExpiresAt, revoked: false });
			return { id };
		},
		async issueToken(familyId, ttlMs) {
			const now = new Date();
			prune(now);
			const rawToken = randomBytesHex(32);
			const hash = await sha256(rawToken);
			const expiresAt = new Date(now.getTime() + ttlMs);
			tokens.set(hash, { familyId, used: false, expiresAt });
			return { rawToken, expiresAt };
		},
		async consumeToken(rawToken) {
			const hash = await sha256(rawToken);
			const row = tokens.get(hash);
			if (!row) return { status: "not_found" };
			const family = families.get(row.familyId);
			if (!family) return { status: "not_found" };
			const ref = { id: family.id };
			if (family.revoked) return { status: "revoked", family: ref };
			const now = new Date();
			if (family.absoluteExpiresAt <= now) {
				family.revoked = true;
				return { status: "expired", family: ref };
			}
			if (row.expiresAt <= now) return { status: "expired", family: ref };
			if (row.used) {
				family.revoked = true;
				return { status: "reuse", family: ref };
			}
			row.used = true;
			return { status: "ok", family: ref };
		},
		async revokeFamily(familyId) {
			const fam = families.get(familyId);
			if (fam) fam.revoked = true;
		},
	};
}

/** In-process jti denylist. Entries are dropped once the token would have expired anyway. */
export function createInMemoryJtiDenylist(): McpJtiDenylist {
	const entries = new Map<string, number>();
	return {
		async revoke(jti, expiresAt) {
			const now = Date.now();
			for (const [id, exp] of entries) {
				if (exp <= now) entries.delete(id);
			}
			entries.set(jti, expiresAt.getTime());
		},
		async isRevoked(jti) {
			const exp = entries.get(jti);
			if (exp === undefined) return false;
			if (exp <= Date.now()) {
				entries.delete(jti);
				return false;
			}
			return true;
		},
	};
}

/**
 * In-process client store with the same admin state rules as the database store: `preserveAdminState` keeps `disabled`, `disabledReason` and the agent binding of an existing client. Per process; token revocation has nothing to delete here.
 */
export function createInMemoryClientStore(): McpClientStore {
	const clients = new Map<string, McpClient>();
	function need(clientId: string): McpClient {
		const c = clients.get(clientId);
		if (!c) throw new Error(`Unknown client: ${clientId}`);
		return c;
	}
	return {
		async storeClient(client, options = {}) {
			const existing = clients.get(client.clientId);
			if (existing && options.preserveAdminState) {
				clients.set(client.clientId, {
					...client,
					disabled: existing.disabled,
					disabledReason: existing.disabledReason ?? null,
					agentId: existing.agentId ?? null,
					createdAt: existing.createdAt,
				});
				return;
			}
			// undefined keeps a binding made through setClientAgent, like the database store.
			clients.set(client.clientId, {
				...client,
				agentId: client.agentId !== undefined ? client.agentId : (existing?.agentId ?? null),
			});
		},
		async findClient(clientId) {
			const c = clients.get(clientId);
			return c ? { ...c } : null;
		},
		async updateClientSecret(clientId, hashedSecret) {
			clients.set(clientId, {
				...need(clientId),
				clientSecret: hashedSecret,
				updatedAt: new Date(),
			});
		},
		async setClientAgent(clientId, agentId) {
			clients.set(clientId, { ...need(clientId), agentId, updatedAt: new Date() });
		},
		async setClientDisabled(clientId, disabled, reason) {
			clients.set(clientId, {
				...need(clientId),
				disabled,
				disabledReason: disabled ? (reason ?? null) : null,
				updatedAt: new Date(),
			});
		},
		async revokeClientTokens() {
			return { jtis: [] };
		},
		async listCimdClientIds() {
			return [...clients.values()].filter((c) => c.source === "cimd").map((c) => c.clientId);
		},
	};
}

/** In-process block list. Per process: rules are lost on restart and not shared across instances, so multi instance deployments should use the database store. */
export function createInMemoryBlockStore(): McpClientBlockStore {
	const rules = new Map<string, McpClientBlock>();
	const key = (kind: string, value: string): string => `${kind}\u0000${value}`;
	return {
		async findBlock(url, hosts) {
			const direct = rules.get(key("url", url));
			if (direct) return { ...direct };
			for (const host of normalizeHosts(hosts)) {
				const hit = rules.get(key("host", host));
				if (hit) return { ...hit };
			}
			return null;
		},
		async addBlock(block) {
			const value = normalizeBlockValue(block.kind, block.value);
			if (!value) throw new Error("A block needs a non empty value");
			const existing = rules.get(key(block.kind, value));
			if (existing) return { ...existing };
			const created: McpClientBlock = {
				id: generateId(),
				kind: block.kind,
				value,
				reason: block.reason ?? null,
				createdBy: block.createdBy ?? null,
				createdAt: new Date(Math.floor(Date.now() / 1000) * 1000),
			};
			rules.set(key(created.kind, created.value), created);
			return { ...created };
		},
		async removeBlock(id) {
			for (const [k, v] of rules) if (v.id === id) rules.delete(k);
		},
		async listBlocks() {
			return [...rules.values()]
				.map((b) => ({ ...b }))
				.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
		},
	};
}

/**
 * In-process {@link McpRevocationStore} with the same semantics as the database one (jti, dlg and agent rows deny outright, sub and client rows are watermarks on `iat`). For tests and single process setups; not shared across instances.
 */
export function createInMemoryRevocationStore(): McpRevocationStore {
	const rows = new Map<
		string,
		{ kind: McpRevocationEntry["kind"]; id: string; revokedAtMs: number; expiresAtMs: number }
	>();
	const key = (kind: string, id: string): string => `${kind}\u0000${id}`;
	const revokeMany = async (entries: McpRevocationEntry[], revokedAt?: Date): Promise<void> => {
		const at = (revokedAt ?? new Date()).getTime();
		for (const e of entries) {
			if (e.id.length === 0) continue;
			const k = key(e.kind, e.id);
			const old = rows.get(k);
			rows.set(k, {
				kind: e.kind,
				id: e.id,
				revokedAtMs: Math.max(old?.revokedAtMs ?? 0, at),
				expiresAtMs: Math.max(old?.expiresAtMs ?? 0, e.expiresAt.getTime()),
			});
		}
	};
	return {
		revokeMany,
		async revoke(jti, expiresAt) {
			await revokeMany([{ kind: "jti", id: jti, expiresAt, reason: "token.revoke" }]);
		},
		async isRevoked(jti) {
			return rows.has(key("jti", jti));
		},
		async check(q: McpRevocationQuery): Promise<McpRevocationHit | null> {
			if (rows.has(key("jti", q.jti))) return { kind: "jti", id: q.jti };
			const watermark = (kind: "sub" | "client", id: string): McpRevocationHit | null => {
				const row = rows.get(key(kind, id));
				return row && q.iat * 1000 <= row.revokedAtMs ? { kind, id } : null;
			};
			const hit = watermark("sub", q.sub) ?? watermark("client", q.clientId);
			if (hit) return hit;
			for (const id of q.dlg) if (rows.has(key("dlg", id))) return { kind: "dlg", id };
			for (const id of q.agents) if (rows.has(key("agent", id))) return { kind: "agent", id };
			return null;
		},
		async fingerprint() {
			let max = 0;
			for (const r of rows.values()) max = Math.max(max, r.revokedAtMs);
			return `${rows.size}:${max}`;
		},
		async prune(now, limit = 500) {
			let n = 0;
			for (const [k, r] of rows) {
				if (n >= limit) break;
				if (r.expiresAtMs < now.getTime()) {
					rows.delete(k);
					n += 1;
				}
			}
			return n;
		},
	};
}
