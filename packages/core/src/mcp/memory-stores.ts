import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { McpJtiDenylist, McpTokenFamilyStore } from "./types.js";

/**
 * In-process refresh token family store.
 *
 * This is the default when `config.tokenFamilies` is not set. It gives
 * rotation and reuse detection inside one process. State is lost on restart
 * and not shared across instances, so production deployments with more than
 * one instance should pass `createTokenFamilyStore(db)` instead.
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
