/**
 * SAML state in secondary storage: pending AuthnRequest ids bound to an opaque RelayState token (single use),
 * and the assertion id replay cache, kept until the assertion could no longer be accepted.
 */

import { randomBytesHex } from "../crypto/web-crypto.js";
import type { SecondaryStorage } from "../storage/types.js";

export interface PendingSamlRequest {
	requestId: string;
	connectionId: string;
	/** Application relay state passed to getSamlAuthUrl. */
	appRelayState?: string;
}

export interface SamlStateStore {
	/** Stores a pending request and returns the RelayState token to send to the IdP. */
	issue(pending: PendingSamlRequest): Promise<string>;
	/** Consumes a RelayState token once. Returns null when unknown, expired, already used or for another connection. */
	consume(token: string, connectionId: string): Promise<PendingSamlRequest | null>;
	/** Records an assertion id. Returns false when it was already seen (replay). */
	markAssertionUsed(providerId: string, assertionId: string, ttlSeconds: number): Promise<boolean>;
}

const TOKEN_RE = /^[0-9a-f]{32}$/;

function isPending(v: unknown): v is PendingSamlRequest {
	if (typeof v !== "object" || v === null) return false;
	const r = v as Record<string, unknown>;
	return (
		typeof r.requestId === "string" &&
		typeof r.connectionId === "string" &&
		(r.appRelayState === undefined || typeof r.appRelayState === "string")
	);
}

export function createSamlStateStore(
	storage: SecondaryStorage,
	ttlSeconds: number,
): SamlStateStore {
	return {
		async issue(pending) {
			const token = randomBytesHex(16);
			await storage.set(`saml:req:${token}`, JSON.stringify(pending), ttlSeconds);
			return token;
		},
		async consume(token, connectionId) {
			if (!TOKEN_RE.test(token)) return null;
			// incr is atomic on most backends, so two concurrent posts of one RelayState cannot both win.
			const used = await storage.incr(`saml:req-used:${token}`, ttlSeconds);
			if (used.count !== 1) return null;
			const raw = await storage.get(`saml:req:${token}`);
			await storage.delete(`saml:req:${token}`);
			if (!raw) return null;
			let parsed: unknown;
			try {
				parsed = JSON.parse(raw);
			} catch {
				return null;
			}
			if (!isPending(parsed) || parsed.connectionId !== connectionId) return null;
			return parsed;
		},
		async markAssertionUsed(providerId, assertionId, ttl) {
			const key = `saml:assertion:${providerId}:${assertionId}`;
			const r = await storage.incr(key, Math.max(1, Math.ceil(ttl)));
			return r.count === 1;
		},
	};
}
