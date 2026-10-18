/** Shared fixtures for the agent confirmation tests: keys, DPoP proofs and an auth instance. */
import type { JWK } from "jose";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { sha256Raw, toBase64Url } from "../src/crypto/web-crypto.js";
import type { AgentConfirmationConfig } from "../src/index.js";
import { generateSecureToken } from "../src/mcp/utils.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { BASE, seedUser } from "./http/helpers.js";

export const AUTHORIZE_URL = `${BASE}/authorize/token`;
export const PERMS = [{ resource: "docs", actions: ["read"] }];
export const CALL = { action: "read", resource: "docs" };

export interface Keys {
	privateKey: CryptoKey;
	jwk: JWK;
	jkt: string;
}

export async function newKeys(): Promise<Keys> {
	const { privateKey, publicKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	return { privateKey, jwk, jkt: await calculateJwkThumbprint(jwk, "sha256") };
}

export interface ProofInit {
	htm?: string;
	htu?: string;
	ath?: string;
	nonce?: string;
	jti?: string;
	iat?: number;
}

export async function proof(keys: Keys, token: string, init: ProofInit = {}): Promise<string> {
	return new SignJWT({
		htm: init.htm ?? "POST",
		htu: init.htu ?? AUTHORIZE_URL,
		jti: init.jti ?? generateSecureToken(16),
		iat: init.iat ?? Math.floor(Date.now() / 1000),
		ath: init.ath ?? toBase64Url(await sha256Raw(token)),
		...(init.nonce ? { nonce: init.nonce } : {}),
	})
		.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
		.sign(keys.privateKey);
}

export async function makeAuth(confirmation?: AgentConfirmationConfig): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 1000,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
			...(confirmation && { confirmation }),
		},
		auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
	});
}

export async function boundAgent(
	auth: TheAuth,
	cnf: Record<string, string> | undefined,
	owner = "alice",
) {
	await seedUser(auth, owner);
	return auth.agent.create({
		ownerId: owner,
		name: "bound",
		type: "autonomous",
		permissions: PERMS,
		...(cnf && { cnf }),
	});
}

export async function codeOf(res: Response): Promise<string | undefined> {
	const body = (await res.json()) as { data?: { code?: string }; error?: string };
	return body.data?.code ?? body.error;
}
