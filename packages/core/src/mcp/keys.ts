import type { JWK, JWTPayload, JWTVerifyGetKey } from "jose";
import {
	createLocalJWKSet,
	decodeProtectedHeader,
	exportJWK,
	generateKeyPair,
	importJWK,
	jwtVerify,
} from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { McpAsymmetricAlg, McpAuthContext } from "./types.js";

/**
 * Signing key material for the MCP authorization server.
 *
 * HS256 with `signingSecret` stays the default. Setting `config.signing` opts
 * in to asymmetric signing (ES256 or EdDSA): access tokens carry a `kid`
 * header, public keys are served from the JWKS endpoint, and the previous
 * key(s) stay published and accepted while old tokens age out.
 */

export interface McpSigningKeyPair {
	kid: string;
	alg: McpAsymmetricAlg;
	/** Private JWK, keep secret. */
	privateKey: JWK;
	/** Public JWK with `kid`, `alg` and `use` set. */
	publicKey: JWK;
}

/** Generate a fresh signing key pair. Persist `privateKey` in your secret store. */
export async function generateMcpSigningKey(
	alg: McpAsymmetricAlg,
	kid: string = generateId(),
): Promise<McpSigningKeyPair> {
	const pair =
		alg === "ES256"
			? await generateKeyPair("ES256", { extractable: true })
			: await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
	const privateKey = await exportJWK(pair.privateKey);
	const publicKey = await exportJWK(pair.publicKey);
	return {
		kid,
		alg,
		privateKey: { ...privateKey, kid, alg },
		publicKey: { ...publicKey, kid, alg, use: "sig" },
	};
}

/** Strip private members from a JWK and stamp `kid`, `alg` and `use`. */
export function toPublicJwk(jwk: JWK, kid: string, alg: McpAsymmetricAlg): JWK {
	const pub: JWK = { kty: jwk.kty, kid, alg, use: "sig" };
	if (jwk.crv !== undefined) pub.crv = jwk.crv;
	if (jwk.x !== undefined) pub.x = jwk.x;
	if (jwk.y !== undefined) pub.y = jwk.y;
	return pub;
}

interface ResolvedSigning {
	alg: McpAsymmetricAlg;
	kid: string;
	privateKey: CryptoKey | Uint8Array;
	jwks: { keys: JWK[] };
	getKey: JWTVerifyGetKey;
}

const cache = new WeakMap<object, Promise<ResolvedSigning>>();

async function resolve(signing: NonNullable<McpAuthContext["config"]["signing"]>) {
	const { alg, current, previous = [] } = signing;
	const privateKey = await importJWK(current.privateKey, alg);
	const keys: JWK[] = [toPublicJwk(current.privateKey, current.kid, alg)];
	for (const prev of previous) {
		if (prev.kid === current.kid) continue;
		keys.push(toPublicJwk(prev.publicKey, prev.kid, alg));
	}
	const jwks = { keys };
	return { alg, kid: current.kid, privateKey, jwks, getKey: createLocalJWKSet(jwks) };
}

function load(ctx: McpAuthContext): Promise<ResolvedSigning> | null {
	const signing = ctx.config.signing;
	if (!signing) return null;
	let entry = cache.get(signing);
	if (!entry) {
		entry = resolve(signing);
		cache.set(signing, entry);
	}
	return entry;
}

/** True when asymmetric signing is configured. */
export function usesAsymmetricSigning(ctx: McpAuthContext): boolean {
	return ctx.config.signing !== undefined;
}

/** Signing material for new tokens, or null when HS256 is in use. */
export async function getAsymmetricSigner(
	ctx: McpAuthContext,
): Promise<{ alg: McpAsymmetricAlg; kid: string; key: CryptoKey | Uint8Array } | null> {
	const loaded = load(ctx);
	if (!loaded) return null;
	const r = await loaded;
	return { alg: r.alg, kid: r.kid, key: r.privateKey };
}

/** Public JWKS document (RFC 7517), current key first, then previous keys. */
export async function getJwks(ctx: McpAuthContext): Promise<{ keys: JWK[] }> {
	const loaded = load(ctx);
	if (!loaded) return { keys: [] };
	return (await loaded).jwks;
}

/**
 * Verify an access token JWT and return its payload. Tokens whose header says
 * HS256 are checked with the shared secret (only when one is configured);
 * everything else goes through the JWKS, which pins the algorithm to the
 * configured one. Throws a jose error on any failure.
 */
export async function verifyAccessJwt(
	ctx: McpAuthContext,
	token: string,
	options: { audience?: string } = {},
): Promise<JWTPayload> {
	let header: { alg?: string };
	try {
		header = decodeProtectedHeader(token);
	} catch {
		throw new Error("Malformed token");
	}
	const common = {
		issuer: ctx.config.issuer,
		...(options.audience ? { audience: options.audience } : {}),
	};
	if (header.alg === "HS256") {
		const secret = ctx.config.signingSecret;
		if (!secret) throw new Error("HS256 tokens are not accepted by this server");
		const key = await globalThis.crypto.subtle.importKey(
			"raw",
			new TextEncoder().encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["verify"],
		);
		return (await jwtVerify(token, key, { ...common, algorithms: ["HS256"] })).payload;
	}
	const loaded = load(ctx);
	if (!loaded) throw new Error("Unsupported token algorithm");
	const r = await loaded;
	if (header.alg !== r.alg) throw new Error("Unsupported token algorithm");
	return (await jwtVerify(token, r.getKey, { ...common, algorithms: [r.alg] })).payload;
}
