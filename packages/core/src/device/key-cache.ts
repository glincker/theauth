import type { JWK, JWTVerifyGetKey } from "jose";
import { createLocalJWKSet, importJWK } from "jose";

/**
 * Key import caches for the device bundle and revocation snapshot paths.
 *
 * `createLocalJWKSet` imports a key on first use and keeps it per instance, so building a new one per call
 * re-imports the verification key every time. These caches key on the caller's object, but also on a JSON
 * fingerprint of its contents, so a JWKS or JWK that is changed in place (a rotation) is never served stale.
 */

interface Cached<T> {
	fingerprint: string;
	value: T;
}

const jwkSets = new WeakMap<object, Cached<JWTVerifyGetKey>>();
const signingKeys = new WeakMap<object, Cached<Promise<CryptoKey | Uint8Array>>>();

/** A key resolver over a local JWKS, reused while the same JWKS object keeps the same content. */
export function localJwkSet(jwks: { keys: JWK[] }): JWTVerifyGetKey {
	const fingerprint = JSON.stringify(jwks.keys);
	const hit = jwkSets.get(jwks);
	if (hit && hit.fingerprint === fingerprint) return hit.value;
	const value = createLocalJWKSet(jwks);
	jwkSets.set(jwks, { fingerprint, value });
	return value;
}

/** An imported private key, reused while the same JWK object keeps the same content and algorithm. */
export function importSigningKey(jwk: JWK, alg: string): Promise<CryptoKey | Uint8Array> {
	const fingerprint = `${alg}\n${JSON.stringify(jwk)}`;
	const hit = signingKeys.get(jwk);
	if (hit && hit.fingerprint === fingerprint) return hit.value;
	const value = importJWK(jwk, alg);
	signingKeys.set(jwk, { fingerprint, value });
	value.catch(() => {
		if (signingKeys.get(jwk)?.value === value) signingKeys.delete(jwk);
	});
	return value;
}
