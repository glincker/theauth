import * as jose from "jose";
import type { OidcProviderContext } from "./oidc-provider-types.js";

/** Signing key and public JWK accessors for the OIDC provider (lazily imported and cached). */
export function createOidcKeys(ctx: Pick<OidcProviderContext, "config" | "signingAlg">) {
	const { config, signingAlg } = ctx;

	let signingKeyPromise: Promise<CryptoKey> | undefined;
	let publicJwkPromise: Promise<jose.JWK> | undefined;

	async function getSigningKey(): Promise<CryptoKey> {
		if (!signingKeyPromise) {
			signingKeyPromise = (async () => {
				if (config.signingKey instanceof CryptoKey) {
					return config.signingKey;
				}
				const imported = await jose.importJWK(config.signingKey as jose.JWK, signingAlg);
				return imported as CryptoKey;
			})();
		}
		return signingKeyPromise;
	}

	async function getPublicJwk(): Promise<jose.JWK> {
		if (!publicJwkPromise) {
			publicJwkPromise = (async () => {
				let jwk: jose.JWK;
				if (config.signingKey instanceof CryptoKey) {
					jwk = await jose.exportJWK(config.signingKey);
				} else {
					jwk = { ...(config.signingKey as jose.JWK) };
				}
				const { d, p, q, dp, dq, qi, k, ...publicComponents } = jwk;
				return { ...publicComponents, alg: signingAlg, use: "sig", kid: "theauth-oidc-1" };
			})();
		}
		return publicJwkPromise;
	}

	return {
		getSigningKey,
		getPublicJwk,
	};
}
