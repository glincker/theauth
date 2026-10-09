import type { SecondaryStorage } from "../storage/types.js";

/** JWS algorithms accepted for DPoP proofs. Asymmetric only, never `none` or HMAC. */
export type DpopAlg = "ES256" | "ES384" | "EdDSA" | "PS256";

/** DPoP (RFC 9449) settings for the MCP authorization server and resource server. */
export interface McpDpopConfig {
	/** Accepted proof algorithms. Default: ES256, ES384, EdDSA, PS256. */
	algs?: DpopAlg[];
	/**
	 * Refuse token requests that carry no DPoP proof, so every issued token is
	 * bound, and refuse unbound tokens at the resource server. Default false.
	 */
	required?: boolean;
	/** Oldest accepted proof `iat`, in seconds. Default 300. */
	proofMaxAgeSeconds?: number;
	/** Clock skew allowed in either direction, in seconds. Default 30. */
	clockSkewSeconds?: number;
	/**
	 * Demand a server-issued nonce in every proof (RFC 9449 section 8 and 9).
	 * Missing or stale nonces get `use_dpop_nonce` plus a `DPoP-Nonce` header.
	 */
	requireNonce?: boolean;
	/** Lifetime of an issued nonce, in seconds. Default 300. */
	nonceTtlSeconds?: number;
	/**
	 * Store for the `jti` replay cache and nonces. Pass
	 * `theauth.storage.for("nonces")` so replay protection is shared across
	 * instances. Defaults to an in-process store (single instance only).
	 */
	storage?: SecondaryStorage;
	/**
	 * The `htu` clients sign for the token endpoint. Default is
	 * `<baseUrl>/mcp/token`, the value published as `token_endpoint`.
	 */
	tokenEndpointUrl?: string;
}
