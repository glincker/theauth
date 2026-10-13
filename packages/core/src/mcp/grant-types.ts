import type { JWK } from "jose";
import type { SecondaryStorage } from "../storage/types.js";
import type { DnsResolver } from "./safe-fetch.js";
import type { McpClient } from "./types.js";

// Identifiers

export const GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
/** RFC 8693 */
export const GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
/** RFC 7523 */
export const GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** RFC 8693 section 3 */
export const TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
/** RFC 7523 section 2.2 */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/** JOSE `typ` of an Identity Assertion JWT Authorization Grant (ID-JAG). */
export const ID_JAG_TYP = "oauth-id-jag+jwt";
/** Default cap on nested `act` hops produced by token exchange. */
export const DEFAULT_MAX_CHAIN_DEPTH = 3;

// Lenient client compatibility

/**
 * Compatibility switches for real-world MCP clients that bend the strict
 * rules. Every switch is off unless set.
 */
export interface McpLenientClientsConfig {
	/**
	 * A missing `resource` defaults to the sole configured resource
	 * (`allowedResources` when set, else `resource`). With zero or several
	 * configured resources the request fails with `invalid_target`.
	 */
	optionalResource?: boolean;
	/**
	 * Unsupported scopes are dropped instead of failing the request. The granted
	 * scope is returned in the token response. `invalid_scope` only when scopes
	 * were requested and none remain.
	 */
	dropUnknownScopes?: boolean;
	/**
	 * A registered `http://127.0.0.1` or `http://[::1]` redirect URI matches a
	 * request that differs only by port (RFC 8252 section 7.3). Scheme, host,
	 * path and query stay exact.
	 */
	loopbackAnyPort?: boolean;
	/** Also treat `http://localhost` as loopback for `loopbackAnyPort`. */
	loopbackAllowLocalhost?: boolean;
	/**
	 * A requested `resource` matches a configured one when equal modulo a
	 * trailing slash, or when the configured one is a path prefix on a `/`
	 * boundary. Issued tokens carry the configured canonical resource as `aud`.
	 */
	pathAudience?: boolean;
}

// client_credentials

/** The principal a client_credentials token acts as. */
export interface McpClientPrincipal {
	/** Becomes the token `sub`. */
	subject: string;
	/** Emitted as `agent_id` when set. */
	agentId?: string;
	agentType?: "autonomous" | "delegated" | "supervised";
	trustTier?: "unverified" | "low" | "standard" | "elevated" | "high";
	/**
	 * Upper bound on scopes this principal may receive. Falls back to the
	 * client's registered `scope`. With neither, the request is refused.
	 */
	scopes?: string[];
}

export interface McpClientCredentialsConfig {
	enabled: boolean;
	/**
	 * Map an authenticated confidential client to the agent or service principal
	 * it acts as. Return null to refuse. Required: without a mapping no client
	 * can obtain a token, so open dynamic registration is never enough by itself.
	 */
	resolvePrincipal: (client: McpClient) => Promise<McpClientPrincipal | null>;
}

// RFC 8693 token exchange

export interface McpTokenExchangeInput {
	client: McpClient;
	subject: { userId: string; clientId: string; scopes: string[]; resource: string | null };
	actor: { userId: string; clientId: string } | null;
	scopes: string[];
	resource: string | null;
}

export interface McpTokenExchangeConfig {
	enabled: boolean;
	/** Maximum nested `act` hops on an issued token. Default 3. */
	maxChainDepth?: number;
	/** Extra policy gate. Return false to refuse with `access_denied`. Default allows. */
	authorize?: (input: McpTokenExchangeInput) => Promise<boolean>;
}

// RFC 7523 jwt-bearer and ID-JAG

export interface McpTrustedIssuer {
	/** Exact `iss` value of assertions from this issuer. */
	issuer: string;
	/** HTTPS JWKS URL, fetched through the SSRF-safe fetcher. */
	jwksUri?: string;
	/** Static keys, used instead of or before `jwksUri`. */
	jwks?: { keys: JWK[] };
}

export interface McpJwtBearerSubjectInput {
	issuer: string;
	subject: string;
	clientId: string;
	scopes: string[];
	claims: Record<string, unknown>;
}

export interface McpJwtBearerConfig {
	enabled: boolean;
	trustedIssuers: McpTrustedIssuer[];
	/** Map the assertion subject to a local user id. Return null to refuse. */
	mapSubject: (input: McpJwtBearerSubjectInput) => Promise<string | null>;
	/** Accepted JWS algorithms. Default ES256, ES384, EdDSA, PS256, RS256. */
	algs?: string[];
	/** Longest accepted `exp - iat` in seconds. Default 300. */
	maxLifetimeSeconds?: number;
	/** Clock skew in seconds. Default 30. */
	clockSkewSeconds?: number;
	/** DNS resolver override for JWKS fetches. */
	resolver?: DnsResolver;
	/** Fetch override for JWKS fetches. */
	fetchImpl?: typeof fetch;
}

/** Shared storage option type, re-exported for config docs. */
export type McpAssertionStorage = SecondaryStorage;
