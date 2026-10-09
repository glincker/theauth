import type { JSONWebKeySet, JWTPayload } from "jose";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import type { Result } from "./types.js";
import { err, ok } from "./types.js";

export interface ExternalIssuerConfig {
	/** Short label used as the source name in the ledger, e.g. "auth0". */
	name: string;
	/** Exact `iss` value the token must carry. */
	issuer: string;
	/** Required `aud`. A token matching any one is accepted. */
	audience: string | string[];
	/** Defaults to `<issuer>/.well-known/jwks.json`. */
	jwksUri?: string;
	/** Default ["RS256"]. Symmetric algorithms and "none" are refused. */
	algorithms?: string[];
	/** Seconds of clock skew allowed on exp and nbf. Default 30. */
	clockToleranceSec?: number;
	/** How long a fetched key set is trusted. Default 600 seconds. */
	jwksTtlSec?: number;
	/** Minimum gap between refetches triggered by an unknown kid. Default 30 seconds. */
	refetchCooldownSec?: number;
	/** Allow http:// JWKS for local development only. */
	allowInsecureJwks?: boolean;
	/** Replace fetch, e.g. for tests or a proxy. */
	fetch?: (url: string) => Promise<Response>;
}

export interface ExternalIdentity {
	issuer: string;
	subject: string;
	email: string | null;
	emailVerified: boolean;
	name: string | null;
	expiresAt: Date;
}

const FORBIDDEN_ALG = /^(none|HS\d+)$/i;

/** Presets with the issuer and JWKS URL shapes each provider uses. */
export const issuerPresets = {
	auth0: (domain: string, audience: string): ExternalIssuerConfig => ({
		name: "auth0",
		issuer: `https://${domain}/`,
		audience,
		jwksUri: `https://${domain}/.well-known/jwks.json`,
	}),
	keycloak: (baseUrl: string, realm: string, audience: string): ExternalIssuerConfig => ({
		name: "keycloak",
		issuer: `${baseUrl.replace(/\/$/, "")}/realms/${realm}`,
		audience,
		jwksUri: `${baseUrl.replace(/\/$/, "")}/realms/${realm}/protocol/openid-connect/certs`,
	}),
	clerk: (frontendApi: string, audience: string): ExternalIssuerConfig => ({
		name: "clerk",
		issuer: `https://${frontendApi}`,
		audience,
		jwksUri: `https://${frontendApi}/.well-known/jwks.json`,
	}),
};

interface KeyCache {
	set: ReturnType<typeof createLocalJWKSet> | null;
	keys: JSONWebKeySet | null;
	fetchedAt: number;
}

export function validateIssuerConfig(c: ExternalIssuerConfig): string | null {
	if (!c.name || !c.issuer) return "name and issuer are required";
	const aud = Array.isArray(c.audience) ? c.audience : [c.audience];
	if (aud.length === 0 || aud.some((a) => !a)) return "audience is required (pin it)";
	for (const a of c.algorithms ?? ["RS256"]) {
		if (FORBIDDEN_ALG.test(a)) return `algorithm ${a} is not allowed`;
	}
	const uri = c.jwksUri ?? `${c.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
	if (!uri.startsWith("https://") && !(c.allowInsecureJwks && uri.startsWith("http://"))) {
		return "jwksUri must be https";
	}
	return null;
}

/**
 * Verify tokens from an incumbent IdP. The issuer is chosen by exact match on `iss`,
 * then signature, audience, expiry and algorithm are checked against that issuer only.
 * Keys are cached, and an unknown `kid` triggers one rate-limited refetch so rotation works.
 */
export function createExternalIssuers(
	issuers: ExternalIssuerConfig[],
	options: { now?: () => number } = {},
) {
	const now = options.now ?? (() => Date.now());
	const byIssuer = new Map<string, ExternalIssuerConfig>();
	const caches = new Map<string, KeyCache>();
	const lastRefetch = new Map<string, number>();
	for (const c of issuers) {
		const problem = validateIssuerConfig(c);
		if (problem) throw new Error(`externalIssuers[${c.name}]: ${problem}`);
		byIssuer.set(c.issuer, c);
		caches.set(c.issuer, { set: null, keys: null, fetchedAt: 0 });
	}

	async function load(c: ExternalIssuerConfig, cache: KeyCache): Promise<void> {
		const uri = c.jwksUri ?? `${c.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
		const res = await (c.fetch ?? ((u: string) => fetch(u)))(uri);
		if (!res.ok) throw new Error("jwks fetch failed");
		const keys = (await res.json()) as JSONWebKeySet;
		if (!Array.isArray(keys.keys)) throw new Error("jwks malformed");
		cache.keys = keys;
		cache.set = createLocalJWKSet(keys);
		cache.fetchedAt = now();
	}

	function hasKid(cache: KeyCache, kid: string | undefined): boolean {
		if (!kid) return true;
		return cache.keys?.keys.some((k) => k.kid === kid) ?? false;
	}

	async function verify(token: string): Promise<Result<ExternalIdentity>> {
		let iss: string | undefined;
		let kid: string | undefined;
		try {
			iss = decodeJwt(token).iss;
			const header = JSON.parse(
				atob(token.split(".")[0]?.replace(/-/g, "+").replace(/_/g, "/") ?? ""),
			) as {
				kid?: string;
			};
			kid = header.kid;
		} catch {
			return err("TOKEN_MALFORMED", "Token could not be decoded");
		}
		const config = iss ? byIssuer.get(iss) : undefined;
		const cache = iss ? caches.get(iss) : undefined;
		if (!config || !cache) return err("ISSUER_NOT_ALLOWED", "Issuer is not configured");

		try {
			const ttl = (config.jwksTtlSec ?? 600) * 1000;
			const stale = cache.set === null || now() - cache.fetchedAt > ttl;
			if (stale) await load(config, cache);
			else if (!hasKid(cache, kid)) {
				const cooldown = (config.refetchCooldownSec ?? 30) * 1000;
				if (now() - (lastRefetch.get(config.issuer) ?? 0) >= cooldown) {
					lastRefetch.set(config.issuer, now());
					await load(config, cache);
				}
			}
			if (!cache.set) return err("JWKS_UNAVAILABLE", "No signing keys available");
			const { payload } = await jwtVerify(token, cache.set, {
				issuer: config.issuer,
				audience: config.audience,
				algorithms: config.algorithms ?? ["RS256"],
				clockTolerance: config.clockToleranceSec ?? 30,
				currentDate: new Date(now()),
				requiredClaims: ["exp", "sub", "iss"],
			});
			return ok(identityFrom(config, payload));
		} catch (e) {
			const code = e instanceof Error && "code" in e ? String((e as { code: unknown }).code) : "";
			if (code === "ERR_JWT_EXPIRED") return err("TOKEN_EXPIRED", "Token expired");
			if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED")
				return err("CLAIM_REJECTED", "Issuer or audience mismatch");
			if (code === "ERR_JOSE_ALG_NOT_ALLOWED") return err("ALG_REJECTED", "Algorithm not allowed");
			if (code === "ERR_JWKS_NO_MATCHING_KEY")
				return err("KEY_NOT_FOUND", "No matching signing key");
			if (code.startsWith("ERR_JWS")) return err("SIGNATURE_INVALID", "Signature check failed");
			return err("TOKEN_REJECTED", "Token rejected");
		}
	}

	return { verify, issuerFor: (iss: string) => byIssuer.get(iss)?.name ?? null };
}

function identityFrom(c: ExternalIssuerConfig, p: JWTPayload): ExternalIdentity {
	const s = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);
	return {
		issuer: c.name,
		subject: p.sub as string,
		email: s(p.email)?.toLowerCase() ?? null,
		emailVerified: p.email_verified === true,
		name: s(p.name),
		expiresAt: new Date((p.exp as number) * 1000),
	};
}

export type ExternalIssuers = ReturnType<typeof createExternalIssuers>;
