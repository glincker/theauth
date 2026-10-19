/**
 * SPIFFE ID parsing. Rules from the SPIFFE ID specification (SPIFFE-ID.md) sections 2 to 2.4:
 * scheme `spiffe`, a lowercase trust domain of [a-z0-9.-_], an optional path of non empty segments of
 * [A-Za-z0-9.-_] (no "." or ".." segment, no trailing slash), no userinfo, port, query, fragment or
 * percent encoding, at most 2048 bytes. The spec treats scheme and trust domain as case insensitive
 * when parsing; we refuse an upper case scheme or host instead of folding it, so one workload never
 * has two spellings in a lookup table.
 */
export const MAX_SPIFFE_ID_BYTES = 2048;
const MAX_TRUST_DOMAIN_BYTES = 255;
const TRUST_DOMAIN = /^[a-z0-9._-]+$/;
const SEGMENT = /^[A-Za-z0-9._-]+$/;
const PREFIX = "spiffe://";

export interface SpiffeId {
	/** The whole id, for example `spiffe://example.org/ns/prod/sa/robot`. */
	id: string;
	trustDomain: string;
	/** Empty for a trust domain id, otherwise starts with "/". */
	path: string;
}

export type SpiffeIdResult = ({ ok: true } & SpiffeId) | { ok: false; reason: string };

export function parseSpiffeId(input: string): SpiffeIdResult {
	if (typeof input !== "string") return { ok: false, reason: "SPIFFE ID is not a string" };
	if (input.length > MAX_SPIFFE_ID_BYTES) return { ok: false, reason: "SPIFFE ID is too long" };
	// RFC 3986 allows only ASCII, so a non ASCII byte can never be part of a valid id.
	for (let i = 0; i < input.length; i++) {
		const c = input.charCodeAt(i);
		if (c < 0x21 || c > 0x7e)
			return { ok: false, reason: "SPIFFE ID has a non printable or non ASCII character" };
	}
	if (!input.startsWith(PREFIX))
		return { ok: false, reason: 'SPIFFE ID scheme must be lowercase "spiffe"' };
	const rest = input.slice(PREFIX.length);
	if (/[?#]/.test(rest))
		return { ok: false, reason: "SPIFFE ID must not have a query or fragment" };
	const slash = rest.indexOf("/");
	const trustDomain = slash === -1 ? rest : rest.slice(0, slash);
	const path = slash === -1 ? "" : rest.slice(slash);
	if (trustDomain === "") return { ok: false, reason: "SPIFFE ID has an empty trust domain" };
	if (trustDomain.length > MAX_TRUST_DOMAIN_BYTES)
		return { ok: false, reason: "Trust domain is too long" };
	if (/[@:%]/.test(trustDomain)) {
		return { ok: false, reason: "Trust domain must not have userinfo, a port or percent encoding" };
	}
	if (!TRUST_DOMAIN.test(trustDomain)) {
		return {
			ok: false,
			reason:
				"Trust domain may only contain lowercase letters, digits, dots, dashes and underscores",
		};
	}
	if (path !== "") {
		const segments = path.slice(1).split("/");
		for (const s of segments) {
			if (s === "") return { ok: false, reason: "SPIFFE ID path has an empty segment" };
			if (s === "." || s === "..") return { ok: false, reason: "SPIFFE ID path has a dot segment" };
			if (!SEGMENT.test(s))
				return { ok: false, reason: "SPIFFE ID path has a character outside [A-Za-z0-9._-]" };
		}
	}
	return { ok: true, id: input, trustDomain, path };
}

/** Normalize a configured trust domain name: accepts `example.org` or `spiffe://example.org`. */
export function parseTrustDomain(input: string): string | null {
	const parsed = parseSpiffeId(input.startsWith(PREFIX) ? input : `${PREFIX}${input}`);
	return parsed.ok && parsed.path === "" ? parsed.trustDomain : null;
}
