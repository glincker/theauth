import type { JWK } from "jose";
import { toHex } from "../crypto/web-crypto.js";
import type { HostPolicy } from "./cimd-url.js";
import { screenHostname } from "./cimd-url.js";
import type { McpClient } from "./types.js";
import type { McpClientCimdSnapshot } from "./types-cimd.js";

/**
 * Strict validator for a fetched Client ID Metadata Document. Every rule fails closed: a document
 * that breaks one is never turned into a client. Unknown members are ignored (RFC 7591) except
 * the ones that would change trust if silently dropped.
 */

export type CimdDocumentResult =
	| { ok: true; client: McpClient; digest: string }
	| { ok: false; field: string; message: string };

export interface CimdValidateOptions {
	/** Fetch time. Default: now. */
	now?: Date;
	/** Seconds the snapshot stays fresh. Default 3600. */
	cacheSeconds?: number;
	/** Only `deniedHosts` is used (for the jwks_uri host). */
	hostPolicy?: HostPolicy;
}

export const CIMD_MAX_TOP_LEVEL_KEYS = 64;
export const CIMD_MAX_REDIRECT_URIS = 10;
export const CIMD_MAX_URI_LENGTH = 2048;
export const CIMD_MAX_JWKS_KEYS = 10;
const MAX_CLIENT_NAME = 200;
const MAX_SCOPE = 1024;
const MAX_CONTACTS = 5;
const MAX_CONTACT_LENGTH = 254;
const MAX_SOFTWARE_FIELD = 255;
const MAX_KID = 256;
const MAX_NESTED_DEPTH = 8;
const DEFAULT_CACHE_SECONDS = 3600;

/** Members that only exist on private or symmetric JWKs. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const JWK_KEY_TYPES = new Set(["EC", "OKP", "RSA"]);
const ALLOWED_GRANTS = new Set(["authorization_code", "refresh_token"]);
const LOOPBACK_REDIRECT_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Compared after lowercasing and removing `_` and `-`, so `Agent-Id` and `agentId` are caught too. */
const FORBIDDEN_MEMBERS = new Set([
	"clientsecret",
	"clientsecretexpiresat",
	"registrationaccesstoken",
	"registrationclienturi",
	"agentid",
	"agent",
	"admin",
	"disabled",
	"disabledreason",
	"userid",
	"source",
	"clienttype",
	"crit",
]);

type Fail = { ok: false; field: string; message: string };
const fail = (field: string, message: string): Fail => ({ ok: false, field, message });

function isRecord(v: unknown): v is Record<string, unknown> {
	if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
	const proto = Object.getPrototypeOf(v) as unknown;
	return proto === Object.prototype || proto === null;
}

function normalizeMember(key: string): string {
	return key.toLowerCase().replace(/[_-]/g, "");
}

function isUnsafeChar(code: number): boolean {
	return (
		code <= 0x1f ||
		(code >= 0x7f && code <= 0x9f) ||
		(code >= 0x200b && code <= 0x200f) ||
		(code >= 0x2028 && code <= 0x202e) ||
		(code >= 0x2060 && code <= 0x2069) ||
		code === 0xfeff
	);
}

/** True when `value` holds C0 or C1 controls, whitespace or separators that must not appear in a URI. */
function hasUnsafeChar(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (isUnsafeChar(code) || code === 0x20 || code === 0xa0) return true;
	}
	return false;
}

/** Drops C0, C1 controls, bidi embeddings, overrides and isolates, zero width and line separators. */
function cleanText(value: string): string {
	let out = "";
	for (let i = 0; i < value.length; i++) {
		if (!isUnsafeChar(value.charCodeAt(i))) out += value.charAt(i);
	}
	return out.trim();
}

function depthOk(value: unknown, depth = 0): boolean {
	if (depth > MAX_NESTED_DEPTH) return false;
	if (Array.isArray(value)) return value.every((v) => depthOk(v, depth + 1));
	if (typeof value === "object" && value !== null) {
		return Object.values(value).every((v) => depthOk(v, depth + 1));
	}
	return true;
}

function stringList(value: unknown, field: string, max: number, itemMax: number): string[] | Fail {
	if (!Array.isArray(value)) return fail(field, `${field} must be an array of strings`);
	if (value.length === 0 || value.length > max) {
		return fail(field, `${field} must hold 1 to ${max} entries`);
	}
	for (const item of value) {
		if (typeof item !== "string" || item === "" || item.length > itemMax) {
			return fail(
				field,
				`${field} entries must be non-empty strings of at most ${itemMax} characters`,
			);
		}
	}
	return value as string[];
}

function validRedirectUri(uri: string): boolean {
	if (hasUnsafeChar(uri) || uri.includes("\\") || uri.includes("*") || uri.includes("#"))
		return false;
	let u: URL;
	try {
		u = new URL(uri);
	} catch {
		return false;
	}
	if (u.username || u.password || u.hash) return false;
	if (u.protocol === "https:") return u.hostname !== "";
	return u.protocol === "http:" && LOOPBACK_REDIRECT_HOSTS.has(u.hostname);
}

function optionalUri(value: unknown, field: string): string | null | Fail {
	if (value === undefined || value === null) return null;
	if (typeof value !== "string") return fail(field, `${field} must be a string`);
	if (value.length > CIMD_MAX_URI_LENGTH) return null;
	try {
		const u = new URL(value);
		if (u.protocol !== "https:" || u.username || u.password) return null;
		return value;
	} catch {
		return null;
	}
}

function optionalText(value: unknown, field: string, max: number): string | null | Fail {
	if (value === undefined || value === null) return null;
	if (typeof value !== "string") return fail(field, `${field} must be a string`);
	const cleaned = cleanText(value);
	if (cleaned.length > max) return fail(field, `${field} is too long`);
	return cleaned === "" ? null : cleaned;
}

function validateJwks(value: unknown): { keys: JWK[] } | Fail {
	if (!isRecord(value) || !Array.isArray(value.keys)) return fail("jwks", "jwks must hold keys");
	const keys = value.keys as unknown[];
	if (keys.length === 0 || keys.length > CIMD_MAX_JWKS_KEYS) {
		return fail("jwks", `jwks must hold 1 to ${CIMD_MAX_JWKS_KEYS} keys`);
	}
	const kids = new Set<string>();
	for (const key of keys) {
		if (!isRecord(key)) return fail("jwks", "jwks keys must be objects");
		if (PRIVATE_JWK_MEMBERS.some((m) => m in key))
			return fail("jwks", "jwks must hold public keys");
		if (typeof key.kty !== "string" || !JWK_KEY_TYPES.has(key.kty)) {
			return fail("jwks", "jwks key type must be EC, OKP or RSA");
		}
		if (key.kid !== undefined) {
			if (typeof key.kid !== "string" || key.kid.length > MAX_KID) {
				return fail("jwks", "jwks kid must be a short string");
			}
			if (kids.has(key.kid)) return fail("jwks", "jwks kid values must be unique");
			kids.add(key.kid);
		}
	}
	return { keys: keys as JWK[] };
}

function validateJwksUri(value: unknown, policy: HostPolicy | undefined): string | Fail {
	if (typeof value !== "string" || value.length > CIMD_MAX_URI_LENGTH) {
		return fail("jwks_uri", "jwks_uri must be an https URL");
	}
	let u: URL;
	try {
		u = new URL(value);
	} catch {
		return fail("jwks_uri", "jwks_uri must be an https URL");
	}
	if (u.protocol !== "https:" || u.username || u.password || u.hash) {
		return fail("jwks_uri", "jwks_uri must be an https URL without credentials or fragment");
	}
	if (u.port && u.port !== "443") return fail("jwks_uri", "jwks_uri must use the default port");
	// The same host policy as the client_id: an allow list is the only full guarantee, so a
	// document on an allowed host cannot point the server at any other host.
	const screened = screenHostname(u.hostname, {
		...(policy?.deniedHosts ? { deniedHosts: policy.deniedHosts } : {}),
		...(policy?.allowedHosts ? { allowedHosts: policy.allowedHosts } : {}),
	});
	if (!screened.ok) return fail("jwks_uri", "jwks_uri host is not allowed");
	return value;
}

function stableStringify(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
	if (typeof value === "object" && value !== null) {
		const rec = value as Record<string, unknown>;
		return `{${Object.keys(rec)
			.sort()
			.filter((k) => rec[k] !== undefined)
			.map((k) => `${JSON.stringify(k)}:${stableStringify(rec[k])}`)
			.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

/** SHA-256 hex over the trust relevant members. Drives change detection on refresh. */
export async function computeCimdDigest(parts: {
	redirectUris: string[];
	tokenEndpointAuthMethod: string;
	jwks?: { keys: JWK[] };
	jwksUri?: string;
	grantTypes: string[];
}): Promise<string> {
	const canonical = stableStringify({
		redirect_uris: parts.redirectUris,
		token_endpoint_auth_method: parts.tokenEndpointAuthMethod,
		jwks: parts.jwks,
		jwks_uri: parts.jwksUri,
		grant_types: parts.grantTypes,
	});
	const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
	return toHex(new Uint8Array(hash));
}

/** Builds the stored snapshot. The raw document is kept as fetched. */
export function buildCimdSnapshot(
	document: Record<string, unknown>,
	digest: string,
	fetchedAt: Date,
	cacheSeconds: number,
): McpClientCimdSnapshot {
	return {
		digest,
		fetchedAt,
		expiresAt: new Date(fetchedAt.getTime() + cacheSeconds * 1000),
		document,
	};
}

/** Validate `doc` (parsed JSON fetched from `clientId`) and build the client. */
export async function validateCimdDocument(
	clientId: string,
	doc: unknown,
	options: CimdValidateOptions = {},
): Promise<CimdDocumentResult> {
	if (!isRecord(doc)) return fail("document", "document must be a JSON object");
	const keys = Object.keys(doc);
	if (keys.length > CIMD_MAX_TOP_LEVEL_KEYS)
		return fail("document", "document has too many members");
	if (!depthOk(doc)) return fail("document", "document is nested too deeply");
	for (const key of keys) {
		const n = normalizeMember(key);
		if (
			key === "__proto__" ||
			FORBIDDEN_MEMBERS.has(n) ||
			n.startsWith("clientsecret") ||
			n.startsWith("theauth") ||
			n.startsWith("xtheauth")
		) {
			return fail(key, "document contains a member that is not allowed");
		}
	}

	// The document must name itself. This is the core CIMD binding.
	if (doc.client_id !== clientId)
		return fail("client_id", "client_id does not match the document URL");

	const redirects = stringList(
		doc.redirect_uris,
		"redirect_uris",
		CIMD_MAX_REDIRECT_URIS,
		CIMD_MAX_URI_LENGTH,
	);
	if (!Array.isArray(redirects)) return redirects;
	if (!redirects.every(validRedirectUri))
		return fail("redirect_uris", "redirect_uris holds an invalid URI");
	if (new Set(redirects).size !== redirects.length) {
		return fail("redirect_uris", "redirect_uris must not repeat");
	}

	const method = doc.token_endpoint_auth_method;
	if (method !== undefined && method !== "none" && method !== "private_key_jwt") {
		return fail("token_endpoint_auth_method", "only none and private_key_jwt are supported");
	}
	const privateKey = method === "private_key_jwt";
	let jwks: { keys: JWK[] } | undefined;
	let jwksUri: string | undefined;
	if (privateKey) {
		if ((doc.jwks === undefined) === (doc.jwks_uri === undefined)) {
			return fail("jwks", "private_key_jwt needs exactly one of jwks or jwks_uri");
		}
		if (doc.jwks !== undefined) {
			const checked = validateJwks(doc.jwks);
			if ("ok" in checked) return checked;
			jwks = checked;
		} else {
			const checked = validateJwksUri(doc.jwks_uri, options.hostPolicy);
			if (typeof checked !== "string") return checked;
			jwksUri = checked;
		}
	} else if (doc.jwks !== undefined || doc.jwks_uri !== undefined) {
		return fail("jwks", "jwks and jwks_uri need token_endpoint_auth_method private_key_jwt");
	}

	let grantTypes = ["authorization_code", "refresh_token"];
	if (doc.grant_types !== undefined) {
		const grants = stringList(doc.grant_types, "grant_types", ALLOWED_GRANTS.size, 64);
		if (!Array.isArray(grants)) return grants;
		if (!grants.every((g) => ALLOWED_GRANTS.has(g)) || new Set(grants).size !== grants.length) {
			return fail("grant_types", "grant_types may only hold authorization_code and refresh_token");
		}
		if (!grants.includes("authorization_code")) {
			return fail("grant_types", "grant_types must include authorization_code");
		}
		grantTypes = grants;
	}
	if (doc.response_types !== undefined) {
		const rt = doc.response_types;
		if (!Array.isArray(rt) || rt.length !== 1 || rt[0] !== "code") {
			return fail("response_types", 'response_types must be ["code"]');
		}
	}

	const name = optionalText(doc.client_name, "client_name", MAX_CLIENT_NAME);
	if (typeof name === "object" && name !== null) return name;
	const uris: Array<string | null> = [];
	for (const field of ["client_uri", "logo_uri", "tos_uri", "policy_uri"]) {
		const v = optionalUri(doc[field], field);
		if (typeof v === "object" && v !== null) return v;
		uris.push(v);
	}
	let scope: string | null = null;
	if (doc.scope !== undefined) {
		if (
			typeof doc.scope !== "string" ||
			doc.scope.length > MAX_SCOPE ||
			!/^[\x21\x23-\x5b\x5d-\x7e]+( [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(doc.scope)
		) {
			return fail("scope", "scope must be space separated tokens");
		}
		scope = doc.scope;
	}
	let contacts: string[] | null = null;
	if (doc.contacts !== undefined) {
		const list = stringList(doc.contacts, "contacts", MAX_CONTACTS, MAX_CONTACT_LENGTH);
		if (!Array.isArray(list)) return list;
		contacts = list.map(cleanText).filter((c) => c !== "");
	}
	const softwareId = optionalText(doc.software_id, "software_id", MAX_SOFTWARE_FIELD);
	if (typeof softwareId === "object" && softwareId !== null) return softwareId;
	const softwareVersion = optionalText(
		doc.software_version,
		"software_version",
		MAX_SOFTWARE_FIELD,
	);
	if (typeof softwareVersion === "object" && softwareVersion !== null) return softwareVersion;

	const authMethod = privateKey ? "private_key_jwt" : "none";
	const digest = await computeCimdDigest({
		redirectUris: redirects,
		tokenEndpointAuthMethod: authMethod,
		...(jwks ? { jwks } : {}),
		...(jwksUri ? { jwksUri } : {}),
		grantTypes,
	});
	const now = options.now ?? new Date();
	const snapshot = buildCimdSnapshot(
		doc,
		digest,
		now,
		options.cacheSeconds ?? DEFAULT_CACHE_SECONDS,
	);
	return {
		ok: true,
		digest,
		client: {
			clientId,
			clientSecret: null,
			clientName: name,
			clientUri: uris[0] ?? null,
			logoUri: uris[1] ?? null,
			redirectUris: redirects,
			grantTypes,
			responseTypes: ["code"],
			tokenEndpointAuthMethod: authMethod,
			scope,
			contacts,
			tosUri: uris[2] ?? null,
			policyUri: uris[3] ?? null,
			softwareId,
			softwareVersion,
			clientType: privateKey ? "confidential" : "public",
			disabled: false,
			disabledReason: null,
			userId: null,
			source: "cimd",
			...(jwks ? { jwks } : {}),
			...(jwksUri ? { jwksUri } : {}),
			cimd: snapshot,
			createdAt: now,
			updatedAt: now,
		},
	};
}
