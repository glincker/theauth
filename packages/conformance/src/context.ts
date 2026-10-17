import { createHash, randomBytes } from "node:crypto";
import type { HttpResult, JsonRecord } from "./http.js";
import { asRecord, asString, asStringArray, formBody, jsonBody, request } from "./http.js";
import type { Options } from "./types.js";

export interface Document {
	/** URL the document was fetched from. */
	url: string;
	body: JsonRecord;
}

export interface Discovery {
	as: Document | null;
	prm: Document | null;
	/** Every URL tried, with the status it returned. */
	tried: Array<{ url: string; status: number | string }>;
}

export interface RegisteredClient {
	clientId: string;
	redirectUri: string;
	source: "dcr" | "provided";
}

export interface ProtectedResource {
	url: string;
	response: HttpResult;
	explicit: boolean;
}

export type AuthorizeKind =
	| "rejected"
	| "rejected-redirect"
	| "code-issued"
	| "redirect-other"
	| "page"
	| "server-error";

export interface AuthorizeProbe {
	kind: AuthorizeKind;
	status: number;
	location: string | null;
	body: string;
}

export const DEFAULT_REDIRECT_URI = "https://conformance.example.test/callback";

function wellKnown(base: URL, suffix: string): string {
	const path = base.pathname === "/" ? "" : base.pathname.replace(/\/$/, "");
	return `${base.origin}/.well-known/${suffix}${path}`;
}

export function s256(verifier: string): string {
	return createHash("sha256").update(verifier).digest("base64url");
}

export interface Context {
	opts: Options;
	/** Why no client could be obtained, for skip messages. */
	clientNote(): string;
	send(url: string, init?: RequestInit): Promise<HttpResult>;
	discover(): Promise<Discovery>;
	/** The client used for authorize and token probes: provided, else registered through DCR. */
	client(): Promise<RegisteredClient | null>;
	/** Probe candidate URLs for an unauthenticated MCP request that returns 401. */
	protectedResource(): Promise<ProtectedResource | null>;
	probeResource(url: string, headers?: Record<string, string>): Promise<HttpResult>;
	/** Resource value to send as RFC 8707 `resource` in authorize requests. */
	resourceParam(): Promise<string>;
	probeAuthorize(overrides: Record<string, string | null>): Promise<AuthorizeProbe | null>;
	/** A fully valid authorize request. Negative probes only count when this is not rejected. */
	control(): Promise<AuthorizeProbe | null>;
	postToken(params: Record<string, string>): Promise<HttpResult | null>;
}

export function createContext(opts: Options): Context {
	let discoveryP: Promise<Discovery> | null = null;
	let clientP: Promise<RegisteredClient | null> | null = null;
	let resourceP: Promise<ProtectedResource | null> | null = null;
	let controlP: Promise<AuthorizeProbe | null> | null = null;
	let clientNote = "";

	const base = new URL(opts.target);

	const send = (url: string, init: RequestInit = {}): Promise<HttpResult> =>
		request(url, init, opts.timeoutMs);

	async function fetchDoc(url: string, tried: Discovery["tried"]): Promise<Document | null> {
		try {
			const res = await send(url, { headers: { Accept: "application/json" } });
			tried.push({ url, status: res.status });
			const body = asRecord(res.json);
			return res.status === 200 && body ? { url, body } : null;
		} catch (error) {
			tried.push({ url, status: error instanceof Error ? error.message : "network error" });
			return null;
		}
	}

	async function firstDoc(urls: string[], tried: Discovery["tried"]): Promise<Document | null> {
		for (const url of urls) {
			const doc = await fetchDoc(url, tried);
			if (doc) return doc;
		}
		return null;
	}

	const asUrls = (from: URL): string[] => [
		wellKnown(from, "oauth-authorization-server"),
		wellKnown(from, "openid-configuration"),
	];

	async function runDiscovery(): Promise<Discovery> {
		const tried: Discovery["tried"] = [];
		const rootBase = new URL(base.origin);
		const prm = await firstDoc(
			[
				wellKnown(base, "oauth-protected-resource"),
				wellKnown(rootBase, "oauth-protected-resource"),
			],
			tried,
		);
		let as = await firstDoc(asUrls(base), tried);
		if (!as && prm) {
			const issuer = asStringArray(prm.body.authorization_servers)[0];
			if (issuer) {
				try {
					as = await firstDoc(asUrls(new URL(issuer)), tried);
				} catch {
					// An unparsable authorization_servers entry is reported by the metadata check.
				}
			}
		}
		return { as, prm, tried };
	}

	const discover = (): Promise<Discovery> => {
		discoveryP ??= runDiscovery();
		return discoveryP;
	};

	async function obtainClient(): Promise<RegisteredClient | null> {
		if (opts.clientId) {
			return {
				clientId: opts.clientId,
				redirectUri: opts.redirectUri ?? DEFAULT_REDIRECT_URI,
				source: "provided",
			};
		}
		const { as } = await discover();
		const endpoint = asString(as?.body.registration_endpoint);
		if (!endpoint) {
			clientNote = "no registration_endpoint advertised and no --client-id given";
			return null;
		}
		const res = await send(
			endpoint,
			jsonBody({
				client_name: "theauth-conformance probe",
				redirect_uris: [DEFAULT_REDIRECT_URI],
				grant_types: ["authorization_code", "refresh_token"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			}),
		).catch(() => null);
		const body = asRecord(res?.json);
		const clientId = asString(body?.client_id);
		if (!res || !clientId || (res.status !== 201 && res.status !== 200)) {
			clientNote = `dynamic registration did not succeed (HTTP ${res?.status ?? "no response"})`;
			return null;
		}
		return { clientId, redirectUri: DEFAULT_REDIRECT_URI, source: "dcr" };
	}

	const client = (): Promise<RegisteredClient | null> => {
		clientP ??= obtainClient();
		return clientP;
	};

	const probeResource = (url: string, headers: Record<string, string> = {}): Promise<HttpResult> =>
		send(url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json, text/event-stream",
				...headers,
			},
			body: JSON.stringify({
				jsonrpc: "2.0",
				id: 1,
				method: "initialize",
				params: {
					protocolVersion: "2025-06-18",
					capabilities: {},
					clientInfo: { name: "theauth-conformance", version: "0.1.0" },
				},
			}),
		});

	async function findResource(): Promise<ProtectedResource | null> {
		if (opts.resource) {
			const response = await probeResource(opts.resource);
			return { url: opts.resource, response, explicit: true };
		}
		const { prm } = await discover();
		const resource = asString(prm?.body.resource);
		const candidates = [opts.target];
		if (resource) candidates.push(resource, `${resource.replace(/\/$/, "")}/mcp`);
		for (const url of [...new Set(candidates)]) {
			try {
				const response = await probeResource(url);
				if (response.status === 401) return { url, response, explicit: false };
			} catch {
				// Try the next candidate.
			}
		}
		return null;
	}

	const protectedResource = (): Promise<ProtectedResource | null> => {
		resourceP ??= findResource();
		return resourceP;
	};

	async function resourceParam(): Promise<string> {
		const { prm, as } = await discover();
		return (
			opts.resource ?? asString(prm?.body.resource) ?? asString(as?.body.issuer) ?? opts.target
		);
	}

	async function authorizeUrl(overrides: Record<string, string | null>): Promise<string | null> {
		const { as } = await discover();
		const endpoint = asString(as?.body.authorization_endpoint);
		const registered = await client();
		if (!endpoint || !registered) return null;
		const verifier = randomBytes(32).toString("base64url");
		const merged: Record<string, string | null> = {
			response_type: "code",
			client_id: registered.clientId,
			redirect_uri: registered.redirectUri,
			state: randomBytes(8).toString("hex"),
			code_challenge: s256(verifier),
			code_challenge_method: "S256",
			resource: await resourceParam(),
			...overrides,
		};
		const url = new URL(endpoint);
		for (const [key, value] of Object.entries(merged)) {
			if (value !== null) url.searchParams.set(key, value);
		}
		return url.toString();
	}

	async function probeAuthorize(
		overrides: Record<string, string | null>,
	): Promise<AuthorizeProbe | null> {
		const url = await authorizeUrl(overrides);
		if (!url) return null;
		const res = await send(url, { headers: { Accept: "text/html,application/json" } });
		return classifyAuthorize(res, url);
	}

	const control = (): Promise<AuthorizeProbe | null> => {
		controlP ??= probeAuthorize({});
		return controlP;
	};

	async function postToken(params: Record<string, string>): Promise<HttpResult | null> {
		const { as } = await discover();
		const endpoint = asString(as?.body.token_endpoint);
		return endpoint ? send(endpoint, formBody(params)) : null;
	}

	return {
		opts,
		clientNote: () => clientNote,
		send,
		discover,
		client,
		protectedResource,
		probeResource,
		resourceParam,
		probeAuthorize,
		control,
		postToken,
	};
}

export function classifyAuthorize(res: HttpResult, requestUrl: string): AuthorizeProbe {
	const location = res.headers.get("location");
	const base = { status: res.status, location, body: res.text.slice(0, 200) };
	if (res.status >= 300 && res.status < 400 && location) {
		const target = new URL(location, requestUrl);
		if (target.searchParams.has("error")) return { kind: "rejected-redirect", ...base };
		if (target.searchParams.has("code")) return { kind: "code-issued", ...base };
		return { kind: "redirect-other", ...base };
	}
	if (res.status >= 400 && res.status < 500) return { kind: "rejected", ...base };
	if (res.status >= 500) return { kind: "server-error", ...base };
	return { kind: "page", ...base };
}
