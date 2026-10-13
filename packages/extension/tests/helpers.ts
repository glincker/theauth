import type {
	ExtensionAuthOptions,
	ExtensionStorageLike,
	IdentityLike,
	StorageAreaLike,
} from "../src/index.js";
import { createMemoryKeyStore } from "../src/index.js";
import { createMemoryArea } from "../src/platform.js";

export const ISSUER = "https://auth.example.test";
export const REDIRECT = "https://abcdef.chromiumapp.org/";

export interface FakeStorage extends ExtensionStorageLike {
	local: StorageAreaLike;
	session: StorageAreaLike;
}

export function fakeStorage(): FakeStorage {
	return { local: createMemoryArea(), session: createMemoryArea() };
}

export interface FakeIdentity extends IdentityLike {
	urls: string[];
}

/** `respond` receives the authorization URL and returns the redirect URL (or throws). */
export function fakeIdentity(respond: (url: URL) => string | undefined): FakeIdentity {
	const urls: string[] = [];
	return {
		urls,
		getRedirectURL: () => REDIRECT,
		async launchWebAuthFlow({ url }) {
			urls.push(url);
			return respond(new URL(url));
		},
	};
}

/** Redirects back with a code and the request's own state. */
export function approve(extra: Record<string, string> = {}) {
	return (url: URL): string => {
		const back = new URL(REDIRECT);
		back.searchParams.set("code", "code-1");
		back.searchParams.set("state", url.searchParams.get("state") ?? "");
		for (const [k, v] of Object.entries(extra)) back.searchParams.set(k, v);
		return back.toString();
	};
}

export interface TokenCall {
	url: string;
	params: URLSearchParams;
	headers: Headers;
}

export interface FakeServer {
	fetch: typeof fetch;
	calls: TokenCall[];
	/** Replace the token endpoint behaviour. */
	onToken: (call: TokenCall, n: number) => Response | Promise<Response>;
}

export function tokenJson(
	over: Record<string, unknown> = {},
	headers: Record<string, string> = {},
): Response {
	return new Response(
		JSON.stringify({
			access_token: "at-1",
			token_type: "Bearer",
			expires_in: 3600,
			refresh_token: "rt-1",
			scope: "read",
			...over,
		}),
		{ status: 200, headers: { "Content-Type": "application/json", ...headers } },
	);
}

export function fakeServer(): FakeServer {
	const server: FakeServer = {
		calls: [],
		onToken: () => tokenJson(),
		fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
			const req = new Request(input, init);
			const url = new URL(req.url);
			if (url.pathname.startsWith("/.well-known/oauth-authorization-server")) {
				return Response.json({
					issuer: ISSUER,
					authorization_endpoint: `${ISSUER}/authorize`,
					token_endpoint: `${ISSUER}/token`,
					revocation_endpoint: `${ISSUER}/revoke`,
				});
			}
			const body = await req.clone().text();
			const call: TokenCall = {
				url: req.url,
				params: new URLSearchParams(body),
				headers: req.headers,
			};
			if (url.pathname === "/revoke") {
				server.calls.push(call);
				return new Response(null, { status: 200 });
			}
			server.calls.push(call);
			return server.onToken(call, server.calls.filter((c) => c.url.endsWith("/token")).length);
		}) as typeof fetch,
	};
	return server;
}

export function tokenCalls(server: FakeServer): TokenCall[] {
	return server.calls.filter((c) => c.url.endsWith("/token"));
}

export function baseOptions(
	server: FakeServer,
	storage: FakeStorage,
	over: Partial<ExtensionAuthOptions> = {},
): ExtensionAuthOptions {
	return {
		issuer: ISSUER,
		clientId: "ext-client",
		scopes: ["read", "offline_access"],
		storage,
		identity: fakeIdentity(approve()),
		fetch: server.fetch,
		keyStore: createMemoryKeyStore(),
		lockPollMs: 2,
		...over,
	};
}
