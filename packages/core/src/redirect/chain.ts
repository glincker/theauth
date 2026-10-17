import { generateId } from "../crypto/web-crypto.js";

export interface RedirectConfig {
	/** Cookie name for storing the redirect chain (default: "theauth_redirect") */
	cookieName?: string;
	/** Max age in seconds for the redirect cookie (default: 600 = 10 min) */
	maxAge?: number;
	/** Default path when no redirect is stored (default: "/") */
	defaultPath?: string;
	/** Paths that should never be stored as destinations (auth pages, etc.) */
	excludePaths?: string[];
	/** Whether to preserve query params from the original URL (default: true) */
	preserveQuery?: boolean;
	/** Whether to preserve hash fragments (default: true) */
	preserveHash?: boolean;
	/** Max chain depth to prevent infinite loops (default: 10) */
	maxDepth?: number;
	cookie?: {
		httpOnly?: boolean;
		secure?: boolean;
		sameSite?: "lax" | "strict" | "none";
		path?: string;
		domain?: string;
	};
}

export interface RedirectEntry {
	id: string;
	path: string;
	query: Record<string, string>;
	hash: string;
	createdAt: number;
	/** Optional label for debugging ("onboarding", "verify-email", etc.) */
	label?: string;
}

export interface RedirectChainState {
	origin: RedirectEntry;
	// Intermediate steps, last in first out: the last pushed is the first popped.
	steps: RedirectEntry[];
	createdAt: number;
}

export interface RedirectChainManager {
	/** Captures the current request's URL as the origin destination. Call it in your auth middleware. */
	capture(request: Request): string;

	/** Pushes an intermediate step onto the chain, e.g. onboarding or email verification after sign-up. */
	push(path: string, options?: { label?: string; query?: Record<string, string> }): string;

	/** Pops the next destination from the chain. */
	pop(request: Request): { url: string; done: boolean; clearCookie: string | null };

	/** Peeks at the next destination without consuming it. */
	peek(request: Request): { url: string; remaining: number } | null;

	/** Returns the original destination (the URL the user first tried to visit), or null. */
	getOrigin(request: Request): RedirectEntry | null;

	/** Clears the chain. Returns the Set-Cookie header that clears the cookie. */
	clear(): string;

	/** Parse the chain state from a request's cookies. Returns null if no chain exists or if it's expired. */
	parse(request: Request): RedirectChainState | null;

	buildUrl(entry: RedirectEntry): string;

	createEntry(url: string | Request, label?: string): RedirectEntry;
}

const DEFAULT_COOKIE_NAME = "theauth_redirect";
const DEFAULT_MAX_AGE = 600; // 10 minutes
const DEFAULT_PATH = "/";
const DEFAULT_MAX_DEPTH = 10;
const DEFAULT_EXCLUDE_PATHS = [
	"/sign-in",
	"/sign-up",
	"/forgot-password",
	"/reset-password",
	"/verify-email",
	"/api/",
];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeState(state: RedirectChainState): string {
	const json = JSON.stringify(state);
	const bytes = encoder.encode(json);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeState(encoded: string): RedirectChainState | null {
	try {
		let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
		while (base64.length % 4 !== 0) {
			base64 += "=";
		}
		const binary = atob(base64);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) {
			bytes[i] = binary.charCodeAt(i);
		}
		const json = decoder.decode(bytes);
		const parsed: unknown = JSON.parse(json);
		if (!isValidChainState(parsed)) return null;
		return parsed;
	} catch {
		return null;
	}
}

function isValidChainState(value: unknown): value is RedirectChainState {
	if (typeof value !== "object" || value === null) return false;
	const obj = value as Record<string, unknown>;
	if (typeof obj.createdAt !== "number") return false;
	if (!isValidEntry(obj.origin)) return false;
	if (!Array.isArray(obj.steps)) return false;
	for (const step of obj.steps) {
		if (!isValidEntry(step)) return false;
	}
	return true;
}

function isValidEntry(value: unknown): value is RedirectEntry {
	if (typeof value !== "object" || value === null) return false;
	const obj = value as Record<string, unknown>;
	return (
		typeof obj.id === "string" &&
		typeof obj.path === "string" &&
		typeof obj.query === "object" &&
		obj.query !== null &&
		typeof obj.hash === "string" &&
		typeof obj.createdAt === "number"
	);
}

function parseCookies(request: Request): Record<string, string> {
	const header = request.headers.get("cookie");
	if (!header) return {};
	const cookies: Record<string, string> = {};
	for (const pair of header.split(";")) {
		const eqIdx = pair.indexOf("=");
		if (eqIdx === -1) continue;
		const key = pair.slice(0, eqIdx).trim();
		const val = pair.slice(eqIdx + 1).trim();
		cookies[key] = val;
	}
	return cookies;
}

function isExcluded(path: string, excludePaths: string[]): boolean {
	for (const excluded of excludePaths) {
		if (excluded.endsWith("/")) {
			if (path.startsWith(excluded) || path === excluded.slice(0, -1)) return true;
		} else {
			if (path === excluded) return true;
		}
	}
	return false;
}

/** Create a redirect chain manager with the given config. */
export function createRedirectChain(config?: RedirectConfig): RedirectChainManager {
	const cookieName = config?.cookieName ?? DEFAULT_COOKIE_NAME;
	const maxAge = config?.maxAge ?? DEFAULT_MAX_AGE;
	const defaultPath = config?.defaultPath ?? DEFAULT_PATH;
	const excludePaths = config?.excludePaths ?? DEFAULT_EXCLUDE_PATHS;
	const preserveQuery = config?.preserveQuery ?? true;
	const preserveHash = config?.preserveHash ?? true;
	const maxDepth = config?.maxDepth ?? DEFAULT_MAX_DEPTH;
	const cookieOpts = {
		httpOnly: config?.cookie?.httpOnly ?? true,
		secure: config?.cookie?.secure ?? true,
		sameSite: config?.cookie?.sameSite ?? ("lax" as const),
		path: config?.cookie?.path ?? "/",
		domain: config?.cookie?.domain,
	};

	// Internal state held in memory for push() which doesn't take a request.
	// Updated on every parse/capture/push/pop call.
	let currentState: RedirectChainState | null = null;

	function buildCookieHeader(value: string, age: number): string {
		const parts = [`${cookieName}=${value}`, `Path=${cookieOpts.path}`, `Max-Age=${age}`];
		if (cookieOpts.httpOnly) parts.push("HttpOnly");
		if (cookieOpts.secure) parts.push("Secure");
		parts.push(
			`SameSite=${cookieOpts.sameSite.charAt(0).toUpperCase()}${cookieOpts.sameSite.slice(1)}`,
		);
		if (cookieOpts.domain) parts.push(`Domain=${cookieOpts.domain}`);
		return parts.join("; ");
	}

	function buildClearCookie(): string {
		return buildCookieHeader("", 0);
	}

	function serializeAndSetCookie(state: RedirectChainState): string {
		currentState = state;
		const encoded = encodeState(state);
		return buildCookieHeader(encoded, maxAge);
	}

	function parseFromRequest(request: Request): RedirectChainState | null {
		const cookies = parseCookies(request);
		const raw = cookies[cookieName];
		if (!raw) return null;
		const state = decodeState(raw);
		if (!state) return null;

		const elapsed = Date.now() - state.createdAt;
		if (elapsed > maxAge * 1000) return null;

		currentState = state;
		return state;
	}

	function createEntryFromUrl(url: string | Request, label?: string): RedirectEntry {
		let parsed: URL;
		if (typeof url === "string") {
			if (url.startsWith("/")) {
				parsed = new URL(url, "http://localhost");
			} else {
				parsed = new URL(url);
			}
		} else {
			parsed = new URL(url.url);
		}

		const query: Record<string, string> = {};
		if (preserveQuery) {
			parsed.searchParams.forEach((value, key) => {
				query[key] = value;
			});
		}

		return {
			id: generateId(),
			path: parsed.pathname,
			query,
			hash: preserveHash ? parsed.hash.replace(/^#/, "") : "",
			createdAt: Date.now(),
			label,
		};
	}

	function buildUrlFromEntry(entry: RedirectEntry): string {
		let url = entry.path;
		const params = Object.entries(entry.query);
		if (params.length > 0) {
			const searchParams = new URLSearchParams();
			for (const [key, value] of params) {
				searchParams.set(key, value);
			}
			url += `?${searchParams.toString()}`;
		}
		if (entry.hash) {
			url += `#${entry.hash}`;
		}
		return url;
	}

	const manager: RedirectChainManager = {
		capture(request: Request): string {
			const existing = parseFromRequest(request);
			if (existing) {
				return serializeAndSetCookie(existing);
			}

			const entry = createEntryFromUrl(request);

			if (isExcluded(entry.path, excludePaths)) {
				entry.path = defaultPath;
				entry.query = {};
				entry.hash = "";
			}

			const state: RedirectChainState = {
				origin: entry,
				steps: [],
				createdAt: Date.now(),
			};

			return serializeAndSetCookie(state);
		},

		push(path: string, options?: { label?: string; query?: Record<string, string> }): string {
			if (!currentState) {
				currentState = {
					origin: {
						id: generateId(),
						path: defaultPath,
						query: {},
						hash: "",
						createdAt: Date.now(),
					},
					steps: [],
					createdAt: Date.now(),
				};
			}

			if (currentState.steps.length >= maxDepth) {
				return serializeAndSetCookie(currentState);
			}

			const entry: RedirectEntry = {
				id: generateId(),
				path,
				query: options?.query ?? {},
				hash: "",
				createdAt: Date.now(),
				label: options?.label,
			};

			currentState.steps.push(entry);
			return serializeAndSetCookie(currentState);
		},

		pop(request: Request): { url: string; done: boolean; clearCookie: string | null } {
			const state = parseFromRequest(request);
			if (!state) {
				return { url: defaultPath, done: true, clearCookie: buildClearCookie() };
			}

			if (state.steps.length > 0) {
				const next = state.steps.shift() as RedirectEntry;
				const url = buildUrlFromEntry(next);

				if (state.steps.length === 0) {
					currentState = state;
					return {
						url,
						done: false,
						clearCookie: null,
					};
				}

				return {
					url,
					done: false,
					clearCookie: null,
				};
			}

			const url = buildUrlFromEntry(state.origin);
			currentState = null;
			return {
				url,
				done: true,
				clearCookie: buildClearCookie(),
			};
		},

		peek(request: Request): { url: string; remaining: number } | null {
			const state = parseFromRequest(request);
			if (!state) return null;

			if (state.steps.length > 0) {
				const next = state.steps[0] as RedirectEntry;
				return {
					url: buildUrlFromEntry(next),
					remaining: state.steps.length, // +origin is implicit
				};
			}

			return {
				url: buildUrlFromEntry(state.origin),
				remaining: 0,
			};
		},

		getOrigin(request: Request): RedirectEntry | null {
			const state = parseFromRequest(request);
			if (!state) return null;
			return state.origin;
		},

		clear(): string {
			currentState = null;
			return buildClearCookie();
		},

		parse(request: Request): RedirectChainState | null {
			return parseFromRequest(request);
		},

		buildUrl(entry: RedirectEntry): string {
			return buildUrlFromEntry(entry);
		},

		createEntry(url: string | Request, label?: string): RedirectEntry {
			return createEntryFromUrl(url, label);
		},
	};

	return manager;
}
