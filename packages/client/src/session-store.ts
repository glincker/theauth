/**
 * Framework-neutral session store. It holds `{ session, isLoading }`, lets a UI
 * framework subscribe to changes, and talks to the routes the theAuth handler serves:
 * `POST /auth/sign-out` and `GET /auth/session`, plus either the username routes
 * (`/auth/username/sign-in`, `/auth/username/sign-up`, which you mount with
 * `theauth.username.handleRequest`) or, with `emailPassword: true`, the email and
 * password routes `createTheAuthHandler` serves under `/auth/email/*`. `signInPath` and
 * `signUpPath` let you point at your own. It uses only Web Standard APIs (fetch), so it
 * runs in browsers, workers and edge runtimes. Storage is injected, so nothing touches
 * `window` unless you pass `localStorage`.
 *
 * The store never logs and never puts a token in an error message.
 */
import type { RefetchOptions } from "./refetch.js";
import { attachRefetch } from "./refetch.js";

export interface StoreUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

export interface StoreSession {
	token: string;
	user: StoreUser;
	expiresAt?: string;
}

export interface SessionState {
	session: StoreSession | null;
	isLoading: boolean;
}

/**
 * `verificationRequired` is set by an email sign-up that created the account but no
 * session: the user must open the emailed link, then sign in. `code` is the server's
 * error code when it sent one, for example `EMAIL_NOT_VERIFIED` or `SIGN_IN_LOCKED`.
 */
export type StoreActionResult =
	| { success: true; verificationRequired?: boolean }
	| { success: false; error: string; code?: string };

/** The routes and body field of the core email and password module (`emailPassword` config). */
export const EMAIL_PASSWORD_ROUTES = {
	signInPath: "/auth/email/sign-in",
	signUpPath: "/auth/email/sign-up",
	identifierField: "email",
} as const;

/** The subset of `Storage` the store needs. */
export interface SessionStorageLike {
	getItem(key: string): string | null;
	setItem(key: string, value: string): void;
	removeItem(key: string): void;
}

export interface SessionStoreOptions {
	/** Route prefix of the theAuth handler. Default `/api/theauth`. */
	basePath?: string;
	storage?: SessionStorageLike;
	storageKey?: string;
	fetch?: typeof fetch;
	/**
	 * Use the core email and password routes (`/auth/email/sign-in`, `/auth/email/sign-up`,
	 * body field `email`). Explicit `signInPath`, `signUpPath` and `identifierField` still win.
	 */
	emailPassword?: boolean;
	/** Default `/auth/username/sign-in`, or `/auth/email/sign-in` with `emailPassword`. */
	signInPath?: string;
	/** Default `/auth/username/sign-up`, or `/auth/email/sign-up` with `emailPassword`. */
	signUpPath?: string;
	/** Body field that carries the first argument of `signIn` and `signUp`. Default `username`, or `email` with `emailPassword`. */
	identifierField?: string;
	/**
	 * Refetch triggers (focus, reconnect, interval). They run while the store has at
	 * least one subscriber, and stop when the last one leaves.
	 */
	refetch?: RefetchOptions;
}

/** What `hydrateSession` accepts. The token is optional so SSR never has to serialize it. */
export interface HydrateInput {
	token?: string;
	user: StoreUser;
	expiresAt?: string;
}

export interface SessionStore {
	getState(): SessionState;
	/** Calls `listener` after every change. Returns the unsubscribe function. */
	subscribe(listener: (state: SessionState) => void): () => void;
	/**
	 * Reads the session from the server (`GET /auth/session`, cookie or stored bearer
	 * token). A 401 or 403 clears the session. A network error or a 5xx keeps what
	 * the store has. Concurrent calls share one request.
	 */
	refresh(): Promise<void>;
	/**
	 * Seeds the store from a session the server already resolved (SSR), with no request.
	 * Pass `null` when the server found none. An expired or malformed value counts as none.
	 */
	hydrateSession(initial: HydrateInput | null): void;
	/** Starts refetch triggers by hand. Returns a `stop` function. No-op without a window. */
	startAutoRefresh(options?: RefetchOptions): () => void;
	/** Aborts an in-flight refresh and stops every refetch trigger. The store stays usable. */
	destroy(): void;
	signIn(identifier: string, password: string): Promise<StoreActionResult>;
	/**
	 * With the email routes and verification on, success carries `verificationRequired: true`
	 * and the store stays signed out until the user verifies and signs in.
	 */
	signUp(identifier: string, password: string, name?: string): Promise<StoreActionResult>;
	/** Confirms an address with the token from the verification email (`POST /auth/email/verify`). */
	verifyEmail(token: string): Promise<StoreActionResult>;
	/** Asks for another verification email. Succeeds whether or not the address exists. */
	resendVerification(email: string): Promise<StoreActionResult>;
	/** Emails a reset link. Succeeds whether or not the address exists. Needs `passwordReset` on the server. */
	requestPasswordReset(email: string): Promise<StoreActionResult>;
	/** Sets a new password from the emailed token. Needs `passwordReset` on the server. */
	resetPassword(token: string, password: string): Promise<StoreActionResult>;
	/** Clears local state at once, then revokes the session on the server. */
	signOut(): Promise<StoreActionResult>;
}

interface WireUser {
	id?: unknown;
	email?: unknown;
	username?: unknown;
	name?: unknown;
	image?: unknown;
}

interface WireBody {
	user?: WireUser;
	session?: { token?: unknown; expiresAt?: unknown };
	token?: unknown;
	error?: unknown;
	verificationRequired?: unknown;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function toUser(raw: WireUser | undefined): StoreUser | null {
	const id = str(raw?.id);
	if (!raw || !id) return null;
	const username = str(raw.username);
	const email = str(raw.email) ?? (username?.includes("@") ? username : undefined);
	return { id, email, name: str(raw.name), image: str(raw.image) };
}

function errorOf(body: WireBody | null, fallback: string): string {
	const e = body?.error;
	if (typeof e === "string" && e) return e;
	if (e && typeof e === "object" && "message" in e) {
		const m = (e as { message?: unknown }).message;
		if (typeof m === "string" && m) return m;
	}
	return fallback;
}

function codeOf(body: WireBody | null): { code: string } | Record<string, never> {
	const e = body?.error;
	if (e && typeof e === "object" && "code" in e) {
		const c = (e as { code?: unknown }).code;
		if (typeof c === "string" && c) return { code: c };
	}
	return {};
}

function isExpired(expiresAt: string | undefined): boolean {
	if (!expiresAt) return false;
	const t = Date.parse(expiresAt);
	return Number.isFinite(t) && t <= Date.now();
}

export function createSessionStore(options: SessionStoreOptions = {}): SessionStore {
	const base = (options.basePath ?? "/api/theauth").replace(/\/+$/, "");
	const key = options.storageKey ?? "theauth_session";
	const preset = options.emailPassword
		? EMAIL_PASSWORD_ROUTES
		: {
				signInPath: "/auth/username/sign-in",
				signUpPath: "/auth/username/sign-up",
				identifierField: "username",
			};
	const signInPath = options.signInPath ?? preset.signInPath;
	const signUpPath = options.signUpPath ?? preset.signUpPath;
	const field = options.identifierField ?? preset.identifierField;
	const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
	const listeners = new Set<(state: SessionState) => void>();
	let state: SessionState = { session: null, isLoading: true };
	// Bumped by every action that decides the session, so a slower refresh cannot overwrite it.
	let epoch = 0;
	let inFlight: Promise<void> | null = null;
	let controller: AbortController | null = null;
	let stopTriggers: (() => void) | null = null;

	function set(next: SessionState): void {
		state = next;
		for (const l of [...listeners]) l(state);
	}

	function read(): StoreSession | null {
		try {
			const raw = options.storage?.getItem(key);
			return raw ? (JSON.parse(raw) as StoreSession) : null;
		} catch {
			return null;
		}
	}

	function forget(): void {
		try {
			options.storage?.removeItem(key);
		} catch {
			// Ignore blocked storage.
		}
	}

	function remember(session: StoreSession): void {
		if (!session.token) return;
		try {
			options.storage?.setItem(key, JSON.stringify(session));
		} catch {
			// Storage can be full or blocked. The in-memory session still works.
		}
	}

	function persist(session: StoreSession): void {
		remember(session);
		set({ session, isLoading: false });
	}

	function bearer(token: string | undefined): Record<string, string> {
		return token ? { Authorization: `Bearer ${token}` } : {};
	}

	async function post(path: string, payload: unknown): Promise<Response | string> {
		try {
			return await doFetch(`${base}${path}`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});
		} catch (err) {
			return err instanceof Error ? err.message : "Network error";
		}
	}

	async function failure(res: Response, label: string): Promise<StoreActionResult> {
		const body = (await res.json().catch(() => null)) as WireBody | null;
		return {
			success: false,
			error: errorOf(body, `${label} failed (${res.status})`),
			...codeOf(body),
		};
	}

	async function authenticate(
		path: string,
		payload: Record<string, unknown>,
		label: string,
	): Promise<StoreActionResult> {
		const res = await post(path, payload);
		if (typeof res === "string") return { success: false, error: res };
		if (!res.ok) return failure(res, label);
		const body = (await res.json().catch(() => null)) as WireBody | null;
		if (body?.verificationRequired === true) {
			// The account exists but has no session yet. Stay signed out.
			return { success: true, verificationRequired: true };
		}
		const user = toUser(body?.user);
		const token = str(body?.session?.token) ?? str(body?.token);
		if (!user || !token)
			return { success: false, error: `${label} returned an unexpected response` };
		epoch += 1;
		persist({ token, user, expiresAt: str(body?.session?.expiresAt) });
		return { success: true };
	}

	/** A POST whose answer is only success or an error, like verify and reset. */
	async function act(path: string, payload: unknown, label: string): Promise<StoreActionResult> {
		const res = await post(path, payload);
		if (typeof res === "string") return { success: false, error: res };
		return res.ok ? { success: true } : failure(res, label);
	}

	async function run(): Promise<void> {
		const mine = epoch;
		// Some runtimes (Lynx's PrimJS) have fetch but no AbortController. Then a refresh
		// cannot be cancelled, and the epoch check still drops its late answer.
		const ctl = typeof AbortController === "undefined" ? null : new AbortController();
		controller = ctl;
		const stored = read();
		if (!state.session && stored) set({ session: stored, isLoading: true });
		const token = state.session?.token || stored?.token;
		try {
			const res = await doFetch(`${base}/auth/session`, {
				method: "GET",
				credentials: "include",
				headers: bearer(token),
				...(ctl && { signal: ctl.signal }),
			});
			if (mine !== epoch) return;
			if (res.status === 401 || res.status === 403) {
				forget();
				set({ session: null, isLoading: false });
			} else if (res.ok) {
				const body = (await res.json().catch(() => null)) as WireBody | null;
				const user = toUser(body?.user);
				if (mine !== epoch) return;
				if (user) {
					persist({
						token: token ?? "",
						user,
						expiresAt: str(body?.session?.expiresAt) ?? state.session?.expiresAt,
					});
				} else {
					set({ session: state.session, isLoading: false });
				}
			} else {
				set({ session: state.session, isLoading: false });
			}
		} catch {
			// Offline or aborted: keep whatever the store already has.
			if (mine === epoch) set({ session: state.session, isLoading: false });
		} finally {
			if (controller === ctl) controller = null;
		}
	}

	function refresh(): Promise<void> {
		if (!inFlight) {
			inFlight = run().finally(() => {
				inFlight = null;
			});
		}
		return inFlight;
	}

	function startAutoRefresh(opts?: RefetchOptions): () => void {
		return attachRefetch(() => {
			void refresh();
		}, opts);
	}

	function destroy(): void {
		epoch += 1;
		controller?.abort();
		stopTriggers?.();
		stopTriggers = null;
		if (state.isLoading) set({ session: state.session, isLoading: false });
	}

	return {
		getState: () => state,
		subscribe(listener) {
			listeners.add(listener);
			if (listeners.size === 1 && options.refetch && !stopTriggers) {
				stopTriggers = startAutoRefresh(options.refetch);
			}
			return () => {
				listeners.delete(listener);
				if (listeners.size === 0 && stopTriggers) {
					stopTriggers();
					stopTriggers = null;
				}
			};
		},
		refresh,
		hydrateSession(initial) {
			epoch += 1;
			const user = toUser(initial?.user);
			if (!initial || !user || isExpired(initial.expiresAt)) {
				forget();
				set({ session: null, isLoading: false });
				return;
			}
			persist({ token: initial.token ?? "", user, expiresAt: initial.expiresAt });
		},
		startAutoRefresh,
		destroy,
		signIn: (identifier, password) =>
			authenticate(signInPath, { [field]: identifier, password }, "Sign-in"),
		signUp: (identifier, password, name) =>
			authenticate(signUpPath, { [field]: identifier, password, name }, "Sign-up"),
		verifyEmail: (token) => act("/auth/email/verify", { token }, "Verification"),
		resendVerification: (email) => act("/auth/email/resend-verification", { email }, "Resend"),
		requestPasswordReset: (email) => act("/auth/email/forgot-password", { email }, "Reset request"),
		resetPassword: (token, password) =>
			act("/auth/email/reset-password", { token, password }, "Password reset"),
		async signOut() {
			epoch += 1;
			controller?.abort();
			const token = state.session?.token || read()?.token;
			forget();
			set({ session: null, isLoading: false });
			try {
				const res = await doFetch(`${base}/auth/sign-out`, {
					method: "POST",
					credentials: "include",
					headers: bearer(token),
				});
				// 401 means the server already had no session for us: nothing to revoke.
				if (res.ok || res.status === 401) return { success: true };
				return failure(res, "Sign-out");
			} catch (err) {
				return { success: false, error: err instanceof Error ? err.message : "Network error" };
			}
		},
	};
}
