import type {
	HydrateInput,
	RefetchOptions,
	SessionState,
	SessionStorageLike,
	StoreActionResult,
} from "@glinr/theauth-client";
import { createSessionStore } from "@glinr/theauth-client";
import type { Readable } from "svelte/store";
import { derived, readable, writable } from "svelte/store";
import type {
	ActionResult,
	CreateAgentInput,
	TheAuthAgent,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";

interface AgentApiResponse {
	data: TheAuthAgent[];
}

interface AgentSingleApiResponse {
	data: TheAuthAgent;
}

interface ApiErrorResponse {
	error: {
		code: string;
		message: string;
	};
}

function extractError(body: unknown, fallback: string): string {
	if (
		body !== null &&
		typeof body === "object" &&
		"error" in body &&
		body.error !== null &&
		typeof body.error === "object" &&
		"message" in body.error &&
		typeof (body as ApiErrorResponse).error.message === "string"
	) {
		return (body as ApiErrorResponse).error.message;
	}
	return fallback;
}

export interface TheAuthClientOptions {
	basePath?: string;
	/** Refetch the session on focus, reconnect or an interval. Runs while a store has a subscriber. */
	refetch?: RefetchOptions;
	/** Session the server already resolved (SSR). Skips the first request. `null` means signed out. */
	initialSession?: HydrateInput | null;
	/** Default `/auth/username/sign-in`. The core has no email and password route. */
	signInPath?: string;
	/** Default `/auth/username/sign-up`. */
	signUpPath?: string;
	/** Body field for the sign-in identifier. Default `username`. */
	identifierField?: string;
	/** Defaults to `window.localStorage` when the browser allows it. */
	storage?: SessionStorageLike;
	fetch?: typeof fetch;
}

export interface TheAuthClient {
	session: Readable<TheAuthSession | null>;
	user: Readable<TheAuthUser | null>;
	isAuthenticated: Readable<boolean>;
	isLoading: Readable<boolean>;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
	/** Seeds the session from SSR output with no request. */
	hydrateSession: (initial: HydrateInput | null) => void;
	/** Stops refetch triggers and aborts an in-flight refresh. */
	destroy: () => void;
}

function browserStorage(): SessionStorageLike | undefined {
	try {
		return typeof window === "undefined" ? undefined : window.localStorage;
	} catch {
		return undefined;
	}
}

function toActionResult(r: StoreActionResult): ActionResult {
	return r.success ? { success: true, data: undefined } : { success: false, error: r.error };
}

/**
 * Creates a self-contained auth client backed by Svelte stores.
 *
 * Call this once (e.g. in a module or Svelte context) and spread or
 * pass the returned object to whatever components need it.
 */
export function createTheAuthClient(options?: TheAuthClientOptions): TheAuthClient {
	const basePath = (options?.basePath ?? "/api/theauth").replace(/\/$/, "");
	const store = createSessionStore({
		basePath,
		storage: options?.storage ?? browserStorage(),
		fetch: options?.fetch,
		signInPath: options?.signInPath,
		signUpPath: options?.signUpPath,
		identifierField: options?.identifierField,
		refetch: options?.refetch,
	});

	// Subscribing to any derived store starts the session store's refetch triggers,
	// and the last unsubscribe stops them.
	const state: Readable<SessionState> = readable(store.getState(), (set) => {
		set(store.getState());
		return store.subscribe(set);
	});
	const session = derived(state, ($s) => $s.session);
	const isLoading = derived(state, ($s) => $s.isLoading);
	const user = derived(state, ($s) => $s.session?.user ?? null);
	const isAuthenticated = derived(state, ($s) => $s.session !== null);

	if (options?.initialSession !== undefined) {
		store.hydrateSession(options.initialSession);
	} else if (typeof window === "undefined") {
		store.destroy();
	} else {
		void store.refresh();
	}

	return {
		session: session as Readable<TheAuthSession | null>,
		user: user as Readable<TheAuthUser | null>,
		isAuthenticated: isAuthenticated as Readable<boolean>,
		isLoading: isLoading as Readable<boolean>,
		signIn: async (email, password) => toActionResult(await store.signIn(email, password)),
		signUp: async (email, password, name) =>
			toActionResult(await store.signUp(email, password, name)),
		signOut: async () => {
			await store.signOut();
		},
		refresh: () => store.refresh(),
		hydrateSession: (initial) => store.hydrateSession(initial),
		destroy: () => store.destroy(),
	};
}

export interface AgentStoreOptions {
	basePath?: string;
	/** Pass the user store from a TheAuthClient to enable auto-load. */
	user?: Readable<TheAuthUser | null>;
}

export interface AgentStore {
	agents: Readable<TheAuthAgent[]>;
	isLoading: Readable<boolean>;
	error: Readable<string | null>;
	load: (userId: string) => Promise<void>;
	create: (input: CreateAgentInput) => Promise<ActionResult<TheAuthAgent>>;
	revoke: (agentId: string) => Promise<ActionResult>;
	rotate: (agentId: string) => Promise<ActionResult<TheAuthAgent>>;
}

/**
 * Creates a store for managing agent identity records.
 *
 * Pass `user` from a `TheAuthClient` to have the store load automatically
 * whenever a user is present. Otherwise call `load(userId)` manually.
 */
export function createAgentStore(options?: AgentStoreOptions): AgentStore {
	const basePath = options?.basePath ?? "/api/theauth";

	const agents = writable<TheAuthAgent[]>([]);
	const isLoading = writable(false);
	const error = writable<string | null>(null);

	async function load(userId: string): Promise<void> {
		isLoading.set(true);
		error.set(null);
		try {
			const res = await fetch(`${basePath}/agents?userId=${encodeURIComponent(userId)}`, {
				credentials: "include",
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				error.set(extractError(json, `Failed to load agents (${res.status})`));
				return;
			}
			agents.set((json as AgentApiResponse).data);
		} catch (err) {
			error.set(err instanceof Error ? err.message : "Network error");
		} finally {
			isLoading.set(false);
		}
	}

	async function create(input: CreateAgentInput): Promise<ActionResult<TheAuthAgent>> {
		try {
			const res = await fetch(`${basePath}/agents`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(input),
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				return {
					success: false,
					error: extractError(json, `Failed to create agent (${res.status})`),
				};
			}
			const agent = (json as AgentSingleApiResponse).data;
			await load(input.ownerId);
			return { success: true, data: agent };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	async function revoke(agentId: string): Promise<ActionResult> {
		try {
			const res = await fetch(`${basePath}/agents/${encodeURIComponent(agentId)}`, {
				method: "DELETE",
				credentials: "include",
			});
			if (!res.ok && res.status !== 204) {
				const json: unknown = await res.json().catch(() => null);
				return {
					success: false,
					error: extractError(json, `Failed to revoke agent (${res.status})`),
				};
			}
			// Optimistically remove from local state while reload is in flight
			agents.update((prev) => prev.filter((a) => a.id !== agentId));
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	async function rotate(agentId: string): Promise<ActionResult<TheAuthAgent>> {
		try {
			const res = await fetch(`${basePath}/agents/${encodeURIComponent(agentId)}/rotate`, {
				method: "POST",
				credentials: "include",
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				return {
					success: false,
					error: extractError(json, `Failed to rotate agent token (${res.status})`),
				};
			}
			const agent = (json as AgentSingleApiResponse).data;
			agents.update((prev) => prev.map((a) => (a.id === agentId ? agent : a)));
			return { success: true, data: agent };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	if (typeof window !== "undefined" && options?.user) {
		let initialised = false;
		options.user.subscribe((u) => {
			if (u && !initialised) {
				initialised = true;
				void load(u.id);
			}
			if (!u) {
				initialised = false;
				agents.set([]);
			}
		});
	}

	return {
		agents: { subscribe: agents.subscribe } as Readable<TheAuthAgent[]>,
		isLoading: { subscribe: isLoading.subscribe } as Readable<boolean>,
		error: { subscribe: error.subscribe } as Readable<string | null>,
		load,
		create,
		revoke,
		rotate,
	};
}

// Kept for backward compatibility with the pre-rebrand "TheAuth" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthClientOptions` instead. Will be removed in a future major version. */
export type AuthClientOptions = TheAuthClientOptions;

/** @deprecated Use `TheAuthClient` instead. Will be removed in a future major version. */
export type AuthClient = TheAuthClient;

/** @deprecated Use `createTheAuthClient` instead. Will be removed in a future major version. */
export const createAuthClient = createTheAuthClient;
