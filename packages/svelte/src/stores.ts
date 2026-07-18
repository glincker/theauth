import type { Readable } from "svelte/store";
import { derived, writable } from "svelte/store";
import type {
	ActionResult,
	CreateAgentInput,
	KavachAgent,
	KavachSession,
	KavachUser,
} from "./types.js";

// ─── Internal helpers ─────────────────────────────────────────────────────────

interface AgentApiResponse {
	data: KavachAgent[];
}

interface AgentSingleApiResponse {
	data: KavachAgent;
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

// ─── createTheAuthClient ──────────────────────────────────────────────────────

export interface TheAuthClientOptions {
	basePath?: string;
}

export interface TheAuthClient {
	session: Readable<KavachSession | null>;
	user: Readable<KavachUser | null>;
	isAuthenticated: Readable<boolean>;
	isLoading: Readable<boolean>;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

/**
 * Creates a self-contained auth client backed by Svelte stores.
 *
 * Call this once (e.g. in a module or Svelte context) and spread or
 * pass the returned object to whatever components need it.
 */
export function createTheAuthClient(options?: TheAuthClientOptions): TheAuthClient {
	const basePath = options?.basePath ?? "/api/kavach";

	const session = writable<KavachSession | null>(null);
	const isLoading = writable(true);

	const user = derived(session, ($session) => $session?.user ?? null);
	const isAuthenticated = derived(session, ($session) => $session !== null);

	const STORAGE_KEY = "kavach_session";

	async function fetchSession(): Promise<void> {
		isLoading.set(true);
		try {
			if (typeof window === "undefined") {
				session.set(null);
				return;
			}
			const raw = window.localStorage.getItem(STORAGE_KEY);
			if (raw) {
				session.set(JSON.parse(raw) as KavachSession);
			} else {
				session.set(null);
			}
		} catch {
			session.set(null);
		} finally {
			isLoading.set(false);
		}
	}

	async function signIn(email: string, password: string): Promise<ActionResult> {
		try {
			const res = await fetch(`${basePath}/auth/sign-in`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email, password }),
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				return { success: false, error: extractError(json, `Sign-in failed (${res.status})`) };
			}
			const okBody = json as { user: KavachUser; session: { token: string; expiresAt: string } };
			const sessionData: KavachSession = {
				token: okBody.session.token,
				user: okBody.user,
				expiresAt: okBody.session.expiresAt,
			};
			session.set(sessionData);
			if (typeof window !== "undefined") {
				window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sessionData));
			}
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	async function signUp(email: string, password: string, name?: string): Promise<ActionResult> {
		try {
			const res = await fetch(`${basePath}/auth/sign-up`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email, password, name }),
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				return { success: false, error: extractError(json, `Sign-up failed (${res.status})`) };
			}
			const okBody = json as { user: KavachUser; token: string };
			const sessionData: KavachSession = {
				token: okBody.token,
				user: okBody.user,
			};
			session.set(sessionData);
			if (typeof window !== "undefined") {
				window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sessionData));
			}
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	async function signOut(): Promise<void> {
		session.set(null);
		if (typeof window !== "undefined") {
			window.localStorage.removeItem(STORAGE_KEY);
		}
	}

	// Restore session from localStorage on creation — guard for SSR environments
	if (typeof window !== "undefined") {
		void fetchSession();
	} else {
		isLoading.set(false);
	}

	return {
		session: { subscribe: session.subscribe } as Readable<KavachSession | null>,
		user: user as Readable<KavachUser | null>,
		isAuthenticated: isAuthenticated as Readable<boolean>,
		isLoading: { subscribe: isLoading.subscribe } as Readable<boolean>,
		signIn,
		signUp,
		signOut,
		refresh: fetchSession,
	};
}

// ─── createAgentStore ─────────────────────────────────────────────────────────

export interface AgentStoreOptions {
	basePath?: string;
	/** Pass the user store from a TheAuthClient to enable auto-load. */
	user?: Readable<KavachUser | null>;
}

export interface AgentStore {
	agents: Readable<KavachAgent[]>;
	isLoading: Readable<boolean>;
	error: Readable<string | null>;
	load: (userId: string) => Promise<void>;
	create: (input: CreateAgentInput) => Promise<ActionResult<KavachAgent>>;
	revoke: (agentId: string) => Promise<ActionResult>;
	rotate: (agentId: string) => Promise<ActionResult<KavachAgent>>;
}

/**
 * Creates a store for managing agent identity records.
 *
 * Pass `user` from a `TheAuthClient` to have the store load automatically
 * whenever a user is present. Otherwise call `load(userId)` manually.
 */
export function createAgentStore(options?: AgentStoreOptions): AgentStore {
	const basePath = options?.basePath ?? "/api/kavach";

	const agents = writable<KavachAgent[]>([]);
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

	async function create(input: CreateAgentInput): Promise<ActionResult<KavachAgent>> {
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
			// Refresh by reloading current agents from the server
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

	async function rotate(agentId: string): Promise<ActionResult<KavachAgent>> {
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
			// Update the rotated agent in place
			agents.update((prev) => prev.map((a) => (a.id === agentId ? agent : a)));
			return { success: true, data: agent };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	// Auto-load when user store is provided and user becomes available (browser only)
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
		agents: { subscribe: agents.subscribe } as Readable<KavachAgent[]>,
		isLoading: { subscribe: isLoading.subscribe } as Readable<boolean>,
		error: { subscribe: error.subscribe } as Readable<string | null>,
		load,
		create,
		revoke,
		rotate,
	};
}

// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthClientOptions` instead. Will be removed in a future major version. */
export type KavachClientOptions = TheAuthClientOptions;

/** @deprecated Use `TheAuthClient` instead. Will be removed in a future major version. */
export type KavachClient = TheAuthClient;

/** @deprecated Use `createTheAuthClient` instead. Will be removed in a future major version. */
export const createKavachClient = createTheAuthClient;
