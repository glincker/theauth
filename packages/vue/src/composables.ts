import { ref } from "vue";
import { useRequiredContext } from "./plugin.js";
import type { ActionResult, CreateAgentInput, TheAuthAgent } from "./types.js";

// ─── useSession ───────────────────────────────────────────────────────────────

/**
 * Returns the current session, loading state, and a manual refresh function.
 */
export function useSession() {
	const ctx = useRequiredContext("useSession");
	return {
		get session() {
			return ctx.session;
		},
		get isLoading() {
			return ctx.isLoading;
		},
		refresh: ctx.refresh,
	};
}

// ─── useUser ──────────────────────────────────────────────────────────────────

/**
 * Returns the current user, loading state, and authentication status.
 */
export function useUser() {
	const ctx = useRequiredContext("useUser");
	return {
		get user() {
			return ctx.user;
		},
		get isAuthenticated() {
			return ctx.isAuthenticated;
		},
		get isLoading() {
			return ctx.isLoading;
		},
	};
}

// ─── useSignIn ────────────────────────────────────────────────────────────────

/**
 * Returns a signIn function plus local loading and error state.
 */
export function useSignIn() {
	const ctx = useRequiredContext("useSignIn");
	const isLoading = ref(false);
	const error = ref<string | null>(null);

	async function signIn(email: string, password: string): Promise<ActionResult> {
		isLoading.value = true;
		error.value = null;
		const result = await ctx.signIn(email, password);
		if (!result.success) {
			error.value = result.error;
		}
		isLoading.value = false;
		return result;
	}

	return { signIn, isLoading, error };
}

// ─── useSignUp ────────────────────────────────────────────────────────────────

/**
 * Returns a signUp function plus local loading and error state.
 */
export function useSignUp() {
	const ctx = useRequiredContext("useSignUp");
	const isLoading = ref(false);
	const error = ref<string | null>(null);

	async function signUp(email: string, password: string, name?: string): Promise<ActionResult> {
		isLoading.value = true;
		error.value = null;
		const result = await ctx.signUp(email, password, name);
		if (!result.success) {
			error.value = result.error;
		}
		isLoading.value = false;
		return result;
	}

	return { signUp, isLoading, error };
}

// ─── useSignOut ───────────────────────────────────────────────────────────────

/**
 * Returns a signOut function.
 */
export function useSignOut() {
	const ctx = useRequiredContext("useSignOut");
	return { signOut: ctx.signOut };
}

// ─── useAgents ────────────────────────────────────────────────────────────────

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

/**
 * Manages agent identity records for a given user.
 *
 * Fetches the agent list and exposes create, revoke, and rotate helpers.
 * All mutations refresh the list automatically.
 */
export function useAgents() {
	const ctx = useRequiredContext("useAgents");
	const base = ctx.basePath;

	const agents = ref<TheAuthAgent[]>([]);
	const isLoading = ref(false);
	const error = ref<string | null>(null);

	async function load(): Promise<void> {
		if (!ctx.user) {
			agents.value = [];
			return;
		}
		isLoading.value = true;
		error.value = null;
		try {
			const res = await fetch(`${base}/agents?userId=${encodeURIComponent(ctx.user.id)}`, {
				credentials: "include",
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				error.value = extractError(json, `Failed to load agents (${res.status})`);
				return;
			}
			agents.value = (json as AgentApiResponse).data;
		} catch (err) {
			error.value = err instanceof Error ? err.message : "Network error";
		} finally {
			isLoading.value = false;
		}
	}

	// Load once when invoked in browser context and user is available
	if (typeof window !== "undefined" && ctx.user) {
		void load();
	}

	async function create(input: CreateAgentInput): Promise<ActionResult<TheAuthAgent>> {
		try {
			const res = await fetch(`${base}/agents`, {
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
			await load();
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
			const res = await fetch(`${base}/agents/${encodeURIComponent(agentId)}`, {
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
			await load();
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
			const res = await fetch(`${base}/agents/${encodeURIComponent(agentId)}/rotate`, {
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
			await load();
			return { success: true, data: agent };
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}
	}

	return { agents, isLoading, error, load, create, revoke, rotate };
}
