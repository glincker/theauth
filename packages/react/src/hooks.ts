import { useCallback, useContext, useState } from "react";
import { KavachContext } from "./context.js";
import type { ActionResult, CreateAgentInput, KavachAgent } from "./types.js";

// ─── Guards ────────────────────────────────────────────────────────────────────

function useRequiredContext(hookName: string) {
	const ctx = useContext(KavachContext);
	if (!ctx) {
		throw new Error(`${hookName} must be used inside <KavachProvider>`);
	}
	return ctx;
}

// ─── useSession ───────────────────────────────────────────────────────────────

/**
 * Returns the current session, loading state, and a manual refresh function.
 */
export function useSession() {
	const { session, isLoading, refresh } = useRequiredContext("useSession");
	return { session, isLoading, refresh };
}

// ─── useUser ──────────────────────────────────────────────────────────────────

/**
 * Returns the current user, loading state, and authentication status.
 */
export function useUser() {
	const { user, isLoading, isAuthenticated } = useRequiredContext("useUser");
	return { user, isLoading, isAuthenticated };
}

// ─── useSignIn ────────────────────────────────────────────────────────────────

/**
 * Returns a signIn function plus local loading and error state.
 */
export function useSignIn() {
	const { signIn } = useRequiredContext("useSignIn");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const execute = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			setIsLoading(true);
			setError(null);
			const result = await signIn(email, password);
			if (!result.success) {
				setError(result.error);
			}
			setIsLoading(false);
			return result;
		},
		[signIn],
	);

	return { signIn: execute, isLoading, error };
}

// ─── useSignUp ────────────────────────────────────────────────────────────────

/**
 * Returns a signUp function plus local loading and error state.
 */
export function useSignUp() {
	const { signUp } = useRequiredContext("useSignUp");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const execute = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			setIsLoading(true);
			setError(null);
			const result = await signUp(email, password, name);
			if (!result.success) {
				setError(result.error);
			}
			setIsLoading(false);
			return result;
		},
		[signUp],
	);

	return { signUp: execute, isLoading, error };
}

// ─── useSignOut ───────────────────────────────────────────────────────────────

/**
 * Returns a signOut function.
 */
export function useSignOut() {
	const { signOut } = useRequiredContext("useSignOut");
	return { signOut };
}

// ─── useRotateSession ─────────────────────────────────────────────────────────

/**
 * Convenience hook for the v0.5 rotation API. Mirrors the values exposed
 * on the context — `rotate` (single-flight), `status` (`idle | rotating |
 * error`), and `isOnline`.
 *
 * In managed mode (no `external.refreshPath`) `rotate()` resolves with
 * `{ success: false, code: "network_error" }` so call sites can stay
 * uniform across modes.
 *
 * @example
 * ```tsx
 * const { rotate, status, isOnline } = useRotateSession();
 * useEffect(() => {
 *   if (!isOnline) return;
 *   void rotate();
 * }, [isOnline, rotate]);
 * ```
 */
export function useRotateSession() {
	const { rotateSession, rotationStatus, isOnline } = useRequiredContext("useRotateSession");
	return { rotate: rotateSession, status: rotationStatus, isOnline };
}

// ─── useAgents ────────────────────────────────────────────────────────────────

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

/**
 * Manages agent identity records for a given user.
 *
 * Fetches the agent list and exposes create, revoke, and rotate helpers.
 * All mutations refresh the list automatically.
 */
export function useAgents(basePath = "/api/kavach") {
	const { user } = useRequiredContext("useAgents");
	const base = basePath.replace(/\/$/, "");

	const [agents, setAgents] = useState<KavachAgent[]>([]);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const load = useCallback(async (): Promise<void> => {
		if (!user) {
			setAgents([]);
			return;
		}
		setIsLoading(true);
		setError(null);
		try {
			const res = await fetch(`${base}/agents?userId=${encodeURIComponent(user.id)}`, {
				credentials: "include",
			});
			const json: unknown = await res.json();
			if (!res.ok) {
				setError(extractError(json, `Failed to load agents (${res.status})`));
				return;
			}
			setAgents((json as AgentApiResponse).data);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Network error");
		} finally {
			setIsLoading(false);
		}
	}, [base, user]);

	// Load once when user is available
	const [loaded, setLoaded] = useState(false);
	if (user && !loaded) {
		setLoaded(true);
		// Use a microtask to avoid calling setState during render
		void Promise.resolve().then(load);
	}
	if (!user && loaded) {
		setLoaded(false);
		setAgents([]);
	}

	const create = useCallback(
		async (input: CreateAgentInput): Promise<ActionResult<KavachAgent>> => {
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
		},
		[base, load],
	);

	const revoke = useCallback(
		async (agentId: string): Promise<ActionResult> => {
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
		},
		[base, load],
	);

	const rotate = useCallback(
		async (agentId: string): Promise<ActionResult<KavachAgent>> => {
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
		},
		[base, load],
	);

	return { agents, isLoading, error, load, create, revoke, rotate };
}
