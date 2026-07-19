import { useCallback, useContext, useState } from "react";
import { TheAuthExpoContext } from "./provider.js";
import type { ActionResult, CreateAgentInput, TheAuthAgent } from "./types.js";

// ─── Guards ────────────────────────────────────────────────────────────────────

function useRequiredContext(hookName: string) {
	const ctx = useContext(TheAuthExpoContext);
	if (!ctx) {
		throw new Error(`${hookName} must be used inside <TheAuthExpoProvider>`);
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
 * Sends the session token via Authorization header (not cookies) to work
 * correctly in React Native environments.
 */
export function useAgents(basePath: string) {
	const { user, session } = useRequiredContext("useAgents");
	const base = basePath.replace(/\/$/, "");

	const [agents, setAgents] = useState<TheAuthAgent[]>([]);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const token = session?.token ?? null;

	const authHeaders = useCallback((): Record<string, string> => {
		if (token) {
			return { Authorization: `Bearer ${token}` };
		}
		return {};
	}, [token]);

	const load = useCallback(async (): Promise<void> => {
		if (!user) {
			setAgents([]);
			return;
		}
		setIsLoading(true);
		setError(null);
		try {
			const res = await fetch(`${base}/agents?userId=${encodeURIComponent(user.id)}`, {
				headers: authHeaders(),
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
	}, [base, user, authHeaders]);

	// Load once when user is available
	const [loaded, setLoaded] = useState(false);
	if (user && !loaded) {
		setLoaded(true);
		void Promise.resolve().then(load);
	}
	if (!user && loaded) {
		setLoaded(false);
		setAgents([]);
	}

	const create = useCallback(
		async (input: CreateAgentInput): Promise<ActionResult<TheAuthAgent>> => {
			try {
				const res = await fetch(`${base}/agents`, {
					method: "POST",
					headers: { "Content-Type": "application/json", ...authHeaders() },
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
		[base, load, authHeaders],
	);

	const revoke = useCallback(
		async (agentId: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/agents/${encodeURIComponent(agentId)}`, {
					method: "DELETE",
					headers: authHeaders(),
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
		[base, load, authHeaders],
	);

	const rotate = useCallback(
		async (agentId: string): Promise<ActionResult<TheAuthAgent>> => {
			try {
				const res = await fetch(`${base}/agents/${encodeURIComponent(agentId)}/rotate`, {
					method: "POST",
					headers: authHeaders(),
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
		[base, load, authHeaders],
	);

	return { agents, isLoading, error, load, create, revoke, rotate };
}
