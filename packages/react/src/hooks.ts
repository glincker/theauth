import { useCallback, useContext, useState } from "react";
import { TheAuthContext } from "./context.js";
import type { ActionResult, CreateAgentInput, SignUpData, TheAuthAgent } from "./types.js";

function useRequiredContext(hookName: string) {
	const ctx = useContext(TheAuthContext);
	if (!ctx) {
		throw new Error(`${hookName} must be used inside <TheAuthProvider>`);
	}
	return ctx;
}

export function useSession() {
	const { session, isLoading, refresh } = useRequiredContext("useSession");
	return { session, isLoading, refresh };
}

export function useUser() {
	const { user, isLoading, isAuthenticated } = useRequiredContext("useUser");
	return { user, isLoading, isAuthenticated };
}

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

export function useSignUp() {
	const { signUp } = useRequiredContext("useSignUp");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const execute = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult<SignUpData>> => {
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

/**
 * Verify, resend, forgot and reset for the email and password routes
 * (`managed: { emailPassword: true }`). Each result carries the server `code` on failure.
 */
export function useEmailPassword() {
	const { verifyEmail, resendVerification, requestPasswordReset, resetPassword } =
		useRequiredContext("useEmailPassword");
	return { verifyEmail, resendVerification, requestPasswordReset, resetPassword };
}

export function useSignOut() {
	const { signOut } = useRequiredContext("useSignOut");
	return { signOut };
}

/**
 * In managed mode (no `external.refreshPath`) `rotate()` resolves with `network_error`
 * so call sites stay uniform across modes.
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

/** Agent identity records for a user. Mutations refresh the list automatically. */
export function useAgents(basePath = "/api/theauth") {
	const { user } = useRequiredContext("useAgents");
	const base = basePath.replace(/\/$/, "");

	const [agents, setAgents] = useState<TheAuthAgent[]>([]);
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
		async (input: CreateAgentInput): Promise<ActionResult<TheAuthAgent>> => {
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
		async (agentId: string): Promise<ActionResult<TheAuthAgent>> => {
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
