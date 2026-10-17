import { useCallback, useContext, useState } from "react";
import { TheAuthExpoContext } from "./provider.js";
import type { ActionResult, CreateAgentInput, TheAuthAgent } from "./types.js";

function useRequiredContext(hookName: string) {
	const ctx = useContext(TheAuthExpoContext);
	if (!ctx) {
		throw new Error(`${hookName} must be used inside <TheAuthExpoProvider>`);
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

/** Needs `social` in the provider config. */
export function useSocialSignIn() {
	const { signInWithProvider } = useRequiredContext("useSocialSignIn");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const execute = useCallback(
		async (provider: string): Promise<ActionResult> => {
			setIsLoading(true);
			setError(null);
			const result = await signInWithProvider(provider);
			if (!result.success) setError(result.error);
			setIsLoading(false);
			return result;
		},
		[signInWithProvider],
	);

	return { signInWithProvider: execute, isLoading, error };
}

/** Needs `passkeys` in the provider config. */
export function usePasskeys() {
	const { signInWithPasskey, registerPasskey } = useRequiredContext("usePasskeys");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const run = useCallback(async (action: () => Promise<ActionResult>): Promise<ActionResult> => {
		setIsLoading(true);
		setError(null);
		const result = await action();
		if (!result.success) setError(result.error);
		setIsLoading(false);
		return result;
	}, []);

	const signIn = useCallback(
		(userId?: string) => run(() => signInWithPasskey(userId)),
		[run, signInWithPasskey],
	);
	const register = useCallback(
		(deviceName?: string) => run(() => registerPasskey(deviceName)),
		[run, registerPasskey],
	);

	return { signInWithPasskey: signIn, registerPasskey: register, isLoading, error };
}

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

export function useSignOut() {
	const { signOut } = useRequiredContext("useSignOut");
	return { signOut };
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

/** Sends the session token in the Authorization header, not cookies, for React Native. */
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
