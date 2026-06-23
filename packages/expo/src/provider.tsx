import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { createMemoryStorage } from "./storage.js";
import type {
	ActionResult,
	AuthContextValue,
	AuthExpoConfig,
	AuthSession,
	AuthStorage,
	AuthUser,
} from "./types.js";

const SESSION_KEY = "theauth_session";

// ─── Context ──────────────────────────────────────────────────────────────────

export const AuthExpoContext = createContext<AuthContextValue | null>(null);

/** @deprecated Use {@link AuthExpoContext} instead. Will be removed in v3.0. */
export const KavachExpoContext = AuthExpoContext;

export function useAuthContext(): AuthContextValue {
	const ctx = useContext(AuthExpoContext);
	if (!ctx) {
		throw new Error("useAuthContext must be used inside <AuthExpoProvider>");
	}
	return ctx;
}

/** @deprecated Use {@link useAuthContext} instead. Will be removed in v3.0. */
export function useKavachContext(): AuthContextValue {
	return useAuthContext();
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export interface AuthExpoProviderProps {
	config: AuthExpoConfig;
	children: ReactNode;
}

/** @deprecated Use {@link AuthExpoProviderProps} instead. Will be removed in v3.0. */
export type KavachExpoProviderProps = AuthExpoProviderProps;

export function AuthExpoProvider({ config, children }: AuthExpoProviderProps): ReactNode {
	const [session, setSession] = useState<AuthSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Strip trailing slash from basePath once
	const base = config.basePath.replace(/\/$/, "");

	// Storage adapter — stable ref so callbacks don't re-create on each render
	const storageRef = useRef<AuthStorage>(config.storage ?? createMemoryStorage());

	// Keep storage ref in sync when config changes
	useEffect(() => {
		storageRef.current = config.storage ?? createMemoryStorage();
	}, [config.storage]);

	// ─── Fetch session from server (using stored token) ──────────────────────

	const fetchSession = useCallback(async (): Promise<void> => {
		const token = await storageRef.current.getItem(SESSION_KEY);
		if (!token) {
			setSession(null);
			return;
		}

		try {
			const res = await fetch(`${base}/session`, {
				headers: { Authorization: `Bearer ${token}` },
			});
			if (res.ok) {
				const json = (await res.json()) as { data?: AuthSession };
				setSession(json.data ?? null);
				if (!json.data) {
					await storageRef.current.removeItem(SESSION_KEY);
				}
			} else {
				setSession(null);
				await storageRef.current.removeItem(SESSION_KEY);
			}
		} catch {
			setSession(null);
		}
	}, [base]);

	// Fetch session on mount
	useEffect(() => {
		setIsLoading(true);
		void fetchSession().finally(() => {
			setIsLoading(false);
		});
	}, [fetchSession]);

	const refresh = useCallback(async (): Promise<void> => {
		await fetchSession();
	}, [fetchSession]);

	// ─── Sign in ──────────────────────────────────────────────────────────────

	const signIn = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/sign-in/email`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password }),
				});

				const json = (await res.json()) as
					| { data: AuthSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
					};
				}

				const okBody = json as { data: AuthSession };
				await storageRef.current.setItem(SESSION_KEY, okBody.data.token);
				setSession(okBody.data);
				return { success: true, data: undefined };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base],
	);

	// ─── Sign up ──────────────────────────────────────────────────────────────

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/sign-up/email`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password, name }),
				});

				const json = (await res.json()) as
					| { data: AuthSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-up failed (${res.status})`,
					};
				}

				const okBody = json as { data: AuthSession };
				await storageRef.current.setItem(SESSION_KEY, okBody.data.token);
				setSession(okBody.data);
				return { success: true, data: undefined };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base],
	);

	// ─── Sign out ─────────────────────────────────────────────────────────────

	const signOut = useCallback(async (): Promise<void> => {
		const token = await storageRef.current.getItem(SESSION_KEY);
		try {
			if (token) {
				await fetch(`${base}/sign-out`, {
					method: "POST",
					headers: { Authorization: `Bearer ${token}` },
				});
			}
		} finally {
			await storageRef.current.removeItem(SESSION_KEY);
			setSession(null);
		}
	}, [base]);

	const user: AuthUser | null = session?.user ?? null;

	const value: AuthContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: session !== null,
		signIn,
		signUp,
		signOut,
		refresh,
	};

	return <AuthExpoContext.Provider value={value}>{children}</AuthExpoContext.Provider>;
}

/** @deprecated Use {@link AuthExpoProvider} instead. Will be removed in v3.0. */
export const KavachExpoProvider = AuthExpoProvider;
