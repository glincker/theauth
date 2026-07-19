import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { createMemoryStorage } from "./storage.js";
import type {
	ActionResult,
	TheAuthContextValue,
	TheAuthExpoConfig,
	TheAuthSession,
	TheAuthStorage,
	TheAuthUser,
} from "./types.js";

const SESSION_KEY = "theauth_session";

// ─── Context ──────────────────────────────────────────────────────────────────

export const TheAuthExpoContext = createContext<TheAuthContextValue | null>(null);

/** @deprecated Use `TheAuthExpoContext` instead. Will be removed in a future major version. */
export const AuthExpoContext = TheAuthExpoContext;

/** @deprecated Use `TheAuthExpoContext` instead. Will be removed in a future major version. */
export const KavachExpoContext = TheAuthExpoContext;

export function useTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(TheAuthExpoContext);
	if (!ctx) {
		throw new Error("useTheAuthContext must be used inside <TheAuthExpoProvider>");
	}
	return ctx;
}

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useAuthContext = useTheAuthContext;

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useKavachContext = useTheAuthContext;

// ─── Provider ─────────────────────────────────────────────────────────────────

export interface TheAuthExpoProviderProps {
	config: TheAuthExpoConfig;
	children: ReactNode;
}

/** @deprecated Use `TheAuthExpoProviderProps` instead. Will be removed in a future major version. */
export type AuthExpoProviderProps = TheAuthExpoProviderProps;

/** @deprecated Use `TheAuthExpoProviderProps` instead. Will be removed in a future major version. */
export type KavachExpoProviderProps = TheAuthExpoProviderProps;

export function TheAuthExpoProvider({ config, children }: TheAuthExpoProviderProps): ReactNode {
	const [session, setSession] = useState<TheAuthSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Strip trailing slash from basePath once
	const base = config.basePath.replace(/\/$/, "");

	// Storage adapter — stable ref so callbacks don't re-create on each render
	const storageRef = useRef<TheAuthStorage>(config.storage ?? createMemoryStorage());

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
				const json = (await res.json()) as { data?: TheAuthSession };
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
					| { data: TheAuthSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
					};
				}

				const okBody = json as { data: TheAuthSession };
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
					| { data: TheAuthSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-up failed (${res.status})`,
					};
				}

				const okBody = json as { data: TheAuthSession };
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

	const user: TheAuthUser | null = session?.user ?? null;

	const value: TheAuthContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: session !== null,
		signIn,
		signUp,
		signOut,
		refresh,
	};

	return <TheAuthExpoContext.Provider value={value}>{children}</TheAuthExpoContext.Provider>;
}

// ─── Deprecated aliases ─────────────────────────────────────────────────────
// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthExpoProvider` instead. Will be removed in a future major version. */
export const AuthExpoProvider = TheAuthExpoProvider;

/** @deprecated Use `TheAuthExpoProvider` instead. Will be removed in a future major version. */
export const KavachExpoProvider = TheAuthExpoProvider;
