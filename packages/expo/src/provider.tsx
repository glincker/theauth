import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { runPasskeyRegistration, runPasskeySignIn } from "./passkey.js";
import { runSocialSignIn } from "./social.js";
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

export const TheAuthExpoContext = createContext<TheAuthContextValue | null>(null);

/** @deprecated Use `TheAuthExpoContext` instead. Will be removed in a future major version. */
export const AuthExpoContext = TheAuthExpoContext;

export function useTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(TheAuthExpoContext);
	if (!ctx) {
		throw new Error("useTheAuthContext must be used inside <TheAuthExpoProvider>");
	}
	return ctx;
}

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useAuthContext = useTheAuthContext;

export interface TheAuthExpoProviderProps {
	config: TheAuthExpoConfig;
	children: ReactNode;
}

/** @deprecated Use `TheAuthExpoProviderProps` instead. Will be removed in a future major version. */
export type AuthExpoProviderProps = TheAuthExpoProviderProps;

export function TheAuthExpoProvider({ config, children }: TheAuthExpoProviderProps): ReactNode {
	const [session, setSession] = useState<TheAuthSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	const base = config.basePath.replace(/\/$/, "");

	// Stable storage ref so callbacks don't re-create on each render
	const storageRef = useRef<TheAuthStorage>(config.storage ?? createMemoryStorage());

	// Every request goes through this, so a DPoP or pinned fetch applies everywhere.
	const fetchRef = useRef<typeof fetch>(config.fetch ?? fetch);
	useEffect(() => {
		fetchRef.current = config.fetch ?? fetch;
	}, [config.fetch]);

	useEffect(() => {
		storageRef.current = config.storage ?? createMemoryStorage();
	}, [config.storage]);

	const fetchSession = useCallback(async (): Promise<void> => {
		const token = await storageRef.current.getItem(SESSION_KEY);
		if (!token) {
			setSession(null);
			return;
		}

		try {
			const res = await fetchRef.current(`${base}/session`, {
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

	useEffect(() => {
		setIsLoading(true);
		void fetchSession().finally(() => {
			setIsLoading(false);
		});
	}, [fetchSession]);

	const refresh = useCallback(async (): Promise<void> => {
		await fetchSession();
	}, [fetchSession]);

	const signIn = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			try {
				const res = await fetchRef.current(`${base}/sign-in/email`, {
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

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			try {
				const res = await fetchRef.current(`${base}/sign-up/email`, {
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

	const socialConfig = config.social;
	const signInWithProvider = useCallback(
		async (provider: string): Promise<ActionResult> => {
			if (!socialConfig) {
				return { success: false, error: "Social sign-in is not configured" };
			}
			const result = await runSocialSignIn(base, provider, socialConfig, fetchRef.current);
			if (!result.success) return result;
			await storageRef.current.setItem(SESSION_KEY, result.data.token);
			setSession(result.data);
			return { success: true, data: undefined };
		},
		[base, socialConfig],
	);

	const passkeys = config.passkeys;
	const signInWithPasskey = useCallback(
		async (userId?: string): Promise<ActionResult> => {
			if (!passkeys) return { success: false, error: "Passkeys are not configured" };
			const result = await runPasskeySignIn(base, passkeys, fetchRef.current, userId);
			if (!result.success) return result;
			await storageRef.current.setItem(SESSION_KEY, result.data.token);
			setSession(result.data);
			// The sign-in response carries only the user id, so load the full profile.
			void fetchSession();
			return { success: true, data: undefined };
		},
		[base, passkeys, fetchSession],
	);

	const registerPasskey = useCallback(
		async (deviceName?: string): Promise<ActionResult> => {
			if (!passkeys) return { success: false, error: "Passkeys are not configured" };
			const token = await storageRef.current.getItem(SESSION_KEY);
			if (!token) return { success: false, error: "Sign in before adding a passkey" };
			return runPasskeyRegistration(base, passkeys, fetchRef.current, token, deviceName);
		},
		[base, passkeys],
	);

	const appState = config.appState;
	useEffect(() => {
		if (!appState) return;
		const sub = appState.addEventListener("change", (state) => {
			if (state === "active") void fetchSession();
		});
		return () => sub.remove();
	}, [appState, fetchSession]);

	const signOut = useCallback(async (): Promise<void> => {
		const token = await storageRef.current.getItem(SESSION_KEY);
		try {
			if (token) {
				await fetchRef.current(`${base}/sign-out`, {
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
		signInWithProvider,
		signInWithPasskey,
		registerPasskey,
		signOut,
		refresh,
	};

	return <TheAuthExpoContext.Provider value={value}>{children}</TheAuthExpoContext.Provider>;
}

// Backward-compat aliases for the pre-rebrand API.

/** @deprecated Use `TheAuthExpoProvider` instead. Will be removed in a future major version. */
export const AuthExpoProvider = TheAuthExpoProvider;
