import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { runPasskeyRegistration, runPasskeySignIn } from "./passkey.js";
import { runSocialSignIn } from "./social.js";
import { createMemoryStorage } from "./storage.js";
import type {
	ActionResult,
	SignUpData,
	TheAuthContextValue,
	TheAuthExpoConfig,
	TheAuthSession,
	TheAuthStorage,
	TheAuthUser,
} from "./types.js";
import { failure, isVerificationRequired, parseSession } from "./wire.js";

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
	const signInPath =
		config.signInPath ?? (config.emailPassword ? "/auth/email/sign-in" : "/auth/username/sign-in");
	const signUpPath =
		config.signUpPath ?? (config.emailPassword ? "/auth/email/sign-up" : "/auth/username/sign-up");
	const identifierField = config.identifierField ?? (config.emailPassword ? "email" : "username");

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
			const res = await fetchRef.current(`${base}/auth/session`, {
				headers: { Authorization: `Bearer ${token}` },
			});
			if (res.ok) {
				// GET /auth/session carries no token, so keep the one we sent.
				const next = parseSession(await res.json().catch(() => null), token);
				setSession(next);
				if (!next) {
					await storageRef.current.removeItem(SESSION_KEY);
				}
			} else if (res.status === 401 || res.status === 403) {
				setSession(null);
				await storageRef.current.removeItem(SESSION_KEY);
			}
			// A 5xx keeps the stored token so a server blip does not sign the user out.
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
				const res = await fetchRef.current(`${base}${signInPath}`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ [identifierField]: email, password }),
				});

				const json: unknown = await res.json().catch(() => null);

				if (!res.ok) {
					return failure(json, `Sign-in failed (${res.status})`);
				}

				const next = parseSession(json);
				if (!next) return { success: false, error: "Sign-in returned an unexpected response" };
				await storageRef.current.setItem(SESSION_KEY, next.token);
				setSession(next);
				return { success: true, data: undefined };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base, signInPath, identifierField],
	);

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult<SignUpData>> => {
			try {
				const res = await fetchRef.current(`${base}${signUpPath}`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ [identifierField]: email, password, name }),
				});

				const json: unknown = await res.json().catch(() => null);

				if (!res.ok) {
					return failure(json, `Sign-up failed (${res.status})`);
				}

				// The account exists but has no session yet: the user verifies, then signs in.
				if (isVerificationRequired(json)) {
					return { success: true, data: { verificationRequired: true } };
				}

				const next = parseSession(json);
				if (!next) return { success: false, error: "Sign-up returned an unexpected response" };
				await storageRef.current.setItem(SESSION_KEY, next.token);
				setSession(next);
				return { success: true, data: { verificationRequired: false } };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base, signUpPath, identifierField],
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
				await fetchRef.current(`${base}/auth/sign-out`, {
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
