import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type {
	ActionResult,
	ExternalAuthConfig,
	KavachContextValue,
	KavachSession,
	KavachUser,
} from "./types.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export const KavachContext = createContext<KavachContextValue | null>(null);

export function useKavachContext(): KavachContextValue {
	const ctx = useContext(KavachContext);
	if (!ctx) {
		throw new Error("useKavachContext must be used inside <KavachProvider>");
	}
	return ctx;
}

// ─── Provider props ───────────────────────────────────────────────────────────

export interface KavachProviderProps {
	children: ReactNode;
	/** Base path where KavachOS is mounted. Defaults to "/api/kavach". */
	basePath?: string;
	/**
	 * External auth mode — delegates authentication to an external API.
	 * When set, KavachOS acts as a thin client:
	 * - User is fetched from `external.apiUrl + external.mePath`
	 * - Login redirects to `external.apiUrl + external.loginPath`
	 * - Logout calls `external.apiUrl + external.logoutPath`
	 * - No localStorage sessions — the external API manages auth via httpOnly cookies
	 *
	 * @example
	 * ```tsx
	 * <KavachProvider external={{
	 *   apiUrl: "http://localhost:8080",
	 *   loginPath: "/auth/github",
	 *   mePath: "/api/auth/me",
	 *   logoutPath: "/auth/logout",
	 * }}>
	 * ```
	 */
	external?: ExternalAuthConfig;
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export function KavachProvider({
	children,
	basePath = "/api/kavach",
	external,
}: KavachProviderProps): ReactNode {
	if (external) {
		return <ExternalProvider config={external}>{children}</ExternalProvider>;
	}
	return <ManagedProvider basePath={basePath}>{children}</ManagedProvider>;
}

// ─── External auth provider ───────────────────────────────────────────────────

function ExternalProvider({
	children,
	config,
}: {
	children: ReactNode;
	config: ExternalAuthConfig;
}): ReactNode {
	const [user, setUser] = useState<KavachUser | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	const apiUrl = config.apiUrl.replace(/\/$/, "");
	const mePath = config.mePath ?? "/api/auth/me";
	const loginPath = config.loginPath ?? "/auth/github";
	const logoutPath = config.logoutPath ?? "/auth/logout";
	const logoutMethod = config.logoutMethod ?? "POST";
	const mapUser = config.mapUser ?? defaultMapUser;

	const refresh = useCallback(async (): Promise<void> => {
		if (typeof window === "undefined") {
			setIsLoading(false);
			return;
		}
		try {
			const res = await fetch(`${apiUrl}${mePath}`, {
				credentials: "include",
			});
			if (res.ok) {
				const data: Record<string, unknown> = await res.json();
				setUser(mapUser(data));
			} else {
				setUser(null);
			}
		} catch {
			setUser(null);
		} finally {
			setIsLoading(false);
		}
	}, [apiUrl, mePath, mapUser]);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	const signIn = useCallback(async (): Promise<ActionResult> => {
		if (typeof window !== "undefined") {
			window.location.href = `${apiUrl}${loginPath}`;
		}
		return { success: true, data: undefined };
	}, [apiUrl, loginPath]);

	const signOut = useCallback(async (): Promise<void> => {
		try {
			await fetch(`${apiUrl}${logoutPath}`, {
				method: logoutMethod,
				credentials: "include",
			});
		} catch {
			// Best effort — clear client state regardless
		}
		setUser(null);
		if (config.onLogout) {
			config.onLogout();
		}
	}, [apiUrl, logoutPath, logoutMethod, config]);

	const signUp = useCallback(async (): Promise<ActionResult> => {
		// External auth doesn't support sign-up separately — redirect to login
		if (typeof window !== "undefined") {
			window.location.href = `${apiUrl}${loginPath}`;
		}
		return { success: true, data: undefined };
	}, [apiUrl, loginPath]);

	const session: KavachSession | null = user ? { token: "__external__", user } : null;

	const value: KavachContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: user !== null,
		signIn,
		signUp,
		signOut,
		refresh,
	};

	return <KavachContext.Provider value={value}>{children}</KavachContext.Provider>;
}

// ─── Default user mapper ──────────────────────────────────────────────────────

function defaultMapUser(data: Record<string, unknown>): KavachUser {
	return {
		id: (data.user_id as string) ?? (data.id as string) ?? (data.sub as string) ?? "unknown",
		email: data.email as string | undefined,
		name: data.name as string | undefined,
		image: (data.avatar as string | undefined) ?? (data.image as string | undefined),
	};
}

// ─── Managed (original) provider ──────────────────────────────────────────────

function ManagedProvider({
	children,
	basePath,
}: {
	children: ReactNode;
	basePath: string;
}): ReactNode {
	const [session, setSession] = useState<KavachSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Strip trailing slash from basePath once
	const base = basePath.replace(/\/$/, "");

	const STORAGE_KEY = "kavach_session";

	const fetchSession = useCallback(async (): Promise<void> => {
		if (typeof window === "undefined") return;
		try {
			const raw = window.localStorage.getItem(STORAGE_KEY);
			if (raw) {
				const stored = JSON.parse(raw) as KavachSession;
				setSession(stored);
			} else {
				setSession(null);
			}
		} catch {
			setSession(null);
		}
	}, []);

	// Restore session from localStorage on mount (only in browser)
	useEffect(() => {
		if (typeof window === "undefined") {
			setIsLoading(false);
			return;
		}
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
				const res = await fetch(`${base}/auth/sign-in`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password }),
				});
				const json = (await res.json()) as
					| { user: KavachUser; session: { token: string; expiresAt: string } }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
					};
				}

				const okBody = json as { user: KavachUser; session: { token: string; expiresAt: string } };
				const sessionData: KavachSession = {
					token: okBody.session.token,
					user: okBody.user,
					expiresAt: okBody.session.expiresAt,
				};
				setSession(sessionData);
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
		},
		[base],
	);

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/auth/sign-up`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password, name }),
				});
				const json = (await res.json()) as
					| { user: KavachUser; token: string }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-up failed (${res.status})`,
					};
				}

				const okBody = json as { user: KavachUser; token: string };
				const sessionData: KavachSession = {
					token: okBody.token,
					user: okBody.user,
				};
				setSession(sessionData);
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
		},
		[base],
	);

	const signOut = useCallback(async (): Promise<void> => {
		setSession(null);
		if (typeof window !== "undefined") {
			window.localStorage.removeItem(STORAGE_KEY);
		}
	}, []);

	const user: KavachUser | null = session?.user ?? null;

	const value: KavachContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: session !== null,
		signIn,
		signUp,
		signOut,
		refresh,
	};

	return <KavachContext.Provider value={value}>{children}</KavachContext.Provider>;
}
