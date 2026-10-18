import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { SecureStorage } from "./storage.js";
import { parseError, parseSession } from "./wire.js";

interface TheAuthUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

interface TheAuthSession {
	token: string;
	user: TheAuthUser;
	expiresAt?: string;
}

type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

interface TheAuthContextValue {
	session: TheAuthSession | null;
	user: TheAuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

export interface ElectronTheAuthProviderProps {
	children: ReactNode;
	basePath?: string;
	/** Custom storage adapter. Defaults to in-memory if not provided. */
	storage?: SecureStorage;
	/** Persist session to secure storage across restarts. Defaults to true. */
	persistSession?: boolean;
	/**
	 * Sign-in route under `basePath`. Default `/auth/username/sign-in`, the route the
	 * username module serves. The core has no email and password route: point this at
	 * your own, or at the one `@glinr/theauth-email` serves (`/auth/sign-in`, with
	 * `identifierField: "email"`).
	 */
	signInPath?: string;
	/** Sign-up route under `basePath`. Default `/auth/username/sign-up`. */
	signUpPath?: string;
	/** Body field that carries the first argument of `signIn` and `signUp`. Default `username`. */
	identifierField?: string;
}

const SESSION_STORAGE_KEY = "theauth:session";

export const ElectronTheAuthContext = createContext<TheAuthContextValue | null>(null);

export function useElectronTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(ElectronTheAuthContext);
	if (!ctx) {
		throw new Error("useElectronTheAuthContext must be used inside <ElectronTheAuthProvider>");
	}
	return ctx;
}

/**
 * Wraps your Electron renderer with TheAuth auth state.
 *
 * Extends the base TheAuthProvider behaviour with:
 * - Session persistence to Electron's safeStorage on sign-in
 * - Session restoration from storage on app launch
 * - Storage cleared on sign-out
 *
 * Pass a SecureStorage created by createElectronStorage() or createIpcStorage()
 * depending on whether your renderer runs with Node integration or via IPC.
 */
export function ElectronTheAuthProvider({
	children,
	basePath = "/api/theauth",
	storage,
	persistSession = true,
	signInPath = "/auth/username/sign-in",
	signUpPath = "/auth/username/sign-up",
	identifierField = "username",
}: ElectronTheAuthProviderProps): ReactNode {
	const [session, setSession] = useState<TheAuthSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	const base = basePath.replace(/\/$/, "");
	// GET /auth/session carries no token, so keep the one sign-in or storage gave us.
	const tokenRef = useRef("");

	const persistToStorage = useCallback(
		async (s: TheAuthSession | null): Promise<void> => {
			if (!storage || !persistSession) return;
			if (s === null) {
				await storage.remove(SESSION_STORAGE_KEY);
			} else {
				await storage.set(SESSION_STORAGE_KEY, JSON.stringify(s));
			}
		},
		[storage, persistSession],
	);

	const restoreFromStorage = useCallback(async (): Promise<TheAuthSession | null> => {
		if (!storage || !persistSession) return null;
		try {
			const raw = await storage.get(SESSION_STORAGE_KEY);
			if (!raw) return null;
			const parsed: unknown = JSON.parse(raw);
			if (
				parsed !== null &&
				typeof parsed === "object" &&
				"token" in parsed &&
				typeof (parsed as TheAuthSession).token === "string" &&
				"user" in parsed &&
				typeof (parsed as TheAuthSession).user === "object"
			) {
				return parsed as TheAuthSession;
			}
			return null;
		} catch {
			return null;
		}
	}, [storage, persistSession]);

	const fetchSession = useCallback(async (): Promise<void> => {
		try {
			const res = await fetch(`${base}/auth/session`, { credentials: "include" });
			if (res.ok) {
				const s = parseSession(await res.json().catch(() => null), tokenRef.current || undefined);
				setSession(s);
				await persistToStorage(s);
			} else if (res.status === 401 || res.status === 403) {
				tokenRef.current = "";
				setSession(null);
				await persistToStorage(null);
			}
			// A 5xx keeps the restored session so a server blip does not sign the user out.
		} catch {
			setSession(null);
		}
	}, [base, persistToStorage]);

	useEffect(() => {
		setIsLoading(true);

		void (async () => {
			const stored = await restoreFromStorage();
			if (stored) {
				tokenRef.current = stored.token;
				setSession(stored);
			}
			// Always verify the session with the server regardless of storage.
			await fetchSession();
			setIsLoading(false);
		})();
	}, [restoreFromStorage, fetchSession]);

	const refresh = useCallback(async (): Promise<void> => {
		await fetchSession();
	}, [fetchSession]);

	const signIn = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}${signInPath}`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ [identifierField]: email, password }),
				});
				const json: unknown = await res.json().catch(() => null);

				if (!res.ok) {
					return { success: false, error: parseError(json, `Sign-in failed (${res.status})`) };
				}

				const s = parseSession(json);
				if (!s) return { success: false, error: "Sign-in returned an unexpected response" };
				tokenRef.current = s.token;
				setSession(s);
				await persistToStorage(s);
				return { success: true, data: undefined };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base, signInPath, identifierField, persistToStorage],
	);

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}${signUpPath}`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ [identifierField]: email, password, name }),
				});
				const json: unknown = await res.json().catch(() => null);

				if (!res.ok) {
					return { success: false, error: parseError(json, `Sign-up failed (${res.status})`) };
				}

				const s = parseSession(json);
				if (!s) return { success: false, error: "Sign-up returned an unexpected response" };
				tokenRef.current = s.token;
				setSession(s);
				await persistToStorage(s);
				return { success: true, data: undefined };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base, signUpPath, identifierField, persistToStorage],
	);

	const signOut = useCallback(async (): Promise<void> => {
		try {
			await fetch(`${base}/auth/sign-out`, {
				method: "POST",
				credentials: "include",
			});
		} finally {
			tokenRef.current = "";
			setSession(null);
			await persistToStorage(null);
		}
	}, [base, persistToStorage]);

	const value: TheAuthContextValue = {
		session,
		user: session?.user ?? null,
		isLoading,
		isAuthenticated: session !== null,
		signIn,
		signUp,
		signOut,
		refresh,
	};

	return (
		<ElectronTheAuthContext.Provider value={value}>{children}</ElectronTheAuthContext.Provider>
	);
}

// Kept for backward compatibility with the pre-rebrand "TheAuth" API. Will be
// removed in a future major version.
