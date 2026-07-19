import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { SecureStorage } from "./storage.js";

// ─── Types ────────────────────────────────────────────────────────────────────

interface KavachUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

interface KavachSession {
	token: string;
	user: KavachUser;
	expiresAt?: string;
}

type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

interface KavachContextValue {
	session: KavachSession | null;
	user: KavachUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

export interface ElectronTheAuthProviderProps {
	children: ReactNode;
	/** Base path where TheAuth is mounted. Defaults to "/api/kavach". */
	basePath?: string;
	/** Custom storage adapter. Defaults to in-memory if not provided. */
	storage?: SecureStorage;
	/** Persist session to secure storage across restarts. Defaults to true. */
	persistSession?: boolean;
}

/** @deprecated Use `ElectronTheAuthProviderProps` instead. Will be removed in a future major version. */
export type ElectronKavachProviderProps = ElectronTheAuthProviderProps;

// ─── Storage key ──────────────────────────────────────────────────────────────

const SESSION_STORAGE_KEY = "kavach:session";

// ─── Context ──────────────────────────────────────────────────────────────────

export const ElectronTheAuthContext = createContext<KavachContextValue | null>(null);

/** @deprecated Use `ElectronTheAuthContext` instead. Will be removed in a future major version. */
export const ElectronKavachContext = ElectronTheAuthContext;

export function useElectronTheAuthContext(): KavachContextValue {
	const ctx = useContext(ElectronTheAuthContext);
	if (!ctx) {
		throw new Error("useElectronTheAuthContext must be used inside <ElectronTheAuthProvider>");
	}
	return ctx;
}

/** @deprecated Use `useElectronTheAuthContext` instead. Will be removed in a future major version. */
export const useElectronKavachContext = useElectronTheAuthContext;

// ─── JSON fetch helpers ───────────────────────────────────────────────────────

type JsonErrorBody = { error?: { code?: string; message?: string } };

function extractErrorMessage(body: unknown, fallback: string): string {
	if (
		body !== null &&
		typeof body === "object" &&
		"error" in body &&
		typeof (body as JsonErrorBody).error === "object" &&
		typeof (body as JsonErrorBody).error?.message === "string"
	) {
		return (body as JsonErrorBody).error?.message ?? fallback;
	}
	return fallback;
}

// ─── Provider ─────────────────────────────────────────────────────────────────

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
	basePath = "/api/kavach",
	storage,
	persistSession = true,
}: ElectronTheAuthProviderProps): ReactNode {
	const [session, setSession] = useState<KavachSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	const base = basePath.replace(/\/$/, "");

	// ── Persist / restore helpers ───────────────────────────────────────────

	const persistToStorage = useCallback(
		async (s: KavachSession | null): Promise<void> => {
			if (!storage || !persistSession) return;
			if (s === null) {
				await storage.remove(SESSION_STORAGE_KEY);
			} else {
				await storage.set(SESSION_STORAGE_KEY, JSON.stringify(s));
			}
		},
		[storage, persistSession],
	);

	const restoreFromStorage = useCallback(async (): Promise<KavachSession | null> => {
		if (!storage || !persistSession) return null;
		try {
			const raw = await storage.get(SESSION_STORAGE_KEY);
			if (!raw) return null;
			const parsed: unknown = JSON.parse(raw);
			if (
				parsed !== null &&
				typeof parsed === "object" &&
				"token" in parsed &&
				typeof (parsed as KavachSession).token === "string" &&
				"user" in parsed &&
				typeof (parsed as KavachSession).user === "object"
			) {
				return parsed as KavachSession;
			}
			return null;
		} catch {
			return null;
		}
	}, [storage, persistSession]);

	// ── Session fetch ───────────────────────────────────────────────────────

	const fetchSession = useCallback(async (): Promise<void> => {
		try {
			const res = await fetch(`${base}/session`, { credentials: "include" });
			if (res.ok) {
				const json = (await res.json()) as { data?: KavachSession };
				const s = json.data ?? null;
				setSession(s);
				await persistToStorage(s);
			} else {
				setSession(null);
			}
		} catch {
			setSession(null);
		}
	}, [base, persistToStorage]);

	// ── Mount: restore from storage, then verify with server ───────────────

	useEffect(() => {
		setIsLoading(true);

		void (async () => {
			const stored = await restoreFromStorage();
			if (stored) {
				setSession(stored);
			}
			// Always verify the session with the server regardless of storage.
			await fetchSession();
			setIsLoading(false);
		})();
	}, [restoreFromStorage, fetchSession]);

	// ── Auth actions ────────────────────────────────────────────────────────

	const refresh = useCallback(async (): Promise<void> => {
		await fetchSession();
	}, [fetchSession]);

	const signIn = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/sign-in/email`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password }),
				});
				const json = (await res.json()) as
					| { data: KavachSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					return {
						success: false,
						error: extractErrorMessage(json, `Sign-in failed (${res.status})`),
					};
				}

				const s = (json as { data: KavachSession }).data;
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
		[base, persistToStorage],
	);

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> => {
			try {
				const res = await fetch(`${base}/sign-up/email`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email, password, name }),
				});
				const json = (await res.json()) as
					| { data: KavachSession }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					return {
						success: false,
						error: extractErrorMessage(json, `Sign-up failed (${res.status})`),
					};
				}

				const s = (json as { data: KavachSession }).data;
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
		[base, persistToStorage],
	);

	const signOut = useCallback(async (): Promise<void> => {
		try {
			await fetch(`${base}/sign-out`, {
				method: "POST",
				credentials: "include",
			});
		} finally {
			setSession(null);
			await persistToStorage(null);
		}
	}, [base, persistToStorage]);

	// ── Context value ───────────────────────────────────────────────────────

	const value: KavachContextValue = {
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

// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `ElectronTheAuthProvider` instead. Will be removed in a future major version. */
export const ElectronKavachProvider = ElectronTheAuthProvider;
