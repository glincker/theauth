import type { ReactNode } from "react";
import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useRef,
	useState,
} from "react";
import type {
	ActionResult,
	ExternalAuthConfig,
	RotateErrorCode,
	RotateResult,
	RotateRetryConfig,
	RotationStatus,
	TheAuthContextValue,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export const TheAuthContext = createContext<TheAuthContextValue | null>(null);

export function useTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(TheAuthContext);
	if (!ctx) {
		throw new Error("useTheAuthContext must be used inside <TheAuthProvider>");
	}
	return ctx;
}

// ─── Provider props ───────────────────────────────────────────────────────────

export interface TheAuthProviderProps {
	children: ReactNode;
	/** Base path where TheAuth is mounted. Defaults to "/api/kavach". */
	basePath?: string;
	/**
	 * External auth mode - delegates authentication to an external API.
	 * When set, TheAuth acts as a thin client:
	 * - User is fetched from `external.apiUrl + external.mePath`
	 * - Login redirects to `external.apiUrl + external.loginPath`
	 * - Logout calls `external.apiUrl + external.logoutPath`
	 * - No localStorage sessions - the external API manages auth via httpOnly cookies
	 *
	 * @example
	 * ```tsx
	 * <TheAuthProvider external={{
	 *   apiUrl: "http://localhost:8080",
	 *   loginPath: "/auth/github",
	 *   mePath: "/api/auth/me",
	 *   logoutPath: "/auth/logout",
	 *   refreshPath: "/auth/refresh",
	 * }}>
	 * ```
	 */
	external?: ExternalAuthConfig;
	/**
	 * Enable verbose console logging of auth state transitions
	 * (mount, /me result, signIn, signOut, rotation start/success/failure,
	 * proactive timer scheduling, online/offline events).
	 *
	 * Useful when integrating against a new backend. Defaults to `false`.
	 *
	 * Also enabled at runtime when `localStorage.DEBUG === "theauth"` so
	 * consumers can flip it on without redeploying.
	 */
	debug?: boolean;
}

// ─── Debug helper ─────────────────────────────────────────────────────────────

function resolveDebug(propDebug?: boolean): boolean {
	if (propDebug) return true;
	if (typeof window === "undefined") return false;
	try {
		return window.localStorage.getItem("DEBUG") === "theauth";
	} catch {
		return false;
	}
}

function makeLogger(enabled: boolean) {
	return (_event: string, _detail?: unknown): void => {
		if (!enabled) return;
	};
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export function TheAuthProvider({
	children,
	basePath = "/api/kavach",
	external,
	debug,
}: TheAuthProviderProps): ReactNode {
	const debugEnabled = resolveDebug(debug);
	if (external) {
		return (
			<ExternalProvider config={external} debug={debugEnabled}>
				{children}
			</ExternalProvider>
		);
	}
	return (
		<ManagedProvider basePath={basePath} debug={debugEnabled}>
			{children}
		</ManagedProvider>
	);
}

// ─── Rotation defaults ────────────────────────────────────────────────────────

const DEFAULT_PROACTIVE_LEAD_MS = 120_000;
const DEFAULT_RETRY: Required<RotateRetryConfig> = {
	maxRetries: 3,
	initialDelayMs: 1_000,
	backoffMultiplier: 2,
	maxDelayMs: 10_000,
	requestTimeoutMs: 15_000,
};

const AUTH_ERROR_CODES: ReadonlySet<RotateErrorCode> = new Set([
	"token_missing",
	"token_not_found",
	"token_expired",
	"token_reuse",
	"family_revoked",
	"absolute_timeout",
]);

const KNOWN_SERVER_CODES: ReadonlySet<RotateErrorCode> = new Set([
	"token_missing",
	"token_not_found",
	"token_expired",
	"token_reuse",
	"family_revoked",
	"absolute_timeout",
]);

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeNoopRotation(message: string): () => Promise<RotateResult> {
	return async (): Promise<RotateResult> => ({
		success: false,
		code: "network_error",
		message,
	});
}

// ─── External auth provider ───────────────────────────────────────────────────

function ExternalProvider({
	children,
	config,
	debug = false,
}: {
	children: ReactNode;
	config: ExternalAuthConfig;
	debug?: boolean;
}): ReactNode {
	// Stable identity across renders so useCallback deps don't churn.
	const log = useMemo(() => makeLogger(debug), [debug]);
	const [user, setUser] = useState<TheAuthUser | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [rotationStatus, setRotationStatus] = useState<RotationStatus>("idle");
	const [isOnline, setIsOnline] = useState<boolean>(() =>
		typeof navigator !== "undefined" ? navigator.onLine : true,
	);

	const apiUrl = config.apiUrl.replace(/\/$/, "");
	const mePath = config.mePath ?? "/api/auth/me";
	const loginPath = config.loginPath ?? "/auth/github";
	const logoutPath = config.logoutPath ?? "/auth/logout";
	const logoutMethod = config.logoutMethod ?? "POST";
	const mapUser = config.mapUser ?? defaultMapUser;

	const refreshPath = config.refreshPath;
	const rotationEnabled = typeof refreshPath === "string" && refreshPath.length > 0;
	const proactiveLeadMs = config.proactiveRefreshLeadMs ?? DEFAULT_PROACTIVE_LEAD_MS;
	// Memoize so deeper useCallback deps don't churn on every render.
	const retryCfg: Required<RotateRetryConfig> = useMemo(
		() => ({
			maxRetries: config.retry?.maxRetries ?? DEFAULT_RETRY.maxRetries,
			initialDelayMs: config.retry?.initialDelayMs ?? DEFAULT_RETRY.initialDelayMs,
			backoffMultiplier: config.retry?.backoffMultiplier ?? DEFAULT_RETRY.backoffMultiplier,
			maxDelayMs: config.retry?.maxDelayMs ?? DEFAULT_RETRY.maxDelayMs,
			requestTimeoutMs: config.retry?.requestTimeoutMs ?? DEFAULT_RETRY.requestTimeoutMs,
		}),
		[
			config.retry?.maxRetries,
			config.retry?.initialDelayMs,
			config.retry?.backoffMultiplier,
			config.retry?.maxDelayMs,
			config.retry?.requestTimeoutMs,
		],
	);

	// Refs survive re-renders without invalidating callbacks.
	const inFlightRef = useRef<Promise<RotateResult> | null>(null);
	const proactiveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
	const expiresAtRef = useRef<number | null>(null);
	const queuedWhileOfflineRef = useRef<boolean>(false);
	const onAuthErrorRef = useRef(config.onAuthError);
	const onSessionRotatedRef = useRef(config.onSessionRotated);
	const errorCodeMapRef = useRef(config.errorCodeMap);

	// Keep callback refs current without re-running rotation effects.
	useEffect(() => {
		onAuthErrorRef.current = config.onAuthError;
		onSessionRotatedRef.current = config.onSessionRotated;
		errorCodeMapRef.current = config.errorCodeMap;
	}, [config.onAuthError, config.onSessionRotated, config.errorCodeMap]);

	// ── /me bootstrap ──────────────────────────────────────────────────────

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
				const mapped = mapUser(data);
				setUser(mapped);
				log("me:authenticated", { userId: mapped.id });
			} else {
				setUser(null);
				log("me:unauthenticated", { status: res.status });
			}
		} catch (err) {
			setUser(null);
			log("me:network-error", { error: (err as Error).message });
		} finally {
			setIsLoading(false);
		}
	}, [apiUrl, mePath, mapUser, log]);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	// ── Rotation core ──────────────────────────────────────────────────────

	const mapServerCode = useCallback((raw: unknown): RotateErrorCode => {
		if (typeof raw !== "string") return "unknown";
		const override = errorCodeMapRef.current?.[raw];
		if (override) return override;
		if (KNOWN_SERVER_CODES.has(raw as RotateErrorCode)) {
			return raw as RotateErrorCode;
		}
		return "unknown";
	}, []);

	const performAttempt = useCallback(
		async (attempt: number): Promise<RotateResult> => {
			if (typeof window === "undefined" || !rotationEnabled) {
				return {
					success: false,
					code: "network_error",
					message: "Rotation unavailable",
				};
			}

			if (typeof navigator !== "undefined" && !navigator.onLine) {
				queuedWhileOfflineRef.current = true;
				return {
					success: false,
					code: "network_error",
					message: "Offline",
				};
			}

			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), retryCfg.requestTimeoutMs);

			try {
				const res = await fetch(`${apiUrl}${refreshPath}`, {
					method: "POST",
					credentials: "include",
					signal: controller.signal,
					headers: { "X-Retry-Attempt": String(attempt) },
				});

				clearTimeout(timeoutId);

				if (res.ok) {
					let parsed: { accessTokenExpiresAt?: string } = {};
					try {
						parsed = (await res.json()) as { accessTokenExpiresAt?: string };
					} catch {
						// Tolerate empty body — server may rotate via cookies only.
					}
					const expiresAt = parsed.accessTokenExpiresAt
						? new Date(parsed.accessTokenExpiresAt)
						: null;
					if (expiresAt && !Number.isNaN(expiresAt.getTime())) {
						return { success: true, accessTokenExpiresAt: expiresAt };
					}
					// No usable expiry — still success, but we cannot schedule next.
					return {
						success: true,
						accessTokenExpiresAt: new Date(Date.now() + proactiveLeadMs * 5),
					};
				}

				// Non-2xx — try to parse the canonical error envelope.
				let body: { error?: unknown } = {};
				try {
					body = (await res.json()) as { error?: unknown };
				} catch {
					// ignore parse failure
				}

				if (res.status === 401) {
					const code = mapServerCode(body.error);
					return {
						success: false,
						code,
						message: typeof body.error === "string" ? body.error : "Unauthorized",
					};
				}

				if (res.status >= 500) {
					if (attempt < retryCfg.maxRetries) {
						const delay = Math.min(
							retryCfg.initialDelayMs * retryCfg.backoffMultiplier ** (attempt - 1),
							retryCfg.maxDelayMs,
						);
						await sleep(delay);
						return performAttempt(attempt + 1);
					}
					return {
						success: false,
						code: "server_error",
						message: `Server error (${res.status})`,
					};
				}

				return {
					success: false,
					code: "unknown",
					message: `Unexpected status ${res.status}`,
				};
			} catch (error) {
				clearTimeout(timeoutId);

				const isAbort = error instanceof DOMException && error.name === "AbortError";
				const isNetwork = error instanceof TypeError || isAbort;

				if (isNetwork && attempt < retryCfg.maxRetries) {
					const delay = Math.min(
						retryCfg.initialDelayMs * retryCfg.backoffMultiplier ** (attempt - 1),
						retryCfg.maxDelayMs,
					);
					await sleep(delay);
					return performAttempt(attempt + 1);
				}

				return {
					success: false,
					code: isNetwork ? "network_error" : "unknown",
					message: error instanceof Error ? error.message : "Unknown error",
				};
			}
		},
		[apiUrl, refreshPath, rotationEnabled, retryCfg, proactiveLeadMs, mapServerCode],
	);

	// Forward declaration via ref breaks the circular runRotation ↔ scheduleProactive
	// dependency. The ref is assigned after runRotation is created (effect below);
	// scheduleProactive reads the current rotation function at firing time.
	const runRotationRef = useRef<(() => Promise<RotateResult>) | null>(null);

	const scheduleProactive = useCallback(
		(expiresAtMs: number) => {
			if (typeof window === "undefined" || !rotationEnabled) return;
			if (proactiveLeadMs <= 0) return;

			if (proactiveTimerRef.current) {
				clearTimeout(proactiveTimerRef.current);
				proactiveTimerRef.current = null;
			}

			const delay = Math.max(0, expiresAtMs - Date.now() - proactiveLeadMs);
			proactiveTimerRef.current = setTimeout(() => {
				proactiveTimerRef.current = null;
				void runRotationRef.current?.();
			}, delay);
		},
		[rotationEnabled, proactiveLeadMs],
	);

	const runRotation = useCallback(async (): Promise<RotateResult> => {
		if (!rotationEnabled) {
			return {
				success: false,
				code: "network_error",
				message: "refreshPath not configured",
			};
		}
		if (inFlightRef.current) {
			return inFlightRef.current;
		}

		setRotationStatus("rotating");
		log("rotate:start");
		const promise = (async (): Promise<RotateResult> => {
			const result = await performAttempt(1);

			if (result.success) {
				expiresAtRef.current = result.accessTokenExpiresAt.getTime();
				queuedWhileOfflineRef.current = false;
				scheduleProactive(result.accessTokenExpiresAt.getTime());
				setRotationStatus("idle");
				log("rotate:success", {
					expiresAt: result.accessTokenExpiresAt.toISOString(),
				});
				try {
					onSessionRotatedRef.current?.({
						accessTokenExpiresAt: result.accessTokenExpiresAt,
					});
				} catch {
					// Consumer callback failures must not break rotation flow.
				}
			} else {
				setRotationStatus("error");
				log("rotate:failure", { code: result.code, message: result.message });
				if (AUTH_ERROR_CODES.has(result.code)) {
					try {
						onAuthErrorRef.current?.(result.code);
					} catch {
						// ignore
					}
				}
			}

			return result;
		})();

		inFlightRef.current = promise;
		try {
			return await promise;
		} finally {
			inFlightRef.current = null;
		}
	}, [rotationEnabled, performAttempt, scheduleProactive, log]);

	// Keep the forward-ref in sync so scheduleProactive's setTimeout can dispatch
	// to the current rotation function across re-renders.
	useEffect(() => {
		runRotationRef.current = runRotation;
	}, [runRotation]);

	// ── Online / offline tracking ──────────────────────────────────────────

	useEffect(() => {
		if (typeof window === "undefined") return;

		const handleOnline = () => {
			setIsOnline(true);
			log("network:online");
			if (!rotationEnabled) return;
			if (queuedWhileOfflineRef.current) {
				queuedWhileOfflineRef.current = false;
				void runRotation();
			} else if (expiresAtRef.current) {
				scheduleProactive(expiresAtRef.current);
			}
		};
		const handleOffline = () => {
			setIsOnline(false);
			log("network:offline");
		};

		window.addEventListener("online", handleOnline);
		window.addEventListener("offline", handleOffline);
		return () => {
			window.removeEventListener("online", handleOnline);
			window.removeEventListener("offline", handleOffline);
		};
	}, [rotationEnabled, runRotation, scheduleProactive, log]);

	// ── Proactive bootstrap once user is loaded ────────────────────────────

	useEffect(() => {
		if (typeof window === "undefined") return;
		if (!rotationEnabled) return;
		if (!user) return;
		// Proactive rotation is opt-out: setting `proactiveRefreshLeadMs: 0`
		// disables the bootstrap rotation and the timer entirely.
		if (proactiveLeadMs <= 0) return;

		// If we already have a cached expiry (e.g. server-rendered), either
		// rotate immediately when within the lead window or schedule the timer.
		// Otherwise rotate once on mount to learn an expiry.
		if (expiresAtRef.current) {
			const ms = expiresAtRef.current - Date.now() - proactiveLeadMs;
			if (ms <= 0) {
				void runRotation();
			} else {
				scheduleProactive(expiresAtRef.current);
			}
		} else {
			void runRotation();
		}

		return () => {
			if (proactiveTimerRef.current) {
				clearTimeout(proactiveTimerRef.current);
				proactiveTimerRef.current = null;
			}
		};
	}, [user, rotationEnabled, proactiveLeadMs, runRotation, scheduleProactive]);

	// ── Auth actions ───────────────────────────────────────────────────────

	const signIn = useCallback(async (): Promise<ActionResult> => {
		log("signIn:redirect", { url: `${apiUrl}${loginPath}` });
		if (typeof window !== "undefined") {
			window.location.href = `${apiUrl}${loginPath}`;
		}
		return { success: true, data: undefined };
	}, [apiUrl, loginPath, log]);

	const signOut = useCallback(async (): Promise<void> => {
		log("signOut:start");
		try {
			await fetch(`${apiUrl}${logoutPath}`, {
				method: logoutMethod,
				credentials: "include",
			});
		} catch {
			// Best effort — clear client state regardless
		}
		if (proactiveTimerRef.current) {
			clearTimeout(proactiveTimerRef.current);
			proactiveTimerRef.current = null;
		}
		expiresAtRef.current = null;
		queuedWhileOfflineRef.current = false;
		setRotationStatus("idle");
		setUser(null);
		log("signOut:complete");
		if (config.onLogout) {
			config.onLogout();
		}
	}, [apiUrl, logoutPath, logoutMethod, config, log]);

	const signUp = useCallback(async (): Promise<ActionResult> => {
		// External auth doesn't support sign-up separately — redirect to login
		if (typeof window !== "undefined") {
			window.location.href = `${apiUrl}${loginPath}`;
		}
		return { success: true, data: undefined };
	}, [apiUrl, loginPath]);

	const session: TheAuthSession | null = user ? { token: "__external__", user } : null;

	const value: TheAuthContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: user !== null,
		signIn,
		signUp,
		signOut,
		refresh,
		rotateSession: runRotation,
		rotationStatus,
		isOnline,
	};

	return <TheAuthContext.Provider value={value}>{children}</TheAuthContext.Provider>;
}

// ─── Default user mapper ──────────────────────────────────────────────────────

function defaultMapUser(data: Record<string, unknown>): TheAuthUser {
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
	debug = false,
}: {
	children: ReactNode;
	basePath: string;
	debug?: boolean;
}): ReactNode {
	const log = useMemo(() => makeLogger(debug), [debug]);
	const [session, setSession] = useState<TheAuthSession | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [isOnline, setIsOnline] = useState<boolean>(() =>
		typeof navigator !== "undefined" ? navigator.onLine : true,
	);

	// Strip trailing slash from basePath once
	const base = basePath.replace(/\/$/, "");

	const STORAGE_KEY = "kavach_session";

	const fetchSession = useCallback(async (): Promise<void> => {
		if (typeof window === "undefined") return;
		try {
			const raw = window.localStorage.getItem(STORAGE_KEY);
			if (raw) {
				const stored = JSON.parse(raw) as TheAuthSession;
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

	// Track online/offline so the value is stable across providers.
	useEffect(() => {
		if (typeof window === "undefined") return;
		const handleOnline = () => setIsOnline(true);
		const handleOffline = () => setIsOnline(false);
		window.addEventListener("online", handleOnline);
		window.addEventListener("offline", handleOffline);
		return () => {
			window.removeEventListener("online", handleOnline);
			window.removeEventListener("offline", handleOffline);
		};
	}, []);

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
					| { user: TheAuthUser; session: { token: string; expiresAt: string } }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
					};
				}

				const okBody = json as { user: TheAuthUser; session: { token: string; expiresAt: string } };
				const sessionData: TheAuthSession = {
					token: okBody.session.token,
					user: okBody.user,
					expiresAt: okBody.session.expiresAt,
				};
				setSession(sessionData);
				log("signIn:success", { userId: okBody.user.id });
				if (typeof window !== "undefined") {
					window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sessionData));
				}
				return { success: true, data: undefined };
			} catch (err) {
				log("signIn:error", { error: (err as Error).message });
				return {
					success: false,
					error: err instanceof Error ? err.message : "Network error",
				};
			}
		},
		[base, log],
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
					| { user: TheAuthUser; token: string }
					| { error: { code: string; message: string } };

				if (!res.ok) {
					const errBody = json as { error: { code: string; message: string } };
					return {
						success: false,
						error: errBody.error?.message ?? `Sign-up failed (${res.status})`,
					};
				}

				const okBody = json as { user: TheAuthUser; token: string };
				const sessionData: TheAuthSession = {
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
		log("signOut");
		setSession(null);
		if (typeof window !== "undefined") {
			window.localStorage.removeItem(STORAGE_KEY);
		}
	}, [log]);

	const user: TheAuthUser | null = session?.user ?? null;

	const rotateSession = useCallback(
		makeNoopRotation("rotateSession is only available in external mode with refreshPath set"),
		[],
	);

	const value: TheAuthContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: session !== null,
		signIn,
		signUp,
		signOut,
		refresh,
		rotateSession,
		rotationStatus: "idle",
		isOnline,
	};

	return <TheAuthContext.Provider value={value}>{children}</TheAuthContext.Provider>;
}

// ─── Deprecated aliases ─────────────────────────────────────────────────────
// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthContext` instead. Will be removed in a future major version. */
export const AuthContext = TheAuthContext;

/** @deprecated Use `TheAuthContext` instead. Will be removed in a future major version. */
export const KavachContext = TheAuthContext;

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useAuthContext = useTheAuthContext;

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useKavachContext = useTheAuthContext;

/** @deprecated Use `TheAuthProvider` instead. Will be removed in a future major version. */
export const AuthProvider = TheAuthProvider;

/** @deprecated Use `TheAuthProvider` instead. Will be removed in a future major version. */
export const KavachProvider = TheAuthProvider;

/** @deprecated Use `TheAuthProviderProps` instead. Will be removed in a future major version. */
export type AuthProviderProps = TheAuthProviderProps;

/** @deprecated Use `TheAuthProviderProps` instead. Will be removed in a future major version. */
export type KavachProviderProps = TheAuthProviderProps;
