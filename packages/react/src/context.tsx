import type { SessionStorageLike, StoreActionResult } from "@glinr/theauth-client";
import { attachRefetch, createSessionStore } from "@glinr/theauth-client";
import type { ReactNode } from "react";
import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useRef,
	useState,
	useSyncExternalStore,
} from "react";
import type {
	ActionResult,
	ExternalAuthConfig,
	ManagedAuthConfig,
	RotateErrorCode,
	RotateResult,
	RotateRetryConfig,
	RotationStatus,
	TheAuthContextValue,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";

export const TheAuthContext = createContext<TheAuthContextValue | null>(null);

export function useTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(TheAuthContext);
	if (!ctx) {
		throw new Error("useTheAuthContext must be used inside <TheAuthProvider>");
	}
	return ctx;
}

export interface TheAuthProviderProps {
	children: ReactNode;
	/** Base path where TheAuth is mounted. Defaults to "/api/theauth". */
	basePath?: string;
	/**
	 * Delegates authentication to an external API. Sessions live in httpOnly cookies,
	 * not localStorage. Paths are joined onto `external.apiUrl`.
	 */
	external?: ExternalAuthConfig;
	/** Options for the built in session store (refetch triggers, SSR seed, route paths). */
	managed?: ManagedAuthConfig;
	/** Logs auth state transitions to the console. Also on when `localStorage.DEBUG === "theauth"`. */
	debug?: boolean;
}

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

export function TheAuthProvider({
	children,
	basePath = "/api/theauth",
	external,
	managed,
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
		<ManagedProvider basePath={basePath} debug={debugEnabled} managed={managed}>
			{children}
		</ManagedProvider>
	);
}

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
	const [user, setUser] = useState<TheAuthUser | null>(config.initialUser ?? null);
	const [isLoading, setIsLoading] = useState(config.initialUser === undefined);
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
			// Keep the current user: a dropped connection is not a sign-out.
			log("me:network-error", { error: (err as Error).message });
		} finally {
			setIsLoading(false);
		}
	}, [apiUrl, mePath, mapUser, log]);

	const hydratedRef = useRef(config.initialUser !== undefined);
	useEffect(() => {
		// A user seeded from the server needs no first request.
		if (hydratedRef.current) {
			hydratedRef.current = false;
			return;
		}
		void refresh();
	}, [refresh]);

	// Refetch on focus, reconnect or an interval. `refresh` never overlaps itself:
	// a trigger while one is running is dropped.
	const refetchRef = useRef(config.refetch);
	refetchRef.current = config.refetch;
	const refreshingRef = useRef(false);
	useEffect(() => {
		if (!refetchRef.current) return;
		return attachRefetch(() => {
			if (refreshingRef.current) return;
			refreshingRef.current = true;
			void refresh().finally(() => {
				refreshingRef.current = false;
			});
		}, refetchRef.current);
	}, [refresh]);

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
						// Tolerate empty body: server may rotate via cookies only.
					}
					const expiresAt = parsed.accessTokenExpiresAt
						? new Date(parsed.accessTokenExpiresAt)
						: null;
					if (expiresAt && !Number.isNaN(expiresAt.getTime())) {
						return { success: true, accessTokenExpiresAt: expiresAt };
					}
					// No usable expiry: still success, but the next rotation cannot be scheduled.
					return {
						success: true,
						accessTokenExpiresAt: new Date(Date.now() + proactiveLeadMs * 5),
					};
				}

				let body: { error?: unknown } = {};
				try {
					body = (await res.json()) as { error?: unknown };
				} catch {}

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

	// Forward ref breaks the runRotation <-> scheduleProactive cycle. Assigned after runRotation exists.
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
					} catch {}
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

	useEffect(() => {
		runRotationRef.current = runRotation;
	}, [runRotation]);

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

	useEffect(() => {
		if (typeof window === "undefined") return;
		if (!rotationEnabled) return;
		if (!user) return;
		// proactiveRefreshLeadMs: 0 disables bootstrap rotation and the timer.
		if (proactiveLeadMs <= 0) return;

		// Cached expiry: rotate now if inside the lead window, else schedule. No expiry: rotate once.
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
			// Best effort: clear client state regardless
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
		// External auth has no separate sign-up, so redirect to login
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

function defaultMapUser(data: Record<string, unknown>): TheAuthUser {
	return {
		id: (data.user_id as string) ?? (data.id as string) ?? (data.sub as string) ?? "unknown",
		email: data.email as string | undefined,
		name: data.name as string | undefined,
		image: (data.avatar as string | undefined) ?? (data.image as string | undefined),
	};
}

function browserStorage(): SessionStorageLike | undefined {
	try {
		return typeof window === "undefined" ? undefined : window.localStorage;
	} catch {
		return undefined;
	}
}

function toActionResult(r: StoreActionResult): ActionResult {
	return r.success ? { success: true, data: undefined } : { success: false, error: r.error };
}

function ManagedProvider({
	children,
	basePath,
	debug = false,
	managed,
}: {
	children: ReactNode;
	basePath: string;
	debug?: boolean;
	managed?: ManagedAuthConfig;
}): ReactNode {
	const log = useMemo(() => makeLogger(debug), [debug]);
	const [isOnline, setIsOnline] = useState<boolean>(() =>
		typeof navigator !== "undefined" ? navigator.onLine : true,
	);

	const base = basePath.replace(/\/$/, "");
	// The store holds the session. Options are read once per base path, like the other
	// bindings, so pass a stable `managed` object or none.
	const managedRef = useRef(managed);
	managedRef.current = managed;
	const store = useMemo(() => {
		const m = managedRef.current;
		const created = createSessionStore({
			basePath: base,
			storage: browserStorage(),
			signInPath: m?.signInPath,
			signUpPath: m?.signUpPath,
			identifierField: m?.identifierField,
			refetch: m?.refetch,
		});
		if (m?.initialSession !== undefined) created.hydrateSession(m.initialSession);
		return created;
	}, [base]);
	const state = useSyncExternalStore(store.subscribe, store.getState, store.getState);

	useEffect(() => {
		if (managedRef.current?.initialSession === undefined) void store.refresh();
		return () => store.destroy();
	}, [store]);

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

	const refresh = useCallback(() => store.refresh(), [store]);

	const signIn = useCallback(
		async (email: string, password: string): Promise<ActionResult> => {
			const result = await store.signIn(email, password);
			log(result.success ? "signIn:success" : "signIn:error");
			return toActionResult(result);
		},
		[store, log],
	);

	const signUp = useCallback(
		async (email: string, password: string, name?: string): Promise<ActionResult> =>
			toActionResult(await store.signUp(email, password, name)),
		[store],
	);

	const signOut = useCallback(async (): Promise<void> => {
		log("signOut");
		await store.signOut();
	}, [store, log]);

	const session: TheAuthSession | null = state.session;
	const user: TheAuthUser | null = session?.user ?? null;

	const rotateSession = useCallback(
		makeNoopRotation("rotateSession is only available in external mode with refreshPath set"),
		[],
	);

	const value: TheAuthContextValue = {
		session,
		user,
		isLoading: state.isLoading,
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

// Backward-compat aliases for the pre-rebrand API.

/** @deprecated Use `TheAuthContext` instead. Will be removed in a future major version. */
export const AuthContext = TheAuthContext;

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useAuthContext = useTheAuthContext;

/** @deprecated Use `TheAuthProvider` instead. Will be removed in a future major version. */
export const AuthProvider = TheAuthProvider;

/** @deprecated Use `TheAuthProviderProps` instead. Will be removed in a future major version. */
export type AuthProviderProps = TheAuthProviderProps;
