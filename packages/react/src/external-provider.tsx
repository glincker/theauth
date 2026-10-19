import { attachRefetch } from "@glinr/theauth-client";
import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { TheAuthContext } from "./auth-context.js";
import { makeLogger } from "./debug.js";
import {
	AUTH_ERROR_CODES,
	DEFAULT_PROACTIVE_LEAD_MS,
	DEFAULT_RETRY,
	defaultMapUser,
	KNOWN_SERVER_CODES,
	performRotationAttempt,
} from "./rotation.js";
import type {
	ActionResult,
	ExternalAuthConfig,
	RotateErrorCode,
	RotateResult,
	RotateRetryConfig,
	RotationStatus,
	SignUpData,
	TheAuthContextValue,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";

/** External auth has no email routes of its own: the host API owns them. */
const unsupported = async (): Promise<ActionResult> => ({
	success: false,
	error: "Not available with external auth",
});

export function ExternalProvider({
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
		(attempt: number): Promise<RotateResult> =>
			performRotationAttempt(
				{
					apiUrl,
					refreshPath,
					rotationEnabled,
					retryCfg,
					proactiveLeadMs,
					mapServerCode,
					onQueuedOffline: () => {
						queuedWhileOfflineRef.current = true;
					},
				},
				attempt,
			),
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

	const signUp = useCallback(async (): Promise<ActionResult<SignUpData>> => {
		// External auth has no separate sign-up, so redirect to login
		if (typeof window !== "undefined") {
			window.location.href = `${apiUrl}${loginPath}`;
		}
		return { success: true, data: { verificationRequired: false } };
	}, [apiUrl, loginPath]);

	const session: TheAuthSession | null = user ? { token: "__external__", user } : null;

	const value: TheAuthContextValue = {
		session,
		user,
		isLoading,
		isAuthenticated: user !== null,
		signIn,
		signUp,
		verifyEmail: unsupported,
		resendVerification: unsupported,
		requestPasswordReset: unsupported,
		resetPassword: unsupported,
		signOut,
		refresh,
		rotateSession: runRotation,
		rotationStatus,
		isOnline,
	};

	return <TheAuthContext.Provider value={value}>{children}</TheAuthContext.Provider>;
}
