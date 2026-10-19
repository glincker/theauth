import type { SessionStorageLike, StoreActionResult } from "@glinr/theauth-client";
import { createSessionStore } from "@glinr/theauth-client";
import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { TheAuthContext } from "./auth-context.js";
import { makeLogger } from "./debug.js";
import { makeNoopRotation } from "./rotation.js";
import type {
	ActionResult,
	ManagedAuthConfig,
	SignUpData,
	TheAuthContextValue,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";

function browserStorage(): SessionStorageLike | undefined {
	try {
		return typeof window === "undefined" ? undefined : window.localStorage;
	} catch {
		return undefined;
	}
}

function toActionResult(r: StoreActionResult): ActionResult {
	return r.success
		? { success: true, data: undefined }
		: { success: false, error: r.error, ...(r.code !== undefined && { code: r.code }) };
}

function toSignUpResult(r: StoreActionResult): ActionResult<SignUpData> {
	if (!r.success) return toActionResult(r) as ActionResult<SignUpData>;
	return { success: true, data: { verificationRequired: r.verificationRequired === true } };
}

export function ManagedProvider({
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
			emailPassword: m?.emailPassword,
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
		async (email: string, password: string, name?: string): Promise<ActionResult<SignUpData>> =>
			toSignUpResult(await store.signUp(email, password, name)),
		[store],
	);

	const verifyEmail = useCallback(
		async (token: string) => toActionResult(await store.verifyEmail(token)),
		[store],
	);
	const resendVerification = useCallback(
		async (email: string) => toActionResult(await store.resendVerification(email)),
		[store],
	);
	const requestPasswordReset = useCallback(
		async (email: string) => toActionResult(await store.requestPasswordReset(email)),
		[store],
	);
	const resetPassword = useCallback(
		async (token: string, password: string) =>
			toActionResult(await store.resetPassword(token, password)),
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
		verifyEmail,
		resendVerification,
		requestPasswordReset,
		resetPassword,
		signOut,
		refresh,
		rotateSession,
		rotationStatus: "idle",
		isOnline,
	};

	return <TheAuthContext.Provider value={value}>{children}</TheAuthContext.Provider>;
}
