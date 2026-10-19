import type {
	HydrateInput,
	RefetchOptions,
	SessionState,
	SessionStorageLike,
	StoreActionResult,
} from "@glinr/theauth-client";
import { createSessionStore } from "@glinr/theauth-client";
import type { App, InjectionKey } from "vue";
import { inject, shallowRef } from "vue";
import type { ActionResult, SignUpData, TheAuthContextValue, TheAuthUser } from "./types.js";

export const THEAUTH_KEY: InjectionKey<TheAuthContextValue> = Symbol("theauth");

/** @deprecated Use `THEAUTH_KEY` instead. Will be removed in a future major version. */
export const AUTH_KEY = THEAUTH_KEY;

export function useRequiredContext(composableName: string): TheAuthContextValue {
	const ctx = inject(THEAUTH_KEY);
	if (!ctx) {
		throw new Error(
			`${composableName} must be used inside a component wrapped by createTheAuthPlugin`,
		);
	}
	return ctx;
}

export interface TheAuthPluginOptions {
	basePath?: string;
	/** Refetch the session on focus, reconnect or an interval. Off unless set. */
	refetch?: RefetchOptions;
	/** Session the server already resolved (SSR). Skips the first request. `null` means signed out. */
	initialSession?: HydrateInput | null;
	/**
	 * Use the core email and password routes (`/auth/email/*`, served when the server sets the
	 * `emailPassword` config). Explicit `signInPath`, `signUpPath` and `identifierField` still win.
	 */
	emailPassword?: boolean;
	/** Default `/auth/username/sign-in`, or `/auth/email/sign-in` with `emailPassword`. */
	signInPath?: string;
	/** Default `/auth/username/sign-up`, or `/auth/email/sign-up` with `emailPassword`. */
	signUpPath?: string;
	/** Body field for the sign-in identifier. Default `username`, or `email` with `emailPassword`. */
	identifierField?: string;
	/** Defaults to `window.localStorage` when the browser allows it. */
	storage?: SessionStorageLike;
	fetch?: typeof fetch;
}

/** @deprecated Use `TheAuthPluginOptions` instead. Will be removed in a future major version. */
export type AuthPluginOptions = TheAuthPluginOptions;

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

export function createTheAuthPlugin(options: TheAuthPluginOptions = {}) {
	return {
		install(app: App) {
			const base = (options.basePath ?? "/api/theauth").replace(/\/$/, "");
			const store = createSessionStore({
				basePath: base,
				storage: options.storage ?? browserStorage(),
				fetch: options.fetch,
				emailPassword: options.emailPassword,
				signInPath: options.signInPath,
				signUpPath: options.signUpPath,
				identifierField: options.identifierField,
				refetch: options.refetch,
			});
			const state = shallowRef<SessionState>(store.getState());
			// One subscription for the life of the app keeps the refetch triggers attached.
			const unsubscribe = store.subscribe((next) => {
				state.value = next;
			});

			if (options.initialSession !== undefined) {
				store.hydrateSession(options.initialSession);
			} else if (typeof window === "undefined") {
				store.destroy();
			} else {
				void store.refresh();
			}

			const unmount = app.unmount.bind(app);
			app.unmount = () => {
				unsubscribe();
				store.destroy();
				unmount();
			};

			const context: TheAuthContextValue = {
				get session() {
					return state.value.session;
				},
				get user(): TheAuthUser | null {
					return state.value.session?.user ?? null;
				},
				get isLoading() {
					return state.value.isLoading;
				},
				get isAuthenticated() {
					return state.value.session !== null;
				},
				basePath: base,
				signIn: async (email, password) => toActionResult(await store.signIn(email, password)),
				signUp: async (email, password, name) =>
					toSignUpResult(await store.signUp(email, password, name)),
				verifyEmail: async (token) => toActionResult(await store.verifyEmail(token)),
				resendVerification: async (email) => toActionResult(await store.resendVerification(email)),
				requestPasswordReset: async (email) =>
					toActionResult(await store.requestPasswordReset(email)),
				resetPassword: async (token, password) =>
					toActionResult(await store.resetPassword(token, password)),
				signOut: async () => {
					await store.signOut();
				},
				refresh: () => store.refresh(),
			};

			app.provide(THEAUTH_KEY, context);
		},
	};
}

// Kept for backward compatibility with the pre-rebrand "TheAuth" API. Will be
// removed in a future major version.

/** @deprecated Use `createTheAuthPlugin` instead. Will be removed in a future major version. */
export const createAuthPlugin = createTheAuthPlugin;
