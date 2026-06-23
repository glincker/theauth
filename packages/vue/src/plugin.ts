import type { App, InjectionKey, Ref } from "vue";
import { inject, ref } from "vue";
import type { ActionResult, AuthContextValue, AuthSession, AuthUser } from "./types.js";

// ─── Injection key ────────────────────────────────────────────────────────────

export const AUTH_KEY: InjectionKey<AuthContextValue> = Symbol("auth");

/** @deprecated Use {@link AUTH_KEY} instead. Will be removed in v3.0. */
export const KAVACH_KEY: InjectionKey<AuthContextValue> = AUTH_KEY;

// ─── useRequiredContext ───────────────────────────────────────────────────────

export function useRequiredContext(composableName: string): AuthContextValue {
	const ctx = inject(AUTH_KEY);
	if (!ctx) {
		throw new Error(
			`${composableName} must be used inside a component wrapped by createAuthPlugin`,
		);
	}
	return ctx;
}

// ─── Plugin ───────────────────────────────────────────────────────────────────

export interface AuthPluginOptions {
	/** Base path where TheAuth is mounted. Defaults to "/api/kavach". */
	basePath?: string;
}

/** @deprecated Use {@link AuthPluginOptions} instead. Will be removed in v3.0. */
export type KavachPluginOptions = AuthPluginOptions;

export function createAuthPlugin(options: AuthPluginOptions = {}) {
	return {
		install(app: App) {
			const base = (options.basePath ?? "/api/kavach").replace(/\/$/, "");
			const STORAGE_KEY = "kavach_session";

			const session: Ref<AuthSession | null> = ref(null);
			const isLoading: Ref<boolean> = ref(true);

			async function fetchSession(): Promise<void> {
				if (typeof window === "undefined") {
					isLoading.value = false;
					return;
				}
				try {
					const raw = window.localStorage.getItem(STORAGE_KEY);
					if (raw) {
						session.value = JSON.parse(raw) as AuthSession;
					} else {
						session.value = null;
					}
				} catch {
					session.value = null;
				}
			}

			async function refresh(): Promise<void> {
				await fetchSession();
			}

			async function signIn(email: string, password: string): Promise<ActionResult> {
				try {
					const res = await fetch(`${base}/auth/sign-in`, {
						method: "POST",
						credentials: "include",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ email, password }),
					});
					const json = (await res.json()) as
						| { user: AuthUser; session: { token: string; expiresAt: string } }
						| { error: { code: string; message: string } };

					if (!res.ok) {
						const errBody = json as { error: { code: string; message: string } };
						return {
							success: false,
							error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
						};
					}

					const okBody = json as {
						user: AuthUser;
						session: { token: string; expiresAt: string };
					};
					const sessionData: AuthSession = {
						token: okBody.session.token,
						user: okBody.user,
						expiresAt: okBody.session.expiresAt,
					};
					session.value = sessionData;
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
			}

			async function signUp(email: string, password: string, name?: string): Promise<ActionResult> {
				try {
					const res = await fetch(`${base}/auth/sign-up`, {
						method: "POST",
						credentials: "include",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ email, password, name }),
					});
					const json = (await res.json()) as
						| { user: AuthUser; token: string }
						| { error: { code: string; message: string } };

					if (!res.ok) {
						const errBody = json as { error: { code: string; message: string } };
						return {
							success: false,
							error: errBody.error?.message ?? `Sign-up failed (${res.status})`,
						};
					}

					const okBody = json as { user: AuthUser; token: string };
					const sessionData: AuthSession = {
						token: okBody.token,
						user: okBody.user,
					};
					session.value = sessionData;
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
			}

			async function signOut(): Promise<void> {
				session.value = null;
				if (typeof window !== "undefined") {
					window.localStorage.removeItem(STORAGE_KEY);
				}
			}

			// Restore session from localStorage on install
			isLoading.value = true;
			void fetchSession().finally(() => {
				isLoading.value = false;
			});

			const context: AuthContextValue = {
				get session() {
					return session.value;
				},
				get user(): AuthUser | null {
					return session.value?.user ?? null;
				},
				get isLoading() {
					return isLoading.value;
				},
				get isAuthenticated() {
					return session.value !== null;
				},
				basePath: base,
				signIn,
				signUp,
				signOut,
				refresh,
			};

			app.provide(AUTH_KEY, context);
		},
	};
}

/** @deprecated Use {@link createAuthPlugin} instead. Will be removed in v3.0. */
export const createKavachPlugin = createAuthPlugin;
