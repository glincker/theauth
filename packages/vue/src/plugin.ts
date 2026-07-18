import type { App, InjectionKey, Ref } from "vue";
import { inject, ref } from "vue";
import type { ActionResult, KavachSession, KavachUser, TheAuthContextValue } from "./types.js";

// ─── Injection key ────────────────────────────────────────────────────────────

export const THEAUTH_KEY: InjectionKey<TheAuthContextValue> = Symbol("theauth");

/** @deprecated Use `THEAUTH_KEY` instead. Will be removed in a future major version. */
export const KAVACH_KEY = THEAUTH_KEY;

// ─── useRequiredContext ───────────────────────────────────────────────────────

export function useRequiredContext(composableName: string): TheAuthContextValue {
	const ctx = inject(THEAUTH_KEY);
	if (!ctx) {
		throw new Error(
			`${composableName} must be used inside a component wrapped by createTheAuthPlugin`,
		);
	}
	return ctx;
}

// ─── Plugin ───────────────────────────────────────────────────────────────────

export interface TheAuthPluginOptions {
	/** Base path where TheAuth is mounted. Defaults to "/api/kavach". */
	basePath?: string;
}

/** @deprecated Use `TheAuthPluginOptions` instead. Will be removed in a future major version. */
export type KavachPluginOptions = TheAuthPluginOptions;

export function createTheAuthPlugin(options: TheAuthPluginOptions = {}) {
	return {
		install(app: App) {
			const base = (options.basePath ?? "/api/kavach").replace(/\/$/, "");
			const STORAGE_KEY = "kavach_session";

			const session: Ref<KavachSession | null> = ref(null);
			const isLoading: Ref<boolean> = ref(true);

			async function fetchSession(): Promise<void> {
				if (typeof window === "undefined") {
					isLoading.value = false;
					return;
				}
				try {
					const raw = window.localStorage.getItem(STORAGE_KEY);
					if (raw) {
						session.value = JSON.parse(raw) as KavachSession;
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
						| { user: KavachUser; session: { token: string; expiresAt: string } }
						| { error: { code: string; message: string } };

					if (!res.ok) {
						const errBody = json as { error: { code: string; message: string } };
						return {
							success: false,
							error: errBody.error?.message ?? `Sign-in failed (${res.status})`,
						};
					}

					const okBody = json as {
						user: KavachUser;
						session: { token: string; expiresAt: string };
					};
					const sessionData: KavachSession = {
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

			const context: TheAuthContextValue = {
				get session() {
					return session.value;
				},
				get user(): KavachUser | null {
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

			app.provide(THEAUTH_KEY, context);
		},
	};
}

// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `createTheAuthPlugin` instead. Will be removed in a future major version. */
export const createKavachPlugin = createTheAuthPlugin;
