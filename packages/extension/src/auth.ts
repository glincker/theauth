import { discoverEndpoints } from "./discovery.js";
import { decodeJwtClaims, randomToken, s256Challenge } from "./encoding.js";
import { ExtensionAuthError } from "./errors.js";
import { acquireRefreshLock } from "./lock.js";
import type { TokenResponse } from "./oauth.js";
import {
	classifyLaunchError,
	formBody,
	parseAuthorizationCallback,
	parseTokenResponse,
} from "./oauth.js";
import { createIndexedDbKeyStore, createMemoryArea, webExtensionGlobal } from "./platform.js";
import type { StoredAccess } from "./token-store.js";
import { createTokenStore } from "./token-store.js";
import type {
	AuthorizationServerEndpoints,
	DPoPClientLike,
	DPoPModuleLike,
	ExtensionAuth,
	ExtensionAuthOptions,
	ExtensionSession,
	SignOutResult,
} from "./types.js";

const DEFAULT_SKEW_SECONDS = 60;
const DEFAULT_LOCK_TTL_MS = 30_000;
const DEFAULT_LOCK_POLL_MS = 100;
const CLIENT_MODULE = "@glinr/theauth-client";

function toSession(access: StoredAccess): ExtensionSession {
	const claims = access.idToken ? decodeJwtClaims(access.idToken) : undefined;
	return {
		scope: access.scope,
		expiresAt: access.expiresAt,
		tokenType: access.tokenType,
		...(claims ? { idTokenClaims: claims } : {}),
	};
}

export function createExtensionAuth(options: ExtensionAuthOptions): ExtensionAuth {
	const g = webExtensionGlobal();
	const storage = options.storage ?? g?.storage;
	const identity = options.identity ?? g?.identity;
	if (!storage) {
		throw new ExtensionAuthError("invalid_config", "No storage: pass `storage` or grant `storage`");
	}
	if (!identity) {
		throw new ExtensionAuthError("invalid_config", "No identity API: pass `identity`");
	}
	if (!options.issuer && !options.endpoints) {
		throw new ExtensionAuthError("invalid_config", "Pass `issuer` or `endpoints`");
	}

	const clock = options.clock ?? Date.now;
	const baseFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
	const skewMs = (options.refreshSkewSeconds ?? DEFAULT_SKEW_SECONDS) * 1000;
	const prefix = `theauth:ext:${options.namespace ?? options.clientId}`;
	const keyStore = options.keyStore ?? createIndexedDbKeyStore();
	const store = createTokenStore({
		prefix,
		storage,
		memoryArea: createMemoryArea(),
		keyStore,
		encryptRefreshToken: options.encryptRefreshToken === true,
	});
	const lockOwner = randomToken(12);
	const listeners = new Set<(session: ExtensionSession | null) => void>();

	function emit(session: ExtensionSession | null): void {
		for (const listener of [...listeners]) {
			try {
				listener(session);
			} catch {
				// A throwing listener must not break the auth flow.
			}
		}
	}

	let endpointsPromise: Promise<AuthorizationServerEndpoints> | undefined;
	function getEndpoints(): Promise<AuthorizationServerEndpoints> {
		if (options.endpoints) return Promise.resolve(options.endpoints);
		endpointsPromise ??= discoverEndpoints(options.issuer ?? "", baseFetch).catch((e: unknown) => {
			endpointsPromise = undefined;
			throw e;
		});
		return endpointsPromise;
	}

	let dpopPromise: Promise<DPoPClientLike | null> | undefined;
	function getDpop(): Promise<DPoPClientLike | null> {
		if (!options.dpop) return Promise.resolve(null);
		dpopPromise ??= (async () => {
			const custom = typeof options.dpop === "object" ? options.dpop.module : undefined;
			const mod: DPoPModuleLike =
				custom ?? ((await import(/* @vite-ignore */ CLIENT_MODULE)) as DPoPModuleLike);
			const keyName = `${prefix}:dpop`;
			let pair = await keyStore.get(keyName);
			if (!pair || !("privateKey" in pair)) {
				pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
					"sign",
					"verify",
				]);
				await keyStore.put(keyName, pair);
			}
			return mod.createDPoPClient({ keyPair: pair, fetch: baseFetch, now: clock });
		})().catch((e: unknown) => {
			dpopPromise = undefined;
			throw e instanceof ExtensionAuthError
				? e
				: new ExtensionAuthError("invalid_config", "DPoP is enabled but could not be loaded", {
						cause: e instanceof Error ? e.message : String(e),
					});
		});
		return dpopPromise;
	}

	async function postToken(url: string, params: Record<string, string | undefined>) {
		const dpop = await getDpop();
		const init: RequestInit = {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json",
			},
			body: formBody(params),
		};
		const res = dpop ? await dpop.fetch(url, init) : await baseFetch(url, init);
		return parseTokenResponse(res);
	}

	async function persist(tokens: TokenResponse, previousRefresh?: string): Promise<StoredAccess> {
		const access: StoredAccess = {
			accessToken: tokens.accessToken,
			tokenType: tokens.tokenType,
			scope: tokens.scope ?? options.scopes.join(" "),
			expiresAt: clock() + tokens.expiresIn * 1000,
			...(tokens.idToken ? { idToken: tokens.idToken } : {}),
		};
		const refresh = tokens.refreshToken ?? previousRefresh;
		if (refresh) await store.writeRefreshToken(refresh);
		await store.writeAccess(access);
		return access;
	}

	async function clearAndEmit(): Promise<void> {
		await store.clear();
		emit(null);
	}

	let signInInflight: Promise<ExtensionSession> | undefined;

	async function runSignIn(): Promise<ExtensionSession> {
		const endpoints = await getEndpoints();
		const redirectUri = options.redirectUri ?? identity?.getRedirectURL() ?? "";
		const verifier = randomToken(48);
		const state = randomToken(24);
		const wantsOidc = options.scopes.includes("openid");
		const nonce = wantsOidc ? randomToken(24) : undefined;

		const url = new URL(endpoints.authorization);
		const query: Record<string, string | undefined> = {
			response_type: "code",
			client_id: options.clientId,
			redirect_uri: redirectUri,
			scope: options.scopes.join(" "),
			state,
			nonce,
			code_challenge: await s256Challenge(verifier),
			code_challenge_method: "S256",
			resource: options.resource,
		};
		for (const [k, v] of Object.entries(query)) {
			if (v !== undefined) url.searchParams.set(k, v);
		}

		let responseUrl: string | undefined;
		try {
			responseUrl = await identity?.launchWebAuthFlow({ url: url.toString(), interactive: true });
		} catch (cause) {
			throw classifyLaunchError(cause);
		}
		const { code } = parseAuthorizationCallback(responseUrl, {
			state,
			issuer: endpoints.issuer ?? options.issuer,
			issuerRequired: endpoints.issuerParameterSupported === true,
		});

		const result = await postToken(endpoints.token, {
			grant_type: "authorization_code",
			code,
			redirect_uri: redirectUri,
			client_id: options.clientId,
			code_verifier: verifier,
			resource: options.resource,
		});
		if (!result.ok) {
			throw new ExtensionAuthError("token_exchange_failed", "The token request was rejected", {
				status: result.status,
				error: result.error.error,
			});
		}
		if (result.tokens.idToken && nonce) {
			const claims = decodeJwtClaims(result.tokens.idToken);
			if (claims?.nonce !== nonce) {
				throw new ExtensionAuthError("token_exchange_failed", "The ID token nonce did not match");
			}
		}
		const access = await persist(result.tokens);
		const session = toSession(access);
		emit(session);
		return session;
	}

	function isFresh(a: StoredAccess | null): boolean {
		return a !== null && a.expiresAt - skewMs > clock();
	}

	async function refreshLocked(): Promise<StoredAccess> {
		const release = await acquireRefreshLock({
			store,
			owner: lockOwner,
			ttlMs: options.lockTtlMs ?? DEFAULT_LOCK_TTL_MS,
			pollMs: options.lockPollMs ?? DEFAULT_LOCK_POLL_MS,
			clock,
		});
		try {
			// Another worker may have refreshed while we waited for the lock.
			const current = await store.readAccess();
			if (current && isFresh(current)) return current;

			let refreshToken: string | null;
			try {
				refreshToken = await store.readRefreshToken();
			} catch (e) {
				await clearAndEmit();
				throw e;
			}
			if (!refreshToken) {
				if (current && current.expiresAt > clock()) return current;
				await clearAndEmit();
				throw new ExtensionAuthError("not_signed_in", "No session. Call signIn() first");
			}

			const endpoints = await getEndpoints();
			let result: Awaited<ReturnType<typeof postToken>>;
			try {
				result = await postToken(endpoints.token, {
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					client_id: options.clientId,
					resource: options.resource,
				});
			} catch (cause) {
				if (cause instanceof ExtensionAuthError) throw cause;
				throw new ExtensionAuthError("refresh_failed", "The refresh request could not be sent", {
					cause: cause instanceof Error ? cause.message : String(cause),
				});
			}
			if (!result.ok) {
				if (result.error.error === "invalid_grant") {
					await clearAndEmit();
				}
				throw new ExtensionAuthError("refresh_failed", "The refresh request was rejected", {
					status: result.status,
					error: result.error.error,
				});
			}
			const access = await persist(result.tokens, refreshToken);
			emit(toSession(access));
			return access;
		} finally {
			await release();
		}
	}

	let refreshInflight: Promise<StoredAccess> | undefined;

	async function getValidAccess(): Promise<StoredAccess> {
		const current = await store.readAccess();
		if (current && isFresh(current)) return current;
		refreshInflight ??= refreshLocked().finally(() => {
			refreshInflight = undefined;
		});
		return refreshInflight;
	}

	return {
		signIn() {
			signInInflight ??= runSignIn().finally(() => {
				signInInflight = undefined;
			});
			return signInInflight;
		},

		async getAccessToken() {
			return (await getValidAccess()).accessToken;
		},

		async getSession() {
			try {
				return toSession(await getValidAccess());
			} catch (e) {
				if (e instanceof ExtensionAuthError && e.code === "not_signed_in") return null;
				throw e;
			}
		},

		async signOut(): Promise<SignOutResult> {
			let revoked = false;
			let idToken: string | undefined;
			try {
				const access = await store.readAccess();
				idToken = access?.idToken;
				let refresh: string | null = null;
				try {
					refresh = await store.readRefreshToken();
				} catch {
					refresh = null;
				}
				const endpoints = await getEndpoints().catch(() => undefined);
				const token = refresh ?? access?.accessToken;
				if (endpoints?.revocation && token) {
					try {
						const res = await baseFetch(endpoints.revocation, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: formBody({
								token,
								token_type_hint: refresh ? "refresh_token" : "access_token",
								client_id: options.clientId,
							}),
						});
						revoked = res.ok;
					} catch {
						revoked = false;
					}
				}
				if (options.endSession && endpoints?.endSession) {
					const post =
						typeof options.endSession === "object"
							? options.endSession.postLogoutRedirectUri
							: undefined;
					const end = new URL(endpoints.endSession);
					end.searchParams.set("client_id", options.clientId);
					if (idToken) end.searchParams.set("id_token_hint", idToken);
					end.searchParams.set(
						"post_logout_redirect_uri",
						post ?? identity?.getRedirectURL() ?? "",
					);
					try {
						await identity?.launchWebAuthFlow({ url: end.toString(), interactive: false });
					} catch {
						// The IdP page may not redirect back. Local state is cleared either way.
					}
				}
			} finally {
				await clearAndEmit();
			}
			return { revoked };
		},

		onChange(callback) {
			listeners.add(callback);
			return () => {
				listeners.delete(callback);
			};
		},

		async fetch(input, init) {
			const access = await getValidAccess();
			if (access.tokenType === "DPoP") {
				const dpop = await getDpop();
				if (!dpop) {
					throw new ExtensionAuthError("invalid_config", "The token is DPoP bound but dpop is off");
				}
				return dpop.fetch(input, init, { accessToken: access.accessToken });
			}
			const headers = new Headers(init?.headers);
			headers.set("Authorization", `Bearer ${access.accessToken}`);
			return baseFetch(input, { ...init, headers });
		},
	};
}
