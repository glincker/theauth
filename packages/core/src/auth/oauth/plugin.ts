import { eq } from "drizzle-orm";
import { users } from "../../db/schema.js";
import {
	buildClearCookie,
	buildSessionSetCookie,
	buildSetCookie,
	getCookie,
	parseRememberMe,
} from "../../plugin/helpers.js";
import type { PluginInitResult, TheAuthPlugin } from "../../plugin/types.js";
import { createBaseUrlResolver } from "../../session/base-url.js";
import { normalizeEmail } from "../normalize-email.js";
import { createOneTimeTokenModule } from "../one-time-token.js";
import { withRateLimit } from "../rate-limit-middleware.js";
import { createRateLimiter } from "../rate-limiter.js";
import { signInGateRedirect } from "../sign-in-gate.js";
import { OAuthTokenError } from "./errors.js";
import { idpAmrFromTokens } from "./idp-amr.js";
import type { MobileFlow, MobileOAuthConfig } from "./mobile.js";
import { createMobileOAuth, MOBILE_COOKIE } from "./mobile.js";
import { createOAuthModule } from "./module.js";
import type { OAuthModuleConfig, OAuthTokens, OAuthUserInfo } from "./types.js";

export interface OAuthPluginConfig extends OAuthModuleConfig {
	/** Build the redirect URI for a given provider. */
	buildRedirectUri?: (provider: string, baseUrl: string) => string;
	/**
	 * Native app sign-in. When set, `authorize` accepts `mobile_redirect` and a PKCE `code_challenge`, and the app trades the code it receives for a session at `POST /auth/oauth/mobile/exchange`. Off when omitted.
	 */
	mobile?: MobileOAuthConfig;
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function redirectResponse(url: string, setCookie?: string): Response {
	return new Response(null, {
		status: 302,
		headers: { Location: url, ...(setCookie && { "Set-Cookie": setCookie }) },
	});
}

/** Carries the optional `rememberMe` choice from the authorize redirect to the callback. Short lived, never holds a secret. */
const REMEMBER_COOKIE = "theauth_oauth_remember";

const TOKEN_ERROR_STATUS: Record<OAuthTokenError["code"], number> = {
	no_account: 404,
	no_refresh_token: 409,
	refresh_failed: 502,
	revoked: 409,
	decrypt_failed: 500,
	last_credential: 409,
};

function tokenErrorResponse(err: unknown, fallback: string): Response {
	if (err instanceof OAuthTokenError) {
		return jsonResponse({ error: err.message, code: err.code }, TOKEN_ERROR_STATUS[err.code]);
	}
	return jsonResponse({ error: fallback }, 500);
}

export function oauth(config: OAuthPluginConfig): TheAuthPlugin {
	return {
		id: "theauth-oauth",

		async init(ctx): Promise<PluginInitResult> {
			const module = createOAuthModule(ctx.db, config);

			const baseUrl = ctx.config.baseUrl ?? "";
			const baseUrls = ctx.config.allowedHosts?.length
				? createBaseUrlResolver({
						baseUrl: ctx.config.baseUrl,
						allowedHosts: ctx.config.allowedHosts,
						trustForwardedHeaders: ctx.config.trustForwardedHeaders,
					})
				: null;

			const sessionManager = ctx.sessionManager;
			if (!sessionManager) {
				throw new Error(
					"theauth-oauth plugin requires auth.session to be configured so that sessions can be issued on successful OAuth callback.",
				);
			}

			const authorizeLimiter = createRateLimiter({ max: 20, window: 60 });
			const exchangeLimiter = createRateLimiter({ max: 20, window: 60 });
			const mobile = config.mobile
				? createMobileOAuth(config.mobile, createOneTimeTokenModule({}, ctx.db))
				: null;

			function getRedirectUri(provider: string, request: Request): string {
				let base = baseUrl;
				if (baseUrls) {
					const resolved = baseUrls.resolve(request);
					if (resolved.success) base = resolved.data;
				}
				if (config.buildRedirectUri) {
					return config.buildRedirectUri(provider, base);
				}
				return `${base}/auth/oauth/callback/${provider}`;
			}

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth/authorize/:provider",
				metadata: {
					description: "Initiate OAuth authorization flow for a provider",
					rateLimit: { window: 60, max: 20 },
				},
				handler: withRateLimit(async (request) => {
					const url = new URL(request.url);
					const provider = url.searchParams.get("_param_provider");

					if (!provider) {
						return jsonResponse({ error: "Missing provider parameter" }, 400);
					}

					const redirectUri = getRedirectUri(provider, request);

					let mobileFlow: MobileFlow | null = null;
					if (url.searchParams.has("mobile_redirect")) {
						const parsed = mobile?.parseStart(url.searchParams);
						if (!parsed) return jsonResponse({ error: "Mobile sign-in is not enabled" }, 400);
						if ("error" in parsed) return jsonResponse({ error: parsed.error }, 400);
						mobileFlow = parsed.flow;
					}

					try {
						const { url: authUrl } = await module.getAuthorizationUrl(provider, redirectUri);
						if (mobile && mobileFlow) {
							const pending = await mobile.begin(mobileFlow);
							const secure = baseUrl.startsWith("https://");
							return new Response(null, {
								status: 302,
								headers: {
									Location: authUrl,
									"Set-Cookie": buildSetCookie(MOBILE_COOKIE, pending, 600, "/", secure),
								},
							});
						}
						const rememberMe = parseRememberMe(url.searchParams.get("rememberMe"));
						return redirectResponse(
							authUrl,
							rememberMe === undefined
								? undefined
								: buildSetCookie(
										REMEMBER_COOKIE,
										rememberMe ? "1" : "0",
										600,
										"/",
										baseUrl.startsWith("https://"),
									),
						);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to build authorization URL" },
							400,
						);
					}
				}, authorizeLimiter),
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth/callback/:provider",
				metadata: { description: "Handle OAuth provider callback" },
				async handler(request) {
					const url = new URL(request.url);
					const provider = url.searchParams.get("_param_provider");
					const code = url.searchParams.get("code");
					const state = url.searchParams.get("state");

					// A native app started this flow in the system browser. The
					// pending flow is consumed here, so a failure restarts it.
					const flow = mobile ? await mobile.resume(getCookie(request, MOBILE_COOKIE)) : null;
					const clearMobile = buildClearCookie(MOBILE_COOKIE);
					const fail = (message: string, status: number): Response => {
						if (!mobile || !flow) return jsonResponse({ error: message }, status);
						return new Response(null, {
							status: 302,
							headers: {
								Location: mobile.redirectWith(flow.redirectUri, { error: message }),
								"Set-Cookie": clearMobile,
							},
						});
					};

					if (!provider) {
						return fail("Missing provider parameter", 400);
					}

					if (!code || !state) {
						return fail("Missing code or state query parameter", 400);
					}

					const redirectUri = getRedirectUri(provider, request);

					try {
						const result = await module.handleCallback(provider, code, state, redirectUri);

						// Find or create a theauth user by email
						const email = result.userInfo.email;
						let userId = result.account.userId;

						if (userId === "__pending__" && email && ctx.db) {
							const normalized = normalizeEmail(email);
							const existing = await ctx.db.select().from(users).where(eq(users.email, normalized));

							if (existing[0]) {
								// Linking by email is only safe when both sides vouch for the
								// address. An unverified provider email lets anyone who controls
								// a provider account with the victim's address sign in as them,
								// and an unverified local account may be a pre-registered squat.
								if (result.userInfo.emailVerified !== true || !existing[0].emailVerified) {
									return fail(
										"An account with this email already exists. Sign in with your existing method and link this provider from account settings.",
										409,
									);
								}
								userId = existing[0].id;
							} else {
								const newId = crypto.randomUUID();
								await ctx.db.insert(users).values({
									id: newId,
									email: normalized,
									name: result.userInfo.name ?? null,
									externalProvider: `oauth:${provider}`,
									externalId: result.userInfo.id,
									emailVerified: result.userInfo.emailVerified === true ? 1 : 0,
									createdAt: new Date(),
									updatedAt: new Date(),
								});
								userId = newId;
							}

							await module.linkAccount(userId, provider, result.userInfo, {
								accessToken: result.account.accessToken,
								refreshToken: result.account.refreshToken ?? undefined,
								tokenType: "Bearer",
								raw: {},
							});
						}

						if (userId !== "__pending__") {
							// A forced password change or a required second factor must be
							// satisfied before a session exists. The challenge travels in the
							// URL fragment, never in the query string.
							const gateDecision = await ctx.signInGate?.evaluate({
								userId,
								method: "social",
								request,
							});
							if (gateDecision && gateDecision.action !== "allow") {
								if (flow) return signInGateRedirect(flow.redirectUri, gateDecision, [clearMobile]);
								return signInGateRedirect(`${baseUrl}/`, gateDecision);
							}

							// Native apps get a single-use code, never the session.
							if (mobile && flow) {
								const exchangeCode = await mobile.issueCode(flow, userId);
								return new Response(null, {
									status: 302,
									headers: {
										Location: mobile.redirectWith(flow.redirectUri, { code: exchangeCode }),
										"Set-Cookie": clearMobile,
									},
								});
							}

							const remembered = getCookie(request, REMEMBER_COOKIE);
							const rememberMe = remembered === "1" ? true : remembered === "0" ? false : undefined;
							const { session, token } = await sessionManager.create(userId, undefined, {
								authMethods: ["federated"],
								idpAmr: idpAmrFromTokens(result.tokens),
								...(rememberMe !== undefined && { rememberMe }),
							});
							const isSecure = baseUrl.startsWith("https://");
							const cookie = buildSessionSetCookie(
								sessionManager.cookieName ?? "theauth_session",
								token,
								session,
								isSecure,
							);

							// Pass user info (not the token) as a URL param for the frontend
							const userInfo = encodeURIComponent(JSON.stringify({ id: userId, email }));
							const callbackUrl = `${baseUrl}/?auth_user=${userInfo}`;

							const headers = new Headers({ Location: callbackUrl });
							headers.append("Set-Cookie", cookie);
							if (remembered !== null)
								headers.append("Set-Cookie", buildClearCookie(REMEMBER_COOKIE));
							return new Response(null, { status: 302, headers });
						}

						// Fallback: return JSON if userId is still pending
						return jsonResponse({
							isNewAccount: result.isNewAccount,
							account: result.account,
							userInfo: result.userInfo,
						});
					} catch (err) {
						return fail(err instanceof Error ? err.message : "OAuth callback failed", 400);
					}
				},
			});

			if (mobile) {
				ctx.addEndpoint({
					method: "POST",
					path: "/auth/oauth/mobile/exchange",
					metadata: {
						description: "Trade a native app sign-in code and PKCE verifier for a session",
						rateLimit: { window: 60, max: 20 },
					},
					handler: withRateLimit(async (request) => {
						let body: unknown;
						try {
							body = await request.json();
						} catch {
							return jsonResponse({ error: "Invalid JSON body" }, 400);
						}
						const b = (body ?? {}) as Record<string, unknown>;
						const code = typeof b.code === "string" ? b.code : "";
						const verifier = typeof b.code_verifier === "string" ? b.code_verifier : "";
						const userId = code && verifier ? await mobile.redeem(code, verifier) : null;
						if (!userId) {
							return jsonResponse({ error: "Invalid or expired code" }, 400);
						}
						const found = await ctx.db?.select().from(users).where(eq(users.id, userId));
						const user = found?.[0];
						if (!user) return jsonResponse({ error: "Invalid or expired code" }, 400);

						const { session, token } = await sessionManager.create(userId, undefined, {
							authMethods: ["federated"],
						});
						return jsonResponse({
							data: {
								token,
								user: { id: user.id, email: user.email, name: user.name ?? undefined },
								expiresAt: session.expiresAt.toISOString(),
							},
						});
					}, exchangeLimiter),
				});
			}

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/oauth/link",
				metadata: {
					requireAuth: true,
					description: "Link an OAuth provider account to the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					let body: unknown;
					try {
						body = await request.json();
					} catch {
						return jsonResponse({ error: "Invalid JSON body" }, 400);
					}

					const b = body as Record<string, unknown>;
					const provider = typeof b.provider === "string" ? b.provider : null;
					const userInfo =
						typeof b.userInfo === "object" && b.userInfo !== null
							? (b.userInfo as OAuthUserInfo)
							: null;
					const tokens =
						typeof b.tokens === "object" && b.tokens !== null ? (b.tokens as OAuthTokens) : null;

					if (!provider || !userInfo || !tokens) {
						return jsonResponse(
							{ error: "Missing required fields: provider, userInfo, tokens" },
							400,
						);
					}

					try {
						const account = await module.linkAccount(user.id, provider, userInfo, tokens);
						return jsonResponse({ account });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to link account" },
							400,
						);
					}
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth/accounts",
				metadata: {
					requireAuth: true,
					description: "List the provider accounts linked to the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) return jsonResponse({ error: "Authentication required" }, 401);
					try {
						return jsonResponse({ accounts: await module.listAccounts(user.id) });
					} catch (err) {
						return tokenErrorResponse(err, "Failed to list accounts");
					}
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/oauth/accounts/:provider",
				metadata: {
					requireAuth: true,
					description: "Unlink a provider account (refused for the last sign-in method)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) return jsonResponse({ error: "Authentication required" }, 401);
					const provider = new URL(request.url).searchParams.get("_param_provider");
					if (!provider) return jsonResponse({ error: "Missing provider parameter" }, 400);
					try {
						await module.unlinkAccount(user.id, provider);
						return jsonResponse({ success: true });
					} catch (err) {
						return tokenErrorResponse(err, "Failed to unlink account");
					}
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth/providers",
				metadata: { description: "List configured OAuth providers" },
				async handler() {
					const providers = Object.values(config.providers).map((p) => ({
						id: p.id,
						name: p.name,
					}));
					return jsonResponse({ providers });
				},
			});

			// Server-side access: ctx.pluginContext.oauth.getAccessToken({ userId, provider }).
			return { context: { oauth: module } };
		},
	};
}
