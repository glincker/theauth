import { eq } from "drizzle-orm";
import { users } from "../../db/schema.js";
import { buildSetCookie } from "../../plugin/helpers.js";
import type { TheAuthPlugin } from "../../plugin/types.js";
import { createBaseUrlResolver } from "../../session/base-url.js";
import { normalizeEmail } from "../normalize-email.js";
import { withRateLimit } from "../rate-limit-middleware.js";
import { createRateLimiter } from "../rate-limiter.js";
import { createOAuthModule } from "./module.js";
import type { OAuthModuleConfig, OAuthTokens, OAuthUserInfo } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface OAuthPluginConfig extends OAuthModuleConfig {
	/**
	 * Build the redirect URI for a given provider.
	 *
	 * When omitted the plugin constructs the URI from `ctx.config.baseUrl`
	 * using the pattern `{baseUrl}/auth/oauth/callback/{provider}`.
	 */
	buildRedirectUri?: (provider: string, baseUrl: string) => string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function redirectResponse(url: string): Response {
	return new Response(null, {
		status: 302,
		headers: { Location: url },
	});
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function oauth(config: OAuthPluginConfig): TheAuthPlugin {
	return {
		id: "theauth-oauth",

		async init(ctx): Promise<undefined> {
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

			// GET /auth/oauth/authorize/:provider
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

					try {
						const { url: authUrl } = await module.getAuthorizationUrl(provider, redirectUri);
						return redirectResponse(authUrl);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to build authorization URL" },
							400,
						);
					}
				}, authorizeLimiter),
			});

			// GET /auth/oauth/callback/:provider
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth/callback/:provider",
				metadata: { description: "Handle OAuth provider callback" },
				async handler(request) {
					const url = new URL(request.url);
					const provider = url.searchParams.get("_param_provider");
					const code = url.searchParams.get("code");
					const state = url.searchParams.get("state");

					if (!provider) {
						return jsonResponse({ error: "Missing provider parameter" }, 400);
					}

					if (!code || !state) {
						return jsonResponse({ error: "Missing code or state query parameter" }, 400);
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
									return jsonResponse(
										{
											error:
												"An account with this email already exists. Sign in with your existing method and link this provider from account settings.",
										},
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

						// Create session and redirect
						if (userId !== "__pending__") {
							const { session, token } = await sessionManager.create(userId);
							const maxAge = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);
							const isSecure = baseUrl.startsWith("https://");
							const cookie = buildSetCookie("theauth_session", token, maxAge, "/", isSecure);

							// Pass user info (not the token) as a URL param for the frontend
							const userInfo = encodeURIComponent(JSON.stringify({ id: userId, email }));
							const callbackUrl = `${baseUrl}/?auth_user=${userInfo}`;

							return new Response(null, {
								status: 302,
								headers: {
									Location: callbackUrl,
									"Set-Cookie": cookie,
								},
							});
						}

						// Fallback: return JSON if userId is still pending
						return jsonResponse({
							isNewAccount: result.isNewAccount,
							account: result.account,
							userInfo: result.userInfo,
						});
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "OAuth callback failed" },
							400,
						);
					}
				},
			});

			// POST /auth/oauth/link
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

			// GET /auth/oauth/providers
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
		},
	};
}
