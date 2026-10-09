import { eq } from "drizzle-orm";
import { generateCodeVerifier } from "../auth/oauth/pkce.js";
import type { ResolvedUser } from "../auth/types.js";
import { constantTimeEqual, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import { agents } from "../db/schema.js";
import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { TokenVault, TokenVaultConfig } from "./types.js";
import { createTokenVault } from "./vault.js";

export interface TokenVaultPluginConfig extends Omit<TokenVaultConfig, "db" | "storage"> {
	/** Map a signed-in user to a tenant. Default: no tenant. */
	resolveTenantId?: (user: ResolvedUser) => string | null | Promise<string | null>;
	/** Override the callback URL. Default `{baseUrl}/auth/vault/callback/{provider}`. */
	buildRedirectUri?: (provider: string, baseUrl: string) => string;
	/** Where to send the browser after a successful connect. Omit to return JSON. */
	successRedirect?: string;
}

interface PendingState {
	userId: string;
	tenantId: string | null;
	provider: string;
	verifier: string;
	redirectUri: string;
}

const STATE_TTL_SECONDS = 600;
const te = new TextEncoder();

function safeEqual(a: string, b: string): boolean {
	return constantTimeEqual(te.encode(a), te.encode(b));
}

export function tokenVault(config: TokenVaultPluginConfig): TheAuthPlugin {
	return {
		id: "theauth-token-vault",

		async init(ctx) {
			if (!ctx.secondaryStorage) {
				throw new Error("theauth-token-vault requires secondaryStorage (set it on createTheAuth)");
			}
			const storage = ctx.secondaryStorage.for("tokenVault");
			const vault: TokenVault = await createTokenVault({ ...config, db: ctx.db, storage });
			const baseUrl = ctx.config.baseUrl ?? "";
			const redirectUriFor = (provider: string) =>
				config.buildRedirectUri
					? config.buildRedirectUri(provider, baseUrl)
					: `${baseUrl}/auth/vault/callback/${provider}`;
			const tenantOf = async (u: ResolvedUser) =>
				config.resolveTenantId ? await config.resolveTenantId(u) : null;
			const stateKey = async (state: string) => `state:${await sha256(state)}`;

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/vault/connect/start",
				metadata: { requireAuth: true, rateLimit: { window: 60, max: 20 } },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "Unauthorized" }, 401);
					const body = await parseBody(request);
					if (!body.ok) return body.response;
					const providerId = body.data.provider;
					const cfg = typeof providerId === "string" ? config.providers[providerId] : undefined;
					if (!cfg || typeof providerId !== "string")
						return json({ error: "Unknown provider" }, 400);

					const state = randomBytesHex(32);
					const verifier = generateCodeVerifier();
					const redirectUri = redirectUriFor(providerId);
					const pending: PendingState = {
						userId: user.id,
						tenantId: await tenantOf(user),
						provider: providerId,
						verifier,
						redirectUri,
					};
					await storage.set(await stateKey(state), JSON.stringify(pending), STATE_TTL_SECONDS);
					const url = await cfg.provider.getAuthorizationUrl(state, verifier, redirectUri);
					return json({ url });
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/vault/callback/:provider",
				metadata: { requireAuth: true, rateLimit: { window: 60, max: 30 } },
				async handler(request, ectx) {
					const url = new URL(request.url);
					const providerId = url.searchParams.get("_param_provider");
					const code = url.searchParams.get("code");
					const state = url.searchParams.get("state");
					if (!providerId || !code || !state) return json({ error: "Invalid callback" }, 400);

					const key = await stateKey(state);
					const raw = await storage.get(key);
					// Single use: consume before doing anything else.
					await storage.delete(key);
					if (!raw) return json({ error: "Invalid or expired state" }, 400);
					const pending = JSON.parse(raw) as PendingState;

					const user = await ectx.getUser(request);
					if (
						!user ||
						!safeEqual(user.id, pending.userId) ||
						!safeEqual(providerId, pending.provider)
					) {
						return json({ error: "State does not match the signed-in user" }, 400);
					}
					const cfg = config.providers[providerId];
					if (!cfg) return json({ error: "Unknown provider" }, 400);

					try {
						const tokens = await cfg.provider.exchangeCode(
							code,
							pending.verifier,
							pending.redirectUri,
						);
						const profile = await cfg.provider.getUserInfo(tokens.accessToken);
						const rawScope = tokens.raw.scope;
						const scopes =
							typeof rawScope === "string"
								? rawScope.split(/[\s,]+/).filter(Boolean)
								: cfg.provider.scopes;
						await vault.storeConnection({
							userId: user.id,
							tenantId: pending.tenantId,
							provider: providerId,
							providerAccountId: profile.id,
							accessToken: tokens.accessToken,
							refreshToken: tokens.refreshToken,
							expiresInSeconds: tokens.expiresIn,
							scopes,
						});
					} catch {
						return json({ error: "Could not complete the connection" }, 400);
					}
					if (config.successRedirect) {
						return new Response(null, {
							status: 302,
							headers: { Location: config.successRedirect },
						});
					}
					return json({ connected: true, provider: providerId });
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/vault/connections",
				metadata: { requireAuth: true },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "Unauthorized" }, 401);
					const list = await vault.listConnections(user.id, await tenantOf(user));
					return json({
						connections: list.map((c) => ({
							provider: c.provider,
							scopes: c.scopes,
							status: c.status,
						})),
					});
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/vault/connections/:provider",
				metadata: { requireAuth: true },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "Unauthorized" }, 401);
					const provider = new URL(request.url).searchParams.get("_param_provider");
					if (!provider) return json({ error: "Missing provider" }, 400);
					await vault.disconnect(user.id, provider, await tenantOf(user));
					return json({ disconnected: true });
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/vault/consents",
				metadata: { requireAuth: true },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "Unauthorized" }, 401);
					const body = await parseBody(request);
					if (!body.ok) return body.response;
					const { agentId, provider, scopes, delegationChainId, expiresAt } = body.data;
					if (
						typeof agentId !== "string" ||
						typeof provider !== "string" ||
						!Array.isArray(scopes) ||
						scopes.length === 0 ||
						!scopes.every((s): s is string => typeof s === "string")
					) {
						return json({ error: "agentId, provider and scopes are required" }, 400);
					}
					const rows = await ctx.db.select().from(agents).where(eq(agents.id, agentId)).limit(1);
					const agent = rows[0];
					// Users can only consent for agents they own.
					if (!agent || !safeEqual(agent.ownerId, user.id))
						return json({ error: "Unknown agent" }, 404);
					const res = await vault.grantConsent({
						userId: user.id,
						agentId,
						tenantId: agent.tenantId,
						provider,
						scopes,
						delegationChainId:
							typeof delegationChainId === "string" ? delegationChainId : undefined,
						expiresAt: typeof expiresAt === "string" ? new Date(expiresAt) : undefined,
					});
					return json({ id: res.id }, 201);
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/vault/consents/:id",
				metadata: { requireAuth: true },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "Unauthorized" }, 401);
					const id = new URL(request.url).searchParams.get("_param_id");
					if (!id) return json({ error: "Missing id" }, 400);
					await vault.revokeConsent(id, user.id);
					return json({ revoked: true });
				},
			});

			return { context: { tokenVault: vault } };
		},
	};
}
