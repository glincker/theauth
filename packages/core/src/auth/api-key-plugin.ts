import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { ApiKeyManagerConfig } from "./api-key-manager.js";
import { createApiKeyManagerModule } from "./api-key-manager.js";

export type { ApiKeyManagerConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function apiKeys(config?: ApiKeyManagerConfig): TheAuthPlugin {
	return {
		id: "theauth-api-key",

		async init(ctx): Promise<undefined> {
			const module = createApiKeyManagerModule(config ?? {}, ctx.db);

			// POST /auth/api-keys
			// Creates a new API key for the authenticated user. Returns the full
			// key once — it is never stored in plaintext and cannot be retrieved again.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/api-keys",
				metadata: {
					requireAuth: true,
					description: "Create a new API key for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const name =
						typeof bodyResult.data.name === "string" ? bodyResult.data.name.trim() : null;
					const permissions = Array.isArray(bodyResult.data.permissions)
						? bodyResult.data.permissions
						: null;

					if (!name || !permissions) {
						return json({ error: "Missing required fields: name, permissions" }, 400);
					}

					const expiresAt = bodyResult.data.expiresAt
						? new Date(bodyResult.data.expiresAt as string)
						: undefined;

					try {
						const result = await module.create({
							userId: user.id,
							name,
							permissions: permissions as string[],
							expiresAt,
						});
						return json(result, 201);
					} catch (err) {
						return json(
							{ error: err instanceof Error ? err.message : "Failed to create API key" },
							500,
						);
					}
				},
			});

			// GET /auth/api-keys
			// Lists all API keys for the authenticated user (hashes and prefixes only —
			// full keys are never returned after creation).
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/api-keys",
				metadata: {
					requireAuth: true,
					description: "List API keys for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const keys = await module.list(user.id);
					return json({ apiKeys: keys });
				},
			});

			// DELETE /auth/api-keys/:id
			// Revokes an API key. The key must belong to the authenticated user.
			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/api-keys/:id",
				metadata: {
					requireAuth: true,
					description: "Revoke an API key for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "api-keys", "<id>"]
					const keyId = segments[2];

					if (!keyId) {
						return json({ error: "Missing API key ID in path" }, 400);
					}

					// Confirm ownership before revoking.
					const keys = await module.list(user.id);
					const owned = keys.some((k) => k.id === decodeURIComponent(keyId));
					if (!owned) {
						return json({ error: "API key not found" }, 404);
					}

					await module.revoke(decodeURIComponent(keyId));
					return json({ revoked: true });
				},
			});

			// POST /auth/api-keys/:id/rotate
			// Revokes the existing key and issues a new one with identical settings.
			// Returns the new key once — the same one-time-display rule applies.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/api-keys/:id/rotate",
				metadata: {
					requireAuth: true,
					description: "Rotate an API key — revokes the old one and returns a new key",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "api-keys", "<id>", "rotate"]
					const keyId = segments[2];

					if (!keyId) {
						return json({ error: "Missing API key ID in path" }, 400);
					}

					// Confirm ownership before rotating.
					const keys = await module.list(user.id);
					const owned = keys.some((k) => k.id === decodeURIComponent(keyId));
					if (!owned) {
						return json({ error: "API key not found" }, 404);
					}

					try {
						const result = await module.rotate(decodeURIComponent(keyId));
						return json(result);
					} catch (err) {
						return json(
							{ error: err instanceof Error ? err.message : "Failed to rotate API key" },
							400,
						);
					}
				},
			});
		},
	};
}
