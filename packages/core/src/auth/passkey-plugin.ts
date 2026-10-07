import { buildSetCookie } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { PasskeyConfig } from "./passkey.js";
import { createPasskeyModule } from "./passkey.js";

export type { PasskeyConfig };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function passkey(config: PasskeyConfig): TheAuthPlugin {
	return {
		id: "theauth-passkey",

		async init(ctx): Promise<undefined> {
			const module = createPasskeyModule(config, ctx.db);

			// POST /auth/passkey/register/options
			// Accepts { userId: string; userName: string } and returns WebAuthn
			// registration options to pass to navigator.credentials.create().
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/passkey/register/options",
				metadata: {
					requireAuth: true,
					description: "Get WebAuthn registration options for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const userId = typeof body.userId === "string" ? body.userId : user.id;
					const userName =
						typeof body.userName === "string" ? body.userName : (user.email ?? user.id);

					try {
						const options = await module.getRegistrationOptions(userId, userName);
						return jsonResponse(options);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to generate options" },
							500,
						);
					}
				},
			});

			// POST /auth/passkey/register/verify
			// Accepts the PublicKeyCredential response from the browser and stores
			// the credential after verifying the attestation.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/passkey/register/verify",
				metadata: {
					requireAuth: true,
					description: "Verify WebAuthn registration and store the credential",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const userId = typeof body.userId === "string" ? body.userId : user.id;
					const response = body.response as
						| Parameters<typeof module.verifyRegistration>[1]
						| undefined;

					if (!response) {
						return jsonResponse({ error: "Missing required field: response" }, 400);
					}

					try {
						const result = await module.verifyRegistration(userId, response);
						return jsonResponse(result);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Registration failed" },
							400,
						);
					}
				},
			});

			// POST /auth/passkey/authenticate/options
			// Returns a WebAuthn authentication challenge. Pass userId to limit
			// the allowed credentials to those belonging to that user.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/passkey/authenticate/options",
				metadata: {
					description: "Get WebAuthn authentication options",
				},
				async handler(request) {
					const body = await parseBody(request);
					const userId = typeof body.userId === "string" ? body.userId : undefined;

					try {
						const options = await module.getAuthenticationOptions(userId);
						return jsonResponse(options);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to generate options" },
							500,
						);
					}
				},
			});

			// POST /auth/passkey/authenticate/verify
			// Verifies the authenticator assertion and returns userId + credential.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/passkey/authenticate/verify",
				metadata: {
					description: "Verify a WebAuthn assertion and return the authenticated user",
				},
				async handler(request) {
					const body = await parseBody(request);
					const response = body.response as
						| Parameters<typeof module.verifyAuthentication>[0]
						| undefined;

					if (!response) {
						return jsonResponse({ error: "Missing required field: response" }, 400);
					}

					try {
						const result = await module.verifyAuthentication(response);
						if (!result) {
							return jsonResponse({ error: "Authentication failed" }, 401);
						}

						// Issue a session if session manager is available
						if (ctx.sessionManager) {
							const { session, token } = await ctx.sessionManager.create(result.userId);
							const maxAge = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);

							return new Response(
								JSON.stringify({
									user: { id: result.userId },
									session: { token, expiresAt: session.expiresAt },
									credential: result.credential,
								}),
								{
									status: 200,
									headers: {
										"Content-Type": "application/json",
										"Set-Cookie": buildSetCookie(
											"theauth_session",
											token,
											maxAge,
											"/",
											(ctx.config.baseUrl ?? "").startsWith("https://"),
										),
									},
								},
							);
						}

						// Fallback: no session manager, return raw result
						return jsonResponse(result);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Authentication failed" },
							401,
						);
					}
				},
			});

			// GET /auth/passkey/credentials
			// Lists all passkey credentials for the authenticated user.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/passkey/credentials",
				metadata: {
					requireAuth: true,
					description: "List passkey credentials for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					try {
						const credentials = await module.listCredentials(user.id);
						return jsonResponse({ credentials });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to list credentials" },
							500,
						);
					}
				},
			});

			// DELETE /auth/passkey/credentials/:id
			// Removes a specific passkey credential belonging to the authenticated user.
			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/passkey/credentials/:id",
				metadata: {
					requireAuth: true,
					description: "Remove a passkey credential for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "passkey", "credentials", "<id>"]
					const credentialId = segments[3];

					if (!credentialId) {
						return jsonResponse({ error: "Missing credential ID in path" }, 400);
					}

					try {
						await module.removeCredential(credentialId, user.id);
						return jsonResponse({ removed: true });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to remove credential" },
							500,
						);
					}
				},
			});
		},
	};
}
