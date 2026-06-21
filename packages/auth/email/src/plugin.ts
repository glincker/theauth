import type { KavachPlugin, PluginContext } from "@glinr/theauth";
import { createRateLimiter, withRateLimit } from "@glinr/theauth/auth";
import { createEmailAuth } from "./email-auth.js";
import { EmailAuthError, ErrorCodes } from "./errors.js";
import type { EmailAuthConfig } from "./types.js";

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function jsonOk(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function jsonError(code: string, message: string, status = 400): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
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

function errorToResponse(err: unknown): Response {
	if (err instanceof EmailAuthError) {
		const status =
			err.code === ErrorCodes.INVALID_CREDENTIALS || err.code === ErrorCodes.EMAIL_NOT_VERIFIED
				? 401
				: err.code === ErrorCodes.DUPLICATE_EMAIL
					? 409
					: err.code === ErrorCodes.USER_NOT_FOUND
						? 404
						: 400;
		return jsonError(err.code, err.message, status);
	}
	return jsonError("INTERNAL_ERROR", "An unexpected error occurred.", 500);
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

/**
 * Email + password authentication plugin for TheAuth.
 *
 * Usage:
 * ```ts
 * const kavach = createKavach({
 *   plugins: [emailPassword({ appUrl: "https://app.example.com", ... })],
 * });
 * ```
 */
export function emailPassword(config: EmailAuthConfig): KavachPlugin {
	return {
		id: "kavach-email-password",

		async init(ctx: PluginContext): Promise<undefined> {
			const emailAuth = createEmailAuth(config, ctx.db);

			const signUpLimiter = createRateLimiter({ max: 5, window: 60 });
			const signInLimiter = createRateLimiter({ max: 10, window: 60 });
			const resetLimiter = createRateLimiter({ max: 3, window: 60 });

			// POST /auth/sign-up
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/sign-up",
				metadata: {
					description: "Register a new user with email and password",
					rateLimit: { window: 60, max: 5 },
				},
				handler: withRateLimit(async (request) => {
					try {
						const body = await parseBody(request);
						const result = await emailAuth.signUp({
							email: String(body.email ?? ""),
							password: String(body.password ?? ""),
							name: body.name != null ? String(body.name) : undefined,
						});
						return jsonOk(result, 201);
					} catch (err) {
						return errorToResponse(err);
					}
				}, signUpLimiter),
			});

			// POST /auth/sign-in
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/sign-in",
				metadata: {
					description: "Sign in with email and password",
					rateLimit: { window: 60, max: 10 },
				},
				handler: withRateLimit(async (request) => {
					try {
						const body = await parseBody(request);
						const result = await emailAuth.signIn({
							email: String(body.email ?? ""),
							password: String(body.password ?? ""),
						});
						return jsonOk(result);
					} catch (err) {
						return errorToResponse(err);
					}
				}, signInLimiter),
			});

			// POST /auth/verify-email
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/verify-email",
				metadata: {
					description: "Verify email address with token from email link",
				},
				async handler(request) {
					try {
						const body = await parseBody(request);
						const result = await emailAuth.verifyEmail(String(body.token ?? ""));
						return jsonOk(result);
					} catch (err) {
						return errorToResponse(err);
					}
				},
			});

			// POST /auth/request-reset
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/request-reset",
				metadata: {
					description: "Request a password reset email",
					rateLimit: { window: 60, max: 3 },
				},
				handler: withRateLimit(async (request) => {
					try {
						const body = await parseBody(request);
						await emailAuth.requestReset(String(body.email ?? ""));
						// Always return success — do not reveal whether the email exists
						return jsonOk({ success: true });
					} catch (err) {
						return errorToResponse(err);
					}
				}, resetLimiter),
			});

			// POST /auth/reset-password
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/reset-password",
				metadata: {
					description: "Reset password using token from email link",
				},
				async handler(request) {
					try {
						const body = await parseBody(request);
						const result = await emailAuth.resetPassword(
							String(body.token ?? ""),
							String(body.newPassword ?? ""),
						);
						return jsonOk(result);
					} catch (err) {
						return errorToResponse(err);
					}
				},
			});

			// POST /auth/change-password (requires authentication)
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/change-password",
				metadata: {
					description: "Change password for the authenticated user",
					requireAuth: true,
				},
				async handler(request, endpointCtx) {
					try {
						const user = await endpointCtx.getUser(request);
						if (!user) {
							return jsonError("UNAUTHORIZED", "Authentication required.", 401);
						}

						const body = await parseBody(request);
						const result = await emailAuth.changePassword(
							user.id,
							String(body.currentPassword ?? ""),
							String(body.newPassword ?? ""),
						);
						return jsonOk(result);
					} catch (err) {
						return errorToResponse(err);
					}
				},
			});

			return undefined;
		},
	};
}
