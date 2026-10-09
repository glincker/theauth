import type { TheAuthPlugin } from "../plugin/types.js";
import type { OtpService } from "./otp.js";
import type { OtpChannel } from "./otp-senders.js";
import type { TotpConfig } from "./totp.js";
import { createTotpModule } from "./totp.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * Optional second method: a one-time code sent by email or SMS. Off unless
 * `otp` is set. TOTP behavior is unchanged either way.
 */
export interface TwoFactorOtpConfig {
	service: OtpService;
	/** Where to deliver the code for a user. Return null when none is on file. */
	resolveContact: (userId: string) => Promise<{ channel: OtpChannel; identifier: string } | null>;
}

export type TwoFactorConfig = TotpConfig & { otp?: TwoFactorOtpConfig };

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

export function twoFactor(config?: TwoFactorConfig): TheAuthPlugin {
	return {
		id: "theauth-2fa",

		async init(ctx): Promise<undefined> {
			const module = createTotpModule(config ?? {}, ctx.db);
			const otp = config?.otp;

			if (otp) {
				// POST /auth/2fa/otp/send: deliver a two-factor code to the signed-in user's
				// contact on file. Always answers 202 so a missing contact is not revealed.
				ctx.addEndpoint({
					method: "POST",
					path: "/auth/2fa/otp/send",
					metadata: {
						requireAuth: true,
						rateLimit: { window: 60, max: 5 },
						description: "Send a two-factor code by email or SMS",
					},
					async handler(request, endpointCtx) {
						const user = await endpointCtx.getUser(request);
						if (!user) return jsonResponse({ error: "Authentication required" }, 401);

						const contact = await otp.resolveContact(user.id);
						if (contact) {
							await otp.service.send({ purpose: "two-factor", ...contact });
						}
						return jsonResponse({ sent: true }, 202);
					},
				});

				// POST /auth/2fa/otp/verify: check a two-factor code for the signed-in user.
				ctx.addEndpoint({
					method: "POST",
					path: "/auth/2fa/otp/verify",
					metadata: {
						requireAuth: true,
						rateLimit: { window: 60, max: 10 },
						description: "Verify a two-factor code sent by email or SMS",
					},
					async handler(request, endpointCtx) {
						const user = await endpointCtx.getUser(request);
						if (!user) return jsonResponse({ error: "Authentication required" }, 401);

						const body = await parseBody(request);
						const code = typeof body.code === "string" ? body.code : null;
						if (!code) return jsonResponse({ error: "Missing required field: code" }, 400);

						const contact = await otp.resolveContact(user.id);
						if (!contact) return jsonResponse({ error: "Invalid or expired code" }, 400);

						const result = await otp.service.verify({
							purpose: "two-factor",
							identifier: contact.identifier,
							code,
						});
						if (!result.success) {
							const locked = result.error.code === "OTP_LOCKED";
							return jsonResponse(
								{
									error: locked ? "Too many attempts. Try again later." : "Invalid or expired code",
								},
								locked ? 429 : 400,
							);
						}
						return jsonResponse({ valid: true });
					},
				});
			}

			// POST /auth/2fa/enroll
			// Generates a TOTP secret and QR code URI for the authenticated user.
			// The user must call /auth/2fa/verify to activate 2FA after scanning.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/2fa/enroll",
				metadata: {
					requireAuth: true,
					description: "Generate a TOTP secret and QR code URI for enrollment",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					try {
						const setup = await module.setup(user.id);
						return jsonResponse(setup);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Enrollment failed" },
							500,
						);
					}
				},
			});

			// POST /auth/2fa/verify
			// Verifies a TOTP code. Activates 2FA on first use after enroll
			// (calls enable internally when not yet enabled), or validates during login.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/2fa/verify",
				metadata: {
					requireAuth: true,
					description: "Verify a TOTP code and enable 2FA if not yet active",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const code = typeof body.code === "string" ? body.code : null;

					if (!code) {
						return jsonResponse({ error: "Missing required field: code" }, 400);
					}

					// If 2FA is not yet enabled, treat this verify call as the
					// confirmation step that activates it (post-enrollment flow).
					const enabled = await module.isEnabled(user.id);
					if (!enabled) {
						const result = await module.enable(user.id, code);
						if (!result.enabled) {
							return jsonResponse({ error: "Invalid TOTP code" }, 400);
						}
						return jsonResponse({ valid: true, activated: true });
					}

					const result = await module.verify(user.id, code);
					return jsonResponse(result);
				},
			});

			// POST /auth/2fa/disable
			// Disables 2FA. Requires a valid TOTP code or backup code as confirmation.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/2fa/disable",
				metadata: {
					requireAuth: true,
					description: "Disable 2FA — requires a valid TOTP or backup code",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const code = typeof body.code === "string" ? body.code : null;

					if (!code) {
						return jsonResponse({ error: "Missing required field: code" }, 400);
					}

					const result = await module.disable(user.id, code);
					if (!result.disabled) {
						return jsonResponse({ error: "Invalid TOTP code" }, 400);
					}

					return jsonResponse(result);
				},
			});

			// GET /auth/2fa/status
			// Returns whether 2FA is enabled for the authenticated user.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/2fa/status",
				metadata: {
					requireAuth: true,
					description: "Return whether 2FA is enabled for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const enabled = await module.isEnabled(user.id);
					return jsonResponse({ enabled });
				},
			});

			// POST /auth/2fa/backup-codes
			// Regenerates backup codes. Requires a valid TOTP code as confirmation.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/2fa/backup-codes",
				metadata: {
					requireAuth: true,
					description: "Regenerate backup codes — requires a valid TOTP code",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const code = typeof body.code === "string" ? body.code : null;

					if (!code) {
						return jsonResponse({ error: "Missing required field: code" }, 400);
					}

					try {
						const result = await module.regenerateBackupCodes(user.id, code);
						return jsonResponse(result);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to regenerate backup codes" },
							400,
						);
					}
				},
			});
		},
	};
}
