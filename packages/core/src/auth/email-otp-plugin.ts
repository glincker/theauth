import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { EmailOtpConfig } from "./email-otp.js";
import { createEmailOtpModule } from "./email-otp.js";

export type { EmailOtpConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function emailOtp(config: EmailOtpConfig): TheAuthPlugin {
	return {
		id: "theauth-email-otp",

		async init(ctx): Promise<undefined> {
			if (!ctx.sessionManager) {
				throw new Error(
					"theauth-email-otp plugin requires auth.session to be configured so that sessions can be issued on successful verification.",
				);
			}

			const module = createEmailOtpModule(config, ctx.db, ctx.sessionManager);

			// POST /auth/email-otp/send
			// Accepts { email: string } and sends an OTP code to that address.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/email-otp/send",
				metadata: {
					rateLimit: { window: 60, max: 5 },
					description: "Send a one-time passcode to the provided email address",
				},
				async handler(request) {
					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const rawEmail =
						typeof bodyResult.data.email === "string"
							? bodyResult.data.email.trim().toLowerCase()
							: null;

					if (!rawEmail) {
						return json({ error: "Missing required field: email" }, 400);
					}

					try {
						const result = await module.sendCode(rawEmail);
						return json(result);
					} catch (err) {
						return json({ error: err instanceof Error ? err.message : "Failed to send OTP" }, 500);
					}
				},
			});

			// POST /auth/email-otp/verify
			// Accepts { email: string; code: string } and returns user + session on success.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/email-otp/verify",
				metadata: {
					rateLimit: { window: 60, max: 10 },
					description: "Verify an OTP code and return a session on success",
				},
				async handler(request) {
					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const rawEmail =
						typeof bodyResult.data.email === "string"
							? bodyResult.data.email.trim().toLowerCase()
							: null;
					const code =
						typeof bodyResult.data.code === "string" ? bodyResult.data.code.trim() : null;

					if (!rawEmail || !code) {
						return json({ error: "Missing required fields: email, code" }, 400);
					}

					const result = await module.verifyCode(rawEmail, code);

					if (!result) {
						return json({ error: "Invalid or expired OTP code" }, 401);
					}

					return json(result);
				},
			});
		},
	};
}
