/**
 * HTTP routes for the unified OTP service.
 *
 * Opt-in: nothing is mounted unless you register the plugin.
 *
 * - `POST /auth/code/send`   body `{ purpose?, channel?, identifier }`
 * - `POST /auth/code/verify` body `{ purpose?, identifier, code }`
 *
 * Responses are enumeration safe. Send answers `202 { sent: true }` for every
 * well formed request, whether or not a code went out (cooldown, lockout,
 * delivery failure and `canSend` refusals are not distinguishable). Verify
 * answers `400` with one message for every wrong, expired or unknown code, and
 * `429` only after the identifier is locked, which does not depend on whether
 * an account exists.
 */

import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { OtpService } from "./otp.js";
import type { OtpChannel, OtpPurpose } from "./otp-senders.js";

export interface OtpRoutesConfig {
	service: OtpService;
	/**
	 * Purposes reachable over HTTP. Default `["sign-in", "verify-email"]`.
	 * `reset-password` and `two-factor` are better served by their own modules,
	 * which bind the code to an account.
	 */
	purposes?: OtpPurpose[];
	/** Channel used when the request does not name one. Default `"email"`. */
	defaultChannel?: OtpChannel;
	/**
	 * Return false to silently skip delivery (for example when no account owns
	 * the identifier). The caller still sees the normal 202.
	 */
	canSend?: (
		input: { purpose: OtpPurpose; channel: OtpChannel; identifier: string },
		request: Request,
	) => boolean | Promise<boolean>;
	/**
	 * Runs after a code verifies. Whatever it returns is merged into the 200
	 * body, so this is where you open a session or mark an email verified.
	 */
	onVerified?: (
		input: { purpose: OtpPurpose; identifier: string },
		request: Request,
	) => Promise<Record<string, unknown> | undefined> | Record<string, unknown> | undefined;
	/** Per-IP limit on send. Default 5 per 60 seconds. */
	sendRateLimit?: { window: number; max: number };
	/** Per-IP limit on verify. Default 10 per 60 seconds. */
	verifyRateLimit?: { window: number; max: number };
}

const ALL_PURPOSES: readonly OtpPurpose[] = [
	"sign-in",
	"verify-email",
	"reset-password",
	"two-factor",
];
const MAX_IDENTIFIER_LENGTH = 254;

function isPurpose(value: unknown): value is OtpPurpose {
	return typeof value === "string" && (ALL_PURPOSES as readonly string[]).includes(value);
}

function isChannel(value: unknown): value is OtpChannel {
	return value === "email" || value === "sms";
}

export function otpRoutes(config: OtpRoutesConfig): TheAuthPlugin {
	const allowed = new Set<OtpPurpose>(config.purposes ?? ["sign-in", "verify-email"]);
	const defaultChannel = config.defaultChannel ?? "email";

	function parsePurpose(value: unknown): OtpPurpose | null {
		const purpose = value === undefined ? "sign-in" : value;
		return isPurpose(purpose) && allowed.has(purpose) ? purpose : null;
	}

	function parseIdentifier(value: unknown): string | null {
		if (typeof value !== "string") return null;
		const trimmed = value.trim();
		return trimmed && trimmed.length <= MAX_IDENTIFIER_LENGTH ? trimmed : null;
	}

	return {
		id: "theauth-otp-routes",

		async init(ctx): Promise<undefined> {
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/code/send",
				metadata: {
					rateLimit: config.sendRateLimit ?? { window: 60, max: 5 },
					description: "Send a one-time code by email or SMS",
				},
				async handler(request) {
					const body = await parseBody(request);
					if (!body.ok) return body.response;

					const purpose = parsePurpose(body.data.purpose);
					const identifier = parseIdentifier(body.data.identifier);
					const channel = body.data.channel === undefined ? defaultChannel : body.data.channel;
					if (!purpose || !identifier || !isChannel(channel)) {
						return json({ error: "Invalid purpose, channel or identifier" }, 400);
					}

					const input = { purpose, channel, identifier };
					if (config.canSend && !(await config.canSend(input, request))) {
						return json({ sent: true }, 202);
					}

					const result = await config.service.send(input);
					if (!result.success && result.error.code === "OTP_CHANNEL_UNAVAILABLE") {
						return json({ error: "Invalid purpose, channel or identifier" }, 400);
					}
					return json({ sent: true }, 202);
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/code/verify",
				metadata: {
					rateLimit: config.verifyRateLimit ?? { window: 60, max: 10 },
					description: "Verify a one-time code",
				},
				async handler(request) {
					const body = await parseBody(request);
					if (!body.ok) return body.response;

					const purpose = parsePurpose(body.data.purpose);
					const identifier = parseIdentifier(body.data.identifier);
					const code = typeof body.data.code === "string" ? body.data.code.trim() : "";
					if (!purpose || !identifier || !code || code.length > 16) {
						return json({ error: "Invalid or expired code" }, 400);
					}

					const result = await config.service.verify({ purpose, identifier, code });
					if (!result.success) {
						if (result.error.code === "OTP_LOCKED") {
							const retryAfter = Number(result.error.details?.retryAfter ?? 0);
							const response = json({ error: "Too many attempts. Try again later." }, 429);
							if (retryAfter > 0) response.headers.set("Retry-After", String(retryAfter));
							return response;
						}
						return json({ error: "Invalid or expired code" }, 400);
					}

					const extra = config.onVerified
						? await config.onVerified({ purpose, identifier }, request)
						: undefined;
					return json({ verified: true, ...(extra ?? {}) });
				},
			});
		},
	};
}
