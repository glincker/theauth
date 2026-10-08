/**
 * Pluggable delivery for one-time codes. A sender gets a fully formed message
 * (channel, recipient, code, purpose) and is responsible only for delivery.
 */

import type { EmailProvider } from "../email/types.js";

export type OtpChannel = "email" | "sms";

/** What a code is for. Codes are scoped by purpose and never valid across purposes. */
export type OtpPurpose = "sign-in" | "verify-email" | "reset-password" | "two-factor";

export interface OtpMessage {
	channel: OtpChannel;
	/** Email address or E.164 phone number. */
	to: string;
	code: string;
	purpose: OtpPurpose;
	expiresInSeconds: number;
}

export interface OtpSender {
	send(message: OtpMessage): Promise<void>;
}

const PURPOSE_LABEL: Record<OtpPurpose, string> = {
	"sign-in": "sign-in code",
	"verify-email": "email verification code",
	"reset-password": "password reset code",
	"two-factor": "verification code",
};

function describe(message: OtpMessage): string {
	const minutes = Math.max(1, Math.round(message.expiresInSeconds / 60));
	return `Your ${PURPOSE_LABEL[message.purpose]} is ${message.code}. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
}

// ---------------------------------------------------------------------------
// Email: wraps any EmailProvider (resend, ses, postmark, sendgrid, smtp, console)
// ---------------------------------------------------------------------------

export interface EmailOtpSenderOptions {
	subject?: (message: OtpMessage) => string;
	/** Override the body. Return plain text and HTML. */
	render?: (message: OtpMessage) => { text: string; html: string };
}

export function emailOtpSender(
	provider: EmailProvider,
	options: EmailOtpSenderOptions = {},
): OtpSender {
	return {
		async send(message) {
			if (message.channel !== "email") {
				throw new Error("[theauth/otp] emailOtpSender can only deliver the email channel.");
			}
			const body = options.render?.(message) ?? {
				text: describe(message),
				// Code is digits only and the label is a fixed string, so no escaping is needed.
				html: `<p>${describe(message)}</p>`,
			};
			await provider.send({
				to: message.to,
				subject: options.subject?.(message) ?? `Your ${PURPOSE_LABEL[message.purpose]}`,
				text: body.text,
				html: body.html,
			});
		},
	};
}

// ---------------------------------------------------------------------------
// SMS: Twilio (raw fetch, no SDK)
// ---------------------------------------------------------------------------

export interface TwilioSenderConfig {
	accountSid: string;
	authToken: string;
	/** Sending number in E.164. Provide this or `messagingServiceSid`. */
	from?: string;
	messagingServiceSid?: string;
}

export function twilioOtpSender(config: TwilioSenderConfig): OtpSender {
	if (!config.accountSid || !config.authToken) {
		throw new Error("[theauth/otp] twilio: accountSid and authToken are required.");
	}
	if (!config.from && !config.messagingServiceSid) {
		throw new Error("[theauth/otp] twilio: provide `from` or `messagingServiceSid`.");
	}
	const auth = btoa(`${config.accountSid}:${config.authToken}`);
	return {
		async send(message) {
			if (message.channel !== "sms") {
				throw new Error("[theauth/otp] twilioOtpSender can only deliver the sms channel.");
			}
			const form = new URLSearchParams({ To: message.to, Body: describe(message) });
			if (config.messagingServiceSid) form.set("MessagingServiceSid", config.messagingServiceSid);
			else if (config.from) form.set("From", config.from);

			const response = await fetch(
				`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.accountSid)}/Messages.json`,
				{
					method: "POST",
					headers: {
						Authorization: `Basic ${auth}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: form.toString(),
				},
			);
			if (!response.ok) {
				const text = await response.text().catch(() => "(no body)");
				throw new Error(
					`[theauth/otp] twilio: request failed with status ${response.status}: ${text}`,
				);
			}
		},
	};
}

// ---------------------------------------------------------------------------
// Console (development)
// ---------------------------------------------------------------------------

export function consoleOtpSender(logger?: (line: string) => void): OtpSender {
	// biome-ignore lint/suspicious/noConsole: the console sender exists to print codes in development
	const log = logger ?? console.log;
	return {
		async send(message) {
			log(
				`[theauth/otp] ${message.channel} to ${message.to} (${message.purpose}): ${message.code}`,
			);
		},
	};
}
