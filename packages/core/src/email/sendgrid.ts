import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface SendGridConfig {
	/** SendGrid API key (required). */
	apiKey: string;
	/** Default from address, e.g. "auth@example.com" */
	from?: string;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Email provider backed by SendGrid (https://sendgrid.com).
 * Uses raw fetch() — no SDK dependency, edge-compatible.
 */
export function sendgrid(config: SendGridConfig): EmailProvider {
	if (!config.apiKey) {
		throw new Error(
			"[theauth/email] sendgrid: apiKey is required. " +
				"Pass { apiKey: process.env.SENDGRID_API_KEY } when creating the provider.",
		);
	}

	const from = config.from ?? "noreply@example.com";

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const senderEmail = options.from ?? from;

			const body: Record<string, unknown> = {
				personalizations: [{ to: [{ email: options.to }] }],
				from: { email: senderEmail },
				subject: options.subject,
				content: [{ type: "text/html", value: options.html }],
			};

			if (options.text) {
				const content = body.content as Array<{ type: string; value: string }>;
				content.unshift({ type: "text/plain", value: options.text });
			}

			if (options.replyTo) {
				body.reply_to = { email: options.replyTo };
			}

			const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
				method: "POST",
				headers: {
					Authorization: `Bearer ${config.apiKey}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify(body),
			});

			if (!response.ok) {
				const text = await response.text().catch(() => "(no body)");
				throw new Error(
					`[theauth/email] sendgrid: request failed with status ${response.status}: ${text}`,
				);
			}

			// SendGrid returns 202 Accepted with no body; generate a synthetic id
			// from the X-Message-Id response header when present.
			const messageId = response.headers.get("X-Message-Id") ?? crypto.randomUUID();
			return { id: messageId };
		},
	};
}
