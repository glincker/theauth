import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ResendConfig {
	/** Resend API key (required). Must start with "re_". */
	apiKey: string;
	/** Default from address, e.g. "auth@example.com" or "App Name <auth@example.com>" */
	from?: string;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Email provider backed by Resend (https://resend.com).
 * Uses raw fetch() — no SDK dependency, edge-compatible.
 */
export function resend(config: ResendConfig): EmailProvider {
	if (!config.apiKey) {
		throw new Error(
			"[theauth/email] resend: apiKey is required. " +
				"Pass { apiKey: process.env.RESEND_API_KEY } when creating the provider.",
		);
	}

	const from = config.from ?? "noreply@example.com";

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const body: Record<string, unknown> = {
				from: options.from ?? from,
				to: [options.to],
				subject: options.subject,
				html: options.html,
			};

			if (options.text) {
				body.text = options.text;
			}
			if (options.replyTo) {
				body.reply_to = options.replyTo;
			}

			const response = await fetch("https://api.resend.com/emails", {
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
					`[theauth/email] resend: request failed with status ${response.status}: ${text}`,
				);
			}

			const data = (await response.json()) as { id?: string };
			return { id: data.id ?? "" };
		},
	};
}
