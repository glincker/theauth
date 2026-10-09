import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

export interface PostmarkConfig {
	/** Postmark server token (required). */
	serverToken: string;
	/** Default from address. Must be a verified sender signature. */
	from?: string;
	/** Message stream id (default: "outbound"). */
	messageStream?: string;
}

/**
 * Email provider backed by Postmark (https://postmarkapp.com).
 * Uses raw fetch(), no SDK dependency, edge-compatible.
 */
export function postmark(config: PostmarkConfig): EmailProvider {
	if (!config.serverToken) {
		throw new Error(
			"[theauth/email] postmark: serverToken is required. " +
				"Pass { serverToken: process.env.POSTMARK_SERVER_TOKEN } when creating the provider.",
		);
	}
	const from = config.from ?? "noreply@example.com";

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const body: Record<string, unknown> = {
				From: options.from ?? from,
				To: options.to,
				Subject: options.subject,
				HtmlBody: options.html,
				MessageStream: config.messageStream ?? "outbound",
			};
			if (options.text) body.TextBody = options.text;
			if (options.replyTo) body.ReplyTo = options.replyTo;

			const response = await fetch("https://api.postmarkapp.com/email", {
				method: "POST",
				headers: {
					"X-Postmark-Server-Token": config.serverToken,
					Accept: "application/json",
					"Content-Type": "application/json",
				},
				body: JSON.stringify(body),
			});

			if (!response.ok) {
				const text = await response.text().catch(() => "(no body)");
				throw new Error(
					`[theauth/email] postmark: request failed with status ${response.status}: ${text}`,
				);
			}
			const data = (await response.json()) as { MessageID?: string };
			return { id: data.MessageID ?? "" };
		},
	};
}
