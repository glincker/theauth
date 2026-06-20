import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ConsoleConfig {
	/**
	 * Custom logger function. Defaults to console.log.
	 * Swap to a no-op in test environments where you want silence.
	 */
	logger?: (message: string) => void;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Development / testing email provider that logs emails to stdout instead of
 * actually delivering them. No API keys or network calls needed.
 *
 * This is the recommended default provider for local development.
 */
export function consoleProvider(config: ConsoleConfig = {}): EmailProvider {
	// biome-ignore lint/suspicious/noConsole: console provider's purpose is to log
	const log = config.logger ?? console.log;

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const id = `console-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

			const lines = [
				"",
				"┌─────────────── theauth email (console) ───────────────",
				`│  id      : ${id}`,
				`│  to      : ${options.to}`,
				`│  from    : ${options.from ?? "(not set)"}`,
				`│  subject : ${options.subject}`,
				...(options.replyTo ? [`│  reply-to: ${options.replyTo}`] : []),
				"├─────────────── text ────────────────────────────────────",
				...(options.text ?? "(no text body)").split("\n").map((l) => `│  ${l}`),
				"└─────────────────────────────────────────────────────────",
				"",
			];

			log(lines.join("\n"));

			return { id };
		},
	};
}
