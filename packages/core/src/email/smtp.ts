import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface SmtpConfig {
	/** SMTP hostname, e.g. "smtp.mailgun.org" */
	host: string;
	/** SMTP port. Defaults to 587 (STARTTLS). */
	port?: number;
	/** Use TLS (port 465) or STARTTLS upgrade. Defaults to true. */
	secure?: boolean;
	/** SMTP auth credentials. */
	auth: {
		user: string;
		pass: string;
	};
	/** Default from address, e.g. "auth@example.com" */
	from?: string;
}

// ---------------------------------------------------------------------------
// Nodemailer peer-dep types (subset we need to avoid importing the package at
// the type level — callers who install nodemailer get the real types).
// ---------------------------------------------------------------------------

interface NodemailerTransport {
	sendMail(options: {
		from: string;
		to: string;
		subject: string;
		html: string;
		text?: string;
		replyTo?: string;
	}): Promise<{ messageId: string }>;
}

interface NodemailerModule {
	createTransport(options: {
		host: string;
		port: number;
		secure: boolean;
		auth: { user: string; pass: string };
	}): NodemailerTransport;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Email provider backed by SMTP via nodemailer (peer dependency).
 * Install `nodemailer` separately — it is NOT bundled with theauth.
 *
 * @example
 * ```ts
 * import { smtp } from "theauth/email";
 * smtp({ host: "smtp.mailgun.org", auth: { user: "...", pass: "..." } })
 * ```
 */
export function smtp(config: SmtpConfig): EmailProvider {
	if (!config.host) {
		throw new Error(
			"[theauth/email] smtp: host is required. " +
				'Pass { host: "smtp.example.com", auth: { user, pass } } when creating the provider.',
		);
	}
	if (!config.auth?.user || !config.auth?.pass) {
		throw new Error("[theauth/email] smtp: auth.user and auth.pass are required.");
	}

	const from = config.from ?? "noreply@example.com";
	const port = config.port ?? 587;
	const secure = config.secure ?? port === 465;

	// Lazily resolve nodemailer so that the package import only happens at
	// send time (or when the transport is first constructed). This lets
	// edge-only deployments import this file without errors as long as they
	// never call smtp().
	let transport: NodemailerTransport | null = null;

	async function getTransport(): Promise<NodemailerTransport> {
		if (transport) return transport;

		let nodemailer: NodemailerModule;
		try {
			// @ts-expect-error -- nodemailer is an optional peer dependency
			nodemailer = (await import("nodemailer")) as unknown as NodemailerModule;
		} catch {
			throw new Error(
				"[theauth/email] smtp provider requires the `nodemailer` package. " +
					"Install it with: npm install nodemailer",
			);
		}

		transport = nodemailer.createTransport({
			host: config.host,
			port,
			secure,
			auth: config.auth,
		});

		return transport;
	}

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const t = await getTransport();
			const result = await t.sendMail({
				from: options.from ?? from,
				to: options.to,
				subject: options.subject,
				html: options.html,
				...(options.text ? { text: options.text } : {}),
				...(options.replyTo ? { replyTo: options.replyTo } : {}),
			});
			return { id: result.messageId };
		},
	};
}
