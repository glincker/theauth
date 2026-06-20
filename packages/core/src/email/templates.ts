export interface EmailTemplate {
	subject: string;
	text: string;
	html: string;
}

export type EmailTemplateName =
	| "verification"
	| "passwordReset"
	| "magicLink"
	| "emailOtp"
	| "invitation"
	| "welcome";

export interface EmailTemplateConfig {
	appName?: string;
	appUrl?: string;
	/** Custom templates override defaults */
	templates?: Partial<Record<EmailTemplateName, (vars: Record<string, string>) => EmailTemplate>>;
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

/**
 * Escape characters that have special meaning in HTML to prevent XSS when
 * interpolating user-controlled strings into HTML templates.
 */
export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;")
		.replace(/`/g, "&#96;");
}

const OUTER_STYLES =
	'font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f4f5;margin:0;padding:0;';
const CONTAINER_STYLES =
	"max-width:560px;margin:32px auto;background:#ffffff;border-radius:8px;overflow:hidden;";
const HEADER_STYLES = "background:#C9A84C;padding:24px 32px;";
const HEADER_H1_STYLES =
	"color:#ffffff;margin:0;font-size:20px;font-weight:600;letter-spacing:-0.3px;";
const BODY_STYLES = "padding:32px;";
const P_STYLES = "margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.6;";
const CODE_STYLES =
	"display:inline-block;background:#fef9ec;border:1px solid #e9c97e;border-radius:6px;padding:12px 24px;font-family:JetBrains Mono,monospace;font-size:24px;font-weight:700;letter-spacing:4px;color:#8B6914;";
const BUTTON_STYLES =
	"display:inline-block;background:#C9A84C;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:6px;font-size:15px;font-weight:600;";
const FOOTER_STYLES =
	"border-top:1px solid #e4e4e7;padding:16px 32px;color:#a1a1aa;font-size:13px;";

function html(appName: string, title: string, body: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head>
<body style="${OUTER_STYLES}">
<table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td>
<div style="${CONTAINER_STYLES}">
  <div style="${HEADER_STYLES}"><h1 style="${HEADER_H1_STYLES}">${appName}</h1></div>
  <div style="${BODY_STYLES}">${body}</div>
  <div style="${FOOTER_STYLES}">You received this email because of activity on your ${appName} account.</div>
</div>
</td></tr></table>
</body>
</html>`;
}

function p(content: string): string {
	return `<p style="${P_STYLES}">${content}</p>`;
}

function button(url: string, label: string): string {
	return `<p style="margin:24px 0;"><a href="${url}" style="${BUTTON_STYLES}">${label}</a></p>`;
}

function code(value: string): string {
	return `<p style="margin:24px 0;"><span style="${CODE_STYLES}">${value}</span></p>`;
}

// ---------------------------------------------------------------------------
// Built-in template factories
// ---------------------------------------------------------------------------

function verificationTemplate(
	appName: string,
	appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const verifyUrl = vars.verifyUrl ?? `${appUrl}/verify?token=${vars.token ?? ""}`;

	return {
		subject: `Verify your email - ${appName}`,
		text: [
			`Verify your email address`,
			``,
			`Hi${email ? ` ${email}` : ""},`,
			``,
			`Please verify your email address by visiting the link below:`,
			``,
			verifyUrl,
			``,
			`This link expires in 24 hours. If you did not create an account, you can ignore this email.`,
		].join("\n"),
		html: html(
			appName,
			`Verify your email`,
			[
				p(`Hi${email ? ` <strong>${email}</strong>` : ""},`),
				p("Please verify your email address to complete your sign-up."),
				button(verifyUrl, "Verify email"),
				p(`Or copy this link: <a href="${verifyUrl}" style="color:#C9A84C;">${verifyUrl}</a>`),
				p(
					`This link expires in 24 hours. If you did not create an account, you can safely ignore this email.`,
				),
			].join(""),
		),
	};
}

function passwordResetTemplate(
	appName: string,
	appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const resetUrl = vars.resetUrl ?? `${appUrl}/reset-password?token=${vars.token ?? ""}`;

	return {
		subject: `Reset your password - ${appName}`,
		text: [
			`Reset your password`,
			``,
			`Hi${email ? ` ${email}` : ""},`,
			``,
			`We received a request to reset your password. Click the link below to proceed:`,
			``,
			resetUrl,
			``,
			`This link expires in 1 hour. If you did not request a password reset, you can ignore this email.`,
		].join("\n"),
		html: html(
			appName,
			`Reset your password`,
			[
				p(`Hi${email ? ` <strong>${email}</strong>` : ""},`),
				p("We received a request to reset your password."),
				button(resetUrl, "Reset password"),
				p(`Or copy this link: <a href="${resetUrl}" style="color:#C9A84C;">${resetUrl}</a>`),
				p(
					`This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.`,
				),
			].join(""),
		),
	};
}

function magicLinkTemplate(
	appName: string,
	_appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const url = vars.url ?? "";

	return {
		subject: `Sign in to ${appName}`,
		text: [
			`Sign in to ${appName}`,
			``,
			`Hi${email ? ` ${email}` : ""},`,
			``,
			`Click the link below to sign in to your account. This link expires in 15 minutes and can only be used once.`,
			``,
			url,
		].join("\n"),
		html: html(
			appName,
			`Sign in to ${appName}`,
			[
				p(`Hi${email ? ` <strong>${email}</strong>` : ""},`),
				p(
					"Click the button below to sign in. This link expires in 15 minutes and can only be used once.",
				),
				button(url, `Sign in to ${appName}`),
				p(`Or copy this link: <a href="${url}" style="color:#C9A84C;">${url}</a>`),
			].join(""),
		),
	};
}

function emailOtpTemplate(
	appName: string,
	_appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const otpCode = vars.code ?? "";

	return {
		subject: `Your verification code: ${otpCode}`,
		text: [
			`Your verification code`,
			``,
			`Hi${email ? ` ${email}` : ""},`,
			``,
			`Your ${appName} verification code is:`,
			``,
			otpCode,
			``,
			`This code expires in 10 minutes. Do not share it with anyone.`,
		].join("\n"),
		html: html(
			appName,
			`Your verification code`,
			[
				p(`Hi${email ? ` <strong>${email}</strong>` : ""},`),
				p(`Your ${appName} verification code is:`),
				code(otpCode),
				p("This code expires in 10 minutes. Do not share it with anyone."),
			].join(""),
		),
	};
}

function invitationTemplate(
	appName: string,
	_appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const orgName = vars.orgName ?? "an organization";
	const inviteUrl = vars.inviteUrl ?? "";

	return {
		subject: `You've been invited to ${orgName}`,
		text: [
			`You've been invited to ${orgName}`,
			``,
			`Hi${email ? ` ${email}` : ""},`,
			``,
			`You've been invited to join ${orgName} on ${appName}. Click the link below to accept:`,
			``,
			inviteUrl,
			``,
			`If you were not expecting this invitation, you can ignore this email.`,
		].join("\n"),
		html: html(
			appName,
			`You've been invited to ${orgName}`,
			[
				p(`Hi${email ? ` <strong>${email}</strong>` : ""},`),
				p(`You've been invited to join <strong>${orgName}</strong> on ${appName}.`),
				button(inviteUrl, `Accept invitation`),
				p(`Or copy this link: <a href="${inviteUrl}" style="color:#C9A84C;">${inviteUrl}</a>`),
				p("If you were not expecting this invitation, you can safely ignore this email."),
			].join(""),
		),
	};
}

function welcomeTemplate(
	appName: string,
	appUrl: string,
	vars: Record<string, string>,
): EmailTemplate {
	const email = vars.email ?? "";
	const name = vars.name ?? email;

	return {
		subject: `Welcome to ${appName}`,
		text: [
			`Welcome to ${appName}`,
			``,
			`Hi ${name},`,
			``,
			`Your account is ready. Head over to ${appUrl} to get started.`,
			``,
			`If you have any questions, reply to this email.`,
		].join("\n"),
		html: html(
			appName,
			`Welcome to ${appName}`,
			[
				p(`Hi <strong>${name}</strong>,`),
				p(`Your account is ready. Welcome to ${appName}.`),
				button(appUrl, `Get started`),
				p("If you have any questions, just reply to this email."),
			].join(""),
		),
	};
}

// ---------------------------------------------------------------------------
// Public factory
// ---------------------------------------------------------------------------

export interface EmailTemplates {
	render(name: EmailTemplateName, vars: Record<string, string>): EmailTemplate;
}

export function createEmailTemplates(config: EmailTemplateConfig = {}): EmailTemplates {
	const appName = config.appName ?? "TheAuth";
	const appUrl = config.appUrl ?? "http://localhost:3000";
	const overrides = config.templates ?? {};

	function render(name: EmailTemplateName, vars: Record<string, string>): EmailTemplate {
		const override = overrides[name];
		if (override) {
			return override(vars);
		}

		switch (name) {
			case "verification":
				return verificationTemplate(appName, appUrl, vars);
			case "passwordReset":
				return passwordResetTemplate(appName, appUrl, vars);
			case "magicLink":
				return magicLinkTemplate(appName, appUrl, vars);
			case "emailOtp":
				return emailOtpTemplate(appName, appUrl, vars);
			case "invitation":
				return invitationTemplate(appName, appUrl, vars);
			case "welcome":
				return welcomeTemplate(appName, appUrl, vars);
		}
	}

	return { render };
}
