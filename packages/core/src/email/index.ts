// Types

export type { ConsoleConfig } from "./console.js";
// Providers
export { consoleProvider } from "./console.js";
export type { PostmarkConfig } from "./postmark.js";
export { postmark } from "./postmark.js";
export type { ResendConfig } from "./resend.js";
export { resend } from "./resend.js";
export type { SendGridConfig } from "./sendgrid.js";
export { sendgrid } from "./sendgrid.js";
export type { SesConfig } from "./ses.js";
export { ses } from "./ses.js";
export type { SmtpConfig } from "./smtp.js";
export { smtp } from "./smtp.js";
// Templates
export type {
	EmailTemplate,
	EmailTemplateConfig,
	EmailTemplateName,
	EmailTemplates,
} from "./templates.js";
export { createEmailTemplates, escapeHtml } from "./templates.js";
export type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";
