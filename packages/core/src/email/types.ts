export interface EmailSendOptions {
	to: string;
	subject: string;
	html: string;
	text?: string;
	from?: string;
	replyTo?: string;
}

export interface EmailSendResult {
	id: string;
}

export interface EmailProvider {
	send(options: EmailSendOptions): Promise<EmailSendResult>;
}
