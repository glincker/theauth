/** Shared message text and error shaping for OTP senders. Kept apart so email and SMS senders do not import each other. */

import type { OtpMessage, OtpPurpose } from "./otp-senders.js";

export const PURPOSE_LABEL: Record<OtpPurpose, string> = {
	"sign-in": "sign-in code",
	"verify-email": "email verification code",
	"reset-password": "password reset code",
	"two-factor": "verification code",
};

export function describeOtp(message: OtpMessage): string {
	const minutes = Math.max(1, Math.round(message.expiresInSeconds / 60));
	return `Your ${PURPOSE_LABEL[message.purpose]} is ${message.code}. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
}

/**
 * Build the error for a failed SMS API call. Carries the HTTP status and the vendor's own
 * short error code or title only. The response body is never copied in: it can echo the
 * recipient number or the message text, which holds the one-time code.
 */
export async function smsFailure(provider: string, response: Response): Promise<Error> {
	let detail = "";
	try {
		const parsed: unknown = JSON.parse(await response.text());
		if (parsed && typeof parsed === "object") {
			const rec = parsed as Record<string, unknown>;
			const code = rec.code ?? rec.error_code ?? rec.title ?? rec.type;
			if (typeof code === "string" || typeof code === "number") {
				detail = ` (${String(code)
					.slice(0, 80)
					.replace(/[^\w:/.-]/g, "")})`;
			}
		}
	} catch {
		// Non-JSON body: report the status alone.
	}
	return new Error(
		`[theauth/otp] ${provider}: request failed with status ${response.status}${detail}`,
	);
}
