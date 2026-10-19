/**
 * SMS delivery for one-time codes: Vonage and Plivo, over raw fetch with no SDK.
 * Twilio lives in otp-senders.ts. Every sender implements OtpSender, handles only the
 * sms channel, and never puts credentials, numbers or codes into an error message.
 *
 * Vonage Messages API: https://developer.vonage.com/en/api/messages (POST /v1/messages, Basic auth)
 * Plivo Message API: https://www.plivo.com/docs/messaging/api/message/send-a-message (POST /v1/Account/{auth_id}/Message/, Basic auth)
 */

import { describeOtp, smsFailure } from "./otp-message.js";
import type { OtpSender } from "./otp-senders.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export interface VonageSenderConfig {
	apiKey: string;
	apiSecret: string;
	/** Sender number in E.164, or an alphanumeric sender ID where the destination country allows it. */
	from: string;
	/** Data residency region for the API host. Default `api`. */
	region?: "api" | "api-eu" | "api-us" | "api-ap";
	timeoutMs?: number;
}

export interface PlivoSenderConfig {
	authId: string;
	authToken: string;
	/** Sender number, short code or alphanumeric ID. Provide this or `powerpackUuid`. */
	from?: string;
	powerpackUuid?: string;
	timeoutMs?: number;
}

function requireSms(provider: string, channel: string): void {
	if (channel !== "sms") {
		throw new Error(`[theauth/otp] ${provider}OtpSender can only deliver the sms channel.`);
	}
}

export function vonageOtpSender(config: VonageSenderConfig): OtpSender {
	if (!config.apiKey || !config.apiSecret) {
		throw new Error("[theauth/otp] vonage: apiKey and apiSecret are required.");
	}
	if (!config.from) throw new Error("[theauth/otp] vonage: `from` is required.");
	const auth = btoa(`${config.apiKey}:${config.apiSecret}`);
	const host = `${config.region ?? "api"}.nexmo.com`;
	return {
		async send(message) {
			requireSms("vonage", message.channel);
			const response = await fetch(`https://${host}/v1/messages`, {
				method: "POST",
				headers: {
					Authorization: `Basic ${auth}`,
					"Content-Type": "application/json",
					Accept: "application/json",
				},
				// Vonage wants E.164 without the leading plus.
				body: JSON.stringify({
					message_type: "text",
					channel: "sms",
					to: message.to.replace(/^\+/, ""),
					from: config.from,
					text: describeOtp(message),
				}),
				signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
			});
			if (!response.ok) throw await smsFailure("vonage", response);
		},
	};
}

export function plivoOtpSender(config: PlivoSenderConfig): OtpSender {
	if (!config.authId || !config.authToken) {
		throw new Error("[theauth/otp] plivo: authId and authToken are required.");
	}
	if (!config.from && !config.powerpackUuid) {
		throw new Error("[theauth/otp] plivo: provide `from` or `powerpackUuid`.");
	}
	const auth = btoa(`${config.authId}:${config.authToken}`);
	return {
		async send(message) {
			requireSms("plivo", message.channel);
			const body: Record<string, string> = { dst: message.to, text: describeOtp(message) };
			if (config.powerpackUuid) body.powerpack_uuid = config.powerpackUuid;
			else if (config.from) body.src = config.from;
			const response = await fetch(
				`https://api.plivo.com/v1/Account/${encodeURIComponent(config.authId)}/Message/`,
				{
					method: "POST",
					headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
					body: JSON.stringify(body),
					signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
				},
			);
			if (!response.ok) throw await smsFailure("plivo", response);
		},
	};
}
