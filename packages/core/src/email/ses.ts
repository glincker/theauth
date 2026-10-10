import { compareCodeUnits } from "../compare.js";
import { hmacSha256Raw, sha256, toHex } from "../crypto/web-crypto.js";
import type { EmailProvider, EmailSendOptions, EmailSendResult } from "./types.js";

export interface SesConfig {
	/** AWS region, e.g. "us-east-1" (required). */
	region: string;
	accessKeyId: string;
	secretAccessKey: string;
	/** Session token for temporary credentials (STS, IAM roles). */
	sessionToken?: string;
	/** Default from address. Must be a verified SES identity. */
	from?: string;
	/** Override the endpoint (for localstack or VPC endpoints). */
	endpoint?: string;
}

const SERVICE = "ses";

function amzDate(now: Date): { date: string; stamp: string } {
	const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
	return { stamp: iso, date: iso.slice(0, 8) };
}

async function signingKey(secret: string, date: string, region: string): Promise<Uint8Array> {
	const kDate = await hmacSha256Raw(`AWS4${secret}`, date);
	const kRegion = await hmacSha256Raw(kDate, region);
	const kService = await hmacSha256Raw(kRegion, SERVICE);
	return hmacSha256Raw(kService, "aws4_request");
}

/**
 * Email provider backed by Amazon SES v2 (SendEmail). Requests are signed with
 * SigV4 using Web Crypto, so there is no AWS SDK dependency and it runs on edge
 * runtimes.
 */
export function ses(config: SesConfig): EmailProvider {
	if (!config.region || !config.accessKeyId || !config.secretAccessKey) {
		throw new Error("[theauth/email] ses: region, accessKeyId and secretAccessKey are required.");
	}
	const from = config.from ?? "noreply@example.com";
	const endpoint = config.endpoint ?? `https://email.${config.region}.amazonaws.com`;

	return {
		async send(options: EmailSendOptions): Promise<EmailSendResult> {
			const payload = JSON.stringify({
				FromEmailAddress: options.from ?? from,
				Destination: { ToAddresses: [options.to] },
				...(options.replyTo ? { ReplyToAddresses: [options.replyTo] } : {}),
				Content: {
					Simple: {
						Subject: { Data: options.subject, Charset: "UTF-8" },
						Body: {
							Html: { Data: options.html, Charset: "UTF-8" },
							...(options.text ? { Text: { Data: options.text, Charset: "UTF-8" } } : {}),
						},
					},
				},
			});

			const url = new URL("/v2/email/outbound-emails", endpoint);
			const { date, stamp } = amzDate(new Date());
			const payloadHash = await sha256(payload);

			const headers: Record<string, string> = {
				"content-type": "application/json",
				host: url.host,
				"x-amz-content-sha256": payloadHash,
				"x-amz-date": stamp,
			};
			if (config.sessionToken) headers["x-amz-security-token"] = config.sessionToken;

			const names = Object.keys(headers).sort(compareCodeUnits);
			const canonicalHeaders = names.map((n) => `${n}:${headers[n]}\n`).join("");
			const signedHeaders = names.join(";");
			const canonicalRequest = [
				"POST",
				url.pathname,
				"",
				canonicalHeaders,
				signedHeaders,
				payloadHash,
			].join("\n");

			const scope = `${date}/${config.region}/${SERVICE}/aws4_request`;
			const stringToSign = ["AWS4-HMAC-SHA256", stamp, scope, await sha256(canonicalRequest)].join(
				"\n",
			);
			const key = await signingKey(config.secretAccessKey, date, config.region);
			const signature = toHex(await hmacSha256Raw(key, stringToSign));

			const response = await fetch(url.toString(), {
				method: "POST",
				headers: {
					...headers,
					Authorization: `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
				},
				body: payload,
			});

			if (!response.ok) {
				const text = await response.text().catch(() => "(no body)");
				throw new Error(
					`[theauth/email] ses: request failed with status ${response.status}: ${text}`,
				);
			}
			const data = (await response.json()) as { MessageId?: string };
			return { id: data.MessageId ?? "" };
		},
	};
}
