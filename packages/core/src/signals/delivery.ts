/**
 * Push delivery (RFC 8935) with SSRF-safe URL validation.
 *
 * Reuses the https, port, credential, blocked-host and private-address checks
 * of the MCP safe fetcher. The URL is validated when a stream is configured and
 * again at every delivery attempt, so a hostname that later resolves to a
 * private address is not contacted.
 */

import type { DnsResolver } from "../mcp/safe-fetch.js";
import {
	checkFetchableUrl,
	defaultDnsResolver,
	isBlockedIp,
	isIpLiteral,
} from "../mcp/safe-fetch.js";
import { SET_MEDIA_TYPE } from "./types.js";

export interface UrlGuardOptions {
	resolver?: DnsResolver;
	/** Development only: skip the https and private network checks. */
	allowInsecure?: boolean;
}

export async function validateDeliveryUrl(
	raw: string,
	options: UrlGuardOptions = {},
): Promise<{ ok: true; url: URL } | { ok: false; message: string }> {
	if (options.allowInsecure) {
		try {
			const url = new URL(raw);
			if (url.protocol !== "https:" && url.protocol !== "http:") {
				return { ok: false, message: "only http and https URLs are allowed" };
			}
			return { ok: true, url };
		} catch {
			return { ok: false, message: "not a valid URL" };
		}
	}
	const checked = checkFetchableUrl(raw);
	if (!checked.ok) return checked;
	const host = checked.url.hostname;
	try {
		// An IP literal is its own address; never hand it to the resolver.
		const addresses = isIpLiteral(host)
			? [host]
			: await (options.resolver ?? defaultDnsResolver)(host);
		if (addresses.length === 0) return { ok: false, message: "hostname has no addresses" };
		if (addresses.some(isBlockedIp)) {
			return { ok: false, message: "host resolves to a non-public address" };
		}
	} catch {
		return { ok: false, message: "hostname could not be resolved" };
	}
	return { ok: true, url: checked.url };
}

export type PushOutcome =
	| { kind: "delivered"; status: number }
	| { kind: "retry"; message: string }
	| { kind: "permanent"; message: string };

export interface PushOptions extends UrlGuardOptions {
	authorizationHeader?: string | null;
	fetchImpl?: typeof fetch;
	timeoutMs?: number;
}

/**
 * POST one SET. Never throws.
 *
 * 2xx is success. 408, 429 and 5xx and network errors are retryable. Other
 * statuses (including RFC 8935 `400` error responses) and redirects are
 * permanent. A URL that fails the SSRF check is permanent.
 */
export async function pushSet(
	url: string,
	jwt: string,
	options: PushOptions = {},
): Promise<PushOutcome> {
	const checked = await validateDeliveryUrl(url, options);
	if (!checked.ok) return { kind: "permanent", message: `unsafe url: ${checked.message}` };
	const headers: Record<string, string> = {
		"Content-Type": SET_MEDIA_TYPE,
		Accept: "application/json",
	};
	if (options.authorizationHeader) headers.Authorization = options.authorizationHeader;
	let response: Response;
	try {
		response = await (options.fetchImpl ?? fetch)(checked.url.toString(), {
			method: "POST",
			headers,
			body: jwt,
			redirect: "manual",
			credentials: "omit",
			signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
		});
	} catch {
		return { kind: "retry", message: "receiver unreachable or timed out" };
	}
	if (response.status >= 200 && response.status < 300) {
		return { kind: "delivered", status: response.status };
	}
	if (response.status >= 300 && response.status < 400) {
		return { kind: "permanent", message: "redirects are not followed" };
	}
	if (response.status === 408 || response.status === 429 || response.status >= 500) {
		return { kind: "retry", message: `receiver answered ${response.status}` };
	}
	return { kind: "permanent", message: `receiver answered ${response.status}` };
}

export interface BackoffOptions {
	baseMs?: number;
	maxMs?: number;
}

/** Exponential backoff with up to 20 percent downward jitter. `attempt` starts at 1. */
export function backoffMs(
	attempt: number,
	options: BackoffOptions = {},
	random = Math.random,
): number {
	const base = options.baseMs ?? 1000;
	const max = options.maxMs ?? 5 * 60 * 1000;
	const raw = Math.min(max, base * 2 ** Math.max(0, attempt - 1));
	return Math.round(raw * (1 - 0.2 * random()));
}
