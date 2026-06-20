/**
 * Have I Been Pwned password checking for TheAuth.
 *
 * Uses the k-anonymity model: only the first 5 hex characters of the SHA-1
 * hash are sent to the API. The full hash (and the password itself) never
 * leave the process.
 *
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 */

import { sha1 } from "../crypto/web-crypto.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface HibpConfig {
	/** Reject passwords seen in more than N breaches (default: 0, reject any). */
	threshold?: number;
	/** Custom API base URL, e.g. for a self-hosted HIBP instance. */
	apiUrl?: string;
	/** Request timeout in milliseconds (default: 5000). */
	timeoutMs?: number;
	/**
	 * What to do when the HIBP API is unreachable or returns an error.
	 * - `'allow'` – treat the password as clean and let the user continue.
	 * - `'block'` – reject the password to be safe.
	 * Default: `'allow'`.
	 */
	onError?: "allow" | "block";
}

export interface HibpModule {
	/**
	 * Check whether the password appears in any known data breach.
	 * Returns the number of times it has been seen, or 0 if clean / API error
	 * with `onError: 'allow'`.
	 */
	check(password: string): Promise<number>;
	/**
	 * Like `check`, but throws a `HibpBreachedError` when the breach count
	 * exceeds the configured threshold.
	 */
	enforce(password: string): Promise<void>;
}

export class HibpBreachedError extends Error {
	readonly count: number;

	constructor(count: number) {
		super(`Password has appeared in ${count} known data breach${count === 1 ? "" : "es"}`);
		this.name = "HibpBreachedError";
		this.count = count;
	}
}

// ---------------------------------------------------------------------------
// SHA-1 helper (Web Crypto API)
// ---------------------------------------------------------------------------

async function sha1Hex(input: string): Promise<string> {
	const hex = await sha1(input);
	return hex.toUpperCase();
}

// ---------------------------------------------------------------------------
// Response parser
// ---------------------------------------------------------------------------

/**
 * Parse the HIBP range response body.
 *
 * Each line is `<SUFFIX>:<COUNT>` where SUFFIX is the hash minus the first 5
 * characters (already stripped by the API).
 */
function parseRangeResponse(body: string): Map<string, number> {
	const entries = new Map<string, number>();

	for (const line of body.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;

		const colonIdx = trimmed.indexOf(":");
		if (colonIdx === -1) continue;

		const suffix = trimmed.slice(0, colonIdx).toUpperCase();
		const count = parseInt(trimmed.slice(colonIdx + 1), 10);

		if (suffix && !Number.isNaN(count)) {
			entries.set(suffix, count);
		}
	}

	return entries;
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createHibpModule(config?: HibpConfig): HibpModule {
	const threshold = config?.threshold ?? 0;
	const apiUrl = (config?.apiUrl ?? "https://api.pwnedpasswords.com").replace(/\/$/, "");
	const timeoutMs = config?.timeoutMs ?? 5000;
	const onError = config?.onError ?? "allow";

	async function check(password: string): Promise<number> {
		const hash = await sha1Hex(password);
		// k-anonymity: only the prefix leaves this process
		const prefix = hash.slice(0, 5);
		const suffix = hash.slice(5);

		let body: string;

		try {
			const response = await fetch(`${apiUrl}/range/${prefix}`, {
				headers: {
					// Ask the API not to pad results (reduces response size)
					"Add-Padding": "false",
				},
				signal: AbortSignal.timeout(timeoutMs),
			});

			if (!response.ok) {
				throw new Error(`HIBP API returned HTTP ${response.status}`);
			}

			body = await response.text();
		} catch (err) {
			if (onError === "block") {
				// Surface a distinct error so callers can distinguish API failure
				// from a confirmed breach
				throw new HibpApiError(err instanceof Error ? err.message : "HIBP API request failed");
			}
			// onError === 'allow' — treat as clean
			return 0;
		}

		const entries = parseRangeResponse(body);
		return entries.get(suffix) ?? 0;
	}

	async function enforce(password: string): Promise<void> {
		const count = await check(password);

		if (count > threshold) {
			throw new HibpBreachedError(count);
		}
	}

	return { check, enforce };
}

export class HibpApiError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "HibpApiError";
	}
}
