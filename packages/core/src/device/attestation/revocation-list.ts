import type { RevocationCheck } from "./android-key.js";

export const GOOGLE_ATTESTATION_STATUS_URL = "https://android.googleapis.com/attestation/status";

export interface GoogleRevocationListOptions {
	/** Override for tests or a proxy. Default `globalThis.fetch`. */
	fetch?: typeof globalThis.fetch;
	url?: string;
	/** Refresh interval in seconds. Default: the `Cache-Control: max-age` of the response, else 3600. */
	maxAgeSeconds?: number;
	/** Longest the cached list may be used after a refresh fails, in seconds. Default 0: fail closed at once. */
	staleIfErrorSeconds?: number;
	now?: () => number;
}

interface StatusFile {
	entries?: Record<string, { status?: string }>;
}

/**
 * Revocation check backed by Google's attestation status list (https://source.android.com/docs/security/features/keystore/attestation#certificate-revocation-status-list). A serial counts as revoked when it has an entry with status REVOKED or SUSPENDED. The list is cached by its Cache-Control header. When it cannot be fetched the check throws, which the enrollment hook turns into a refusal, so a network failure never lets a revoked key through.
 */
export function googleRevocationList(options: GoogleRevocationListOptions = {}): RevocationCheck {
	const now = options.now ?? Date.now;
	let cached: { serials: Set<string>; fetchedAt: number; maxAgeMs: number } | undefined;
	let inflight: Promise<void> | undefined;

	async function refresh(): Promise<void> {
		const doFetch = options.fetch ?? globalThis.fetch;
		const res = await doFetch(options.url ?? GOOGLE_ATTESTATION_STATUS_URL, {
			headers: { accept: "application/json" },
		});
		if (!res.ok) throw new Error(`Revocation list request failed with ${res.status}`);
		const body = (await res.json()) as StatusFile;
		if (
			typeof body !== "object" ||
			body === null ||
			typeof body.entries !== "object" ||
			body.entries === null
		) {
			throw new Error("Revocation list has no entries object");
		}
		const serials = new Set<string>();
		for (const [serial, entry] of Object.entries(body.entries)) {
			if (entry?.status === "REVOKED" || entry?.status === "SUSPENDED")
				serials.add(serial.toLowerCase());
		}
		const header = /max-age=(\d+)/.exec(res.headers.get("cache-control") ?? "");
		const seconds = options.maxAgeSeconds ?? (header ? Number(header[1]) : 3600);
		cached = { serials, fetchedAt: now(), maxAgeMs: seconds * 1000 };
	}

	return async (serialHex) => {
		const age = cached ? now() - cached.fetchedAt : Number.POSITIVE_INFINITY;
		if (!cached || age >= cached.maxAgeMs) {
			try {
				inflight ??= refresh().finally(() => {
					inflight = undefined;
				});
				await inflight;
			} catch (err) {
				const grace = (options.staleIfErrorSeconds ?? 0) * 1000;
				if (!cached || age >= cached.maxAgeMs + grace) throw err;
			}
		}
		return cached?.serials.has(serialHex.toLowerCase()) ?? true;
	};
}
