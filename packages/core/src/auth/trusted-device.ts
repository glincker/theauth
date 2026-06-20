/**
 * Trusted device windows for 2FA in TheAuth.
 *
 * After a successful 2FA challenge, a device can be marked as trusted.
 * Subsequent logins from the same device skip 2FA until the trust window
 * expires (default 30 days) or trust is explicitly revoked.
 *
 * Fingerprints are HMAC-signed to prevent client-side spoofing.
 */

import { and, asc, eq, gt } from "drizzle-orm";
import { hmacSha256, randomBytesHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { trustedDevices } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TrustedDeviceConfig {
	/** How long to trust a device in seconds (default: 30 days). */
	trustDurationSeconds?: number;
	/** Maximum number of trusted devices per user (default: 10). */
	maxDevices?: number;
	/**
	 * Secret used to HMAC-sign fingerprints, preventing client spoofing.
	 * Should be a stable application secret (e.g. from env). If omitted a
	 * random per-process key is used (fingerprints won't survive restarts).
	 */
	secret?: string;
}

export interface TrustedDevice {
	id: string;
	fingerprint: string;
	label: string;
	trustedAt: Date;
	expiresAt: Date;
}

export interface TrustedDeviceModule {
	/**
	 * Mark the device identified by `deviceFingerprint` as trusted for
	 * `userId`. Returns a stable trust token (the record id) that can be
	 * stored in a long-lived cookie.
	 */
	trustDevice(userId: string, deviceFingerprint: string): Promise<string>;
	/** Returns true if the device is currently trusted (not expired). */
	isTrusted(userId: string, deviceFingerprint: string): Promise<boolean>;
	/** Remove trust for a single device. */
	revokeDevice(userId: string, deviceFingerprint: string): Promise<void>;
	/** Remove trust for every device belonging to a user. */
	revokeAllDevices(userId: string): Promise<void>;
	/** List all active trusted devices for a user. */
	listDevices(userId: string): Promise<TrustedDevice[]>;
	/**
	 * Derive a stable, HMAC-protected fingerprint from request headers.
	 * The same request will always produce the same fingerprint; changing
	 * user-agent or accept-language invalidates the fingerprint.
	 */
	generateFingerprint(request: Request): Promise<string>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_TRUST_DURATION = 30 * 24 * 60 * 60; // 30 days in seconds
const DEFAULT_MAX_DEVICES = 10;

/** Extract a human-readable label from a User-Agent string. */
function labelFromUserAgent(ua: string): string {
	if (!ua) return "Unknown device";

	// Mobile OS
	if (/iPhone/.test(ua)) return "iPhone";
	if (/iPad/.test(ua)) return "iPad";
	if (/Android/.test(ua)) {
		return /Mobile/.test(ua) ? "Android phone" : "Android tablet";
	}

	// Desktop OS
	if (/Windows NT/.test(ua)) return "Windows";
	if (/Macintosh/.test(ua)) return "Mac";
	if (/Linux/.test(ua)) return "Linux";

	return "Unknown device";
}

/** Generate a URL-safe random id. */
function generateDeviceId(): string {
	return randomBytesHex(16);
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createTrustedDeviceModule(
	config: TrustedDeviceConfig,
	db: Database,
): TrustedDeviceModule {
	const trustDurationSeconds = config.trustDurationSeconds ?? DEFAULT_TRUST_DURATION;
	const maxDevices = config.maxDevices ?? DEFAULT_MAX_DEVICES;
	// Per-process fallback key so the module works without explicit config,
	// but fingerprints will differ across restarts (safe degradation).
	const hmacSecret = config.secret ?? randomBytesHex(32);

	// ── generateFingerprint ────────────────────────────────────────────────

	async function generateFingerprint(request: Request): Promise<string> {
		const ua = request.headers.get("user-agent") ?? "";
		const lang = request.headers.get("accept-language") ?? "";
		const encoding = request.headers.get("accept-encoding") ?? "";
		const accept = request.headers.get("accept") ?? "";

		const payload = [ua, lang, encoding, accept].join("|");

		return hmacSha256(hmacSecret, payload);
	}

	// ── trustDevice ───────────────────────────────────────────────────────

	async function trustDevice(userId: string, deviceFingerprint: string): Promise<string> {
		const now = new Date();
		const expiresAt = new Date(now.getTime() + trustDurationSeconds * 1000);

		// Get existing devices for this user, oldest first
		const existing = await db
			.select()
			.from(trustedDevices)
			.where(eq(trustedDevices.userId, userId))
			.orderBy(asc(trustedDevices.trustedAt));

		// Check if this fingerprint already has a record — refresh it
		const existingRecord = existing.find((d) => d.fingerprint === deviceFingerprint);
		if (existingRecord) {
			await db
				.update(trustedDevices)
				.set({ expiresAt, trustedAt: now })
				.where(eq(trustedDevices.id, existingRecord.id));
			return existingRecord.id;
		}

		// Evict oldest devices when at capacity
		if (existing.length >= maxDevices) {
			const toEvict = existing.slice(0, existing.length - maxDevices + 1);
			for (const device of toEvict) {
				await db.delete(trustedDevices).where(eq(trustedDevices.id, device.id));
			}
		}

		// Derive a user-agent label from the fingerprint's source material by
		// reconstructing it — we store the label separately at trust time.
		// Since we only have the fingerprint here, we store a generic label.
		// Callers who want a specific label should use a separate overload.
		const id = generateDeviceId();

		await db.insert(trustedDevices).values({
			id,
			userId,
			fingerprint: deviceFingerprint,
			label: "Trusted device",
			trustedAt: now,
			expiresAt,
		});

		return id;
	}

	// ── isTrusted ─────────────────────────────────────────────────────────

	async function isTrusted(userId: string, deviceFingerprint: string): Promise<boolean> {
		const now = new Date();

		const rows = await db
			.select({ id: trustedDevices.id })
			.from(trustedDevices)
			.where(
				and(
					eq(trustedDevices.userId, userId),
					eq(trustedDevices.fingerprint, deviceFingerprint),
					gt(trustedDevices.expiresAt, now),
				),
			);

		return rows.length > 0;
	}

	// ── revokeDevice ──────────────────────────────────────────────────────

	async function revokeDevice(userId: string, deviceFingerprint: string): Promise<void> {
		await db
			.delete(trustedDevices)
			.where(
				and(eq(trustedDevices.userId, userId), eq(trustedDevices.fingerprint, deviceFingerprint)),
			);
	}

	// ── revokeAllDevices ──────────────────────────────────────────────────

	async function revokeAllDevices(userId: string): Promise<void> {
		await db.delete(trustedDevices).where(eq(trustedDevices.userId, userId));
	}

	// ── listDevices ───────────────────────────────────────────────────────

	async function listDevices(userId: string): Promise<TrustedDevice[]> {
		const now = new Date();

		const rows = await db
			.select()
			.from(trustedDevices)
			.where(and(eq(trustedDevices.userId, userId), gt(trustedDevices.expiresAt, now)));

		return rows.map((row) => ({
			id: row.id,
			fingerprint: row.fingerprint,
			label: row.label,
			trustedAt: row.trustedAt,
			expiresAt: row.expiresAt,
		}));
	}

	return {
		trustDevice,
		isTrusted,
		revokeDevice,
		revokeAllDevices,
		listDevices,
		generateFingerprint,
	};
}

// ---------------------------------------------------------------------------
// Label helper — exported so adapters can pass a request to produce a label
// ---------------------------------------------------------------------------

/**
 * Derive a human-readable device label from a request's User-Agent header.
 * Useful when calling `trustDevice` so the stored label is descriptive.
 */
export function deviceLabelFromRequest(request: Request): string {
	const ua = request.headers.get("user-agent") ?? "";
	return labelFromUserAgent(ua);
}

// Keep the internal helper available for tests without re-exporting
export { labelFromUserAgent as _labelFromUserAgent };
