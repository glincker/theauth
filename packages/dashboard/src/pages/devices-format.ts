import type {
	CreateEnrollmentTokenInput,
	DeviceCredentialInput,
	DeviceCredentialRow,
	DeviceStatus,
} from "../api/device-types.js";

export type BadgeTone = "green" | "red" | "yellow" | "gray";

export function statusTone(status: DeviceStatus): BadgeTone {
	switch (status) {
		case "active":
			return "green";
		case "suspended":
			return "yellow";
		case "revoked":
			return "red";
	}
}

/** "never", "just now", "5m ago", "3h ago", "2d ago". `now` is injected so tests stay fixed. */
export function formatLastSeen(iso: string | null, now: number): string {
	if (iso === null) return "never";
	const then = new Date(iso).getTime();
	if (Number.isNaN(then)) return "unknown";
	const seconds = Math.max(0, Math.floor((now - then) / 1000));
	if (seconds < 60) return "just now";
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	return `${Math.floor(hours / 24)}d ago`;
}

/** Distinct kinds of the credentials that can still authenticate, for example "jwk, psk". */
export function activeCredentialKinds(credentials: DeviceCredentialRow[]): string {
	const kinds = [...new Set(credentials.filter((c) => c.status === "active").map((c) => c.kind))];
	return kinds.length > 0 ? kinds.sort().join(", ") : "none";
}

export interface EnrollFormValues {
	ownerId: string;
	kind: "claim" | "bulk";
	maxUses: string;
	ttlMinutes: string;
	groups: string;
	deviceKind: string;
}

function positiveInt(raw: string, label: string): number | undefined | string {
	const text = raw.trim();
	if (text === "") return undefined;
	const n = Number(text);
	if (!Number.isInteger(n) || n <= 0) return `${label} must be a whole number above zero`;
	return n;
}

/** Validated request body for POST /devices/enrollment-tokens, or the message to show. */
export function buildEnrollmentInput(form: EnrollFormValues): CreateEnrollmentTokenInput | string {
	const ownerId = form.ownerId.trim();
	if (!ownerId) return "An owner id is required";
	const maxUses = positiveInt(form.maxUses, "Max uses");
	if (typeof maxUses === "string") return maxUses;
	const ttlMinutes = positiveInt(form.ttlMinutes, "Lifetime");
	if (typeof ttlMinutes === "string") return ttlMinutes;
	const groups = form.groups
		.split(",")
		.map((g) => g.trim())
		.filter(Boolean);
	const deviceKind = form.deviceKind.trim();
	return {
		ownerId,
		kind: form.kind,
		...(maxUses !== undefined && { maxUses }),
		...(ttlMinutes !== undefined && { ttlSeconds: ttlMinutes * 60 }),
		...(groups.length > 0 && { groups }),
		...(deviceKind && { deviceKind }),
	};
}

/** "a, b,, a" becomes ["a", "b"]: trimmed, no blanks, no repeats. */
export function parseGroups(raw: string): string[] {
	return [
		...new Set(
			raw
				.split(",")
				.map((g) => g.trim())
				.filter(Boolean),
		),
	];
}

/** Body for POST /devices/:id/credentials from the form, or the message to show. */
export function buildCredentialInput(
	kind: DeviceCredentialInput["kind"],
	text: string,
): DeviceCredentialInput | string {
	if (kind === "psk") return { kind };
	const value = text.trim();
	if (kind === "x509") {
		return value ? { kind, thumbprint: value } : "A certificate thumbprint (x5t#S256) is required";
	}
	if (!value) return "A public JWK is required";
	try {
		const jwk: unknown = JSON.parse(value);
		if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk))
			return "The JWK must be a JSON object";
		return { kind, jwk: jwk as Record<string, unknown> };
	} catch {
		return "The JWK is not valid JSON";
	}
}

/** Optional bundle lifetime in seconds: undefined for blank, a message for anything else invalid. */
export function parseBundleTtl(raw: string): number | undefined | string {
	return positiveInt(raw, "Lifetime");
}

/** Trust domain of a SPIFFE ID (`spiffe://<trust domain>/<path>`), or null when it is not one. */
export function spiffeTrustDomain(id: string): string | null {
	const match = /^spiffe:\/\/([^/]+)\/.+$/.exec(id);
	return match?.[1] ?? null;
}

/** The SPIFFE ID typed into the link form, or the message to show. */
export function buildSpiffeId(text: string): string {
	const value = text.trim();
	if (spiffeTrustDomain(value) === null)
		return "A SPIFFE ID looks like spiffe://example.org/ns/prod/sa/robot";
	return value;
}

export interface AttestationLine {
	label: string;
	value: string;
}

function text(v: unknown): string | undefined {
	return typeof v === "string" && v !== "" ? v : undefined;
}

/**
 * The verified attestation claims of a device as label and value lines for the detail panel, or an empty list when it enrolled without hardware evidence. Reads only claims the verifiers set (android-key-attestation, apple-app-attest, tpm2-quote). Unknown formats show the format name alone: their claims are not interpreted.
 */
export function attestationLines(claims: Record<string, unknown> | undefined): AttestationLine[] {
	if (!claims) return [];
	const format = text(claims.format);
	const lines: AttestationLine[] = [];
	if (format) lines.push({ label: "Format", value: format });
	if (format === "android-key-attestation") {
		const level = text(claims.securityLevel);
		const keyLevel = text(claims.keySecurityLevel);
		if (level)
			lines.push({
				label: "Security level",
				value: keyLevel && keyLevel !== level ? `${level} (key ${keyLevel})` : level,
			});
		const boot = text(claims.verifiedBootState);
		if (boot)
			lines.push({
				label: "Boot state",
				value: claims.deviceLocked === false ? `${boot}, bootloader unlocked` : boot,
			});
		if (Array.isArray(claims.packages) && claims.packages.length > 0) {
			lines.push({
				label: "Apps",
				value: claims.packages.filter((p) => typeof p === "string").join(", "),
			});
		}
	} else if (format === "apple-app-attest") {
		lines.push({ label: "Security level", value: "Secure Enclave" });
		const appId = text(claims.appId);
		if (appId) lines.push({ label: "App", value: appId });
		const env = text(claims.environment);
		if (env) lines.push({ label: "Environment", value: env });
	} else if (format === "tpm2-quote") {
		lines.push({
			label: "Security level",
			value:
				claims.akVerified === true
					? "TPM, attestation key chained to a trusted root"
					: "software, attestation key not verified",
		});
	}
	return lines;
}
