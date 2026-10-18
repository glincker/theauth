import type { JWK } from "jose";
import type { Permission } from "../types.js";

/** Algorithms a device key may use for assertions. RSA is refused (large keys, rare on constrained hardware). */
export type DeviceKeyAlg = "ES256" | "ES384" | "EdDSA";

/** Result of an attestation verifier (RFC 9334 Verifier role). We are the Relying Party. */
export type DeviceAttestationResult =
	| { ok: true; claims?: Record<string, unknown> }
	| { ok: false; reason: string };

export interface DeviceAttestationInput {
	/** Raw evidence from the device, for example an EAT (RFC 9711) as a JWT or base64url CWT. */
	evidence: string;
	/** The nonce from `device.attestationNonce()` the device says it used, already checked as fresh and unused. */
	nonce?: string;
	hardwareId?: string;
	enrollmentId: string;
}

export interface DeviceConfig {
	/** Most devices one owner may have (active or suspended). Default 10000. Separate from `agents.maxPerUser`. */
	maxPerOwner?: number;
	/** `aud` a device assertion must carry. Default "theauth". */
	audience?: string;
	/** `iss` of offline policy bundles. Default "theauth". */
	issuer?: string;
	/**
	 * Asymmetric key that signs offline policy bundles. Without it `device.issueBundle` refuses: devices must never hold a verification secret.
	 * `previous` public keys stay in the JWKS during rotation.
	 */
	bundleSigning?: {
		alg: "ES256" | "EdDSA";
		kid: string;
		privateKey: JWK;
		previous?: Array<{ kid: string; publicKey: JWK }>;
	};
	/** Default offline bundle lifetime in seconds. Default 3600, capped at 86400. */
	bundleTtlSeconds?: number;
	/** Evidence verification at enrollment. Without `verify`, any evidence is refused rather than ignored. */
	attestation?: {
		/** Refuse enrollment without evidence that `verify` accepts. */
		required?: boolean;
		verify?: (input: DeviceAttestationInput) => Promise<DeviceAttestationResult>;
	};
	/**
	 * Return the `x5t#S256` thumbprint (RFC 8705 section 3.1) of the TLS client certificate for this request, or null. TLS ends at your proxy, so only you know it. Never read it from a header a client can set.
	 */
	clientCertThumbprint?: (request: Request) => string | null | Promise<string | null>;
}

export type DeviceStatus = "active" | "suspended" | "revoked";

export interface Device {
	id: string;
	/** Backing agent: holds the permissions, delegation chains and audit rows. */
	agentId: string;
	ownerId: string;
	tenantId?: string;
	name: string;
	kind?: string;
	hardwareId?: string;
	status: DeviceStatus;
	statusReason?: string;
	groups: string[];
	permissions: Permission[];
	metadata: Record<string, unknown>;
	enrollmentId?: string;
	attestation?: Record<string, unknown>;
	expiresAt: Date | null;
	lastSeenAt: Date | null;
	lastSeenIp?: string;
	createdAt: Date;
	updatedAt: Date;
}

export type DeviceCredentialKind = "psk" | "jwk" | "x509";

/** What a caller asks for when adding a credential. */
export type DeviceCredentialInput =
	| { kind: "psk" }
	| { kind: "jwk"; jwk: JWK }
	| { kind: "x509"; thumbprint: string };

export interface DeviceCredential {
	id: string;
	deviceId: string;
	kind: DeviceCredentialKind;
	/** jwk: RFC 7638 thumbprint; x509: x5t#S256; psk: lookup prefix. */
	lookup: string;
	publicJwk?: JWK;
	status: "active" | "revoked";
	expiresAt: Date | null;
	lastUsedAt: Date | null;
	createdAt: Date;
}

/** A credential just created. `secret` is set for psk and shown once. */
export interface IssuedDeviceCredential extends DeviceCredential {
	secret?: string;
}

export interface RegisterDeviceInput {
	ownerId: string;
	tenantId?: string;
	name: string;
	kind?: string;
	hardwareId?: string;
	groups?: string[];
	permissions?: Permission[];
	metadata?: Record<string, unknown>;
	expiresAt?: Date;
	/** Credential to create with the device. */
	credential?: DeviceCredentialInput;
}

export interface DeviceFleetStats {
	total: number;
	active: number;
	suspended: number;
	revoked: number;
	/** Active devices that authenticated in the last hour (last seen is written at most once a minute). */
	seenLastHour: number;
	seenLastDay: number;
	/** Active devices that never authenticated. */
	neverSeen: number;
}

export interface DeviceFilter {
	ownerId?: string;
	tenantId?: string;
	status?: DeviceStatus;
	group?: string;
	enrollmentId?: string;
	limit?: number;
	offset?: number;
}

export interface CreateEnrollmentTokenInput {
	ownerId: string;
	tenantId?: string;
	/** claim: one device, short code for a person to type. bulk: many devices, long token for a factory. */
	kind: "claim" | "bulk";
	/** Uses allowed. Claim codes are always 1. Required for bulk. */
	maxUses?: number;
	/** Seconds until the token expires. Default 900 for claim, 86400 for bulk. Max 30 days. */
	ttlSeconds?: number;
	permissions?: Permission[];
	groups?: string[];
	deviceKind?: string;
	/** Seconds each enrolled device stays valid. Unset: no expiry. */
	deviceTtlSeconds?: number;
}

export interface EnrollmentToken {
	id: string;
	kind: "claim" | "bulk";
	/** Plaintext, shown once. */
	token: string;
	ownerId: string;
	maxUses: number;
	expiresAt: Date;
}

/** One row of the enrollment token list. Never carries the plaintext token or its hash. */
export interface EnrollmentTokenSummary {
	id: string;
	kind: "claim" | "bulk";
	ownerId: string;
	maxUses: number;
	uses: number;
	groups: string[];
	deviceKind?: string;
	status: "active" | "expired" | "revoked" | "used_up";
	expiresAt: Date;
	createdAt: Date;
	revokedAt?: Date;
}

export interface EnrollmentTokenFilter {
	ownerId?: string;
	limit?: number;
	offset?: number;
}

export interface EnrollDeviceInput {
	token: string;
	name: string;
	hardwareId?: string;
	credential: DeviceCredentialInput;
	/** Attestation evidence, checked by `devices.attestation.verify`. */
	evidence?: string;
	/** Nonce from `device.attestationNonce()` bound into the evidence. */
	nonce?: string;
	metadata?: Record<string, unknown>;
}

export interface EnrolledDevice {
	device: Device;
	credential: IssuedDeviceCredential;
}

/** How a device proved itself on a request. */
export type DevicePresentation =
	| { kind: "psk"; secret: string }
	| { kind: "assertion"; jwt: string }
	| { kind: "x509"; thumbprint: string };

export type DeviceAuthFailure =
	| "invalid_credential"
	| "assertion_invalid"
	| "assertion_replayed"
	| "device_not_found"
	| "device_suspended"
	| "device_revoked"
	| "device_expired";

export type DeviceAuthResult =
	| { ok: true; device: Device; credentialId: string }
	| { ok: false; code: DeviceAuthFailure; message: string };

/** Claims of an offline policy bundle. Format documented in docs/iot-devices.mdx. */
export interface DeviceBundleClaims {
	iss: string;
	sub: string;
	aud: string;
	iat: number;
	nbf: number;
	exp: number;
	jti: string;
	/** Issue time in ms. Devices reject a bundle whose seq is lower than the last one accepted. */
	seq: number;
	owner: string;
	groups: string[];
	perms: Permission[];
	/** Resource matching mode of the issuer. Present only for `path`; absent means `colon`. The offline decision uses it so a device agrees with the server. */
	rm?: "path";
}

export interface IssuedDeviceBundle {
	token: string;
	claims: DeviceBundleClaims;
}
