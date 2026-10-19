// Device types (GET /devices, GET /devices/stats, GET /devices/:id, POST /devices/enrollment-tokens)

export type DeviceStatus = "active" | "suspended" | "revoked";

export type DeviceCredentialKind = "psk" | "jwk" | "x509" | "spiffe";

export interface DeviceRow {
	id: string;
	agentId: string;
	ownerId: string;
	name: string;
	kind?: string;
	hardwareId?: string;
	status: DeviceStatus;
	statusReason?: string;
	groups: string[];
	/** Claims the attestation verifier proved at enrollment. Absent for a device enrolled without hardware evidence. */
	attestation?: Record<string, unknown>;
	expiresAt: string | null;
	lastSeenAt: string | null;
	lastSeenIp?: string;
	createdAt: string;
	updatedAt: string;
}

export interface DeviceCredentialRow {
	id: string;
	deviceId: string;
	kind: DeviceCredentialKind;
	lookup: string;
	status: "active" | "revoked";
	expiresAt: string | null;
	lastUsedAt: string | null;
	createdAt: string;
}

/** GET /devices/:id: the device with its credentials. */
export interface DeviceDetail extends DeviceRow {
	credentials: DeviceCredentialRow[];
}

export interface DeviceFleetStats {
	total: number;
	active: number;
	suspended: number;
	revoked: number;
	seenLastHour: number;
	seenLastDay: number;
	neverSeen: number;
}

export interface DeviceFilters {
	status?: DeviceStatus;
	group?: string;
	limit?: number;
	offset?: number;
}

export interface CreateEnrollmentTokenInput {
	ownerId: string;
	kind: "claim" | "bulk";
	maxUses?: number;
	ttlSeconds?: number;
	groups?: string[];
	deviceKind?: string;
}

/** The plaintext token is returned once, at creation. */
export interface EnrollmentToken {
	id: string;
	kind: "claim" | "bulk";
	token: string;
	ownerId: string;
	maxUses: number;
	expiresAt: string;
}

/** One row of GET /devices/enrollment-tokens. The plaintext token is never listed. */
export interface EnrollmentTokenSummary {
	id: string;
	kind: "claim" | "bulk";
	ownerId: string;
	maxUses: number;
	uses: number;
	groups: string[];
	deviceKind?: string;
	status: "active" | "expired" | "revoked" | "used_up";
	expiresAt: string;
	createdAt: string;
	revokedAt?: string;
}

/** Body of POST /devices/:id/credentials. */
export type DeviceCredentialInput =
	| { kind: "psk" }
	| { kind: "jwk"; jwk: Record<string, unknown> }
	| { kind: "x509"; thumbprint: string };

/** The `secret` of a pre shared key is returned once, when the credential is added. */
export interface AddedDeviceCredential extends DeviceCredentialRow {
	secret?: string;
}

/** POST /devices/:id/bundle: a signed policy bundle (typ device-policy+jwt). */
export interface DeviceBundle {
	token: string;
	claims: Record<string, unknown>;
}
