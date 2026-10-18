// Device types (GET /devices, GET /devices/stats, GET /devices/:id, POST /devices/enrollment-tokens)

export type DeviceStatus = "active" | "suspended" | "revoked";

export type DeviceCredentialKind = "psk" | "jwk" | "x509";

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
