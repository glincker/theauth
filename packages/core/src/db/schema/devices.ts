import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import type { Permission } from "../../types.js";
import { bigintNumber, json } from "./columns.js";
import { agents } from "./core.js";

/**
 * IoT devices (migration 0010). Times are plain epoch seconds (`bigintNumber`): TIMESTAMP_COLUMNS is frozen with the baseline.
 *
 * Each device is backed by an agent row of type `device` that holds its permissions, so the permission engine, delegation and audit chain apply unchanged.
 */
export const devices = sqliteTable("theauth_devices", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.unique()
		.references(() => agents.id),
	ownerId: text("owner_id").notNull(),
	tenantId: text("tenant_id"),
	name: text("name").notNull(),
	/** Free form class such as sensor, gateway, appliance, vehicle. */
	kind: text("kind"),
	/** Serial number, MAC, or other stable hardware id. Unique per owner. */
	hardwareId: text("hardware_id"),
	status: text("status", { enum: ["active", "suspended", "revoked"] }).notNull(),
	groups: json<string[]>("device_groups").notNull(),
	metadata: json<Record<string, unknown>>("metadata"),
	/** Enrollment token that created the device, so a leaked bulk token can be scoped. */
	enrollmentId: text("enrollment_id"),
	/** Claims the attestation verifier returned at enrollment. */
	attestation: json<Record<string, unknown>>("attestation"),
	expiresAt: bigintNumber("expires_at"),
	lastSeenAt: bigintNumber("last_seen_at"),
	lastSeenIp: text("last_seen_ip"),
	statusReason: text("status_reason"),
	createdAt: bigintNumber("created_at").notNull(),
	updatedAt: bigintNumber("updated_at").notNull(),
});

/** Device credentials. Only hashes, thumbprints and public keys are stored. */
export const deviceCredentials = sqliteTable("theauth_device_credentials", {
	id: text("id").primaryKey(),
	deviceId: text("device_id")
		.notNull()
		.references(() => devices.id, { onDelete: "cascade" }),
	kind: text("kind", { enum: ["psk", "jwk", "x509", "spiffe"] }).notNull(),
	/** psk: lookup prefix of the secret; jwk: RFC 7638 thumbprint; x509: x5t#S256. Indexed. */
	lookup: text("lookup").notNull(),
	/** psk: SHA-256 hex of the full secret. Null for the other kinds. */
	secretHash: text("secret_hash"),
	publicJwk: json<Record<string, unknown>>("public_jwk"),
	status: text("status", { enum: ["active", "revoked"] }).notNull(),
	expiresAt: bigintNumber("expires_at"),
	lastUsedAt: bigintNumber("last_used_at"),
	createdAt: bigintNumber("created_at").notNull(),
});

/** Template a device inherits when it enrolls with a token. */
export interface DeviceEnrollmentTemplateRow {
	permissions: Permission[];
	groups: string[];
	kind?: string;
	/** Seconds the enrolled device stays valid. */
	deviceTtlSeconds?: number;
}

/** Claim codes and bulk enrollment tokens, stored as SHA-256 hashes. */
export const deviceEnrollments = sqliteTable("theauth_device_enrollments", {
	id: text("id").primaryKey(),
	kind: text("kind", { enum: ["claim", "bulk"] }).notNull(),
	tokenHash: text("token_hash").notNull().unique(),
	ownerId: text("owner_id").notNull(),
	tenantId: text("tenant_id"),
	template: json<DeviceEnrollmentTemplateRow>("template").notNull(),
	maxUses: integer("max_uses").notNull(),
	uses: integer("uses").notNull(),
	expiresAt: bigintNumber("expires_at").notNull(),
	revokedAt: bigintNumber("revoked_at"),
	createdAt: bigintNumber("created_at").notNull(),
});
