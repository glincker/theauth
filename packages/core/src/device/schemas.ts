import { z } from "zod";
import { InputSourcesSchema } from "../audit/provenance-wire.js";
import { PermissionSchema } from "../http/schemas.js";

const GroupsSchema = z.array(z.string().min(1).max(64)).max(32);
const NameSchema = z.string().min(1).max(128);
const HardwareIdSchema = z.string().min(1).max(128);

const PublicJwkSchema = z
	.object({ kty: z.string(), crv: z.string(), x: z.string(), y: z.string().optional() })
	.passthrough()
	.describe("Public EC P-256, EC P-384 or OKP Ed25519 key. Private members are refused.");

export const DeviceCredentialInputSchema = z.discriminatedUnion("kind", [
	z.object({ kind: z.literal("psk") }),
	z.object({ kind: z.literal("jwk"), jwk: PublicJwkSchema }),
	z.object({
		kind: z.literal("x509"),
		thumbprint: z
			.string()
			.describe("x5t#S256: base64url SHA-256 of the DER certificate (RFC 8705)"),
	}),
]);

export const RegisterDeviceSchema = z.object({
	ownerId: z.string().min(1),
	name: NameSchema,
	kind: z.string().max(64).optional(),
	hardwareId: HardwareIdSchema.optional(),
	groups: GroupsSchema.optional(),
	permissions: z.array(PermissionSchema).optional(),
	metadata: z.record(z.unknown()).optional(),
	expiresAt: z.coerce.date().optional(),
	credential: DeviceCredentialInputSchema.optional(),
});

export const UpdateDeviceSchema = z.object({
	name: NameSchema.optional(),
	kind: z.string().max(64).optional(),
	groups: GroupsSchema.optional(),
	permissions: z.array(PermissionSchema).optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const DeviceReasonSchema = z.object({ reason: z.string().max(500).optional() });

export const EnrollmentTokenInputSchema = z.object({
	ownerId: z.string().min(1),
	kind: z.enum(["claim", "bulk"]),
	maxUses: z.number().int().positive().optional(),
	ttlSeconds: z.number().int().positive().optional(),
	permissions: z.array(PermissionSchema).optional(),
	groups: GroupsSchema.optional(),
	deviceKind: z.string().max(64).optional(),
	deviceTtlSeconds: z.number().int().positive().optional(),
});

export const EnrollDeviceSchema = z.object({
	token: z.string().min(1).max(128),
	name: NameSchema,
	hardwareId: HardwareIdSchema.optional(),
	credential: DeviceCredentialInputSchema,
	evidence: z.string().min(1).max(16_384).optional(),
	nonce: z.string().min(1).max(128).optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const DeviceAuthorizeSchema = z.object({
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
	approvalId: z.string().min(1).optional(),
	inputs: InputSourcesSchema.optional(),
});

export const BundleRequestSchema = z.object({
	ttlSeconds: z.number().int().positive().optional(),
});

// Response shapes, used by the OpenAPI document.

export const DeviceSchema = z.object({
	id: z.string(),
	agentId: z.string().describe("Backing agent that holds permissions, delegations and audit rows"),
	ownerId: z.string(),
	tenantId: z.string().optional(),
	name: z.string(),
	kind: z.string().optional(),
	hardwareId: z.string().optional(),
	status: z.enum(["active", "suspended", "revoked"]),
	statusReason: z.string().optional(),
	groups: z.array(z.string()),
	permissions: z.array(PermissionSchema),
	metadata: z.record(z.unknown()),
	enrollmentId: z.string().optional(),
	attestation: z.record(z.unknown()).optional(),
	expiresAt: z.string().nullable(),
	lastSeenAt: z.string().nullable(),
	lastSeenIp: z.string().optional(),
	createdAt: z.string(),
	updatedAt: z.string(),
});

export const DeviceCredentialSchema = z.object({
	id: z.string(),
	deviceId: z.string(),
	kind: z.enum(["psk", "jwk", "x509"]),
	lookup: z.string(),
	publicJwk: z.record(z.unknown()).optional(),
	status: z.enum(["active", "revoked"]),
	expiresAt: z.string().nullable(),
	lastUsedAt: z.string().nullable(),
	createdAt: z.string(),
	secret: z.string().optional().describe("Pre shared key, returned once when created"),
});

export const RegisteredDeviceSchema = z.object({
	device: DeviceSchema,
	credential: DeviceCredentialSchema.optional(),
});

export const EnrollmentTokenSchema = z.object({
	id: z.string(),
	kind: z.enum(["claim", "bulk"]),
	token: z.string().describe("Plaintext claim code or bulk token, returned once"),
	ownerId: z.string(),
	maxUses: z.number().int(),
	expiresAt: z.string(),
});

export const DeviceBundleSchema = z.object({
	token: z.string().describe("Compact JWS, typ device-policy+jwt"),
	claims: z.record(z.unknown()),
});

export const JwksSchema = z.object({ keys: z.array(z.record(z.unknown())) });

export const RevokedDeviceSchema = z.object({ revokedDelegations: z.array(z.string()) });

export const DeviceFleetStatsSchema = z.object({
	total: z.number().int(),
	active: z.number().int(),
	suspended: z.number().int(),
	revoked: z.number().int(),
	seenLastHour: z.number().int(),
	seenLastDay: z.number().int(),
	neverSeen: z.number().int(),
});
