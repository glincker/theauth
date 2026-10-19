import type { OperationMeta, QueryParam } from "../openapi-operations.js";
import { AuthorizeResultSchema } from "../openapi-schemas.js";
import {
	AttestationNonceSchema,
	DeviceBundleSchema,
	DeviceCredentialSchema,
	DeviceFleetStatsSchema,
	DeviceSchema,
	EnrollmentTokenSchema,
	EnrollmentTokenSummarySchema,
	JwksSchema,
	RegisteredDeviceSchema,
	RevokedDeviceSchema,
	TpmActivationSchema,
} from "./schemas.js";
import { SpiffeIssuedTokenSchema, SpiffeVerifyResultSchema } from "./spiffe/schemas.js";

const DEVICE_QUERY: QueryParam[] = [
	{ name: "ownerId", description: "Only devices of this owner" },
	{
		name: "status",
		description: "Only devices in this state",
		enum: ["active", "suspended", "revoked"],
	},
	{ name: "group", description: "Only devices in this group" },
	{ name: "enrollmentId", description: "Only devices enrolled with this token" },
	{ name: "limit", description: "Page size, default 100, max 1000", type: "integer" },
	{ name: "offset", description: "Rows to skip", type: "integer" },
];

const NOT_FOUND = { 404: "Device not found, not yours, or devices are not configured" };

/** OpenAPI metadata for the device routes, merged into OPERATIONS. */
export const DEVICE_OPERATIONS: Record<string, OperationMeta> = {
	"GET /devices": {
		operationId: "listDevices",
		tag: "Devices",
		status: 200,
		response: DeviceSchema,
		list: true,
		query: DEVICE_QUERY,
	},
	"POST /devices": {
		operationId: "registerDevice",
		tag: "Devices",
		status: 201,
		response: RegisteredDeviceSchema,
		errors: { 400: "Invalid input", 409: "Duplicate hardware id or key, or device cap reached" },
	},
	"GET /devices/enrollment-tokens": {
		operationId: "listDeviceEnrollmentTokens",
		tag: "Devices",
		status: 200,
		response: EnrollmentTokenSummarySchema,
		list: true,
		query: [
			{ name: "ownerId", description: "Only tokens of this owner" },
			{ name: "limit", description: "Page size, default 100, max 1000", type: "integer" },
			{ name: "offset", description: "Rows to skip", type: "integer" },
		],
	},
	"POST /devices/enrollment-tokens": {
		operationId: "createDeviceEnrollmentToken",
		tag: "Devices",
		status: 201,
		response: EnrollmentTokenSchema,
		errors: { 400: "Invalid input" },
	},
	"DELETE /devices/enrollment-tokens/:id": {
		operationId: "revokeDeviceEnrollmentToken",
		tag: "Devices",
		status: 204,
		errors: { 404: "Enrollment token not found" },
	},
	"GET /devices/stats": {
		operationId: "getDeviceFleetStats",
		tag: "Devices",
		status: 200,
		response: DeviceFleetStatsSchema,
		query: [{ name: "ownerId", description: "Only devices of this owner" }],
	},
	"GET /devices/:id": {
		operationId: "getDevice",
		tag: "Devices",
		status: 200,
		response: DeviceSchema,
		errors: NOT_FOUND,
	},
	"PATCH /devices/:id": {
		operationId: "updateDevice",
		tag: "Devices",
		status: 200,
		response: DeviceSchema,
		errors: { ...NOT_FOUND, 409: "Device is revoked" },
	},
	"DELETE /devices/:id": {
		operationId: "revokeDevice",
		tag: "Devices",
		status: 200,
		response: RevokedDeviceSchema,
		errors: NOT_FOUND,
	},
	"POST /devices/:id/suspend": {
		operationId: "suspendDevice",
		tag: "Devices",
		status: 200,
		response: DeviceSchema,
		errors: { ...NOT_FOUND, 409: "Device is revoked" },
	},
	"POST /devices/:id/resume": {
		operationId: "resumeDevice",
		tag: "Devices",
		status: 200,
		response: DeviceSchema,
		errors: { ...NOT_FOUND, 409: "Device is revoked" },
	},
	"POST /devices/:id/credentials": {
		operationId: "addDeviceCredential",
		tag: "Devices",
		status: 201,
		response: DeviceCredentialSchema,
		errors: {
			...NOT_FOUND,
			400: "Invalid key or thumbprint",
			409: "Key already registered or device revoked",
		},
	},
	"DELETE /devices/:id/credentials/:credentialId": {
		operationId: "revokeDeviceCredential",
		tag: "Devices",
		status: 204,
		errors: { 404: "Device or credential not found" },
	},
	"POST /devices/:id/bundle": {
		operationId: "issueDeviceBundle",
		tag: "Devices",
		status: 200,
		response: DeviceBundleSchema,
		errors: {
			...NOT_FOUND,
			400: "devices.bundleSigning is not configured",
			409: "Device is not active",
		},
	},
	"POST /device/spiffe/verify": {
		operationId: "verifyDeviceSpiffe",
		tag: "Device API",
		status: 200,
		response: SpiffeVerifyResultSchema,
		errors: {
			401: "SVID missing, invalid, expired, untrusted, or not mapped to an active device or agent",
			404: "The SPIFFE bridge is not configured (devices.spiffe)",
			429: "Rate limited",
		},
	},
	"POST /devices/spiffe/verify": {
		operationId: "verifySpiffeSvid",
		tag: "Devices",
		status: 200,
		response: SpiffeVerifyResultSchema,
		errors: { 404: "The SPIFFE bridge is not configured", 429: "Rate limited" },
	},
	"POST /devices/spiffe/token": {
		operationId: "issueSpiffeAgentToken",
		tag: "Devices",
		status: 201,
		response: SpiffeIssuedTokenSchema,
		errors: {
			400: "SVID refused, or the workload is not an agent",
			404: "The SPIFFE bridge is not configured, or the agent is not yours",
			429: "Rate limited",
		},
	},
	"POST /devices/:id/spiffe": {
		operationId: "linkDeviceSpiffe",
		tag: "Devices",
		status: 201,
		response: DeviceCredentialSchema,
		errors: {
			...NOT_FOUND,
			400: "Not a SPIFFE ID of a configured trust domain, or the SVID was refused",
			409: "SPIFFE ID already linked or device revoked",
			429: "Rate limited",
		},
	},
	"POST /device/enroll": {
		operationId: "enrollDevice",
		tag: "Device API",
		status: 201,
		response: RegisteredDeviceSchema,
		errors: {
			400: "Invalid input or attestation refused",
			401: "Enrollment token invalid, expired or used up",
			404: "Devices are not configured",
			409: "Duplicate hardware id or key",
		},
	},
	"POST /device/attestation-nonce": {
		operationId: "getDeviceAttestationNonce",
		tag: "Device API",
		status: 200,
		response: AttestationNonceSchema,
		errors: { 404: "Devices are not configured" },
	},
	"POST /device/tpm-activation": {
		operationId: "startDeviceTpmActivation",
		tag: "Device API",
		status: 200,
		response: TpmActivationSchema,
		errors: {
			400: "Keys are not valid, or the nonce is unknown, expired or used",
			404: "Devices are not configured",
		},
	},
	"POST /device/authorize": {
		operationId: "authorizeDevice",
		tag: "Device API",
		status: 200,
		response: AuthorizeResultSchema,
		resultStatuses: [403],
		errors: { 401: "Device credential invalid, or device revoked or expired" },
	},
	"GET /device/bundle": {
		operationId: "getDeviceBundle",
		tag: "Device API",
		status: 200,
		response: DeviceBundleSchema,
		errors: {
			400: "devices.bundleSigning is not configured",
			401: "Device credential invalid",
			403: "Device suspended",
		},
	},
	"GET /device/jwks": {
		operationId: "getDeviceBundleJwks",
		tag: "Device API",
		status: 200,
		response: JwksSchema,
		bare: true,
	},
};
