/** Device rows of the route parity table, kept apart so the table file stays readable. */
import type { TheAuth } from "../../src/theauth.js";

export interface DeviceIds {
	deviceId: string;
	devicePsk: string;
	credentialId: string;
	enrollmentId: string;
	enrollmentToken: string;
}

export interface DeviceRow {
	method: string;
	spec: string;
	allowed: number;
	unauthenticated: number;
	forbidden: number | null;
	as: "alice" | "device" | "none";
	call: (ids: DeviceIds) => { method: string; path: string; body?: unknown };
}

/** A device, a PSK and an unused claim code owned by alice. */
export async function freshDevice(auth: TheAuth): Promise<DeviceIds> {
	const devices = auth.device;
	if (!devices) throw new Error("devices not configured");
	const { device, credential } = await devices.register({
		ownerId: "alice",
		name: "d",
		permissions: [{ resource: "docs", actions: ["read"] }],
		credential: { kind: "psk" },
	});
	const extra = await devices.addCredential(device.id, { kind: "psk" });
	const token = await devices.createEnrollmentToken({ ownerId: "alice", kind: "claim" });
	return {
		deviceId: device.id,
		devicePsk: credential?.secret ?? "",
		credentialId: extra.id,
		enrollmentId: token.id,
		enrollmentToken: token.token,
	};
}

const admin = { as: "alice" as const, unauthenticated: 401 };

export const DEVICE_ROWS: DeviceRow[] = [
	{
		...admin,
		method: "GET",
		spec: "/devices/stats",
		allowed: 200,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/devices/stats?ownerId=alice" }),
	},
	{
		...admin,
		method: "GET",
		spec: "/devices",
		allowed: 200,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/devices?ownerId=alice" }),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices",
		allowed: 201,
		forbidden: 403,
		call: () => ({ method: "POST", path: "/devices", body: { ownerId: "alice", name: "n" } }),
	},
	{
		...admin,
		method: "GET",
		spec: "/devices/enrollment-tokens",
		allowed: 200,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/devices/enrollment-tokens?ownerId=alice" }),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/enrollment-tokens",
		allowed: 201,
		forbidden: 403,
		call: () => ({
			method: "POST",
			path: "/devices/enrollment-tokens",
			body: { ownerId: "alice", kind: "claim" },
		}),
	},
	{
		...admin,
		method: "DELETE",
		spec: "/devices/enrollment-tokens/:id",
		allowed: 204,
		forbidden: 404,
		call: (i) => ({ method: "DELETE", path: `/devices/enrollment-tokens/${i.enrollmentId}` }),
	},
	{
		...admin,
		method: "GET",
		spec: "/devices/:id",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({ method: "GET", path: `/devices/${i.deviceId}` }),
	},
	{
		...admin,
		method: "PATCH",
		spec: "/devices/:id",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({ method: "PATCH", path: `/devices/${i.deviceId}`, body: { name: "r" } }),
	},
	{
		...admin,
		method: "DELETE",
		spec: "/devices/:id",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({ method: "DELETE", path: `/devices/${i.deviceId}` }),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/:id/suspend",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: `/devices/${i.deviceId}/suspend`,
			body: { reason: "r" },
		}),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/:id/resume",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({ method: "POST", path: `/devices/${i.deviceId}/resume` }),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/:id/credentials",
		allowed: 201,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: `/devices/${i.deviceId}/credentials`,
			body: { kind: "psk" },
		}),
	},
	{
		...admin,
		method: "DELETE",
		spec: "/devices/:id/credentials/:credentialId",
		allowed: 204,
		forbidden: 404,
		call: (i) => ({
			method: "DELETE",
			path: `/devices/${i.deviceId}/credentials/${i.credentialId}`,
		}),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/:id/bundle",
		allowed: 200,
		forbidden: 404,
		call: (i) => ({ method: "POST", path: `/devices/${i.deviceId}/bundle` }),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/spiffe/verify",
		allowed: 404,
		forbidden: 404,
		call: () => ({
			method: "POST",
			path: "/devices/spiffe/verify",
			body: { jwtSvid: "x", audience: "a" },
		}),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/spiffe/token",
		allowed: 404,
		forbidden: 404,
		call: () => ({
			method: "POST",
			path: "/devices/spiffe/token",
			body: { x509Chain: ["x"], resource: "docs" },
		}),
	},
	{
		...admin,
		method: "POST",
		spec: "/devices/:id/spiffe",
		allowed: 404,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: `/devices/${i.deviceId}/spiffe`,
			body: { spiffeId: "spiffe://example.org/w" },
		}),
	},
	{
		method: "POST",
		spec: "/device/spiffe/verify",
		as: "none",
		allowed: 404,
		unauthenticated: 404,
		forbidden: null,
		call: () => ({ method: "POST", path: "/device/spiffe/verify" }),
	},
	{
		method: "POST",
		spec: "/device/enroll",
		as: "none",
		allowed: 201,
		unauthenticated: 201,
		forbidden: null,
		call: (i) => ({
			method: "POST",
			path: "/device/enroll",
			body: { token: i.enrollmentToken, name: "e", credential: { kind: "psk" } },
		}),
	},
	{
		method: "POST",
		spec: "/device/attestation-nonce",
		as: "none",
		allowed: 200,
		unauthenticated: 200,
		forbidden: null,
		call: () => ({ method: "POST", path: "/device/attestation-nonce" }),
	},
	{
		method: "POST",
		spec: "/device/authorize",
		as: "device",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({
			method: "POST",
			path: "/device/authorize",
			body: { action: "read", resource: "docs" },
		}),
	},
	{
		method: "GET",
		spec: "/device/bundle",
		as: "device",
		allowed: 200,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({ method: "GET", path: "/device/bundle" }),
	},
	{
		method: "GET",
		spec: "/device/jwks",
		as: "none",
		allowed: 200,
		unauthenticated: 200,
		forbidden: null,
		call: () => ({ method: "GET", path: "/device/jwks" }),
	},
];
