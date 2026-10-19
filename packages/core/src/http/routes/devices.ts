import type { ZodTypeAny, z } from "zod";
import { DeviceEnrollmentError } from "../../device/enrollment.js";
import type { DeviceModule } from "../../device/module.js";
import { DeviceInputError } from "../../device/registry.js";
import {
	BundleRequestSchema,
	DeviceCredentialInputSchema,
	DeviceReasonSchema,
	EnrollmentTokenInputSchema,
	RegisterDeviceSchema,
	UpdateDeviceSchema,
} from "../../device/schemas.js";
import type {
	Device,
	DeviceCredentialInput,
	DeviceFilter,
	EnrollmentTokenFilter,
} from "../../device/types.js";
import { HookBlockedError } from "../../hooks/safety.js";
import type { Permission } from "../../types.js";
import {
	created,
	errorResponse,
	internalError,
	noContent,
	notFound,
	ok,
	readBoundedText,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";

/** Map device errors to statuses. Unknown errors are a 500 with a fixed message. */
export function deviceFailure(err: unknown, fallback: string): Response {
	if (err instanceof DeviceInputError) {
		const status = { INVALID_INPUT: 400, CONFLICT: 409, LIMIT_REACHED: 409, NOT_FOUND: 404 }[
			err.code
		];
		return errorResponse(err.code, err.message, status);
	}
	if (err instanceof DeviceEnrollmentError) {
		return errorResponse(
			err.code.toUpperCase(),
			err.message,
			err.code === "invalid_token" ? 401 : 400,
		);
	}
	if (err instanceof HookBlockedError) {
		return errorResponse("FORBIDDEN", "Device policy check failed, request refused", 403);
	}
	return internalError(fallback);
}

export function devicesUnavailable(): Response {
	return notFound("Devices are not configured (set `devices` in createTheAuth)");
}

type Loaded =
	| { ok: true; devices: DeviceModule; device: Device }
	| { ok: false; response: Response };

/** Load the device in the path and check the caller owns its backing agent. Unknown and foreign ids both answer 404. */
async function loadOwned(ctx: RouteContext): Promise<Loaded> {
	const devices = ctx.auth.device;
	if (!devices) return { ok: false, response: devicesUnavailable() };
	if (!ctx.scope) return { ok: false, response: scopeUnavailable() };
	const device = await devices.get(ctx.params.id ?? "");
	if (!device) return { ok: false, response: notFound("Device not found") };
	const denial = await ctx.scope.checkAgent(device.agentId);
	if (denial) return { ok: false, response: notFound("Device not found") };
	return { ok: true, devices, device };
}

/** Parse the JSON body with `schema`. With `optional`, an empty body counts as `{}`. */
export async function readBody<S extends ZodTypeAny>(
	ctx: RouteContext,
	schema: S,
	optional = false,
): Promise<{ ok: true; data: z.infer<S> } | { ok: false; response: Response }> {
	let data: unknown = {};
	if (optional) {
		let text: string;
		try {
			text = await readBoundedText(ctx.request, ctx.maxBodyBytes);
		} catch {
			return { ok: false, response: errorResponse("BAD_REQUEST", "Invalid request body", 400) };
		}
		if (text.trim() !== "") {
			try {
				data = JSON.parse(text);
			} catch {
				return { ok: false, response: errorResponse("BAD_REQUEST", "Invalid JSON body", 400) };
			}
		}
	} else {
		const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
		if (!body.ok) return body;
		data = body.data;
	}
	const parsed = schema.safeParse(data);
	if (!parsed.success) return { ok: false, response: validationError(parsed.error.issues) };
	return { ok: true, data: parsed.data as z.infer<S> };
}

async function listDevices(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	const q = ctx.url.searchParams;
	const filter: DeviceFilter = {};
	const ownerId = q.get("ownerId");
	const status = q.get("status");
	if (ownerId) filter.ownerId = ownerId;
	if (status === "active" || status === "suspended" || status === "revoked") filter.status = status;
	const group = q.get("group");
	if (group) filter.group = group;
	const enrollmentId = q.get("enrollmentId");
	if (enrollmentId) filter.enrollmentId = enrollmentId;
	const limit = Number(q.get("limit"));
	if (Number.isInteger(limit) && limit > 0) filter.limit = limit;
	const offset = Number(q.get("offset"));
	if (Number.isInteger(offset) && offset > 0) filter.offset = offset;
	if (ctx.scope.restricted) {
		if (filter.ownerId !== undefined && filter.ownerId !== ctx.scope.ownerId) {
			return errorResponse("FORBIDDEN", "You can only act on your own resources", 403);
		}
		filter.ownerId = ctx.scope.ownerId ?? "";
	}
	try {
		return ok(await devices.list(filter));
	} catch (err) {
		return deviceFailure(err, "Failed to list devices");
	}
}

async function fleetStats(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	const requested = ctx.url.searchParams.get("ownerId") ?? undefined;
	if (ctx.scope.restricted && requested !== undefined && requested !== ctx.scope.ownerId) {
		return errorResponse("FORBIDDEN", "You can only act on your own resources", 403);
	}
	const ownerId = ctx.scope.restricted ? (ctx.scope.ownerId ?? "") : requested;
	try {
		return ok(await devices.stats(ownerId));
	} catch (err) {
		return deviceFailure(err, "Failed to read device stats");
	}
}

async function registerDevice(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	const body = await readBody(ctx, RegisterDeviceSchema);
	if (!body.ok) return body.response;
	const denial = ctx.scope.checkAgentCreate(body.data.ownerId);
	if (denial) return scopeDenied(denial);
	try {
		const { credential, permissions, ...rest } = body.data;
		return created(
			await devices.register({
				...rest,
				...(permissions && { permissions: permissions as Permission[] }),
				...(credential && { credential: credential as DeviceCredentialInput }),
			}),
		);
	} catch (err) {
		return deviceFailure(err, "Failed to register device");
	}
}

async function getDevice(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	try {
		const credentials = await loaded.devices.listCredentials(loaded.device.id);
		return ok({ ...loaded.device, credentials });
	} catch (err) {
		return deviceFailure(err, "Failed to get device");
	}
}

async function updateDevice(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	const body = await readBody(ctx, UpdateDeviceSchema);
	if (!body.ok) return body.response;
	try {
		const { permissions, ...rest } = body.data;
		return ok(
			await loaded.devices.update(loaded.device.id, {
				...rest,
				...(permissions && { permissions: permissions as Permission[] }),
			}),
		);
	} catch (err) {
		return deviceFailure(err, "Failed to update device");
	}
}

function stateRoute(action: "suspend" | "resume") {
	return async (ctx: RouteContext): Promise<Response> => {
		const loaded = await loadOwned(ctx);
		if (!loaded.ok) return loaded.response;
		const body = await readBody(ctx, DeviceReasonSchema, true);
		if (!body.ok) return body.response;
		try {
			const id = loaded.device.id;
			return ok(
				action === "suspend"
					? await loaded.devices.suspend(id, body.data.reason)
					: await loaded.devices.resume(id),
			);
		} catch (err) {
			return deviceFailure(err, `Failed to ${action} device`);
		}
	};
}

async function revokeDevice(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	try {
		const reason = ctx.url.searchParams.get("reason") ?? undefined;
		return ok(await loaded.devices.revoke(loaded.device.id, reason));
	} catch (err) {
		return deviceFailure(err, "Failed to revoke device");
	}
}

async function addCredential(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	const body = await readBody(ctx, DeviceCredentialInputSchema);
	if (!body.ok) return body.response;
	try {
		return created(
			await loaded.devices.addCredential(loaded.device.id, body.data as DeviceCredentialInput),
		);
	} catch (err) {
		return deviceFailure(err, "Failed to add credential");
	}
}

async function revokeCredential(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	try {
		const done = await loaded.devices.revokeCredential(
			loaded.device.id,
			ctx.params.credentialId ?? "",
		);
		return done ? noContent() : notFound("Credential not found");
	} catch (err) {
		return deviceFailure(err, "Failed to revoke credential");
	}
}

async function issueBundle(ctx: RouteContext): Promise<Response> {
	const loaded = await loadOwned(ctx);
	if (!loaded.ok) return loaded.response;
	const body = await readBody(ctx, BundleRequestSchema, true);
	if (!body.ok) return body.response;
	try {
		return ok(await loaded.devices.issueBundle(loaded.device.id, body.data));
	} catch (err) {
		return deviceFailure(err, "Failed to issue bundle");
	}
}

async function createEnrollmentToken(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	const body = await readBody(ctx, EnrollmentTokenInputSchema);
	if (!body.ok) return body.response;
	const denial = ctx.scope.checkAgentCreate(body.data.ownerId);
	if (denial) return scopeDenied(denial);
	try {
		const { permissions, ...rest } = body.data;
		return created(
			await devices.createEnrollmentToken({
				...rest,
				...(permissions && { permissions: permissions as Permission[] }),
			}),
		);
	} catch (err) {
		return deviceFailure(err, "Failed to create enrollment token");
	}
}

async function listEnrollmentTokens(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	const q = ctx.url.searchParams;
	const filter: EnrollmentTokenFilter = {};
	const ownerId = q.get("ownerId");
	if (ownerId) filter.ownerId = ownerId;
	const limit = Number(q.get("limit"));
	if (Number.isInteger(limit) && limit > 0) filter.limit = limit;
	const offset = Number(q.get("offset"));
	if (Number.isInteger(offset) && offset > 0) filter.offset = offset;
	if (ctx.scope.restricted) {
		if (filter.ownerId !== undefined && filter.ownerId !== ctx.scope.ownerId) {
			return errorResponse("FORBIDDEN", "You can only act on your own resources", 403);
		}
		filter.ownerId = ctx.scope.ownerId ?? "";
	}
	try {
		return ok(await devices.listEnrollmentTokens(filter));
	} catch (err) {
		return deviceFailure(err, "Failed to list enrollment tokens");
	}
}

async function revokeEnrollmentToken(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	if (!ctx.scope) return scopeUnavailable();
	try {
		const row = await devices.getEnrollmentToken(ctx.params.id ?? "");
		if (!row || (ctx.scope.restricted && row.ownerId !== ctx.scope.ownerId)) {
			return notFound("Enrollment token not found");
		}
		await devices.revokeEnrollmentToken(row.id);
		return noContent();
	} catch (err) {
		return deviceFailure(err, "Failed to revoke enrollment token");
	}
}

const admin = { auth: "admin" as const, group: "management" as const };

export const deviceAdminRoutes: HttpRoute[] = [
	{
		...admin,
		method: "GET",
		path: "/devices",
		summary: "List devices (filters: ownerId, status, group, enrollmentId)",
		handle: listDevices,
	},
	{
		...admin,
		method: "POST",
		path: "/devices",
		body: RegisterDeviceSchema,
		summary: "Register a device",
		handle: registerDevice,
	},
	{
		...admin,
		method: "GET",
		path: "/devices/enrollment-tokens",
		summary: "List enrollment tokens with usage and state (never the plaintext)",
		handle: listEnrollmentTokens,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/enrollment-tokens",
		body: EnrollmentTokenInputSchema,
		summary: "Create a claim code or bulk enrollment token",
		handle: createEnrollmentToken,
	},
	{
		...admin,
		method: "DELETE",
		path: "/devices/enrollment-tokens/:id",
		summary: "Revoke an enrollment token",
		handle: revokeEnrollmentToken,
	},
	{
		...admin,
		method: "GET",
		path: "/devices/stats",
		summary: "Fleet health counters (per status, seen in the last hour or day, never seen)",
		handle: fleetStats,
	},
	{
		...admin,
		method: "GET",
		path: "/devices/:id",
		summary: "Get a device and its credentials",
		handle: getDevice,
	},
	{
		...admin,
		method: "PATCH",
		path: "/devices/:id",
		body: UpdateDeviceSchema,
		summary: "Update a device (name, groups, permissions, metadata)",
		handle: updateDevice,
	},
	{
		...admin,
		method: "DELETE",
		path: "/devices/:id",
		summary: "Revoke a device (permanent, cascades delegations)",
		handle: revokeDevice,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/:id/suspend",
		body: DeviceReasonSchema,
		summary: "Suspend a device (reversible)",
		handle: stateRoute("suspend"),
	},
	{
		...admin,
		method: "POST",
		path: "/devices/:id/resume",
		summary: "Resume a suspended device",
		handle: stateRoute("resume"),
	},
	{
		...admin,
		method: "POST",
		path: "/devices/:id/credentials",
		body: DeviceCredentialInputSchema,
		summary: "Add a device credential",
		handle: addCredential,
	},
	{
		...admin,
		method: "DELETE",
		path: "/devices/:id/credentials/:credentialId",
		summary: "Revoke a device credential",
		handle: revokeCredential,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/:id/bundle",
		body: BundleRequestSchema,
		summary: "Issue a signed offline policy bundle for a device",
		handle: issueBundle,
	},
];
