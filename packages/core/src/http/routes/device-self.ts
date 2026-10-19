import type { InputSource } from "../../audit/provenance.js";
import { INPUTS_HEADER, parseInputsHeader } from "../../audit/provenance-wire.js";
import {
	DeviceAuthorizeSchema,
	EnrollDeviceSchema,
	TpmActivationRequestSchema,
} from "../../device/schemas.js";
import type { DeviceAuthResult, DeviceCredentialInput } from "../../device/types.js";
import type { RequestContext } from "../../types.js";
import { statusForDecisionCode } from "../require-agent.js";
import { created, errorResponse, ok } from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";
import { deviceFailure, devicesUnavailable, readBody } from "./devices.js";

function context(ctx: RouteContext, bodyInputs?: InputSource[]): RequestContext {
	const inputs = bodyInputs?.length
		? bodyInputs
		: parseInputsHeader(ctx.request.headers.get(INPUTS_HEADER));
	return {
		ip: ctx.clientIp(ctx.request) ?? undefined,
		userAgent: ctx.request.headers.get("user-agent") ?? undefined,
		...(inputs ? { inputs } : {}),
	};
}

/** 401 for credential problems and dead devices, 403 for a suspended one (known, but paused). */
function refused(result: Extract<DeviceAuthResult, { ok: false }>): Response {
	const status = result.code === "device_suspended" ? 403 : 401;
	return errorResponse(
		result.code,
		result.message,
		status,
		status === 401 ? { "WWW-Authenticate": 'Bearer realm="theauth-device"' } : undefined,
	);
}

async function authenticated(ctx: RouteContext) {
	const devices = ctx.auth.device;
	if (!devices) return { ok: false as const, response: devicesUnavailable() };
	const result = await devices.authenticateRequest(ctx.request, {
		ip: ctx.clientIp(ctx.request) ?? undefined,
	});
	if (!result.ok) return { ok: false as const, response: refused(result) };
	return { ok: true as const, devices, device: result.device };
}

async function enroll(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	const body = await readBody(ctx, EnrollDeviceSchema);
	if (!body.ok) return body.response;
	try {
		const { credential, ...rest } = body.data;
		return created(
			await devices.enroll({ ...rest, credential: credential as DeviceCredentialInput }),
		);
	} catch (err) {
		return deviceFailure(err, "Enrollment failed");
	}
}

async function attestationNonce(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	try {
		return ok(await devices.attestationNonce());
	} catch (err) {
		return deviceFailure(err, "Failed to issue a nonce");
	}
}

async function tpmActivation(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	const body = await readBody(ctx, TpmActivationRequestSchema);
	if (!body.ok) return body.response;
	try {
		return ok(await devices.tpmActivationChallenge(body.data));
	} catch (err) {
		return deviceFailure(err, "Failed to start the TPM credential activation");
	}
}

async function authorizeSelf(ctx: RouteContext): Promise<Response> {
	const auth = await authenticated(ctx);
	if (!auth.ok) return auth.response;
	const body = await readBody(ctx, DeviceAuthorizeSchema);
	if (!body.ok) return body.response;
	try {
		const { inputs, ...request } = body.data;
		const result = await auth.devices.authorize(auth.device.id, request, context(ctx, inputs));
		if (result.allowed) return ok(result);
		return ok(result, statusForDecisionCode(result.code ?? "no_permission"));
	} catch (err) {
		return deviceFailure(err, "Authorization check failed");
	}
}

async function bundleSelf(ctx: RouteContext): Promise<Response> {
	const auth = await authenticated(ctx);
	if (!auth.ok) return auth.response;
	try {
		return ok(await auth.devices.issueBundle(auth.device.id));
	} catch (err) {
		return deviceFailure(err, "Failed to issue bundle");
	}
}

async function jwks(ctx: RouteContext): Promise<Response> {
	const devices = ctx.auth.device;
	if (!devices) return devicesUnavailable();
	return new Response(JSON.stringify(devices.jwks()), {
		status: 200,
		headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
	});
}

const group = "devices" as const;

/** Routes a device calls itself. Kept apart from `/auth/device/*`, the RFC 8628 human sign in flow. */
export const deviceSelfRoutes: HttpRoute[] = [
	{
		method: "POST",
		path: "/device/enroll",
		auth: "public",
		group,
		body: EnrollDeviceSchema,
		summary:
			"Enroll a device with a claim code or bulk token (put this route behind the rate limiter)",
		handle: enroll,
	},
	{
		method: "POST",
		path: "/device/attestation-nonce",
		auth: "public",
		group,
		summary: "Get a single use nonce to bind into attestation evidence (RFC 9334 freshness)",
		handle: attestationNonce,
	},
	{
		method: "POST",
		path: "/device/tpm-activation",
		auth: "public",
		group,
		body: TpmActivationRequestSchema,
		summary:
			"Start a TPM credential activation: TPM2_MakeCredential for the device's EK and AK (needs a live attestation nonce)",
		handle: tpmActivation,
	},
	{
		method: "POST",
		path: "/device/authorize",
		auth: "device",
		group,
		body: DeviceAuthorizeSchema,
		summary: "Check an action as the calling device (401 bad credential, 403 denied)",
		handle: authorizeSelf,
	},
	{
		method: "GET",
		path: "/device/bundle",
		auth: "device",
		group,
		summary: "Get a fresh signed offline policy bundle for the calling device",
		handle: bundleSelf,
	},
	{
		method: "GET",
		path: "/device/jwks",
		auth: "public",
		group,
		summary: "Public keys that verify offline policy bundles",
		handle: jwks,
	},
];
