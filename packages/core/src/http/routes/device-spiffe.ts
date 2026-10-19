import type { SpiffeAuthResult, SpiffePresentation } from "../../device/spiffe/bridge.js";
import {
	SpiffeLinkSchema,
	SpiffePresentationSchema,
	SpiffeTokenRequestSchema,
} from "../../device/spiffe/schemas.js";
import type { DeviceSpiffeService } from "../../device/spiffe/service.js";
import { created, errorResponse, notFound, ok, scopeUnavailable } from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";
import { deviceFailure, devicesUnavailable, readBody } from "./devices.js";

function spiffeOf(ctx: RouteContext): DeviceSpiffeService | Response {
	if (!ctx.auth.device) return devicesUnavailable();
	return ctx.auth.device.spiffe ?? notFound("The SPIFFE bridge is not configured (devices.spiffe)");
}

/** Same text the bridge uses for a truly unmapped id, so a hidden mapping is indistinguishable. */
const UNMAPPED_REASON = "No device or agent is mapped to this SPIFFE ID";

function rateLimited(): Response {
	return errorResponse("RATE_LIMITED", "Too many SPIFFE requests, retry later", 429, {
		"Retry-After": "60",
	});
}

/** Body of a verification answer. Never echoes the certificate or token. */
function summary(result: SpiffeAuthResult) {
	if (!result.ok) return { ok: false, code: result.code, reason: result.reason };
	const principal =
		result.principal.type === "device"
			? {
					type: "device" as const,
					id: result.principal.device.id,
					name: result.principal.device.name,
				}
			: {
					type: "agent" as const,
					id: result.principal.agent.id,
					name: result.principal.agent.name,
				};
	return {
		ok: true,
		code: "ok",
		spiffeId: result.spiffeId,
		svid: {
			kind: result.svid.kind,
			expiresAt: result.svid.expiresAt.toISOString(),
			...(result.svid.thumbprint && { thumbprint: result.svid.thumbprint }),
		},
		principal,
	};
}

/** Device side: the SVID comes from the TLS handshake (or the operator's trusted proxy header) or a Bearer JWT-SVID, never from the body. */
async function verifySelf(ctx: RouteContext): Promise<Response> {
	const spiffe = spiffeOf(ctx);
	if (spiffe instanceof Response) return spiffe;
	if (await spiffe.limited(ctx.clientIp(ctx.request) ?? undefined)) return rateLimited();
	try {
		const result = await spiffe.authenticateRequest(ctx.request);
		if (!result.ok) {
			return errorResponse(result.code, result.reason, 401, {
				"WWW-Authenticate": 'Bearer realm="theauth-spiffe"',
			});
		}
		return ok(summary(result));
	} catch (err) {
		return deviceFailure(err, "SPIFFE verification failed");
	}
}

function toPresentation(
	body: ReturnType<typeof SpiffePresentationSchema.parse>,
): SpiffePresentation {
	return body.kind === "x509"
		? { kind: "x509", chain: body.chain }
		: { kind: "jwt", token: body.token };
}

/** Admin side: check an SVID and report who it maps to. Mints nothing. */
async function verifyAdmin(ctx: RouteContext): Promise<Response> {
	const spiffe = spiffeOf(ctx);
	if (spiffe instanceof Response) return spiffe;
	if (!ctx.scope) return scopeUnavailable();
	if (await spiffe.limited(ctx.clientIp(ctx.request) ?? undefined)) return rateLimited();
	const body = await readBody(ctx, SpiffePresentationSchema);
	if (!body.ok) return body.response;
	try {
		const result = await spiffe.authenticate(toPresentation(body.data));
		// An inactive agent mapped to someone else reads as unmapped.
		if (
			!result.ok &&
			result.code === "principal_inactive" &&
			(!result.agentId || (await ctx.scope.checkAgent(result.agentId)))
		) {
			return ok({
				ok: false,
				code: "unknown_workload",
				reason: UNMAPPED_REASON,
			});
		}
		if (result.ok) {
			const agentId =
				result.principal.type === "device"
					? result.principal.device.agentId
					: result.principal.agent.id;
			if (await ctx.scope.checkAgent(agentId)) {
				return ok({
					ok: false,
					code: "unknown_workload",
					reason: UNMAPPED_REASON,
				});
			}
		}
		return ok(summary(result));
	} catch (err) {
		return deviceFailure(err, "SPIFFE verification failed");
	}
}

/** Add a spiffe credential to a device, from an id in a configured trust domain or from a verified SVID. */
async function link(ctx: RouteContext): Promise<Response> {
	const spiffe = spiffeOf(ctx);
	if (spiffe instanceof Response) return spiffe;
	const devices = ctx.auth.device;
	if (!devices || !ctx.scope) return scopeUnavailable();
	if (await spiffe.limited(ctx.clientIp(ctx.request) ?? undefined)) return rateLimited();
	const device = await devices.get(ctx.params.id ?? "");
	if (!device || (await ctx.scope.checkAgent(device.agentId))) return notFound("Device not found");
	const body = await readBody(ctx, SpiffeLinkSchema);
	if (!body.ok) return body.response;
	try {
		let spiffeId: string;
		if (body.data.presentation) {
			const verified = await spiffe.verify(toPresentation(body.data.presentation));
			if (!verified.ok) return errorResponse(verified.code.toUpperCase(), verified.reason, 400);
			spiffeId = verified.spiffeId;
		} else {
			const checked = spiffe.checkLinkable(body.data.spiffeId ?? "");
			if (!checked.ok) return errorResponse("INVALID_INPUT", checked.reason, 400);
			spiffeId = checked.id;
		}
		return created(await devices.addCredential(device.id, { kind: "spiffe", spiffeId }));
	} catch (err) {
		return deviceFailure(err, "Failed to link the SPIFFE ID");
	}
}

/** Mint an agent token bound to an X.509-SVID (RFC 8705). Admin only, and the token is useless without the certificate key. */
async function issueToken(ctx: RouteContext): Promise<Response> {
	const spiffe = spiffeOf(ctx);
	if (spiffe instanceof Response) return spiffe;
	if (!ctx.scope) return scopeUnavailable();
	if (await spiffe.limited(ctx.clientIp(ctx.request) ?? undefined)) return rateLimited();
	const body = await readBody(ctx, SpiffeTokenRequestSchema);
	if (!body.ok) return body.response;
	try {
		const result = await spiffe.authenticate({ kind: "x509", chain: body.data.chain });
		if (!result.ok) {
			if (
				result.code === "principal_inactive" &&
				(!result.agentId || (await ctx.scope.checkAgent(result.agentId)))
			) {
				return errorResponse("UNKNOWN_WORKLOAD", UNMAPPED_REASON, 400);
			}
			return errorResponse(result.code.toUpperCase(), result.reason, 400);
		}
		const ownerAgentId =
			result.principal.type === "device"
				? result.principal.device.agentId
				: result.principal.agent.id;
		if (await ctx.scope.checkAgent(ownerAgentId)) return notFound("Agent not found");
		if (result.principal.type !== "agent") {
			return errorResponse("INVALID_INPUT", "Only an agent workload gets a token", 400);
		}
		const issued = await spiffe.issueAgentToken(result);
		if (!issued) return errorResponse("INVALID_INPUT", "No token could be issued", 400);
		return created({ agentId: issued.id, token: issued.token, cnf: issued.cnf ?? {} });
	} catch (err) {
		return deviceFailure(err, "Failed to issue a token");
	}
}

const admin = { auth: "admin" as const, group: "management" as const };

export const deviceSpiffeRoutes: HttpRoute[] = [
	{
		method: "POST",
		path: "/device/spiffe/verify",
		auth: "public",
		group: "devices",
		summary:
			"Verify the caller's SVID (TLS certificate or Bearer JWT-SVID) and name the device or agent it maps to",
		handle: verifySelf,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/spiffe/verify",
		body: SpiffePresentationSchema,
		summary: "Check an X.509 or JWT SVID against the trust bundles (diagnostic, mints nothing)",
		handle: verifyAdmin,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/spiffe/token",
		body: SpiffeTokenRequestSchema,
		summary: "Issue an agent token bound to a verified X.509-SVID (rotates the agent token)",
		handle: issueToken,
	},
	{
		...admin,
		method: "POST",
		path: "/devices/:id/spiffe",
		body: SpiffeLinkSchema,
		summary: "Link a SPIFFE ID to a device (by id in a configured trust domain, or by SVID)",
		handle: link,
	},
];
