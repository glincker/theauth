import type { Context } from "../context.js";
import type { HttpResult } from "../http.js";
import { asRecord, asString, asStringArray, formBody } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, GRANT_TOKEN_EXCHANGE, pass, skip } from "./helpers.js";

const PROBE_CLIENT = "theauth-conformance-probe";

function oauthError(res: HttpResult): string | null {
	return asString(asRecord(res.json)?.error);
}

/** A garbage credential must produce a 4xx OAuth error body, never a token or a crash. */
function judgeGarbage(res: HttpResult, what: string, acceptable: string[]) {
	const error = oauthError(res);
	const evidence = { status: res.status, error };
	if (res.status === 200) return fail(`${what} returned HTTP 200.`, evidence);
	if (res.status >= 500) return fail(`${what} caused a server error.`, evidence);
	if (!error) return fail(`${what} was refused without an OAuth error body.`, evidence);
	if (!acceptable.includes(error)) {
		return fail(
			`${what} returned error "${error}", expected one of ${acceptable.join(", ")}.`,
			evidence,
		);
	}
	return pass(`${what} was refused with ${res.status} ${error}.`, evidence);
}

async function clientIdForProbe(ctx: Context): Promise<string> {
	return (await ctx.client())?.clientId ?? PROBE_CLIENT;
}

async function refreshGarbage(ctx: Context) {
	const res = await ctx.postToken({
		grant_type: "refresh_token",
		refresh_token: "conformance-garbage-refresh-token",
		client_id: await clientIdForProbe(ctx),
	});
	if (!res) return skip("No token_endpoint advertised.");
	return judgeGarbage(res, "A made-up refresh token", ["invalid_grant", "invalid_client"]);
}

async function refreshRotation(ctx: Context) {
	const { refreshToken, clientId } = ctx.opts;
	if (!refreshToken || !clientId) {
		return skip(
			"Needs a real refresh token and its client. Pass --refresh-token and --client-id (the token is consumed by the test).",
		);
	}
	const first = await ctx.postToken({
		grant_type: "refresh_token",
		refresh_token: refreshToken,
		client_id: clientId,
	});
	if (!first) return skip("No token_endpoint advertised.");
	const firstBody = asRecord(first.json);
	const rotated = asString(firstBody?.refresh_token);
	if (first.status !== 200) {
		return skip("The supplied refresh token was not accepted, so rotation cannot be tested.", {
			status: first.status,
			error: oauthError(first),
		});
	}
	if (!rotated || rotated === refreshToken) {
		return fail("The refresh token was not rotated: no new, different refresh_token was issued.", {
			status: first.status,
		});
	}
	const replay = await ctx.postToken({
		grant_type: "refresh_token",
		refresh_token: refreshToken,
		client_id: clientId,
	});
	if (replay?.status === 200) {
		return fail("The old refresh token was accepted a second time.", { replayStatus: 200 });
	}
	const successor = await ctx.postToken({
		grant_type: "refresh_token",
		refresh_token: rotated,
		client_id: clientId,
	});
	if (successor?.status === 200) {
		return fail(
			"Reuse of the old token was refused, but the newer token still works. The token family was not revoked.",
			{ replayStatus: replay?.status, successorStatus: 200 },
		);
	}
	return pass("Tokens rotate, replay is refused, and replay revokes the newer token.", {
		replayStatus: replay?.status,
		successorStatus: successor?.status,
	});
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
	const part = token.split(".")[1];
	if (token.split(".").length !== 3 || !part) return null;
	try {
		return asRecord(JSON.parse(Buffer.from(part, "base64url").toString("utf8")));
	} catch {
		return null;
	}
}

async function resourceIndicator(ctx: Context) {
	if (!ctx.opts.accessToken) {
		return skip(
			"Audience binding can only be observed on a real token. Pass --token (or THEAUTH_CONFORMANCE_TOKEN) to inspect one.",
		);
	}
	const payload = decodeJwtPayload(ctx.opts.accessToken);
	if (!payload) return skip("The supplied token is not a JWT, so its audience cannot be read.");
	const aud = Array.isArray(payload.aud) ? asStringArray(payload.aud) : [asString(payload.aud)];
	const audiences = aud.filter((a): a is string => a !== null);
	if (audiences.length === 0)
		return fail("The access token has no aud claim.", { claims: Object.keys(payload) });
	const resource = await ctx.resourceParam();
	const matches = audiences.some((a) => a.replace(/\/$/, "") === resource.replace(/\/$/, ""));
	return matches
		? pass("The access token audience matches the protected resource.", {
				aud: audiences,
				resource,
			})
		: fail("The access token audience does not match the protected resource.", {
				aud: audiences,
				resource,
			});
}

async function tokenExchange(ctx: Context) {
	const { as } = await ctx.discover();
	if (!as) return skip("No authorization server metadata to read.");
	if (!asStringArray(as.body.grant_types_supported).includes(GRANT_TOKEN_EXCHANGE)) {
		return skip("Token exchange is not advertised (optional).");
	}
	const res = await ctx.postToken({
		grant_type: GRANT_TOKEN_EXCHANGE,
		subject_token: "conformance-garbage-subject-token",
		subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
		client_id: await clientIdForProbe(ctx),
	});
	if (!res) return skip("No token_endpoint advertised.");
	return judgeGarbage(res, "A made-up subject token", [
		"invalid_grant",
		"invalid_request",
		"invalid_client",
		"invalid_target",
		"unauthorized_client",
	]);
}

async function actChain(ctx: Context) {
	const { as } = await ctx.discover();
	if (!as) return skip("No authorization server metadata to read.");
	if (!asStringArray(as.body.grant_types_supported).includes(GRANT_TOKEN_EXCHANGE)) {
		return skip("Token exchange is not advertised (optional).");
	}
	return skip(
		"Checking the act claim chain needs a valid subject token and client credentials, which a no-secret probe does not have.",
	);
}

async function introspection(ctx: Context) {
	const { as } = await ctx.discover();
	const endpoint = asString(as?.body.introspection_endpoint);
	if (!endpoint) return skip("No introspection_endpoint advertised (optional).");
	const res = await ctx.send(
		endpoint,
		formBody({ token: "conformance-garbage-token", token_type_hint: "access_token" }),
	);
	if (res.status === 401 || res.status === 403) {
		return skip("Introspection requires client authentication, which was not supplied.", {
			status: res.status,
		});
	}
	const body = asRecord(res.json);
	const evidence = { status: res.status, active: body?.active ?? null };
	if (res.status !== 200) {
		return fail(
			`An unknown token should give HTTP 200 with active=false, got ${res.status}.`,
			evidence,
		);
	}
	return body?.active === false
		? pass("A garbage token introspects as active=false.", evidence)
		: fail("A garbage token did not return active=false.", evidence);
}

export const tokenChecks: Check[] = [
	{
		id: "refresh-garbage-rejected",
		title: "An invalid refresh token is refused with invalid_grant",
		spec: "RFC 6749 section 5.2, OAuth 2.1 section 4.3",
		severity: "must",
		run: refreshGarbage,
	},
	{
		id: "refresh-rotation",
		title: "Refresh tokens rotate and reuse is detected",
		spec: "OAuth 2.1 section 4.3.1, RFC 9700 section 4.14",
		severity: "must",
		run: refreshRotation,
	},
	{
		id: "resource-indicator-audience",
		title: "Access token audience is bound to the resource",
		spec: "RFC 8707 section 2, MCP authorization section 2.6",
		severity: "must",
		run: resourceIndicator,
	},
	{
		id: "token-exchange-rejects-garbage",
		title: "Token exchange refuses an invalid subject token",
		spec: "RFC 8693 section 2.2.2",
		severity: "must",
		run: tokenExchange,
	},
	{
		id: "token-exchange-act-chain",
		title: "Exchanged tokens carry a nested act claim chain",
		spec: "RFC 8693 section 4.1",
		severity: "should",
		run: actChain,
	},
	{
		id: "introspection-inactive",
		title: "Introspection returns active=false for an unknown token",
		spec: "RFC 7662 section 2.2",
		severity: "must",
		run: introspection,
	},
];
