import type { Context } from "../context.js";
import { asRecord, asString, jsonBody } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, pass, skip } from "./helpers.js";

async function registrationEndpoint(ctx: Context): Promise<string | null> {
	const { as } = await ctx.discover();
	return asString(as?.body.registration_endpoint);
}

async function dcrRegistration(ctx: Context) {
	const endpoint = await registrationEndpoint(ctx);
	if (!endpoint) return skip("No registration_endpoint advertised (DCR is optional).");
	const client = await ctx.client();
	if (client?.source !== "dcr") {
		return skip(
			ctx.opts.clientId
				? "A client was supplied with --client-id, so registration was not exercised."
				: `Registration did not complete: ${ctx.clientNote()}. Servers that need an initial access token cannot be probed without credentials.`,
		);
	}
	// The shared probe already registered a client. Register again to read the full response.
	const res = await ctx.send(
		endpoint,
		jsonBody({
			client_name: "theauth-conformance dcr check",
			redirect_uris: [client.redirectUri],
			grant_types: ["authorization_code"],
			response_types: ["code"],
			token_endpoint_auth_method: "none",
		}),
	);
	const body = asRecord(res.json);
	const problems: string[] = [];
	if (res.status !== 201) problems.push(`expected HTTP 201, got ${res.status}`);
	if (!asString(body?.client_id)) problems.push("client_id missing from response");
	const uris = body?.redirect_uris;
	if (!Array.isArray(uris) || !uris.includes(client.redirectUri)) {
		problems.push("redirect_uris not echoed back");
	}
	if (body?.token_endpoint_auth_method !== "none") {
		problems.push("token_endpoint_auth_method not echoed back");
	}
	const cache = res.headers.get("cache-control") ?? "";
	if (!cache.toLowerCase().includes("no-store")) {
		problems.push("response is not Cache-Control: no-store");
	}
	const evidence = { status: res.status, cacheControl: cache, keys: Object.keys(body ?? {}) };
	return problems.length > 0
		? fail(problems.join("; "), evidence)
		: pass("Public client registered with a 201 and an echoed, uncached response.", evidence);
}

async function dcrValidation(ctx: Context) {
	const endpoint = await registrationEndpoint(ctx);
	if (!endpoint) return skip("No registration_endpoint advertised (DCR is optional).");
	const client = await ctx.client();
	if (client?.source !== "dcr") {
		return skip("Open registration did not succeed, so validation cannot be probed.");
	}
	const cases: Array<{ name: string; body: Record<string, unknown> }> = [
		{
			name: "plain http redirect URI on a non-loopback host",
			body: {
				redirect_uris: ["http://attacker.example.test/cb"],
				grant_types: ["authorization_code"],
				token_endpoint_auth_method: "none",
			},
		},
		{
			name: "javascript: redirect URI",
			body: {
				redirect_uris: ["javascript:alert(1)"],
				grant_types: ["authorization_code"],
				token_endpoint_auth_method: "none",
			},
		},
	];
	const verdicts: Array<{ name: string; status: number; error: string | null }> = [];
	for (const testCase of cases) {
		const res = await ctx.send(endpoint, jsonBody(testCase.body));
		const error = asString(asRecord(res.json)?.error);
		verdicts.push({ name: testCase.name, status: res.status, error });
		if (res.status >= 200 && res.status < 300) {
			return fail(`Registration accepted a ${testCase.name}.`, { verdicts });
		}
		if (res.status >= 500) {
			return fail(`A ${testCase.name} caused a server error.`, { verdicts });
		}
		if (res.status !== 400 || !error) {
			return fail(
				`A ${testCase.name} was refused without an RFC 7591 error body (expected 400 with error).`,
				{ verdicts },
			);
		}
	}
	return pass("Unsafe redirect URIs were refused with HTTP 400 and an error code.", { verdicts });
}

export const registrationChecks: Check[] = [
	{
		id: "dcr-registration",
		title: "Dynamic client registration works for a public client",
		spec: "RFC 7591 section 3.1 and 3.2.1",
		severity: "should",
		run: dcrRegistration,
	},
	{
		id: "dcr-validation",
		title: "Dynamic client registration refuses unsafe redirect URIs",
		spec: "RFC 7591 section 3.2.2, OAuth 2.1 section 2.3.1",
		severity: "must",
		run: dcrValidation,
	},
];
