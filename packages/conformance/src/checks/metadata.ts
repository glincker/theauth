import type { Context } from "../context.js";
import { asString, asStringArray, isLoopback } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, pass, skip } from "./helpers.js";

function insecure(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol !== "https:" && !isLoopback(url);
	} catch {
		return true;
	}
}

/** Issuer implied by where the document was served (RFC 8414 section 3.3). */
function impliedIssuer(docUrl: string): string {
	const url = new URL(docUrl);
	const match = /^\/\.well-known\/(?:oauth-authorization-server|openid-configuration)(.*)$/.exec(
		url.pathname,
	);
	return `${url.origin}${match?.[1] ?? ""}`;
}

async function asMetadata(ctx: Context) {
	const { as, tried } = await ctx.discover();
	if (!as) {
		return fail("No authorization server metadata document found.", { tried });
	}
	const meta = as.body;
	const issuer = asString(meta.issuer);
	const problems: string[] = [];
	if (!issuer) problems.push("issuer missing");
	else if (issuer !== impliedIssuer(as.url)) {
		problems.push(`issuer "${issuer}" does not match the URL it was served from`);
	}
	for (const key of ["authorization_endpoint", "token_endpoint"] as const) {
		const value = asString(meta[key]);
		if (!value) problems.push(`${key} missing`);
		else if (insecure(value)) problems.push(`${key} is not https`);
	}
	if (!asStringArray(meta.response_types_supported).includes("code")) {
		problems.push("response_types_supported does not include code");
	}
	const grants = asStringArray(meta.grant_types_supported);
	if (grants.length > 0 && !grants.includes("authorization_code")) {
		problems.push("grant_types_supported does not include authorization_code");
	}
	const evidence = { url: as.url, issuer, grants };
	return problems.length > 0
		? fail(problems.join("; "), evidence)
		: pass("Authorization server metadata is present and well formed.", evidence);
}

async function rsMetadata(ctx: Context) {
	const { prm, tried } = await ctx.discover();
	if (!prm) {
		return fail("No protected resource metadata document found.", { tried });
	}
	const problems: string[] = [];
	const resource = asString(prm.body.resource);
	if (!resource) problems.push("resource missing");
	else if (resource.includes("#")) problems.push("resource contains a fragment");
	const servers = asStringArray(prm.body.authorization_servers);
	if (servers.length === 0) problems.push("authorization_servers missing or empty");
	if (servers.some(insecure)) problems.push("an authorization server URL is not https");
	const evidence = { url: prm.url, resource, authorization_servers: servers };
	return problems.length > 0
		? fail(problems.join("; "), evidence)
		: pass("Protected resource metadata is present and well formed.", evidence);
}

async function consistency(ctx: Context) {
	const { as, prm } = await ctx.discover();
	if (!as || !prm) {
		return skip("Needs both authorization server and protected resource metadata to compare.");
	}
	const issuer = asString(as.body.issuer);
	const servers = asStringArray(prm.body.authorization_servers);
	const problems: string[] = [];
	if (issuer && !servers.includes(issuer)) {
		problems.push(`protected resource does not list issuer "${issuer}" in authorization_servers`);
	}
	const supported = asStringArray(prm.body.scopes_supported);
	const asScopes = asStringArray(as.body.scopes_supported);
	const unknown = asScopes.length > 0 ? supported.filter((s) => !asScopes.includes(s)) : [];
	if (unknown.length > 0) {
		problems.push(`scopes only the resource knows about: ${unknown.join(", ")}`);
	}
	const evidence = { issuer, authorization_servers: servers };
	return problems.length > 0
		? fail(problems.join("; "), evidence)
		: pass("Resource metadata and authorization server metadata agree.", evidence);
}

export const metadataChecks: Check[] = [
	{
		id: "as-metadata",
		title: "Authorization server metadata is published",
		spec: "RFC 8414 section 2 and 3",
		severity: "must",
		run: asMetadata,
	},
	{
		id: "rs-metadata",
		title: "Protected resource metadata is published",
		spec: "RFC 9728 section 2 and 3",
		severity: "should",
		run: rsMetadata,
	},
	{
		id: "metadata-consistency",
		title: "Resource and authorization server metadata agree",
		spec: "RFC 9728 section 3, RFC 8414 section 2",
		severity: "must",
		run: consistency,
	},
];
