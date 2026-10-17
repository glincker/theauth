import type { Context } from "../context.js";
import { asRecord, asString, asStringArray, excerpt } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, pass, skip } from "./helpers.js";

const BAD_DPOP_ALGS = new Set(["none", "HS256", "HS384", "HS512"]);

function resourceMetadataParam(header: string): string | null {
	const match = /resource_metadata\s*=\s*"([^"]+)"/i.exec(header);
	return match?.[1] ?? null;
}

async function wwwAuthenticate(ctx: Context) {
	const found = await ctx.protectedResource();
	if (!found) {
		return skip(
			"No protected MCP resource returned 401. Pass --resource with the URL of a protected endpoint.",
		);
	}
	const { response } = found;
	const header = response.headers.get("www-authenticate") ?? "";
	const evidence = { url: found.url, status: response.status, wwwAuthenticate: header };
	if (response.status !== 401) {
		return fail(`An unauthenticated request got HTTP ${response.status}, expected 401.`, {
			...evidence,
			body: excerpt(response.text),
		});
	}
	if (!/^\s*(Bearer|DPoP)\b/i.test(header)) {
		return fail("The 401 has no Bearer or DPoP challenge in WWW-Authenticate.", evidence);
	}
	const metadataUrl = resourceMetadataParam(header);
	if (!metadataUrl) {
		return fail("The challenge does not carry a resource_metadata parameter.", evidence);
	}
	const doc = await ctx.send(metadataUrl, { headers: { Accept: "application/json" } });
	const body = asRecord(doc.json);
	if (doc.status !== 200 || !asString(body?.resource)) {
		return fail(
			"resource_metadata points at a URL that is not a protected resource metadata document.",
			{
				...evidence,
				metadataUrl,
				metadataStatus: doc.status,
			},
		);
	}
	return pass("The 401 challenge points at working protected resource metadata.", {
		...evidence,
		metadataUrl,
	});
}

async function dpopAdvertised(ctx: Context) {
	const { as, prm } = await ctx.discover();
	const fromAs = asStringArray(as?.body.dpop_signing_alg_values_supported);
	const fromPrm = asStringArray(prm?.body.dpop_signing_alg_values_supported);
	const algs = [...new Set([...fromAs, ...fromPrm])];
	if (algs.length === 0) return skip("DPoP is not advertised (optional).");
	const weak = algs.filter((alg) => BAD_DPOP_ALGS.has(alg));
	return weak.length > 0
		? fail(`DPoP advertises weak or symmetric algorithms: ${weak.join(", ")}.`, { algs })
		: pass("DPoP is advertised with asymmetric signing algorithms.", { algs });
}

async function dpopEnforced(ctx: Context) {
	const { as, prm } = await ctx.discover();
	const advertised =
		asStringArray(as?.body.dpop_signing_alg_values_supported).length > 0 ||
		asStringArray(prm?.body.dpop_signing_alg_values_supported).length > 0;
	if (!advertised) return skip("DPoP is not advertised (optional).");
	const found = await ctx.protectedResource();
	if (!found) {
		return skip("No protected resource found to send a DPoP request to. Pass --resource.");
	}
	const res = await ctx.probeResource(found.url, {
		Authorization: "DPoP conformance-garbage-token",
		DPoP: "not.a.proof",
	});
	const evidence = {
		url: found.url,
		status: res.status,
		wwwAuthenticate: res.headers.get("www-authenticate"),
	};
	if (res.status === 401) {
		return pass("A DPoP request with a garbage token and proof was refused with 401.", evidence);
	}
	return fail(
		`A DPoP request with a garbage token and proof got HTTP ${res.status}, expected 401.`,
		evidence,
	);
}

export const resourceChecks: Check[] = [
	{
		id: "www-authenticate-resource-metadata",
		title: "Protected resource answers 401 with a resource_metadata challenge",
		spec: "RFC 9728 section 5.1, RFC 6750 section 3, MCP authorization section 2.3",
		severity: "must",
		run: wwwAuthenticate,
	},
	{
		id: "dpop-advertised",
		title: "DPoP support is advertised with safe algorithms",
		spec: "RFC 9449 section 5.1 and 5.2, RFC 8414 section 2",
		severity: "may",
		run: dpopAdvertised,
	},
	{
		id: "dpop-enforced",
		title: "Resource refuses an invalid DPoP proof",
		spec: "RFC 9449 section 7.1",
		severity: "must",
		run: dpopEnforced,
	},
];
