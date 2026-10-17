import type { AuthorizeProbe, Context } from "../context.js";
import { asStringArray } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, pass, skip } from "./helpers.js";

function describe(probe: AuthorizeProbe) {
	return { kind: probe.kind, status: probe.status, location: probe.location, body: probe.body };
}

async function prerequisites(ctx: Context) {
	const client = await ctx.client();
	if (!client) return { skipReason: `No client for authorize probes: ${ctx.clientNote()}.` };
	const control = await ctx.control();
	if (!control) return { skipReason: "No authorization_endpoint advertised." };
	if (control.kind === "rejected" || control.kind === "server-error") {
		return {
			skipReason:
				"A fully valid authorize request was itself rejected, so negative probes cannot be isolated.",
			control,
		};
	}
	return { control };
}

/** Judge a request that a conformant server must refuse before any login. */
function judgeRejection(probe: AuthorizeProbe, what: string) {
	switch (probe.kind) {
		case "rejected":
		case "rejected-redirect":
			return pass(`${what} was refused.`, describe(probe));
		case "code-issued":
			return fail(`${what} was accepted and an authorization code was issued.`, describe(probe));
		case "server-error":
			return fail(`${what} caused a server error instead of a clean refusal.`, describe(probe));
		default:
			return skip(
				`${what} was not refused up front (the server moved on to login). A black-box probe cannot see later validation.`,
				describe(probe),
			);
	}
}

async function pkceAdvertised(ctx: Context) {
	const { as } = await ctx.discover();
	if (!as) return skip("No authorization server metadata to read.");
	const methods = asStringArray(as.body.code_challenge_methods_supported);
	if (methods.length === 0) {
		return fail("code_challenge_methods_supported is not advertised.", { methods });
	}
	if (!methods.includes("S256")) return fail("S256 is not advertised.", { methods });
	if (methods.includes("plain")) return fail("The weak plain method is advertised.", { methods });
	return pass("Only S256 is advertised.", { methods });
}

async function pkceRequired(ctx: Context) {
	const pre = await prerequisites(ctx);
	if (pre.skipReason) return skip(pre.skipReason);
	const probe = await ctx.probeAuthorize({ code_challenge: null, code_challenge_method: null });
	if (!probe) return skip("Could not build an authorize request.");
	return judgeRejection(probe, "An authorize request without a PKCE challenge");
}

async function pkcePlain(ctx: Context) {
	const pre = await prerequisites(ctx);
	if (pre.skipReason) return skip(pre.skipReason);
	const probe = await ctx.probeAuthorize({
		code_challenge: "conformance-plain-verifier-0123456789-abcdefghij",
		code_challenge_method: "plain",
	});
	if (!probe) return skip("Could not build an authorize request.");
	return judgeRejection(probe, "An authorize request using code_challenge_method=plain");
}

async function redirectExact(ctx: Context) {
	const pre = await prerequisites(ctx);
	if (pre.skipReason) return skip(pre.skipReason);
	const client = await ctx.client();
	if (!client) return skip("No client available.");
	const registered = new URL(client.redirectUri);
	const variants = [
		`${registered.origin}${registered.pathname}/extra`,
		`https://attacker.example.test${registered.pathname}`,
	];
	const verdicts: Array<{ variant: string; probe: ReturnType<typeof describe> }> = [];
	let inconclusive = 0;
	for (const variant of variants) {
		const probe = await ctx.probeAuthorize({ redirect_uri: variant });
		if (!probe) return skip("Could not build an authorize request.");
		verdicts.push({ variant, probe: describe(probe) });
		const redirectedToVariant = probe.location?.startsWith(variant) === true;
		if (probe.kind === "code-issued" || redirectedToVariant) {
			return fail(`The server redirected to the unregistered URI ${variant}.`, { verdicts });
		}
		if (probe.kind === "server-error") {
			return fail(`The unregistered URI ${variant} caused a server error.`, { verdicts });
		}
		if (probe.kind !== "rejected") inconclusive += 1;
	}
	if (inconclusive > 0) {
		return skip(
			"An unregistered redirect_uri was not refused up front, and was not redirected to either.",
			{ verdicts },
		);
	}
	return pass("Prefix and foreign-host redirect_uri values were refused without redirecting.", {
		verdicts,
	});
}

export const authorizeChecks: Check[] = [
	{
		id: "pkce-s256-advertised",
		title: "PKCE S256 is advertised and plain is not",
		spec: "OAuth 2.1 section 4.1.1, RFC 7636 section 4.2, RFC 8414 section 2",
		severity: "must",
		run: pkceAdvertised,
	},
	{
		id: "pkce-required",
		title: "Authorize requests without PKCE are refused",
		spec: "OAuth 2.1 section 4.1.1, RFC 9700 section 2.1.1",
		severity: "must",
		run: pkceRequired,
	},
	{
		id: "pkce-plain-rejected",
		title: "PKCE plain method is refused",
		spec: "OAuth 2.1 section 4.1.1, RFC 7636 section 4.2",
		severity: "must",
		run: pkcePlain,
	},
	{
		id: "redirect-exact-match",
		title: "Redirect URIs are matched exactly",
		spec: "OAuth 2.1 section 4.1.1, RFC 9700 section 2.1",
		severity: "must",
		run: redirectExact,
	},
];
