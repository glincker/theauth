import { ACR_ORDER, acrList, evaluateAuthRequirement } from "../session/auth-context.js";
import type { McpAuthContext, McpAuthEvidence, Result } from "./types.js";

/** `max_age` values below this are raised to it, so the round trip to the login page and back cannot loop (a login finished a few seconds ago must still count). */
const MIN_AUTHORIZE_MAX_AGE_SECONDS = 30;

interface StepUpParams {
	acr_values?: string;
	max_age?: string;
}

/**
 * Apply `acr_values` and `max_age` (RFC 9470 section 4, OpenID Connect Core 3.1.2.1) to an authorize request.
 *
 * - Not asked and no `resolveAuthContext`: nothing to do, the code carries no evidence.
 * - Asked but the server cannot judge, or names only classes it does not know: `UNMET_AUTHENTICATION_REQUIREMENTS`
 *   (RFC 9470 section 5), so the client does not loop on a token the resource would refuse.
 * - Asked and the session falls short: `LOGIN_REQUIRED` with `prompt=login`, so the login page asks again and sends the user back.
 * - Otherwise the evidence of the session goes into the code, and from there into the access token.
 */
export async function resolveAuthEvidence(
	ctx: McpAuthContext,
	request: Request,
	params: StepUpParams,
	returnTo: string,
): Promise<Result<McpAuthEvidence | undefined>> {
	const wanted = acrList(params.acr_values);
	const maxAge =
		params.max_age === undefined
			? undefined
			: Math.max(Number(params.max_age), MIN_AUTHORIZE_MAX_AGE_SECONDS);
	const asked = wanted.length > 0 || maxAge !== undefined;

	if (!ctx.resolveAuthContext) {
		if (!asked) return { success: true, data: undefined };
		return unmet("This server cannot evaluate acr_values or max_age");
	}
	if (wanted.length > 0 && !wanted.some((v) => (ACR_ORDER as readonly string[]).includes(v))) {
		return unmet(`None of the requested acr_values is supported: ${wanted.join(" ")}`);
	}

	let assertion: Awaited<ReturnType<NonNullable<McpAuthContext["resolveAuthContext"]>>> = null;
	try {
		assertion = await ctx.resolveAuthContext(request);
	} catch {
		// A broken resolver is "unknown": it can never satisfy a requirement.
	}

	if (asked) {
		const verdict = evaluateAuthRequirement(
			assertion,
			{ acr: wanted, ...(maxAge !== undefined && { maxAge }) },
			Math.floor(Date.now() / 1000),
		);
		if (!verdict.ok) {
			return {
				success: false,
				error: {
					code: "LOGIN_REQUIRED",
					message: "A stronger or more recent authentication is required",
					details: {
						loginPage: ctx.config.loginPage,
						returnTo,
						...(wanted.length > 0 && { acrValues: wanted.join(" ") }),
						...(maxAge !== undefined && { maxAge }),
						prompt: "login",
					},
				},
			};
		}
	}

	if (!assertion?.acr || assertion.authTime === undefined)
		return { success: true, data: undefined };
	return {
		success: true,
		data: { acr: assertion.acr, amr: [...(assertion.amr ?? [])], authTime: assertion.authTime },
	};
}

function unmet(message: string): Result<McpAuthEvidence | undefined> {
	return { success: false, error: { code: "UNMET_AUTHENTICATION_REQUIREMENTS", message } };
}
