import micromatch from "micromatch";
import type { GatewayPolicy } from "./types.js";

/** Returns the first policy whose path glob and (if set) method match. Policies are tested in order. */
export function matchPolicy(
	policies: GatewayPolicy[],
	pathname: string,
	method: string,
): GatewayPolicy | undefined {
	for (const policy of policies) {
		if (!matchesPath(policy.path, pathname)) continue;
		if (!matchesMethod(policy.method, method)) continue;
		return policy;
	}
	return undefined;
}

function matchesPath(pattern: string, pathname: string): boolean {
	// Normalise: treat '' same as '/'
	const normalised = pathname === "" ? "/" : pathname;
	return micromatch.isMatch(normalised, pattern, { dot: true });
}

function matchesMethod(policyMethod: string | string[] | undefined, method: string): boolean {
	if (policyMethod === undefined) return true;
	const upper = method.toUpperCase();
	if (Array.isArray(policyMethod)) {
		return policyMethod.map((m) => m.toUpperCase()).includes(upper);
	}
	return policyMethod.toUpperCase() === upper;
}
