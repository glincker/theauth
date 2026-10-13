import { ExtensionAuthError } from "./errors.js";
import type { AuthorizationServerEndpoints } from "./types.js";

/** RFC 8414 section 3.1: the well-known segment goes between host and path. */
export function metadataUrl(issuer: string): string {
	const u = new URL(issuer);
	const path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
	return `${u.origin}/.well-known/oauth-authorization-server${path}`;
}

function str(v: unknown): string | undefined {
	return typeof v === "string" && v.length > 0 ? v : undefined;
}

export async function discoverEndpoints(
	issuer: string,
	fetchImpl: typeof fetch,
): Promise<AuthorizationServerEndpoints> {
	let res: Response;
	try {
		res = await fetchImpl(metadataUrl(issuer), { headers: { Accept: "application/json" } });
	} catch (cause) {
		throw new ExtensionAuthError("discovery_failed", "Could not reach the authorization server", {
			cause: cause instanceof Error ? cause.message : String(cause),
		});
	}
	if (!res.ok) {
		throw new ExtensionAuthError("discovery_failed", `Discovery returned HTTP ${res.status}`);
	}
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		throw new ExtensionAuthError("discovery_failed", "Discovery response was not JSON");
	}
	const meta = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
	const authorization = str(meta.authorization_endpoint);
	const token = str(meta.token_endpoint);
	if (!authorization || !token) {
		throw new ExtensionAuthError(
			"discovery_failed",
			"Metadata is missing authorization_endpoint or token_endpoint",
		);
	}
	if (str(meta.issuer) !== issuer) {
		throw new ExtensionAuthError("discovery_failed", "Metadata issuer does not match", {
			expected: issuer,
		});
	}
	return {
		authorization,
		token,
		revocation: str(meta.revocation_endpoint),
		endSession: str(meta.end_session_endpoint),
		issuer,
		issuerParameterSupported: meta.authorization_response_iss_parameter_supported === true,
	};
}
