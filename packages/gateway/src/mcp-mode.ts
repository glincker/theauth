import type { McpPrincipal } from "@glinr/theauth/mcp";
import type { GatewayMcpConfig } from "./types.js";

const WELL_KNOWN = "/.well-known/oauth-protected-resource";

export interface ResolvedMcp {
	config: GatewayMcpConfig;
	resource: URL;
	metadataUrl: string;
	/** Paths the metadata document is served on (bare and RFC 9728 path-suffixed). */
	metadataPaths: string[];
}

export function resolveMcp(config: GatewayMcpConfig): ResolvedMcp {
	let resource: URL;
	try {
		resource = new URL(config.resource);
	} catch {
		throw new Error(`mcp.resource must be an absolute URL, got "${config.resource}"`);
	}
	if (
		resource.protocol !== "https:" &&
		resource.hostname !== "localhost" &&
		resource.hostname !== "127.0.0.1"
	) {
		throw new Error("mcp.resource must be https (http is allowed only for localhost)");
	}
	const suffix = resource.pathname === "/" ? "" : resource.pathname.replace(/\/$/, "");
	const paths = [WELL_KNOWN, ...(suffix ? [`${WELL_KNOWN}${suffix}`] : [])];
	return {
		config,
		resource,
		metadataUrl: config.resourceMetadataUrl ?? `${resource.origin}${WELL_KNOWN}${suffix}`,
		metadataPaths: paths,
	};
}

/**
 * RFC 9728 document for the upstream. The auth module reports its own issuer as
 * the resource, so the gateway swaps in the URL clients really call.
 */
export function metadataResponse(mcp: ResolvedMcp, cors: Record<string, string>): Response {
	const doc = { ...mcp.config.auth.getProtectedResourceMetadata(), resource: mcp.config.resource };
	return new Response(JSON.stringify(doc), {
		status: 200,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "public, max-age=300",
			"Access-Control-Allow-Origin": "*",
			...cors,
		},
	});
}

export type McpAuthResult =
	| { ok: true; principal: McpPrincipal }
	| { ok: false; response: Response };

/** Run the shared MCP token validation and capture the verified principal. */
export async function authenticateMcp(
	mcp: ResolvedMcp,
	request: Request,
	policyScopes: string[] | undefined,
): Promise<McpAuthResult> {
	const box: { principal: McpPrincipal | null } = { principal: null };
	const requiredScopes = [
		...new Set([...(mcp.config.requiredScopes ?? []), ...(policyScopes ?? [])]),
	];
	// DPoP proofs are bound to the URL the client called, not the internal one.
	const incoming = new URL(request.url);
	const resourceUrl = `${mcp.resource.origin}${incoming.pathname}${incoming.search}`;
	const guarded = mcp.config.auth.requireMcpAuth(
		(_req, principal) => {
			box.principal = principal;
			return new Response(null, { status: 204 });
		},
		{
			expectedAudience: mcp.config.resource,
			requiredScopes,
			resourceUrl,
			resourceMetadataUrl: mcp.metadataUrl,
		},
	);
	const response = await guarded(request);
	if (box.principal) return { ok: true, principal: box.principal };
	return { ok: false, response };
}
