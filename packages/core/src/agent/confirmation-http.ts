import { dpopAlgsOf, readDpopHeader, verifyDpopProofWith } from "../mcp/dpop.js";
import type { McpDpopConfig } from "../mcp/dpop-types.js";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { AgentConfirmation } from "./confirmation.js";
import { CNF_JKT } from "./confirmation.js";

/** Reads one proof of possession from a request, for example the thumbprint of the client certificate a TLS terminator passed on. Return null when the request carries none. */
export type ConfirmationExtractor = (request: Request) => string | null | Promise<string | null>;

/** DPoP settings for agent tokens. Same knobs as the MCP server, see `McpDpopConfig`. */
export type AgentDpopConfig = Omit<McpDpopConfig, "required" | "tokenEndpointUrl"> & {
	/** The URL clients sign as `htu`. Set it behind a proxy, where `request.url` is not the public URL. Default: `request.url`. */
	resourceUrl?: (request: Request) => string;
};

/**
 * How agent tokens are sender constrained (`agents.confirmation`).
 *
 * Set `dpop` to accept DPoP proofs (RFC 9449). Add `methods` for other members of the `cnf` claim: the key is the member name and the value reads the proof from the request, for example `"x5t#S256": (req) => thumbprintFromHeader(req)` for mutual TLS (RFC 8705). A token bound to a member with no extractor is always refused.
 */
export interface AgentConfirmationConfig {
	dpop?: AgentDpopConfig;
	methods?: Record<string, ConfirmationExtractor>;
	/** Refuse agent tokens that are not bound to a key or certificate (FAPI 2.0 section 5.3.2.1 style). Default false. */
	required?: boolean;
}

export type ConfirmationOutcome =
	| { ok: true; confirmation: AgentConfirmation | undefined }
	| { ok: false; response: Response };

export interface AgentConfirmationVerifier {
	readonly config: AgentConfirmationConfig;
	/** Verify every proof the request carries for `token`. `scheme` is the Authorization scheme the token came with. */
	verify(request: Request, token: string, scheme: "Bearer" | "DPoP"): Promise<ConfirmationOutcome>;
}

function json(status: number, body: unknown, headers: Record<string, string>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			"Access-Control-Expose-Headers": "WWW-Authenticate, DPoP-Nonce",
			...headers,
		},
	});
}

/** Quote a challenge parameter value. */
function q(value: string): string {
	return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Build the verifier. Without `dpop` and `methods`, only the pipeline check of `cnf` applies and every bound token is refused. */
export function createAgentConfirmationVerifier(
	config: AgentConfirmationConfig = {},
	storage?: SecondaryStorage,
): AgentConfirmationVerifier {
	const dpop = config.dpop;
	const store = dpop?.storage ?? storage ?? memoryStorage();
	const algs = dpop ? dpopAlgsOf(dpop).join(" ") : "";

	async function verify(
		request: Request,
		token: string,
		scheme: "Bearer" | "DPoP",
	): Promise<ConfirmationOutcome> {
		const confirmation: AgentConfirmation = {};

		if (dpop) {
			const proof = readDpopHeader(request);
			// The DPoP scheme promises a proof. A Bearer request may carry one too (an unbound token ignores it).
			if (scheme === "DPoP" || proof !== null) {
				if (!proof) {
					return {
						ok: false,
						response: json(
							401,
							{
								error: "invalid_dpop_proof",
								error_description: "Exactly one DPoP proof header is required",
							},
							{ "WWW-Authenticate": `DPoP error="invalid_dpop_proof", algs=${q(algs)}` },
						),
					};
				}
				const verified = await verifyDpopProofWith(
					{ config: dpop, storage: store, prefix: "agent:" },
					{
						proof,
						method: request.method,
						url: dpop.resourceUrl ? dpop.resourceUrl(request) : request.url,
						accessToken: token,
					},
				);
				if (!verified.success) {
					const nonce = verified.error.details?.dpopNonce;
					if (verified.error.code === "USE_DPOP_NONCE" && typeof nonce === "string") {
						return {
							ok: false,
							response: json(
								401,
								{ error: "use_dpop_nonce", error_description: verified.error.message },
								{
									"WWW-Authenticate": `DPoP error="use_dpop_nonce", algs=${q(algs)}`,
									"DPoP-Nonce": nonce,
								},
							),
						};
					}
					return {
						ok: false,
						response: json(
							401,
							{ error: "invalid_dpop_proof", error_description: verified.error.message },
							{
								"WWW-Authenticate": `DPoP error="invalid_dpop_proof", error_description=${q(verified.error.message)}, algs=${q(algs)}`,
							},
						),
					};
				}
				confirmation[CNF_JKT] = verified.data.jkt;
			}
		}

		for (const [member, extract] of Object.entries(config.methods ?? {})) {
			let value: string | null = null;
			try {
				value = await extract(request);
			} catch {
				// An extractor that throws proves nothing.
			}
			if (value) confirmation[member] = value;
		}

		return {
			ok: true,
			confirmation: Object.keys(confirmation).length > 0 ? confirmation : undefined,
		};
	}

	return { config, verify };
}
