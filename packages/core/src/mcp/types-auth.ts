import type { McpClient, McpSession } from "./types.js";

/** Options for dynamic client registration (RFC 7591). */
export interface McpRegistrationConfig {
	/** Set to false to turn dynamic client registration off: no registration route, no `registration_endpoint` in metadata, `registerClient` returns REGISTRATION_DISABLED. Existing clients keep working. Default true. */
	enabled?: boolean;
	/**
	 * Decide which agent a newly registered client acts as. Runs on the server side after the request body validated, so a registering client cannot choose its own agent. Return `undefined` to leave the client unbound. The request is the one handed to `registerClient` (a synthetic POST when none was given), which lets you read the caller's session or an initial access token.
	 */
	agentForClient?: (client: McpClient, request: Request) => Promise<string | undefined>;
}

/** Client to agent binding, exposed as `mcp.clients`. */
export interface McpClientBindings {
	/** Bind the client to an agent. Replaces an earlier binding. Rejects when the store cannot bind or the agent does not exist. */
	bindAgent: (clientId: string, agentId: string) => Promise<void>;
	/** Clear the client's binding. */
	unbindAgent: (clientId: string) => Promise<void>;
	/** The agent the client is bound to, or null (unknown client or unbound). */
	agentFor: (clientId: string) => Promise<string | null>;
}

/** Machine readable reason for an MCP authorization failure. */
export type McpAuthErrorCode =
	| "UNAUTHORIZED"
	| "INVALID_TOKEN"
	| "TOKEN_EXPIRED"
	| "INVALID_AUDIENCE"
	| "INVALID_ISSUER"
	| "DELEGATION_REVOKED"
	| "INSUFFICIENT_SCOPE"
	| "DPOP_REQUIRED"
	| "SERVER_ERROR";

/** Who a rejected token belonged to. Only filled from a token whose signature verified. */
export interface McpRejectedToken {
	clientId: string;
	subject: string;
	agentId?: string;
	tokenId: string;
}

/** Result of `requireScopes`: the session, or a typed denial with the ready-made HTTP response. */
export type RequireScopesResult =
	| { authorized: true; session: McpSession }
	| {
			authorized: false;
			status: 401 | 403 | 500;
			error: { code: McpAuthErrorCode; message: string };
			/** Set for a token whose signature verified but that was refused (expired, revoked, wrong audience, missing scope). Never set for a token that could not be verified, so it is safe to attribute in an audit log. */
			rejected?: McpRejectedToken;
			response: Response;
	  };
