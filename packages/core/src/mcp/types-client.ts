import type { JWK } from "jose";
import type { McpClientCimdSnapshot } from "./types-cimd.js";

// OAuth 2.0 Authorization Server Metadata (RFC 8414)

export interface McpServerMetadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	/** Omitted when `registration.enabled === false`. */
	registration_endpoint?: string;
	jwks_uri?: string;
	scopes_supported: string[];
	response_types_supported: string[];
	response_modes_supported: string[];
	grant_types_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	/** RFC 8414: JWS algorithms accepted for `private_key_jwt` assertions. */
	token_endpoint_auth_signing_alg_values_supported?: string[];
	code_challenge_methods_supported: string[];
	service_documentation?: string;
	revocation_endpoint?: string;
	revocation_endpoint_auth_methods_supported?: string[];
	revocation_endpoint_auth_signing_alg_values_supported?: string[];
	/** RFC 8414 / RFC 7662: present only when introspection is enabled (and the route is mounted). */
	introspection_endpoint?: string;
	introspection_endpoint_auth_methods_supported?: string[];
	introspection_endpoint_auth_signing_alg_values_supported?: string[];
	/** RFC 9207: the authorization response carries an `iss` parameter. */
	authorization_response_iss_parameter_supported?: boolean;
	client_id_metadata_document_supported?: boolean;
	/** RFC 9449 section 5.1: JWS algorithms accepted for DPoP proofs. */
	dpop_signing_alg_values_supported?: string[];
	/** RFC 9470 section 7: the server honors `acr_values` and `max_age`. Present when `resolveAuthContext` is set. */
	acr_values_supported?: string[];
}

// Protected Resource Metadata (RFC 9728)

export interface McpProtectedResourceMetadata {
	resource: string;
	authorization_servers: string[];
	jwks_uri?: string;
	scopes_supported: string[];
	bearer_methods_supported: string[];
	resource_signing_alg_values_supported?: string[];
	/** RFC 9728: JWS algorithms accepted for DPoP proofs. */
	dpop_signing_alg_values_supported?: string[];
	/** RFC 9728: true when this resource refuses tokens that are not DPoP-bound. */
	dpop_bound_access_tokens_required?: boolean;
}

// OAuth Client (RFC 7591 Dynamic Client Registration)

export interface McpClient {
	clientId: string;
	clientSecret: string | null;
	clientName: string | null;
	clientUri: string | null;
	logoUri: string | null;
	redirectUris: string[];
	grantTypes: string[];
	responseTypes: string[];
	tokenEndpointAuthMethod: string;
	scope: string | null;
	contacts: string[] | null;
	tosUri: string | null;
	policyUri: string | null;
	softwareId: string | null;
	softwareVersion: string | null;
	clientType: "public" | "confidential";
	disabled: boolean;
	/** Why the client is disabled, for example "blocked" or "cimd_changed_while_bound". */
	disabledReason?: string | null;
	userId: string | null;
	/** The agent this client acts as, or null/absent when unbound. Tokens issued to the client carry it as `agent_id` and the built-in delegation mapping resolves the client to it. */
	agentId?: string | null;
	/** Set to "cimd" for clients resolved from a Client ID Metadata Document. */
	source?: "cimd";
	jwks?: { keys: JWK[] };
	jwksUri?: string;
	/** Snapshot of the fetched Client ID Metadata Document (source "cimd" only). */
	cimd?: McpClientCimdSnapshot;
	createdAt: Date;
	updatedAt: Date;
}

export interface McpClientRegistrationRequest {
	redirect_uris: string[];
	token_endpoint_auth_method?: string;
	grant_types?: string[];
	response_types?: string[];
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	scope?: string;
	contacts?: string[];
	tos_uri?: string;
	policy_uri?: string;
	software_id?: string;
	software_version?: string;
	jwks?: { keys: JWK[] };
	jwks_uri?: string;
}

export interface McpClientRegistrationResponse {
	client_id: string;
	client_secret?: string;
	client_id_issued_at: number;
	client_secret_expires_at?: number;
	redirect_uris: string[];
	token_endpoint_auth_method: string;
	grant_types: string[];
	response_types: string[];
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	scope?: string;
	contacts?: string[];
	tos_uri?: string;
	policy_uri?: string;
	software_id?: string;
	software_version?: string;
	jwks?: { keys: JWK[] };
	jwks_uri?: string;
}
