/** Shared SSO types, error codes and the connection row mapper. */

export const SSO_ERROR = {
	CONNECTION_NOT_FOUND: "SSO_CONNECTION_NOT_FOUND",
	CONNECTION_TYPE_MISMATCH: "SSO_CONNECTION_TYPE_MISMATCH",
	PROVIDER_NOT_CONFIGURED: "SSO_PROVIDER_NOT_CONFIGURED",
	SAML_SIGNATURE_INVALID: "SAML_SIGNATURE_INVALID",
	SAML_SIGNATURE_MISSING: "SAML_SIGNATURE_MISSING",
	SAML_DIGEST_MISMATCH: "SAML_DIGEST_MISMATCH",
	SAML_MISSING_NAMEID: "SAML_MISSING_NAMEID",
	SAML_MISSING_ASSERTION: "SAML_MISSING_ASSERTION",
	SAML_CONDITION_NOT_MET: "SAML_CONDITION_NOT_MET",
	SAML_AUDIENCE_MISMATCH: "SAML_AUDIENCE_MISMATCH",
	SAML_DESTINATION_MISMATCH: "SAML_DESTINATION_MISMATCH",
	SAML_ISSUER_MISMATCH: "SAML_ISSUER_MISMATCH",
	SAML_REPLAY_DETECTED: "SAML_REPLAY_DETECTED",
	SAML_ENCRYPTED_NOT_SUPPORTED: "SAML_ENCRYPTED_NOT_SUPPORTED",
	SAML_XML_PARSE_ERROR: "SAML_XML_PARSE_ERROR",
	SAML_XXE_DETECTED: "SAML_XXE_DETECTED",
	OIDC_DISCOVERY_FAILED: "OIDC_DISCOVERY_FAILED",
	OIDC_TOKEN_EXCHANGE_FAILED: "OIDC_TOKEN_EXCHANGE_FAILED",
	OIDC_NONCE_MISMATCH: "OIDC_NONCE_MISMATCH",
	OIDC_MISSING_EMAIL: "OIDC_MISSING_EMAIL",
	STATE_EXPIRED: "SSO_STATE_EXPIRED",
	RATE_LIMITED: "SSO_RATE_LIMITED",
} as const;

export interface SsoConfig {
	saml?: SamlProvider[];
	oidc?: OidcProvider[];
	/** State parameter TTL in seconds (default: 300 = 5 minutes) */
	stateTtlSeconds?: number;
	/** Rate limit: max SSO attempts per IP per window (default: 10) */
	rateLimitMax?: number;
	/** Rate limit window in seconds (default: 60) */
	rateLimitWindowSeconds?: number;
	onAuditEvent?: (event: SsoAuditEvent) => void;
}

export interface SamlProvider {
	id: string;
	name: string;
	entryPoint: string;
	issuer: string;
	cert: string;
	callbackUrl: string;
	wantAuthnResponseSigned?: boolean;
	/** Our entity ID (used for Audience validation). Defaults to issuer. */
	entityId?: string;
	/** Clock skew tolerance in seconds (default: 120) */
	clockSkewSeconds?: number;
}

export interface OidcProvider {
	id: string;
	name: string;
	issuer: string;
	clientId: string;
	clientSecret: string;
	callbackUrl: string;
	scopes?: string[];
	/** Token endpoint auth method: 'client_secret_post' or 'client_secret_basic' (default: 'client_secret_post') */
	tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
}

export interface SsoConnection {
	id: string;
	orgId: string;
	providerId: string;
	type: "saml" | "oidc";
	domain: string;
	enabled: boolean;
	createdAt: Date;
}

export interface SsoAuditEvent {
	type:
		| "sso_login_attempt"
		| "sso_login_success"
		| "sso_login_failure"
		| "sso_connection_created"
		| "sso_connection_removed";
	connectionId?: string;
	providerId?: string;
	email?: string;
	error?: string;
	timestamp: Date;
	metadata?: Record<string, unknown>;
}

export interface SsoModule {
	createConnection: (input: {
		orgId: string;
		providerId: string;
		type: "saml" | "oidc";
		domain: string;
	}) => Promise<SsoConnection>;
	getConnectionByDomain: (domain: string) => Promise<SsoConnection | null>;
	listConnections: (orgId: string) => Promise<SsoConnection[]>;
	removeConnection: (connectionId: string) => Promise<void>;
	getSamlAuthUrl: (connectionId: string, relayState?: string) => Promise<string>;
	handleSamlResponse: (
		connectionId: string,
		samlResponse: string,
		expectedRequestId?: string,
	) => Promise<{ user: { id: string; email: string; name?: string }; orgId: string }>;
	getOidcAuthUrl: (connectionId: string, state?: string, nonce?: string) => Promise<string>;
	handleOidcCallback: (
		connectionId: string,
		code: string,
		expectedNonce?: string,
	) => Promise<{ user: { id: string; email: string; name?: string }; orgId: string }>;
	handleRequest: (request: Request) => Promise<Response | null>;
	generateState: () => Promise<string>;
	validateState: (state: string) => Promise<boolean>;
}

/** Minimal XML node (namespaces, attributes, text, children). Enough for SAML responses, not a general parser. */
export interface XmlNode {
	localName: string;
	prefix: string;
	tagName: string;
	attributes: Map<string, string>;
	children: XmlNode[];
	textContent: string;
	/** Raw inner XML (for signature verification) */
	rawInnerXml: string;
	/** Raw outer XML (for signature verification) */
	rawOuterXml: string;
}

export class SsoError extends Error {
	constructor(
		public readonly code: string,
		message: string,
	) {
		super(message);
		this.name = "SsoError";
	}
}

export function rowToConnection(row: {
	id: string;
	orgId: string;
	providerId: string;
	type: string;
	domain: string;
	enabled: number;
	createdAt: Date;
}): SsoConnection {
	return {
		id: row.id,
		orgId: row.orgId,
		providerId: row.providerId,
		type: row.type as "saml" | "oidc",
		domain: row.domain,
		enabled: row.enabled === 1,
		createdAt: row.createdAt,
	};
}
