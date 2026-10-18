/** Shared SSO types, error codes and the connection row mapper. */

import type { SecondaryStorage } from "../storage/types.js";

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
	SAML_XML_LIMIT_EXCEEDED: "SAML_XML_LIMIT_EXCEEDED",
	SAML_CONFIG_ERROR: "SAML_CONFIG_ERROR",
	SAML_UNSUPPORTED_ALGORITHM: "SAML_UNSUPPORTED_ALGORITHM",
	SAML_REFERENCE_INVALID: "SAML_REFERENCE_INVALID",
	SAML_DUPLICATE_ID: "SAML_DUPLICATE_ID",
	SAML_SIGNATURE_PLACEMENT: "SAML_SIGNATURE_PLACEMENT",
	SAML_INVALID_STRUCTURE: "SAML_INVALID_STRUCTURE",
	SAML_STATUS_NOT_SUCCESS: "SAML_STATUS_NOT_SUCCESS",
	SAML_RECIPIENT_MISMATCH: "SAML_RECIPIENT_MISMATCH",
	SAML_REQUEST_NOT_FOUND: "SAML_REQUEST_NOT_FOUND",
	SAML_CERT_INVALID: "SAML_CERT_INVALID",
	OIDC_DISCOVERY_FAILED: "OIDC_DISCOVERY_FAILED",
	OIDC_TOKEN_EXCHANGE_FAILED: "OIDC_TOKEN_EXCHANGE_FAILED",
	OIDC_NONCE_MISMATCH: "OIDC_NONCE_MISMATCH",
	OIDC_MISSING_EMAIL: "OIDC_MISSING_EMAIL",
	STATE_EXPIRED: "SSO_STATE_EXPIRED",
	RATE_LIMITED: "SSO_RATE_LIMITED",
} as const;

export interface SsoConfig {
	saml?: SamlProvider[];
	/**
	 * Short-lived state for SAML: pending AuthnRequest ids (bound to RelayState) and the assertion id replay cache.
	 * `createTheAuth` wires `secondaryStorage` (feature `nonces`) here. Defaults to process memory, which does not work behind a load balancer.
	 */
	storage?: SecondaryStorage;
	/** Lifetime of a pending SAML AuthnRequest in seconds (default: 600). */
	samlRequestTtlSeconds?: number;
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
	/** IdP single sign-on URL (HTTP-Redirect binding). */
	entryPoint: string;
	/** Our (SP) issuer, sent in the AuthnRequest. Not the IdP. */
	issuer: string;
	/** IdP signing key: an X.509 certificate (PEM or bare base64 DER) or an RSA public key PEM. KeyInfo in responses is never trusted. */
	cert: string;
	/** Our ACS URL. Checked against Destination and SubjectConfirmationData Recipient. */
	callbackUrl: string;
	/** Required. The IdP entity id; the Issuer of the Assertion (and of the Response, when present) must equal it. */
	idpEntityId?: string;
	/** Our entity ID (used for Audience validation). Defaults to issuer. */
	entityId?: string;
	/** Clock skew tolerance in seconds, 0 to 300 (default: 120). */
	clockSkewSeconds?: number;
	/** Accept RSA-SHA1 signatures and SHA-1 digests. Default false. Only for IdPs that cannot do SHA-256. */
	allowLegacySha1?: boolean;
	/** Accept IdP-initiated (unsolicited) responses that carry no InResponseTo. Default false. */
	allowIdpInitiated?: boolean;
	/**
	 * @deprecated Signature verification is mandatory since 2.0. `false` is a config error; the Response or the Assertion must be signed.
	 */
	wantAuthnResponseSigned?: boolean;
	/** Parser limits for incoming responses. */
	xmlLimits?: Partial<XmlLimits>;
}

/** Limits enforced by the SAML XML parser. */
export interface XmlLimits {
	/** Maximum decoded document size in characters (default: 262144). */
	maxBytes: number;
	/** Maximum element nesting depth (default: 32). */
	maxDepth: number;
	/** Maximum attributes (including namespace declarations) per element (default: 32). */
	maxAttributes: number;
	/** Maximum number of elements (default: 4096). */
	maxElements: number;
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
		options?: string | SamlResponseOptions,
	) => Promise<SamlLoginResult>;
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

/** Options for `handleSamlResponse`. A plain string is treated as `expectedRequestId`. */
export interface SamlResponseOptions {
	/** RelayState posted back by the IdP. Resolves the stored AuthnRequest id (single use). */
	relayState?: string;
	/** Expected InResponseTo, when the caller tracks AuthnRequest ids itself. */
	expectedRequestId?: string;
}

export interface SamlLoginResult {
	user: { id: string; email: string; name?: string };
	orgId: string;
	/** SessionIndex from the verified AuthnStatement, for single logout. */
	sessionIndex?: string;
	/** The application relay state passed to `getSamlAuthUrl`, if any. */
	relayState?: string;
}

/** A non-namespace attribute with its resolved namespace. */
export interface XmlAttr {
	name: string;
	prefix: string;
	localName: string;
	namespaceURI: string;
	value: string;
}

/** Mixed content of an element, in document order. */
export type XmlChild =
	| { kind: "element"; node: XmlNode }
	| { kind: "text"; value: string }
	| { kind: "comment"; value: string }
	| { kind: "pi"; target: string; value: string };

/** XML element node (namespaces, attributes, mixed content). Enough for SAML responses, not a general parser. */
export interface XmlNode {
	localName: string;
	prefix: string;
	tagName: string;
	/** Resolved namespace URI ("" when none). */
	namespaceURI: string;
	/** Every attribute as written, including xmlns declarations (legacy view). */
	attributes: Map<string, string>;
	/** Non-namespace attributes in document order. */
	attrs: XmlAttr[];
	/** Namespace declarations on this element. Key "" is the default namespace. */
	nsDecls: Map<string, string>;
	/** In-scope namespace bindings (inherited plus own). Key "" is the default namespace. */
	inScopeNs: ReadonlyMap<string, string>;
	/** Child elements only. */
	children: XmlNode[];
	/** All child nodes in order (elements, text, comments, processing instructions). */
	content: XmlChild[];
	/** Trimmed concatenation of direct text children (legacy view, never used for claims). */
	textContent: string;
	/** Raw inner XML as received. Not used for signature verification. */
	rawInnerXml: string;
	/** Raw outer XML as received. Not used for signature verification. */
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
