/**
 * Shared types for OpenID Shared Signals Framework 1.0 (SSF), CAEP and RISC.
 */

// Event type URIs

export const SSF_VERIFICATION_EVENT =
	"https://schemas.openid.net/secevent/ssf/event-type/verification";
export const SSF_STREAM_UPDATED_EVENT =
	"https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

export const CAEP_SESSION_REVOKED =
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked";
export const CAEP_CREDENTIAL_CHANGE =
	"https://schemas.openid.net/secevent/caep/event-type/credential-change";
export const CAEP_TOKEN_CLAIMS_CHANGE =
	"https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
export const CAEP_ASSURANCE_LEVEL_CHANGE =
	"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
export const CAEP_DEVICE_COMPLIANCE_CHANGE =
	"https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

export const RISC_ACCOUNT_DISABLED =
	"https://schemas.openid.net/secevent/risc/event-type/account-disabled";
export const RISC_ACCOUNT_ENABLED =
	"https://schemas.openid.net/secevent/risc/event-type/account-enabled";
export const RISC_CREDENTIAL_COMPROMISE =
	"https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
export const RISC_SESSIONS_REVOKED =
	"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";

/** Event types a transmitter can emit by default (the verification event is always allowed). */
export const SUPPORTED_EVENT_TYPES = [
	CAEP_SESSION_REVOKED,
	CAEP_CREDENTIAL_CHANGE,
	CAEP_TOKEN_CLAIMS_CHANGE,
	CAEP_ASSURANCE_LEVEL_CHANGE,
	CAEP_DEVICE_COMPLIANCE_CHANGE,
	RISC_ACCOUNT_DISABLED,
	RISC_ACCOUNT_ENABLED,
	RISC_CREDENTIAL_COMPROMISE,
	RISC_SESSIONS_REVOKED,
] as const;

export const DELIVERY_PUSH = "urn:ietf:rfc:8935";
export const DELIVERY_POLL = "urn:ietf:rfc:8936";
export type DeliveryMethod = typeof DELIVERY_PUSH | typeof DELIVERY_POLL;

export const SET_MEDIA_TYPE = "application/secevent+jwt";
export const SET_JWT_TYP = "secevent+jwt";

// Subjects (RFC 9493 subject identifiers)

export interface IssSubSubject {
	format: "iss_sub";
	iss: string;
	sub: string;
}
export interface EmailSubject {
	format: "email";
	email: string;
}
export interface OpaqueSubject {
	format: "opaque";
	id: string;
}

export type SimpleSubject = IssSubSubject | EmailSubject | OpaqueSubject;

export const COMPLEX_MEMBERS = [
	"user",
	"device",
	"session",
	"application",
	"tenant",
	"org_unit",
	"group",
] as const;
export type ComplexMember = (typeof COMPLEX_MEMBERS)[number];

export interface ComplexSubject {
	format: "complex";
	user?: SimpleSubject;
	device?: SimpleSubject;
	session?: SimpleSubject;
	application?: SimpleSubject;
	tenant?: SimpleSubject;
	org_unit?: SimpleSubject;
	group?: SimpleSubject;
}

export type SubjectIdentifier = SimpleSubject | ComplexSubject;

// Events

/** Event payload: claims inside `events[<uri>]`. `subject` and `event_timestamp` are filled by the emitter. */
export type EventPayload = Record<string, unknown>;

// Security Event Token

export interface SecurityEventToken {
	iss: string;
	iat: number;
	jti: string;
	aud: string | string[];
	/** Event URI to payload. */
	events: Record<string, EventPayload>;
	/** Optional subject (`sub_id`) at the token level. */
	sub_id?: SubjectIdentifier;
	txn?: string;
	toe?: number;
}

// Streams

export type StreamStatus = "enabled" | "paused" | "disabled";

export interface StreamDelivery {
	method: DeliveryMethod;
	/** Push: receiver endpoint. Poll: the transmitter's poll endpoint (assigned). */
	endpoint_url?: string;
	/** Push only: sent as the Authorization header. Write only, never returned. */
	authorization_header?: string;
}

export interface StreamConfiguration {
	stream_id: string;
	iss: string;
	aud: string[];
	events_supported: string[];
	events_requested: string[];
	events_delivered: string[];
	delivery: StreamDelivery;
	min_verification_interval?: number;
	description?: string;
}

export interface StoredStream {
	id: string;
	owner: string;
	aud: string[];
	eventsRequested: string[];
	eventsDelivered: string[];
	deliveryMethod: DeliveryMethod;
	endpointUrl: string | null;
	authorizationHeader: string | null;
	status: StreamStatus;
	statusReason: string | null;
	subjectMode: "all" | "none";
	description: string | null;
	minVerificationInterval: number | null;
	lastVerifiedAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
}

export type OutboxStatus = "pending" | "delivered" | "acked" | "failed";

export interface OutboxRow {
	jti: string;
	streamId: string;
	jwt: string;
	status: OutboxStatus;
	attempts: number;
	nextAttemptAt: Date;
	lastError: string | null;
	createdAt: Date;
}

export type Result<T> = { ok: true; value: T } | { ok: false; code: string; message: string };
