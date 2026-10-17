/** Builders for the CAEP and RISC events this module emits. Each returns the event type URI and payload; the transmitter adds `subject` and `event_timestamp`. */

import type { EventPayload } from "./types.js";
import {
	CAEP_ASSURANCE_LEVEL_CHANGE,
	CAEP_CREDENTIAL_CHANGE,
	CAEP_DEVICE_COMPLIANCE_CHANGE,
	CAEP_SESSION_REVOKED,
	CAEP_TOKEN_CLAIMS_CHANGE,
	RISC_ACCOUNT_DISABLED,
	RISC_ACCOUNT_ENABLED,
	RISC_CREDENTIAL_COMPROMISE,
	RISC_SESSIONS_REVOKED,
} from "./types.js";

export interface BuiltEvent {
	type: string;
	payload: EventPayload;
}

function compact(input: Record<string, unknown>): EventPayload {
	return Object.fromEntries(Object.entries(input).filter(([, v]) => v !== undefined));
}

export const events = {
	sessionRevoked(
		opts: { initiatingEntity?: string; reasonAdmin?: string; reasonUser?: string } = {},
	) {
		return {
			type: CAEP_SESSION_REVOKED,
			payload: compact({
				initiating_entity: opts.initiatingEntity,
				reason_admin: opts.reasonAdmin ? { en: opts.reasonAdmin } : undefined,
				reason_user: opts.reasonUser ? { en: opts.reasonUser } : undefined,
			}),
		} satisfies BuiltEvent;
	},

	credentialChange(opts: {
		credentialType:
			| "password"
			| "pin"
			| "x509"
			| "fido2-platform"
			| "fido2-roaming"
			| "fido-u2f"
			| "verifiable-credential"
			| "phone-voice"
			| "phone-sms"
			| "app";
		changeType: "create" | "revoke" | "update" | "delete";
		friendlyName?: string;
		x509Issuer?: string;
		x509Serial?: string;
		fido2Aaguid?: string;
		initiatingEntity?: string;
		reasonAdmin?: string;
	}) {
		return {
			type: CAEP_CREDENTIAL_CHANGE,
			payload: compact({
				credential_type: opts.credentialType,
				change_type: opts.changeType,
				friendly_name: opts.friendlyName,
				x509_issuer: opts.x509Issuer,
				x509_serial: opts.x509Serial,
				fido2_aaguid: opts.fido2Aaguid,
				initiating_entity: opts.initiatingEntity,
				reason_admin: opts.reasonAdmin ? { en: opts.reasonAdmin } : undefined,
			}),
		} satisfies BuiltEvent;
	},

	tokenClaimsChange(opts: { claims: Record<string, unknown>; initiatingEntity?: string }) {
		return {
			type: CAEP_TOKEN_CLAIMS_CHANGE,
			payload: compact({ claims: opts.claims, initiating_entity: opts.initiatingEntity }),
		} satisfies BuiltEvent;
	},

	assuranceLevelChange(opts: {
		namespace: string;
		currentLevel: string;
		previousLevel?: string;
		changeDirection?: "increase" | "decrease";
		initiatingEntity?: string;
	}) {
		return {
			type: CAEP_ASSURANCE_LEVEL_CHANGE,
			payload: compact({
				current_level: opts.currentLevel,
				previous_level: opts.previousLevel,
				change_direction: opts.changeDirection,
				namespace: opts.namespace,
				initiating_entity: opts.initiatingEntity,
			}),
		} satisfies BuiltEvent;
	},

	deviceComplianceChange(opts: {
		previousStatus: "compliant" | "not-compliant";
		currentStatus: "compliant" | "not-compliant";
		initiatingEntity?: string;
	}) {
		return {
			type: CAEP_DEVICE_COMPLIANCE_CHANGE,
			payload: compact({
				previous_status: opts.previousStatus,
				current_status: opts.currentStatus,
				initiating_entity: opts.initiatingEntity,
			}),
		} satisfies BuiltEvent;
	},

	accountDisabled(opts: { reason?: "hijacking" | "bulk-account" } = {}) {
		return {
			type: RISC_ACCOUNT_DISABLED,
			payload: compact({ reason: opts.reason }),
		} satisfies BuiltEvent;
	},

	accountEnabled() {
		return { type: RISC_ACCOUNT_ENABLED, payload: {} } satisfies BuiltEvent;
	},

	credentialCompromise(opts: { credentialType: string; reasonAdmin?: string }) {
		return {
			type: RISC_CREDENTIAL_COMPROMISE,
			payload: compact({
				credential_type: opts.credentialType,
				reason_admin: opts.reasonAdmin ? { en: opts.reasonAdmin } : undefined,
			}),
		} satisfies BuiltEvent;
	},

	sessionsRevoked() {
		return { type: RISC_SESSIONS_REVOKED, payload: {} } satisfies BuiltEvent;
	},
};
