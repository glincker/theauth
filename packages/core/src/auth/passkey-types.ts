/** Shared passkey types, error codes and the context passed to the passkey sub-factories. */

import type { Database } from "../db/database.js";

export const PASSKEY_ERROR = {
	CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
	CHALLENGE_EXPIRED: "CHALLENGE_EXPIRED",
	CHALLENGE_REPLAY: "CHALLENGE_REPLAY",
	ORIGIN_MISMATCH: "ORIGIN_MISMATCH",
	RPID_MISMATCH: "RPID_MISMATCH",
	CLIENT_DATA_TYPE_MISMATCH: "CLIENT_DATA_TYPE_MISMATCH",
	USER_NOT_PRESENT: "USER_NOT_PRESENT",
	USER_NOT_VERIFIED: "USER_NOT_VERIFIED",
	CREDENTIAL_NOT_FOUND: "CREDENTIAL_NOT_FOUND",
	CREDENTIAL_ALREADY_EXISTS: "CREDENTIAL_ALREADY_EXISTS",
	SIGNATURE_INVALID: "SIGNATURE_INVALID",
	SIGN_COUNT_ROLLBACK: "SIGN_COUNT_ROLLBACK",
	MISSING_ATTESTATION_DATA: "MISSING_ATTESTATION_DATA",
	INVALID_ATTESTATION: "INVALID_ATTESTATION",
	UNSUPPORTED_ALGORITHM: "UNSUPPORTED_ALGORITHM",
	INVALID_COSE_KEY: "INVALID_COSE_KEY",
	INVALID_CLIENT_DATA: "INVALID_CLIENT_DATA",
} as const;

export class PasskeyError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "PasskeyError";
		this.code = code;
	}
}

export interface PasskeyConfig {
	rpName: string;
	rpId: string;
	/** Expected origin (e.g., "https://example.com") */
	origin: string | string[];
	/** Attestation preference (default: "none") */
	attestation?: "none" | "indirect" | "direct";
	/** User verification requirement (default: "preferred") */
	userVerification?: "required" | "preferred" | "discouraged";
	/** Challenge timeout in ms (default: 60000, max: 300000) */
	challengeTimeout?: number;
	/** Called after a passkey is added or removed (emits a Shared Signals credential-change event). Errors are swallowed. */
	onCredentialChange?: (userId: string, change: "added" | "removed") => void | Promise<void>;
}

export interface PasskeyCredential {
	id: string;
	credentialId: string;
	publicKey: string;
	counter: number;
	userId: string;
	deviceName?: string;
	transports?: string[];
	createdAt: Date;
	lastUsedAt: Date;
}

export interface PasskeyModule {
	getRegistrationOptions: (
		userId: string,
		userName: string,
	) => Promise<{
		challenge: string;
		rp: { name: string; id: string };
		user: { id: string; name: string; displayName: string };
		pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
		timeout: number;
		attestation: string;
		authenticatorSelection: {
			userVerification: string;
			residentKey: string;
			requireResidentKey: boolean;
		};
		excludeCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }>;
	}>;

	verifyRegistration: (
		userId: string,
		response: {
			id: string;
			rawId: string;
			type: "public-key";
			response: {
				clientDataJSON: string;
				attestationObject: string;
			};
			deviceName?: string;
			transports?: string[];
		},
	) => Promise<{ credential: PasskeyCredential }>;

	getAuthenticationOptions: (userId?: string) => Promise<{
		challenge: string;
		rpId: string;
		timeout: number;
		userVerification: string;
		allowCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }>;
	}>;

	verifyAuthentication: (response: {
		id: string;
		rawId: string;
		type: "public-key";
		response: {
			clientDataJSON: string;
			authenticatorData: string;
			signature: string;
		};
	}) => Promise<{ userId: string; credential: PasskeyCredential; userVerified: boolean }>;

	listCredentials: (userId: string) => Promise<PasskeyCredential[]>;
	removeCredential: (credentialId: string, userId: string) => Promise<void>;
	handleRequest: (request: Request) => Promise<Response | null>;
}

/** Dependencies shared by the passkey registration and authentication factories. */
export interface PasskeyContext {
	config: PasskeyConfig;
	db: Database;
	timeout: number;
	userVerification: NonNullable<PasskeyConfig["userVerification"]>;
	attestation: NonNullable<PasskeyConfig["attestation"]>;
	notifyCredentialChange: (userId: string, change: "added" | "removed") => Promise<void>;
}
