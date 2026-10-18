/** Passkey authenticator data parsing and HTTP helpers. */

import { PASSKEY_ERROR, PasskeyError } from "./passkey-types.js";

export interface ParsedAuthData {
	rpIdHash: Uint8Array;
	flags: number;
	signCount: number;
	attestedCredentialData?: {
		aaguid: Uint8Array;
		credentialId: Uint8Array;
		credentialPublicKey: Uint8Array;
		credentialPublicKeyOffset: number;
	};
}

export const FLAG_UP = 0x01; // user present
export const FLAG_UV = 0x04; // user verified
const FLAG_AT = 0x40; // attested credential data included

export function parseAuthData(authData: Uint8Array): ParsedAuthData {
	if (authData.length < 37) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_ATTESTATION, "authData too short");
	}

	const rpIdHash = authData.slice(0, 32);
	const flags = authData[32] ?? 0;
	const signCount =
		(((authData[33] ?? 0) << 24) |
			((authData[34] ?? 0) << 16) |
			((authData[35] ?? 0) << 8) |
			(authData[36] ?? 0)) >>>
		0;

	let attestedCredentialData: ParsedAuthData["attestedCredentialData"];

	if (flags & FLAG_AT) {
		if (authData.length < 55) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"authData too short for attested credential data",
			);
		}

		const aaguid = authData.slice(37, 53);
		const credentialIdLength = ((authData[53] ?? 0) << 8) | (authData[54] ?? 0);

		if (authData.length < 55 + credentialIdLength) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"authData too short for credential ID",
			);
		}

		const credentialId = authData.slice(55, 55 + credentialIdLength);
		const credentialPublicKeyOffset = 55 + credentialIdLength;
		const credentialPublicKey = authData.slice(credentialPublicKeyOffset);

		attestedCredentialData = {
			aaguid,
			credentialId,
			credentialPublicKey,
			credentialPublicKeyOffset,
		};
	}

	return { rpIdHash, flags, signCount, attestedCredentialData };
}

export function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

export async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

export function getPathSegments(url: URL): string[] {
	return url.pathname.split("/").filter(Boolean);
}

export function isOriginAllowed(origin: string, allowed: string | string[]): boolean {
	const origins = Array.isArray(allowed) ? allowed : [allowed];
	return origins.includes(origin);
}
