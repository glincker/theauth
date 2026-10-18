/** Passkey registration (attestation) options and verification. */

import { and, eq, lt } from "drizzle-orm";
import { fromBase64Url, randomBytes, toBase64Url, toHex } from "../crypto/web-crypto.js";
import { passkeyChallenges, passkeyCredentials } from "../db/schema.js";
import { decodeCbor } from "./cbor.js";
import { bytesEqual, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_RS256 } from "./passkey-crypto.js";
import { FLAG_UP, FLAG_UV, isOriginAllowed, parseAuthData } from "./passkey-helpers.js";
import type { PasskeyContext, PasskeyCredential, PasskeyModule } from "./passkey-types.js";
import { PASSKEY_ERROR, PasskeyError } from "./passkey-types.js";

export function createPasskeyRegistration(ctx: PasskeyContext) {
	const { config, db, timeout, attestation, userVerification, notifyCredentialChange } = ctx;

	async function getRegistrationOptions(
		userId: string,
		userName: string,
	): ReturnType<PasskeyModule["getRegistrationOptions"]> {
		await db.delete(passkeyChallenges).where(lt(passkeyChallenges.expiresAt, new Date()));

		const challengeBytes = randomBytes(32);
		const challenge = toBase64Url(challengeBytes);
		const id = toHex(randomBytes(16));
		const now = new Date();
		const expiresAt = new Date(now.getTime() + timeout);

		await db.insert(passkeyChallenges).values({
			id,
			challenge,
			userId,
			type: "registration",
			expiresAt,
			createdAt: now,
		});

		const existing = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));

		const excludeCredentials = existing.map((c) => ({
			id: c.credentialId,
			type: "public-key" as const,
			transports: c.transports ? (JSON.parse(c.transports as string) as string[]) : undefined,
		}));

		return {
			challenge,
			rp: { name: config.rpName, id: config.rpId },
			user: { id: userId, name: userName, displayName: userName },
			pubKeyCredParams: [
				{ type: "public-key", alg: COSE_ALG_ES256 },
				{ type: "public-key", alg: COSE_ALG_RS256 },
				{ type: "public-key", alg: COSE_ALG_EDDSA },
			],
			timeout,
			attestation,
			authenticatorSelection: {
				userVerification,
				residentKey: "preferred",
				requireResidentKey: false,
			},
			excludeCredentials,
		};
	}

	async function verifyRegistration(
		userId: string,
		response: Parameters<PasskeyModule["verifyRegistration"]>[1],
	): ReturnType<PasskeyModule["verifyRegistration"]> {
		const clientDataBytes = fromBase64Url(response.response.clientDataJSON);
		let clientData: { type: string; challenge: string; origin: string; crossOrigin?: boolean };
		try {
			clientData = JSON.parse(new TextDecoder().decode(clientDataBytes)) as {
				type: string;
				challenge: string;
				origin: string;
				crossOrigin?: boolean;
			};
		} catch {
			throw new PasskeyError(PASSKEY_ERROR.INVALID_CLIENT_DATA, "Failed to parse clientDataJSON");
		}

		// 1a. Reject cross-origin iframes explicitly
		if (clientData.crossOrigin === true) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				"Cross-origin WebAuthn requests are not allowed",
			);
		}

		if (clientData.type !== "webauthn.create") {
			throw new PasskeyError(
				PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH,
				`Expected type "webauthn.create", got "${clientData.type}"`,
			);
		}
		if (!isOriginAllowed(clientData.origin, config.origin)) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				`Origin mismatch: got "${clientData.origin}"`,
			);
		}

		const challengeRows = await db
			.select()
			.from(passkeyChallenges)
			.where(
				and(
					eq(passkeyChallenges.challenge, clientData.challenge),
					eq(passkeyChallenges.userId, userId),
					eq(passkeyChallenges.type, "registration"),
				),
			);

		const challengeRow = challengeRows[0];
		if (!challengeRow) {
			throw new PasskeyError(
				PASSKEY_ERROR.CHALLENGE_NOT_FOUND,
				"Challenge not found or already used",
			);
		}

		// Delete the challenge FIRST (one-time use, prevent replay even if later steps fail)
		await db.delete(passkeyChallenges).where(eq(passkeyChallenges.id, challengeRow.id));

		if (challengeRow.expiresAt < new Date()) {
			throw new PasskeyError(PASSKEY_ERROR.CHALLENGE_EXPIRED, "Challenge expired");
		}

		const attestationBytes = fromBase64Url(response.response.attestationObject);
		const attestationObj = decodeCbor(attestationBytes);
		if (!(attestationObj instanceof Map)) {
			throw new PasskeyError(PASSKEY_ERROR.INVALID_ATTESTATION, "Invalid attestation object");
		}

		const authDataRaw = attestationObj.get("authData") as Uint8Array;
		if (!authDataRaw || !(authDataRaw instanceof Uint8Array)) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"Missing authData in attestation object",
			);
		}

		const authData = parseAuthData(authDataRaw);

		const expectedRpIdHash = new Uint8Array(
			await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.rpId)),
		);
		if (!bytesEqual(authData.rpIdHash, expectedRpIdHash)) {
			throw new PasskeyError(PASSKEY_ERROR.RPID_MISMATCH, "rpIdHash mismatch");
		}

		if (!(authData.flags & FLAG_UP)) {
			throw new PasskeyError(PASSKEY_ERROR.USER_NOT_PRESENT, "User present flag not set");
		}

		if (userVerification === "required" && !(authData.flags & FLAG_UV)) {
			throw new PasskeyError(
				PASSKEY_ERROR.USER_NOT_VERIFIED,
				"User verified flag not set but required",
			);
		}

		if (!authData.attestedCredentialData) {
			throw new PasskeyError(
				PASSKEY_ERROR.MISSING_ATTESTATION_DATA,
				"No attested credential data in authData",
			);
		}

		const { credentialId, credentialPublicKey } = authData.attestedCredentialData;
		const credentialIdB64 = toBase64Url(credentialId);
		const publicKeyB64 = toBase64Url(credentialPublicKey);

		const existing = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.credentialId, credentialIdB64));

		if (existing.length > 0) {
			throw new PasskeyError(
				PASSKEY_ERROR.CREDENTIAL_ALREADY_EXISTS,
				"Credential already registered",
			);
		}

		const now = new Date();
		const id = toHex(randomBytes(16));

		const transports = response.transports ? JSON.stringify(response.transports) : null;

		await db.insert(passkeyCredentials).values({
			id,
			userId,
			credentialId: credentialIdB64,
			publicKey: publicKeyB64,
			counter: authData.signCount,
			deviceName: response.deviceName ?? null,
			transports,
			createdAt: now,
			lastUsedAt: now,
		});

		const credential: PasskeyCredential = {
			id,
			credentialId: credentialIdB64,
			publicKey: publicKeyB64,
			counter: authData.signCount,
			userId,
			deviceName: response.deviceName,
			transports: response.transports,
			createdAt: now,
			lastUsedAt: now,
		};

		await notifyCredentialChange(userId, "added");
		return { credential };
	}

	return { getRegistrationOptions, verifyRegistration };
}
