/** Passkey authentication (assertion) options and verification. */

import { and, eq, lt } from "drizzle-orm";
import { fromBase64Url, randomBytes, toBase64Url, toHex } from "../crypto/web-crypto.js";
import { passkeyChallenges, passkeyCredentials } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import { bytesEqual, sha256, verifyCoseSignature } from "./passkey-crypto.js";
import { FLAG_UP, FLAG_UV, isOriginAllowed, parseAuthData } from "./passkey-helpers.js";
import type { PasskeyContext, PasskeyCredential, PasskeyModule } from "./passkey-types.js";
import { PASSKEY_ERROR, PasskeyError } from "./passkey-types.js";

export function createPasskeyAuthentication(ctx: PasskeyContext) {
	const { config, db, timeout, userVerification } = ctx;

	async function getAuthenticationOptions(
		userId?: string,
	): ReturnType<PasskeyModule["getAuthenticationOptions"]> {
		await db.delete(passkeyChallenges).where(lt(passkeyChallenges.expiresAt, new Date()));

		const challengeBytes = randomBytes(32);
		const challenge = toBase64Url(challengeBytes);
		const id = toHex(randomBytes(16));
		const now = new Date();
		const expiresAt = new Date(now.getTime() + timeout);

		await db.insert(passkeyChallenges).values({
			id,
			challenge,
			userId: userId ?? null,
			type: "authentication",
			expiresAt,
			createdAt: now,
		});

		let allowCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }> = [];

		if (userId) {
			const creds = await db
				.select()
				.from(passkeyCredentials)
				.where(eq(passkeyCredentials.userId, userId));

			allowCredentials = creds.map((c) => ({
				id: c.credentialId,
				type: "public-key" as const,
				transports: c.transports ? (JSON.parse(c.transports as string) as string[]) : undefined,
			}));
		}

		return {
			challenge,
			rpId: config.rpId,
			timeout,
			userVerification,
			allowCredentials,
		};
	}

	async function verifyAuthentication(
		response: Parameters<PasskeyModule["verifyAuthentication"]>[0],
	): ReturnType<PasskeyModule["verifyAuthentication"]> {
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

		// 1a. Reject cross-origin iframes
		if (clientData.crossOrigin === true) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				"Cross-origin WebAuthn requests are not allowed",
			);
		}

		if (clientData.type !== "webauthn.get") {
			throw new PasskeyError(
				PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH,
				`Expected type "webauthn.get", got "${clientData.type}"`,
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
					eq(passkeyChallenges.type, "authentication"),
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
		// The delete is the claim: of two concurrent requests with one challenge only one removes the row.
		if (!(await singleUseFor(db).passkeyChallenges.consume(challengeRow.id))) {
			throw new PasskeyError(
				PASSKEY_ERROR.CHALLENGE_NOT_FOUND,
				"Challenge not found or already used",
			);
		}

		if (challengeRow.expiresAt < new Date()) {
			throw new PasskeyError(PASSKEY_ERROR.CHALLENGE_EXPIRED, "Challenge expired");
		}

		const credentialId = response.id;
		const credRows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.credentialId, credentialId));

		const credRow = credRows[0];
		if (!credRow) {
			throw new PasskeyError(PASSKEY_ERROR.CREDENTIAL_NOT_FOUND, "Credential not found");
		}

		const authDataBytes = fromBase64Url(response.response.authenticatorData);
		const authData = parseAuthData(authDataBytes);

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

		// 7. Verify signature
		// Data to verify: authData || SHA-256(clientDataJSON)
		const clientDataHash = await sha256(clientDataBytes);
		const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
		signedData.set(authDataBytes, 0);
		signedData.set(clientDataHash, authDataBytes.length);

		const signature = fromBase64Url(response.response.signature);
		const publicKeyBytes = fromBase64Url(credRow.publicKey);

		let valid: boolean;
		try {
			valid = await verifyCoseSignature(publicKeyBytes, signedData, signature);
		} catch (err) {
			if (err instanceof PasskeyError) throw err;
			throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Signature verification failed");
		}

		if (!valid) {
			throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Signature verification failed");
		}

		// 8. Check counter (clone detection)
		// If both the stored counter and the new counter are 0, the authenticator
		// does not support counters and we skip the check.
		if (credRow.counter > 0 && authData.signCount <= credRow.counter) {
			throw new PasskeyError(
				PASSKEY_ERROR.SIGN_COUNT_ROLLBACK,
				`Sign count rollback detected: stored=${credRow.counter}, received=${authData.signCount}`,
			);
		}

		const now = new Date();
		await db
			.update(passkeyCredentials)
			.set({ counter: authData.signCount, lastUsedAt: now })
			.where(eq(passkeyCredentials.id, credRow.id));

		const credential: PasskeyCredential = {
			id: credRow.id,
			credentialId: credRow.credentialId,
			publicKey: credRow.publicKey,
			counter: authData.signCount,
			userId: credRow.userId,
			deviceName: credRow.deviceName ?? undefined,
			transports: credRow.transports
				? (JSON.parse(credRow.transports as string) as string[])
				: undefined,
			createdAt: credRow.createdAt,
			lastUsedAt: now,
		};

		return { userId: credRow.userId, credential, userVerified: (authData.flags & FLAG_UV) !== 0 };
	}

	return { getAuthenticationOptions, verifyAuthentication };
}
