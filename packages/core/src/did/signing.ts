import { importJWK, jwtVerify, SignJWT } from "jose";
import type { SignedPayload, VerificationResult } from "./types.js";

/** Sign a payload as a compact JWS using the agent's DID private key. */
export async function signPayload(
	payload: Record<string, unknown>,
	privateKeyJwk: JsonWebKey,
	did: string,
): Promise<SignedPayload> {
	const privateKey = await importJWK(privateKeyJwk, "EdDSA");

	// The kid is the fragment identifier within the DID document
	const kid = `${did}#${did.split(":").pop() ?? "key-1"}`;

	const jws = await new SignJWT(payload)
		.setProtectedHeader({ alg: "EdDSA", kid })
		.setIssuer(did)
		.setIssuedAt()
		.sign(privateKey);

	return {
		jws,
		payload,
		issuer: did,
	};
}

/** Verify a signed payload using a known public key JWK. */
export async function verifyPayload(
	jws: string,
	publicKeyJwk: JsonWebKey,
): Promise<VerificationResult> {
	try {
		const publicKey = await importJWK(publicKeyJwk, "EdDSA");
		const { payload } = await jwtVerify(jws, publicKey);

		const issuer = typeof payload.iss === "string" ? payload.iss : undefined;

		// Omit standard JWT claims from the returned payload object
		const { iss, iat, exp, nbf, jti, aud, sub, ...rest } = payload;
		void iss;
		void iat;
		void exp;
		void nbf;
		void jti;
		void aud;
		void sub;

		return {
			valid: true,
			payload: rest as Record<string, unknown>,
			issuer,
		};
	} catch (err) {
		return {
			valid: false,
			error: err instanceof Error ? err.message : "Verification failed",
		};
	}
}

/**
 * Create a verifiable presentation JWT.
 * It is audience-bound and short-lived by default.
 */
export async function createPresentation(options: {
	agentId: string;
	did: string;
	privateKeyJwk: JsonWebKey;
	capabilities: string[];
	audience?: string;
	expiresIn?: number; // seconds, default 300
}): Promise<string> {
	const { agentId, did, privateKeyJwk, capabilities, audience, expiresIn = 300 } = options;

	const privateKey = await importJWK(privateKeyJwk, "EdDSA");
	const kid = `${did}#${did.split(":").pop() ?? "key-1"}`;

	const builder = new SignJWT({
		agentId,
		capabilities,
		type: "VerifiablePresentation",
	})
		.setProtectedHeader({ alg: "EdDSA", kid })
		.setIssuer(did)
		.setSubject(agentId)
		.setIssuedAt()
		.setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn);

	if (audience) {
		builder.setAudience(audience);
	}

	return builder.sign(privateKey);
}

/** Verify a presentation JWT and extract the claims. */
export async function verifyPresentation(
	jwt: string,
	publicKeyJwk: JsonWebKey,
): Promise<{
	valid: boolean;
	agentId?: string;
	did?: string;
	capabilities?: string[];
	error?: string;
}> {
	try {
		const publicKey = await importJWK(publicKeyJwk, "EdDSA");
		const { payload } = await jwtVerify(jwt, publicKey);

		const agentId = typeof payload.agentId === "string" ? payload.agentId : undefined;
		const did = typeof payload.iss === "string" ? payload.iss : undefined;
		const capabilities = Array.isArray(payload.capabilities)
			? (payload.capabilities as string[])
			: undefined;

		return {
			valid: true,
			agentId,
			did,
			capabilities,
		};
	} catch (err) {
		return {
			valid: false,
			error: err instanceof Error ? err.message : "Presentation verification failed",
		};
	}
}
