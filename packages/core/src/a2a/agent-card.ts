/**
 * A2A Agent Card management.
 *
 * Creates, validates, signs, and verifies Agent Cards that describe
 * an agent's identity, capabilities, skills, and auth requirements
 * using the A2A protocol format.
 */

import * as jose from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { AgentIdentity } from "../types.js";
import type {
	A2AAgentCapabilities,
	A2AAgentCard,
	A2AAgentProvider,
	A2AAgentSkill,
	A2ASecurityScheme,
	Result,
} from "./types.js";
import { A2A_PROTOCOL_VERSION, A2AAgentCardSchema } from "./types.js";

// ─── Create Agent Card ───────────────────────────────────────────────────────

export interface CreateAgentCardInput {
	/** The TheAuth agent identity to build the card from */
	agent: Pick<AgentIdentity, "id" | "name" | "type">;
	/** The URL where this agent's A2A endpoint is hosted */
	url: string;
	/** Human-readable description of what the agent does */
	description: string;
	/** Semantic version of this agent */
	version: string;
	/** Skills this agent can perform */
	skills: A2AAgentSkill[];
	/** Optional provider information */
	provider?: A2AAgentProvider;
	/** Optional capabilities declaration */
	capabilities?: A2AAgentCapabilities;
	/** Security schemes required to call this agent */
	securitySchemes?: Record<string, A2ASecurityScheme>;
	/** Security requirements (references to securitySchemes keys) */
	security?: Array<Record<string, string[]>>;
	/** Default accepted input MIME types */
	defaultInputModes?: string[];
	/** Default output MIME types */
	defaultOutputModes?: string[];
	/** Link to agent documentation */
	documentationUrl?: string;
	/** Arbitrary metadata */
	metadata?: Record<string, unknown>;
}

/**
 * Create an A2A-compliant Agent Card from a TheAuth agent identity.
 *
 * Maps TheAuth agent fields to the A2A Agent Card format and sets
 * the protocol version automatically.
 */
export function createAgentCard(input: CreateAgentCardInput): A2AAgentCard {
	const card: A2AAgentCard = {
		id: input.agent.id,
		name: input.agent.name,
		description: input.description,
		version: input.version,
		protocolVersion: A2A_PROTOCOL_VERSION,
		url: input.url,
		skills: input.skills,
	};

	if (input.provider) card.provider = input.provider;
	if (input.capabilities) card.capabilities = input.capabilities;
	if (input.securitySchemes) card.securitySchemes = input.securitySchemes;
	if (input.security) card.security = input.security;
	if (input.defaultInputModes) card.defaultInputModes = input.defaultInputModes;
	if (input.defaultOutputModes) card.defaultOutputModes = input.defaultOutputModes;
	if (input.documentationUrl) card.documentationUrl = input.documentationUrl;
	if (input.metadata) card.metadata = input.metadata;

	return card;
}

// ─── Validate Agent Card ─────────────────────────────────────────────────────

/**
 * Validate an incoming Agent Card against the A2A schema.
 *
 * Returns the parsed card on success or a structured error on failure.
 */
export function validateAgentCard(card: unknown): Result<A2AAgentCard> {
	const parsed = A2AAgentCardSchema.safeParse(card);
	if (!parsed.success) {
		const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
		return {
			success: false,
			error: {
				code: "A2A_INVALID_AGENT_CARD",
				message: `Invalid Agent Card: ${issues.join("; ")}`,
				details: { issues },
			},
		};
	}
	return { success: true, data: parsed.data as A2AAgentCard };
}

// ─── Sign Agent Card ─────────────────────────────────────────────────────────

export interface SignAgentCardOptions {
	/** The Agent Card to sign */
	card: A2AAgentCard;
	/** JWK private key used to create the signature */
	privateKey: CryptoKey | jose.JWK;
	/** Signing algorithm. Default: "ES256". */
	algorithm?: string;
	/** Key ID to include in the signature. Auto-generated if not provided. */
	keyId?: string;
}

/**
 * Sign an Agent Card with a private key.
 *
 * Creates a JWS compact signature over the card's canonical JSON
 * (excluding the signature field itself). The signature, algorithm,
 * and key ID are attached to the card's `signature` field.
 */
export async function signAgentCard(options: SignAgentCardOptions): Promise<Result<A2AAgentCard>> {
	const { card, privateKey, algorithm = "ES256", keyId } = options;

	try {
		// Strip existing signature before signing
		const { signature: _ignored, ...cardWithoutSignature } = card;

		const payload = new TextEncoder().encode(JSON.stringify(cardWithoutSignature));

		const key =
			"kty" in (privateKey as jose.JWK)
				? await jose.importJWK(privateKey as jose.JWK, algorithm)
				: privateKey;

		const kid = keyId ?? generateId();

		const jws = await new jose.CompactSign(payload)
			.setProtectedHeader({ alg: algorithm, kid })
			.sign(key as CryptoKey);

		const signedCard: A2AAgentCard = {
			...card,
			signature: {
				algorithm,
				signature: jws,
				keyId: kid,
			},
		};

		return { success: true, data: signedCard };
	} catch (err) {
		return {
			success: false,
			error: {
				code: "A2A_SIGN_FAILED",
				message: err instanceof Error ? err.message : "Failed to sign agent card",
			},
		};
	}
}

// ─── Verify Agent Card ───────────────────────────────────────────────────────

export interface VerifyAgentCardOptions {
	/** The signed Agent Card to verify */
	card: A2AAgentCard;
	/** JWK public key used to verify the signature */
	publicKey: CryptoKey | jose.JWK;
}

/**
 * Verify a signed Agent Card's signature.
 *
 * Checks that the JWS signature in `card.signature` is valid
 * against the provided public key and that the payload matches
 * the card content (minus the signature field).
 */
export async function verifyAgentCard(
	options: VerifyAgentCardOptions,
): Promise<Result<{ valid: boolean; card: A2AAgentCard }>> {
	const { card, publicKey } = options;

	if (!card.signature) {
		return {
			success: false,
			error: {
				code: "A2A_NO_SIGNATURE",
				message: "Agent Card has no signature to verify",
			},
		};
	}

	try {
		const { signature, ...cardWithoutSignature } = card;
		const algorithm = signature.algorithm;

		const key =
			"kty" in (publicKey as jose.JWK)
				? await jose.importJWK(publicKey as jose.JWK, algorithm)
				: publicKey;

		const { payload } = await jose.compactVerify(signature.signature, key as CryptoKey);

		const decoded = new TextDecoder().decode(payload);
		const signedContent = JSON.parse(decoded) as Record<string, unknown>;
		const currentContent = JSON.stringify(cardWithoutSignature);
		const parsedCurrentContent = JSON.parse(currentContent) as Record<string, unknown>;

		// Compare the signed payload against the current card content
		const matches = JSON.stringify(signedContent) === JSON.stringify(parsedCurrentContent);

		return {
			success: true,
			data: { valid: matches, card },
		};
	} catch (err) {
		return {
			success: false,
			error: {
				code: "A2A_VERIFY_FAILED",
				message: err instanceof Error ? err.message : "Failed to verify agent card signature",
			},
		};
	}
}
