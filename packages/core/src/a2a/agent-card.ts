/** A2A Agent Card creation, validation, signing and verification. */

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

export interface CreateAgentCardInput {
	agent: Pick<AgentIdentity, "id" | "name" | "type">;
	url: string;
	description: string;
	version: string;
	skills: A2AAgentSkill[];
	provider?: A2AAgentProvider;
	capabilities?: A2AAgentCapabilities;
	/** Security schemes required to call this agent */
	securitySchemes?: Record<string, A2ASecurityScheme>;
	/** Security requirements (references to securitySchemes keys) */
	security?: Array<Record<string, string[]>>;
	defaultInputModes?: string[];
	defaultOutputModes?: string[];
	documentationUrl?: string;
	metadata?: Record<string, unknown>;
}

/** Create an A2A-compliant Agent Card from a TheAuth agent identity. */
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

/** Validate an incoming Agent Card against the A2A schema. */
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

export interface SignAgentCardOptions {
	card: A2AAgentCard;
	privateKey: CryptoKey | jose.JWK;
	/** Signing algorithm. Default: "ES256". */
	algorithm?: string;
	/** Key ID to include in the signature. Auto-generated if not provided. */
	keyId?: string;
}

/** Sign an Agent Card. The JWS covers the card JSON without its `signature` field. */
export async function signAgentCard(options: SignAgentCardOptions): Promise<Result<A2AAgentCard>> {
	const { card, privateKey, algorithm = "ES256", keyId } = options;

	try {
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

export interface VerifyAgentCardOptions {
	card: A2AAgentCard;
	publicKey: CryptoKey | jose.JWK;
}

/** Verify the JWS signature on a signed Agent Card and that its payload matches the card. */
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
