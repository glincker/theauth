import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agentDids } from "../db/schema.js";
import { generateDidKey, resolveDidKey } from "./key-method.js";
import { createPresentation, signPayload, verifyPayload, verifyPresentation } from "./signing.js";
import type {
	AgentDid,
	DidDocument,
	DidWebConfig,
	SignedPayload,
	VerificationResult,
} from "./types.js";
import { generateDidWeb, resolveDidWeb } from "./web-method.js";

/**
 * Create the DID module.
 *
 * Provides W3C DID generation (did:key and did:web), storage of the public
 * key + DID document in the database, and signing / verification helpers.
 * Private keys are never stored — they are returned to the caller on
 * generation and must be stored securely elsewhere.
 */
export function createDidModule(db: Database, config?: { web?: DidWebConfig }) {
	/**
	 * Generate a did:key identity for an agent.
	 *
	 * Stores the public key and DID document in `theauth_agent_dids`.
	 * Returns the private key to the caller — it is not persisted.
	 */
	async function generateKey(
		agentId: string,
	): Promise<{ agentDid: AgentDid; privateKeyJwk: JsonWebKey }> {
		const keyPair = await generateDidKey();

		const now = new Date();

		await db.insert(agentDids).values({
			agentId,
			did: keyPair.did,
			method: "key",
			publicKeyJwk: JSON.stringify(keyPair.publicKeyJwk),
			didDocument: JSON.stringify(keyPair.didDocument),
			createdAt: now,
		});

		const agentDid: AgentDid = {
			agentId,
			did: keyPair.did,
			method: "key",
			publicKeyJwk: keyPair.publicKeyJwk,
			didDocument: keyPair.didDocument,
			createdAt: now,
		};

		return { agentDid, privateKeyJwk: keyPair.privateKeyJwk };
	}

	/**
	 * Generate a did:web identity for an agent.
	 *
	 * Requires `config.web` to be set with a domain.
	 * Stores the public key and DID document in `theauth_agent_dids`.
	 */
	async function generateWeb(
		agentId: string,
	): Promise<{ agentDid: AgentDid; privateKeyJwk: JsonWebKey }> {
		if (!config?.web) {
			throw new Error(
				"did:web requires a web config (domain). Pass { web: { domain: 'example.com' } } to createDidModule().",
			);
		}

		const keyPair = await generateDidWeb(config.web, agentId);
		const now = new Date();

		await db.insert(agentDids).values({
			agentId,
			did: keyPair.did,
			method: "web",
			publicKeyJwk: JSON.stringify(keyPair.publicKeyJwk),
			didDocument: JSON.stringify(keyPair.didDocument),
			createdAt: now,
		});

		const agentDid: AgentDid = {
			agentId,
			did: keyPair.did,
			method: "web",
			publicKeyJwk: keyPair.publicKeyJwk,
			didDocument: keyPair.didDocument,
			createdAt: now,
		};

		return { agentDid, privateKeyJwk: keyPair.privateKeyJwk };
	}

	/**
	 * Resolve any DID to its DID document.
	 *
	 * - did:key  → resolved locally from the identifier encoding
	 * - did:web  → fetched from the HTTPS well-known URL
	 */
	async function resolve(did: string): Promise<DidDocument | null> {
		if (did.startsWith("did:key:")) {
			return resolveDidKey(did);
		}
		if (did.startsWith("did:web:")) {
			return resolveDidWeb(did);
		}
		return null;
	}

	/**
	 * Get the stored DID record for an agent, or null if none exists.
	 */
	async function getAgentDid(agentId: string): Promise<AgentDid | null> {
		const rows = await db.select().from(agentDids).where(eq(agentDids.agentId, agentId));
		const row = rows[0];
		if (!row) return null;

		return {
			agentId: row.agentId,
			did: row.did,
			method: row.method as "key" | "web",
			publicKeyJwk: JSON.parse(row.publicKeyJwk) as JsonWebKey,
			didDocument: JSON.parse(row.didDocument) as DidDocument,
			createdAt: row.createdAt,
		};
	}

	/**
	 * Sign a payload using the private key provided by the caller.
	 *
	 * The agent's stored DID is used as the issuer (`iss` claim).
	 */
	async function sign(
		agentId: string,
		payload: Record<string, unknown>,
		privateKeyJwk: JsonWebKey,
	): Promise<SignedPayload> {
		const agentDid = await getAgentDid(agentId);
		if (!agentDid) {
			throw new Error(`No DID found for agent "${agentId}". Call generateKey() first.`);
		}
		return signPayload(payload, privateKeyJwk, agentDid.did);
	}

	/**
	 * Verify a JWS signature.
	 *
	 * When `did` is provided, the public key is looked up from the database.
	 * Otherwise the caller must provide a public key JWK directly — use the
	 * lower-level `verifyPayload()` from signing.ts in that case.
	 */
	async function verify(jws: string, did?: string): Promise<VerificationResult> {
		if (!did) {
			return {
				valid: false,
				error: "A DID is required to look up the public key for verification.",
			};
		}

		const rows = await db.select().from(agentDids).where(eq(agentDids.did, did));
		const row = rows[0];
		if (!row) {
			return {
				valid: false,
				error: `No stored public key found for DID "${did}"`,
			};
		}

		const publicKeyJwk = JSON.parse(row.publicKeyJwk) as JsonWebKey;
		return verifyPayload(jws, publicKeyJwk);
	}

	/**
	 * Create a verifiable presentation JWT for an agent.
	 */
	async function createPresentationForAgent(options: {
		agentId: string;
		privateKeyJwk: JsonWebKey;
		capabilities: string[];
		audience?: string;
		expiresIn?: number;
	}): Promise<string> {
		const agentDid = await getAgentDid(options.agentId);
		if (!agentDid) {
			throw new Error(`No DID found for agent "${options.agentId}". Call generateKey() first.`);
		}

		return createPresentation({
			agentId: options.agentId,
			did: agentDid.did,
			privateKeyJwk: options.privateKeyJwk,
			capabilities: options.capabilities,
			audience: options.audience,
			expiresIn: options.expiresIn,
		});
	}

	/**
	 * Verify a presentation JWT.
	 *
	 * Looks up the public key from the stored DID document in the database.
	 * The DID is extracted from the `iss` claim in the JWT header.
	 */
	async function verifyPresentationForAgent(
		jwt: string,
	): Promise<VerificationResult & { capabilities?: string[] }> {
		// Decode header/payload without verification to extract the issuer DID
		const parts = jwt.split(".");
		if (parts.length !== 3) {
			return { valid: false, error: "Malformed JWT: expected 3 parts" };
		}

		let issuerDid: string | undefined;
		try {
			const payloadPart = parts[1] ?? "";
			const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
			const padLen = (4 - (padded.length % 4)) % 4;
			const decoded = atob(padded + "=".repeat(padLen));
			const claims = JSON.parse(decoded) as Record<string, unknown>;
			issuerDid = typeof claims.iss === "string" ? claims.iss : undefined;
		} catch {
			return { valid: false, error: "Failed to decode JWT payload" };
		}

		if (!issuerDid) {
			return { valid: false, error: "JWT missing 'iss' claim" };
		}

		const rows = await db.select().from(agentDids).where(eq(agentDids.did, issuerDid));
		const row = rows[0];
		if (!row) {
			return {
				valid: false,
				error: `No stored public key found for DID "${issuerDid}"`,
			};
		}

		const publicKeyJwk = JSON.parse(row.publicKeyJwk) as JsonWebKey;
		const result = await verifyPresentation(jwt, publicKeyJwk);

		if (!result.valid) {
			return { valid: false, error: result.error };
		}

		return {
			valid: true,
			issuer: result.did,
			payload: undefined,
			capabilities: result.capabilities,
		};
	}

	return {
		generateKey,
		generateWeb,
		resolve,
		getAgentDid,
		sign,
		verify,
		createPresentation: createPresentationForAgent,
		verifyPresentation: verifyPresentationForAgent,
	};
}

export type DidModule = ReturnType<typeof createDidModule>;
