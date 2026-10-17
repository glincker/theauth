import { buildDidDocument, generateDidKey } from "./key-method.js";
import type { DidDocument, DidKeyPair, DidWebConfig } from "./types.js";

/**
 * Build a did:web DID string from a config and agent ID.
 * Spec: https://w3c-ccg.github.io/did-method-web/ did:web:example.com              → root document did:web:example.com:agents:123   → path-based document
 */
function buildDidWeb(config: DidWebConfig, agentId: string): string {
	const domain = config.domain.replace(/\//g, ":");
	if (config.path) {
		const path = config.path.replace(/\//g, ":").replace(/^:|:$/g, "");
		return `did:web:${domain}:${path}:${agentId}`;
	}
	return `did:web:${domain}:${agentId}`;
}

/**
 * Generate a did:web identity for an agent.
 * The private key is returned to the caller and must be stored securely.
 */
export async function generateDidWeb(config: DidWebConfig, agentId: string): Promise<DidKeyPair> {
	// Generate the underlying Ed25519 key material
	const { publicKeyJwk, privateKeyJwk } = await generateDidKey();

	const did = buildDidWeb(config, agentId);
	const didDocument = buildDidDocument(did, publicKeyJwk);

	return {
		did,
		publicKeyJwk,
		privateKeyJwk,
		didDocument,
	};
}

/** Get the HTTPS URL where a did:web document should be hosted. */
export function getDidWebUrl(did: string): string {
	if (!did.startsWith("did:web:")) {
		throw new Error(`Not a did:web identifier: ${did}`);
	}

	const methodSpecific = did.slice("did:web:".length);
	const parts = methodSpecific.split(":");

	// URL-decode each component (colons are percent-encoded path separators in the spec)
	const decoded = parts.map((p) => decodeURIComponent(p));

	if (decoded.length === 1) {
		// Root DID: did:web:example.com → /.well-known/did.json
		return `https://${decoded[0]}/.well-known/did.json`;
	}

	// Path-based DID: did:web:example.com:agents:123 → /agents/123/did.json
	const domain = decoded[0];
	const pathSegments = decoded.slice(1);
	return `https://${domain}/${pathSegments.join("/")}/did.json`;
}

/**
 * Resolve a did:web by fetching the DID document from the web.
 * Returns null if the fetch fails or the document is malformed.
 */
export async function resolveDidWeb(did: string): Promise<DidDocument | null> {
	let url: string;
	try {
		url = getDidWebUrl(did);
	} catch {
		return null;
	}

	try {
		const response = await fetch(url, {
			headers: { Accept: "application/json" },
		});

		if (!response.ok) return null;

		const doc = (await response.json()) as DidDocument;

		// Basic sanity check, must have @context and id
		if (!doc["@context"] || !doc.id) return null;

		return doc;
	} catch {
		return null;
	}
}
