/**
 * Sign In With Ethereum (SIWE) for TheAuth.
 *
 * Authenticates users by verifying an Ethereum wallet signature per EIP-4361.
 * Full secp256k1 recovery requires ethers or viem as peer deps — this module
 * validates message format and nonce integrity. Add a `verify` override via
 * `verifySignature` option when you want cryptographic proof.
 *
 * @example
 * ```typescript
 * const siwe = createSiweModule({
 *   domain: 'example.com',
 *   uri: 'https://example.com',
 *   statement: 'Sign in to Example App',
 * });
 *
 * // 1. Frontend requests a nonce
 * const nonce = await siwe.generateNonce();
 *
 * // 2. Frontend builds the message and asks wallet to sign it
 * const message = siwe.buildMessage('0xAbc...', nonce, 1);
 *
 * // 3. Frontend submits message + signature
 * const { address, chainId } = await siwe.verify(message, signature);
 * ```
 */

import { randomBytesHex } from "../crypto/web-crypto.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SiweConfig {
	/** Your app's domain (e.g., "example.com") */
	domain: string;
	/** URI (e.g., "https://example.com") */
	uri: string;
	/** Statement shown in wallet (optional) */
	statement?: string;
	/** Nonce TTL in seconds (default: 300) */
	nonceTtlSeconds?: number;
	/**
	 * Optional signature verifier. Called with the EIP-4361 message and
	 * hex signature. Should return the recovered Ethereum address.
	 * When omitted, the module trusts the address from the message body
	 * (suitable for development; add viem/ethers recovery in production).
	 */
	verifySignature?: (message: string, signature: string) => Promise<string>;
}

export interface SiweModule {
	/** Generate a nonce for the SIWE message */
	generateNonce(): Promise<string>;
	/** Build the EIP-4361 message for the wallet to sign */
	buildMessage(address: string, nonce: string, chainId?: number): string;
	/** Verify the signed message and return the Ethereum address */
	verify(message: string, signature: string): Promise<{ address: string; chainId: number }>;
	/** Handle full SIWE auth flow via HTTP */
	handleRequest(request: Request): Promise<Response | null>;
}

export interface SiweVerifyResult {
	address: string;
	chainId: number;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface NonceEntry {
	expiresAt: number;
}

interface ParsedSiweMessage {
	domain: string;
	address: string;
	uri: string;
	version: string;
	chainId: number;
	nonce: string;
	issuedAt: string;
	statement?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_NONCE_TTL_SECONDS = 300;
const SIWE_VERSION = "1";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

function generateHexNonce(byteLength = 16): string {
	return randomBytesHex(byteLength);
}

/**
 * Parse an EIP-4361 message into its structured fields.
 * Returns null if the message does not match the expected format.
 */
function parseSiweMessage(message: string): ParsedSiweMessage | null {
	const lines = message.split("\n");
	if (lines.length < 9) return null;

	// Line 0: "${domain} wants you to sign in with your Ethereum account:"
	const domainLine = lines[0] ?? "";
	const domainMatch = /^(.+) wants you to sign in with your Ethereum account:$/.exec(domainLine);
	if (!domainMatch) return null;
	const domain = domainMatch[1] ?? "";

	// Line 1: (blank)
	// Line 2: Ethereum address
	const address = lines[2]?.trim();
	if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return null;

	// Line 3: (blank)
	// Lines 4+: key-value fields, possibly a statement before URI
	let idx = 4;

	// Optional statement block: non-empty line before "URI:" field
	let statement: string | undefined;
	const lineAtIdx = lines[idx];
	if (lineAtIdx && !lineAtIdx.startsWith("URI:")) {
		statement = lineAtIdx;
		idx++;
		// blank line after statement
		if (lines[idx] === "") idx++;
	}

	const fieldLines = lines.slice(idx);
	const fields: Record<string, string> = {};
	for (const line of fieldLines) {
		const colonIdx = line.indexOf(": ");
		if (colonIdx === -1) continue;
		const key = line.slice(0, colonIdx).trim();
		const value = line.slice(colonIdx + 2).trim();
		fields[key] = value;
	}

	const fieldUri = fields.URI;
	const fieldVersion = fields.Version;
	const fieldChainId = fields["Chain ID"];
	const fieldNonce = fields.Nonce;
	const fieldIssuedAt = fields["Issued At"];

	if (!fieldUri || !fieldVersion || !fieldChainId || !fieldNonce || !fieldIssuedAt) {
		return null;
	}

	const chainId = parseInt(fieldChainId, 10);
	if (Number.isNaN(chainId)) return null;

	return {
		domain,
		address,
		uri: fieldUri,
		version: fieldVersion,
		chainId,
		nonce: fieldNonce,
		issuedAt: fieldIssuedAt,
		statement,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createSiweModule(config: SiweConfig): SiweModule {
	const nonceTtlMs = (config.nonceTtlSeconds ?? DEFAULT_NONCE_TTL_SECONDS) * 1000;

	// In-memory nonce store: nonce -> expiry timestamp
	const nonceStore = new Map<string, NonceEntry>();

	function purgeExpiredNonces(): void {
		const now = Date.now();
		for (const [nonce, entry] of nonceStore) {
			if (entry.expiresAt <= now) {
				nonceStore.delete(nonce);
			}
		}
	}

	async function generateNonce(): Promise<string> {
		purgeExpiredNonces();
		const nonce = generateHexNonce();
		nonceStore.set(nonce, { expiresAt: Date.now() + nonceTtlMs });
		return nonce;
	}

	function buildMessage(address: string, nonce: string, chainId = 1): string {
		const lines: string[] = [
			`${config.domain} wants you to sign in with your Ethereum account:`,
			"",
			address,
			"",
		];

		if (config.statement) {
			lines.push(config.statement, "");
		}

		lines.push(
			`URI: ${config.uri}`,
			`Version: ${SIWE_VERSION}`,
			`Chain ID: ${chainId}`,
			`Nonce: ${nonce}`,
			`Issued At: ${new Date().toISOString()}`,
		);

		return lines.join("\n");
	}

	async function verify(message: string, signature: string): Promise<SiweVerifyResult> {
		const parsed = parseSiweMessage(message);
		if (!parsed) {
			throw new Error("Invalid SIWE message format");
		}

		// Domain check
		if (parsed.domain !== config.domain) {
			throw new Error(`Domain mismatch: expected ${config.domain}, got ${parsed.domain}`);
		}

		// URI check
		if (parsed.uri !== config.uri) {
			throw new Error(`URI mismatch: expected ${config.uri}, got ${parsed.uri}`);
		}

		// Version check
		if (parsed.version !== SIWE_VERSION) {
			throw new Error(`Unsupported SIWE version: ${parsed.version}`);
		}

		// Nonce check
		const nonceEntry = nonceStore.get(parsed.nonce);
		if (!nonceEntry) {
			throw new Error("Nonce not found or already used");
		}
		if (nonceEntry.expiresAt <= Date.now()) {
			nonceStore.delete(parsed.nonce);
			throw new Error("Nonce expired");
		}

		// Consume nonce (single use)
		nonceStore.delete(parsed.nonce);

		// Signature verification
		let verifiedAddress: string;
		if (config.verifySignature) {
			verifiedAddress = await config.verifySignature(message, signature);
		} else {
			// Trust-the-message mode: signature presence is checked but not cryptographically verified.
			// Suitable for development. Add verifySignature for production.
			if (!signature || signature.length < 10) {
				throw new Error("Signature is required");
			}
			verifiedAddress = parsed.address;
		}

		// Normalise to checksum-style lowercase for comparison
		if (verifiedAddress.toLowerCase() !== parsed.address.toLowerCase()) {
			throw new Error("Signature does not match address");
		}

		return { address: parsed.address, chainId: parsed.chainId };
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { method, pathname } = { method: request.method, pathname: url.pathname };

		// GET /auth/siwe/nonce
		if (method === "GET" && pathname.endsWith("/auth/siwe/nonce")) {
			const nonce = await generateNonce();
			return jsonResponse({ nonce });
		}

		// POST /auth/siwe/verify
		if (method === "POST" && pathname.endsWith("/auth/siwe/verify")) {
			const body = await parseBody(request);
			const message = typeof body.message === "string" ? body.message : null;
			const signature = typeof body.signature === "string" ? body.signature : null;

			if (!message || !signature) {
				return jsonResponse({ error: "Missing required fields: message, signature" }, 400);
			}

			try {
				const result = await verify(message, signature);
				return jsonResponse({ address: result.address, chainId: result.chainId });
			} catch (err) {
				return jsonResponse(
					{ error: err instanceof Error ? err.message : "Verification failed" },
					400,
				);
			}
		}

		return null;
	}

	return { generateNonce, buildMessage, verify, handleRequest };
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

import type { KavachPlugin } from "../plugin/types.js";

export function siwe(config: SiweConfig): KavachPlugin {
	return {
		id: "kavach-siwe",

		async init(ctx): Promise<undefined> {
			const mod = createSiweModule(config);

			// GET /auth/siwe/nonce
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/siwe/nonce",
				metadata: {
					description: "Generate a SIWE nonce for wallet signing",
					rateLimit: { window: 60_000, max: 60 },
				},
				async handler(_request, _endpointCtx) {
					const nonce = await mod.generateNonce();
					return new Response(JSON.stringify({ nonce }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				},
			});

			// POST /auth/siwe/verify
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/siwe/verify",
				metadata: {
					description: "Verify a SIWE-signed message and return the Ethereum address",
					rateLimit: { window: 60_000, max: 20 },
				},
				async handler(request, _endpointCtx) {
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						body = {};
					}

					const message = typeof body.message === "string" ? body.message : null;
					const signature = typeof body.signature === "string" ? body.signature : null;

					if (!message || !signature) {
						return new Response(
							JSON.stringify({ error: "Missing required fields: message, signature" }),
							{ status: 400, headers: { "Content-Type": "application/json" } },
						);
					}

					try {
						const result = await mod.verify(message, signature);
						return new Response(
							JSON.stringify({ address: result.address, chainId: result.chainId }),
							{ status: 200, headers: { "Content-Type": "application/json" } },
						);
					} catch (err) {
						return new Response(
							JSON.stringify({
								error: err instanceof Error ? err.message : "Verification failed",
							}),
							{ status: 400, headers: { "Content-Type": "application/json" } },
						);
					}
				},
			});

			return undefined;
		},
	};
}
