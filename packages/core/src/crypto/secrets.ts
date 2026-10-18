/**
 * SecretRing: HMAC secret rotation helper.
 * The first secret signs, every secret verifies (the same model as the Go `tokenvault.KeyRing`). To rotate, put the new secret first and keep the old one in the list until everything it signed has expired, then drop it. Secrets are never logged, serialized or placed in error messages. Verification computes the MAC under every candidate key and combines the results without an early exit, so timing does not reveal which key matched. The optional key id only changes the order in which keys are tried.
 */

import { constantTimeEqual, hmacSha256Raw } from "./web-crypto.js";

/** A secret, optionally labelled with a key id emitted next to signatures. */
export type SecretInput = string | { id: string; secret: string };

/** `secret` config value: a single string (no rotation) or `[current, ...previous]`. */
export type SecretRingConfig = SecretInput | readonly SecretInput[];

export interface SecretRingOptions {
	/** Minimum secret length in bytes (UTF-8). Default 32. */
	minBytes?: number;
	/** Name used in error messages, for example `StatelessSessions`. */
	label?: string;
}

export const DEFAULT_MIN_SECRET_BYTES = 32;
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const ENCODER = new TextEncoder();

interface Entry {
	id: string | undefined;
	secret: string;
}

export class SecretRing {
	readonly #entries: readonly Entry[];
	/** Number of keys tried by the most recent `verify`. Exposed for tests. */
	lastVerifyAttempts = 0;

	constructor(input: SecretRingConfig, options: SecretRingOptions = {}) {
		const label = options.label ?? "SecretRing";
		const minBytes = options.minBytes ?? DEFAULT_MIN_SECRET_BYTES;
		const list: readonly SecretInput[] = Array.isArray(input)
			? (input as readonly SecretInput[])
			: [input as SecretInput];
		if (list.length === 0) {
			throw new Error(`${label}: at least one secret is required.`);
		}
		const secrets = new Set<string>();
		const ids = new Set<string>();
		const entries: Entry[] = [];
		list.forEach((item, index) => {
			const secret = typeof item === "string" ? item : item?.secret;
			const id = typeof item === "string" ? undefined : item?.id;
			if (typeof secret !== "string" || secret.length === 0) {
				throw new Error(`${label}: secret at position ${index} is empty.`);
			}
			if (ENCODER.encode(secret).byteLength < minBytes) {
				throw new Error(
					`${label}: secret at position ${index} must be at least ${minBytes} bytes.`,
				);
			}
			if (typeof item !== "string" && (typeof id !== "string" || !KEY_ID_PATTERN.test(id))) {
				throw new Error(
					`${label}: key id at position ${index} must match [A-Za-z0-9_-] and be 1 to 32 characters.`,
				);
			}
			if (secrets.has(secret)) {
				throw new Error(`${label}: duplicate secret at position ${index}.`);
			}
			if (id !== undefined && ids.has(id)) {
				throw new Error(`${label}: duplicate key id "${id}" at position ${index}.`);
			}
			secrets.add(secret);
			if (id !== undefined) ids.add(id);
			entries.push({ id, secret });
		});
		this.#entries = entries;
	}

	/** Build a ring, passing an existing ring through unchanged. */
	static from(input: SecretRingConfig | SecretRing, options?: SecretRingOptions): SecretRing {
		return input instanceof SecretRing ? input : new SecretRing(input, options);
	}

	get size(): number {
		return this.#entries.length;
	}

	/** Key id of the signing key, when it has one. */
	get currentId(): string | undefined {
		return this.#entries[0]?.id;
	}

	/** Sign with the current key. `kid` is set only when the current key has an id. */
	async sign(data: string | Uint8Array): Promise<{ signature: Uint8Array; kid?: string }> {
		const entry = this.#entries[0] as Entry;
		const signature = await hmacSha256Raw(entry.secret, data);
		return entry.id === undefined ? { signature } : { signature, kid: entry.id };
	}

	/** Verify against every key. A matching `kid` is tried first, all keys are always evaluated. */
	async verify(data: string | Uint8Array, signature: Uint8Array, kid?: string): Promise<boolean> {
		const ordered = [...this.#entries].sort(
			(a, b) =>
				Number(b.id === kid && kid !== undefined) - Number(a.id === kid && kid !== undefined),
		);
		let ok = 0;
		let attempts = 0;
		for (const entry of ordered) {
			const expected = await hmacSha256Raw(entry.secret, data);
			ok |= constantTimeEqual(expected, signature) ? 1 : 0;
			attempts += 1;
		}
		this.lastVerifyAttempts = attempts;
		return ok === 1;
	}

	/** Secrets in trial order (current first, or the `kid` match first), for derived keys such as AES. Treat as sensitive. */
	candidates(kid?: string): string[] {
		return [...this.#entries]
			.sort(
				(a, b) =>
					Number(b.id === kid && kid !== undefined) - Number(a.id === kid && kid !== undefined),
			)
			.map((e) => e.secret);
	}

	/** The signing secret, for deriving encryption keys. Treat as sensitive. */
	get current(): string {
		return (this.#entries[0] as Entry).secret;
	}

	toJSON(): { keys: number; currentId?: string } {
		return this.currentId === undefined
			? { keys: this.size }
			: { keys: this.size, currentId: this.currentId };
	}

	toString(): string {
		return `SecretRing(${this.size} keys)`;
	}

	[Symbol.for("nodejs.util.inspect.custom")](): string {
		return this.toString();
	}
}

export function createSecretRing(input: SecretRingConfig, options?: SecretRingOptions): SecretRing {
	return new SecretRing(input, options);
}
