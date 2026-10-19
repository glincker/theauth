/**
 * Id generation for the core tables (users, sessions, OAuth accounts).
 *
 * The default is a random UUID (v4). `advanced.database.generateId` swaps it for a time ordered
 * UUID v7 (RFC 9562 section 5.7) or for your own function. Ids are stored in TEXT columns
 * (VARCHAR(191) on MySQL) and every foreign key references them as strings, so database generated
 * ids (`false` or `"serial"` in Better Auth) are refused instead of half working.
 */
import { generateId } from "../crypto/web-crypto.js";

/** The tables whose ids can be customised. */
export type IdModel = "user" | "session" | "account";

export interface IdGeneratorContext {
	model: IdModel;
}

/** A custom generator. It must return a fresh id for the model on every call. */
export type IdGeneratorFn = (context: IdGeneratorContext) => string;

/** `"uuid"` is a random v4 UUID (the default), `"uuidv7"` a time ordered v7 UUID. */
export type IdGeneratorOption = "uuid" | "uuidv7" | IdGeneratorFn;

export interface IdSource {
	/** A new id for a row of this model. Throws `IdGenerationError` when a custom generator returns a bad value. */
	newId(model: IdModel): string;
}

export class IdGenerationError extends Error {
	readonly code: "THEAUTH_ID_UNSUPPORTED" | "THEAUTH_ID_INVALID";
	constructor(code: IdGenerationError["code"], message: string) {
		super(`${code}: ${message}`);
		this.name = "IdGenerationError";
		this.code = code;
	}
}

/** Longest id every dialect can index (MySQL VARCHAR(191) with utf8mb4). */
export const MAX_ID_LENGTH = 191;
const ID_PATTERN = /^[A-Za-z0-9_.-]+$/;

let lastMs = 0;
let counter = 0;

/**
 * A UUID v7: 48 bit Unix millisecond timestamp, version 7, a 12 bit counter, variant 10, 62 random
 * bits (RFC 9562 section 6.2, method 1). Ids made in the same millisecond keep creation order,
 * and a clock that steps back keeps counting from the last timestamp instead of going backwards.
 */
export function generateUuidV7(now: number = Date.now()): string {
	let ms = now;
	if (ms > lastMs) {
		lastMs = ms;
		counter = randomCounterStart();
	} else {
		counter += 1;
		if (counter > 0xfff) {
			lastMs += 1;
			counter = randomCounterStart();
		}
		ms = lastMs;
	}
	const rand = new Uint8Array(8);
	globalThis.crypto.getRandomValues(rand);
	const bytes = new Uint8Array(16);
	let t = ms;
	for (let i = 5; i >= 0; i--) {
		bytes[i] = t % 256;
		t = Math.floor(t / 256);
	}
	bytes[6] = 0x70 | (counter >> 8);
	bytes[7] = counter & 0xff;
	bytes[8] = 0x80 | ((rand[0] as number) & 0x3f);
	for (let i = 1; i < 8; i++) bytes[8 + i] = rand[i] as number;
	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Start below 0x800 so a run of ids in one millisecond has room before the counter overflows. */
function randomCounterStart(): number {
	const b = new Uint8Array(2);
	globalThis.crypto.getRandomValues(b);
	return (((b[0] as number) << 8) | (b[1] as number)) & 0x7ff;
}

const DEFAULT_SOURCE: IdSource = { newId: () => generateId() };

/** The source used when nothing is configured. */
export function defaultIdSource(): IdSource {
	return DEFAULT_SOURCE;
}

/** Validates the option and returns the source. Throws on `false`, `"serial"` and unknown values. */
export function createIdSource(option: unknown): IdSource {
	if (option === undefined || option === "uuid") return DEFAULT_SOURCE;
	if (option === "uuidv7") return { newId: () => generateUuidV7() };
	if (typeof option === "function") {
		const fn = option as IdGeneratorFn;
		return {
			newId(model) {
				const id: unknown = fn({ model });
				if (
					typeof id !== "string" ||
					id.length === 0 ||
					id.length > MAX_ID_LENGTH ||
					!ID_PATTERN.test(id)
				) {
					throw new IdGenerationError(
						"THEAUTH_ID_INVALID",
						`advanced.database.generateId returned an unusable id for "${model}". Return a string of 1 to ${MAX_ID_LENGTH} characters from A-Z, a-z, 0-9, "_", "-" and ".".`,
					);
				}
				return id;
			},
		};
	}
	if (option === false || option === "serial") {
		throw new IdGenerationError(
			"THEAUTH_ID_UNSUPPORTED",
			`advanced.database.generateId: ${String(option)} (database generated ids) is not supported. theAuth stores ids as text and links every table by them, so it must know an id before the insert. Use "uuidv7" or a function that returns a string.`,
		);
	}
	throw new IdGenerationError(
		"THEAUTH_ID_UNSUPPORTED",
		`advanced.database.generateId must be "uuid", "uuidv7" or a function, got ${JSON.stringify(option)}.`,
	);
}
