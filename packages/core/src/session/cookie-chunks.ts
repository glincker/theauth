/**
 * Chunked cookies for values that do not fit in one 4096 byte cookie.
 *
 * Browsers drop a cookie when `name=value` passes about 4096 bytes, and they
 * do it silently. A value that is too long is split across `name.0`,
 * `name.1`, ... and stitched back together on read. A value that fits stays in
 * a single cookie called `name`, so small payloads cost nothing extra.
 *
 * The value must be cookie-safe text (base64url, JWT, hex). Chunk boundaries
 * never split a percent-escape.
 */

import type { Result } from "../mcp/types.js";
import type { CookieOptions } from "./cookie.js";
import { serializeCookie, serializeCookieDeletion } from "./cookie.js";

/** Practical per-cookie ceiling enforced by browsers (name + value). */
export const COOKIE_MAX_BYTES = 4096;
/** Default budget for the value of one chunk, leaving room for name and attributes. */
export const DEFAULT_CHUNK_BYTES = 3600;
/** Default cap on chunks per logical cookie. */
export const DEFAULT_MAX_CHUNKS = 4;

export interface ChunkedCookieOptions {
	/** Max encoded bytes of value per chunk. Default 3600, hard max 4000. */
	chunkBytes?: number;
	/** Max number of chunks. Default 4. Larger values risk proxy header limits. */
	maxChunks?: number;
}

export interface ChunkedCookieWrite {
	/** `Set-Cookie` header values: the new chunks plus deletions for stale ones. */
	headers: string[];
	/** Number of cookies carrying the value. */
	chunks: number;
	/** Encoded value size in bytes. */
	bytes: number;
}

function chunkName(name: string, index: number): string {
	return `${name}.${index}`;
}

function splitEncoded(value: string, chunkBytes: number): string[] {
	const chunks: string[] = [];
	let current = "";
	let currentBytes = 0;
	for (const ch of value) {
		const size = encodeURIComponent(ch).length;
		if (currentBytes + size > chunkBytes && current) {
			chunks.push(current);
			current = "";
			currentBytes = 0;
		}
		current += ch;
		currentBytes += size;
	}
	if (current || chunks.length === 0) chunks.push(current);
	return chunks;
}

function existingChunkIndexes(name: string, cookies: Record<string, string>): number[] {
	const prefix = `${name}.`;
	const out: number[] = [];
	for (const key of Object.keys(cookies)) {
		if (!key.startsWith(prefix)) continue;
		const n = Number(key.slice(prefix.length));
		if (Number.isInteger(n) && n >= 0) out.push(n);
	}
	return out;
}

/**
 * Build the `Set-Cookie` headers for a possibly chunked cookie.
 *
 * @param existing Cookies currently on the request. Stale chunks (a previous
 *                 longer value) are deleted so they cannot be stitched back in.
 *
 * Fails with `COOKIE_TOO_LARGE` when the value needs more than `maxChunks`.
 */
export function serializeChunkedCookie(
	name: string,
	value: string,
	options: CookieOptions = {},
	chunkOptions: ChunkedCookieOptions = {},
	existing: Record<string, string> = {},
): Result<ChunkedCookieWrite> {
	const chunkBytes = Math.min(
		Math.max(chunkOptions.chunkBytes ?? DEFAULT_CHUNK_BYTES, 200),
		COOKIE_MAX_BYTES - 96,
	);
	const maxChunks = Math.max(chunkOptions.maxChunks ?? DEFAULT_MAX_CHUNKS, 1);
	const budget = Math.max(chunkBytes - name.length - 2, 100);
	const parts = splitEncoded(value, budget);
	const bytes = encodeURIComponent(value).length;

	if (parts.length > maxChunks) {
		return {
			success: false,
			error: {
				code: "COOKIE_TOO_LARGE",
				message: `Cookie "${name}" needs ${parts.length} chunks (${bytes} bytes), limit is ${maxChunks}.`,
				details: { bytes, chunks: parts.length, maxChunks },
			},
		};
	}

	const headers: string[] = [];
	const { maxAge: _m, expires: _e, ...deletion } = options;
	if (parts.length === 1) {
		headers.push(serializeCookie(name, parts[0] as string, options));
		for (const i of existingChunkIndexes(name, existing)) {
			headers.push(serializeCookieDeletion(chunkName(name, i), deletion));
		}
	} else {
		parts.forEach((part, i) => {
			headers.push(serializeCookie(chunkName(name, i), part, options));
		});
		if (name in existing) headers.push(serializeCookieDeletion(name, deletion));
		for (const i of existingChunkIndexes(name, existing)) {
			if (i >= parts.length) headers.push(serializeCookieDeletion(chunkName(name, i), deletion));
		}
	}
	return { success: true, data: { headers, chunks: parts.length, bytes } };
}

/**
 * Read a cookie written by `serializeChunkedCookie`. Returns `undefined` when
 * absent or when a chunk is missing (a partial value is never returned).
 */
export function readChunkedCookie(
	cookies: Record<string, string>,
	name: string,
): string | undefined {
	const single = cookies[name];
	if (single !== undefined) return single;
	const indexes = existingChunkIndexes(name, cookies).sort((a, b) => a - b);
	if (indexes.length === 0) return undefined;
	let out = "";
	for (let i = 0; i < indexes.length; i++) {
		if (indexes[i] !== i) return undefined;
		out += cookies[chunkName(name, i)] ?? "";
	}
	return out;
}

/** Deletion headers for a cookie and every chunk found on the request. */
export function clearChunkedCookie(
	name: string,
	cookies: Record<string, string>,
	options: Omit<CookieOptions, "maxAge" | "expires"> = {},
): string[] {
	const headers = [serializeCookieDeletion(name, options)];
	for (const i of existingChunkIndexes(name, cookies)) {
		headers.push(serializeCookieDeletion(chunkName(name, i), options));
	}
	return headers;
}
