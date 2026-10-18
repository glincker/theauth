/**
 * Fetch-only DNS resolver for runtimes without node:dns (Cloudflare Workers, Deno Deploy).
 * Speaks DNS over HTTPS JSON (application/dns-json) and fails closed: any transport problem,
 * malformed answer, CNAME loop, over-long chain, internal CNAME target or non-public address
 * makes the call throw. An empty array means the name does not exist (NXDOMAIN) or has no A or
 * AAAA records.
 *
 * DoH reflects public DNS only. On split-horizon networks the platform resolver may answer
 * differently, and DNS rebinding between this check and the real connection stays possible.
 */

import { classifyIp, screenHostname } from "./cimd-url.js";

type DnsResolver = (hostname: string) => Promise<string[]>;

export interface DohResolverOptions {
	/** One endpoint or an ordered list tried in turn on transport failure. Must be https. */
	endpoint?: string | readonly string[];
	fetchImpl?: typeof fetch;
	/** Budget for the whole resolution, all queries included. Default 3000, clamped to [200, 15000]. */
	timeoutMs?: number;
	/** Longest CNAME chain followed. Default 8, clamped to [1, 16]. */
	maxCnameDepth?: number;
	/** When true (default) any non-public address in an answer throws. */
	rejectPrivateAnswers?: boolean;
}

export const DEFAULT_DOH_ENDPOINTS: readonly string[] = [
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
];

const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_CNAME_DEPTH = 8;
const MAX_BODY_CHARS = 64 * 1024;
const TYPE_A = 1;
const TYPE_CNAME = 5;
const TYPE_AAAA = 28;

export type DohErrorCode =
	| "invalid_host"
	| "timeout"
	| "transport"
	| "bad_status"
	| "bad_response"
	| "servfail"
	| "cname_loop"
	| "cname_depth"
	| "blocked_cname"
	| "private_address";

export function dohError(code: DohErrorCode, message: string): Error & { code: DohErrorCode } {
	return Object.assign(new Error(message), { name: "DohResolverError", code });
}

interface DohRecord {
	name: string;
	type: number;
	data: string;
}

const clamp = (n: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, n));
const normName = (s: string): string => s.trim().toLowerCase().replace(/\.$/, "");

function parseAnswer(body: unknown): { status: number; records: DohRecord[] } {
	if (typeof body !== "object" || body === null) throw dohError("bad_response", "not an object");
	const obj = body as { Status?: unknown; Answer?: unknown };
	if (typeof obj.Status !== "number") throw dohError("bad_response", "missing Status");
	const records: DohRecord[] = [];
	if (obj.Answer !== undefined) {
		if (!Array.isArray(obj.Answer)) throw dohError("bad_response", "Answer is not an array");
		for (const item of obj.Answer as unknown[]) {
			if (typeof item !== "object" || item === null) continue;
			const r = item as { name?: unknown; type?: unknown; data?: unknown };
			if (typeof r.name !== "string" || typeof r.type !== "number") continue;
			if (r.type !== TYPE_A && r.type !== TYPE_AAAA && r.type !== TYPE_CNAME) continue;
			if (typeof r.data !== "string") throw dohError("bad_response", "record without data");
			records.push({ name: normName(r.name), type: r.type, data: r.data.trim() });
		}
	}
	return { status: obj.Status, records };
}

async function queryOne(
	endpoint: string,
	name: string,
	type: "A" | "AAAA",
	fetchImpl: typeof fetch,
	signal: AbortSignal,
): Promise<{ status: number; records: DohRecord[] }> {
	const url = `${endpoint}${endpoint.includes("?") ? "&" : "?"}name=${encodeURIComponent(name)}&type=${type}`;
	let response: Response;
	try {
		response = await fetchImpl(url, {
			method: "GET",
			headers: { Accept: "application/dns-json" },
			redirect: "error",
			credentials: "omit",
			cache: "no-store",
			signal,
		});
	} catch {
		throw dohError(signal.aborted ? "timeout" : "transport", "DoH request failed");
	}
	if (response.status !== 200) throw dohError("bad_status", `DoH status ${response.status}`);
	const declared = response.headers.get("content-length");
	if (declared !== null && Number(declared) > MAX_BODY_CHARS) {
		throw dohError("bad_response", "DoH body too large");
	}
	let text: string;
	try {
		text = await response.text();
	} catch {
		throw dohError(signal.aborted ? "timeout" : "transport", "DoH body read failed");
	}
	if (text.length > MAX_BODY_CHARS) throw dohError("bad_response", "DoH body too large");
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		throw dohError("bad_response", "DoH body is not JSON");
	}
	return parseAnswer(json);
}

function collectAddresses(
	name: string,
	records: DohRecord[],
	maxDepth: number,
	rejectPrivate: boolean,
): string[] {
	const cnames = new Map<string, string>();
	for (const r of records) {
		if (r.type === TYPE_CNAME) cnames.set(r.name, normName(r.data));
	}
	let current = name;
	const seen = new Set<string>([current]);
	let depth = 0;
	for (;;) {
		const next = cnames.get(current);
		if (next === undefined) break;
		depth++;
		if (depth > maxDepth) throw dohError("cname_depth", "CNAME chain too long");
		if (seen.has(next)) throw dohError("cname_loop", "CNAME loop");
		if (!screenHostname(next).ok) throw dohError("blocked_cname", "CNAME target is not allowed");
		seen.add(next);
		current = next;
	}
	const out: string[] = [];
	for (const r of records) {
		if (r.type === TYPE_CNAME || r.name !== current) continue;
		const cls = classifyIp(r.data);
		if (cls === "invalid") throw dohError("bad_response", "malformed address in answer");
		if (cls !== "public" && rejectPrivate) {
			throw dohError("private_address", "name resolves to a non-public address");
		}
		if (!out.includes(r.data)) out.push(r.data);
	}
	return out;
}

/** DNS over HTTPS (application/dns-json). Queries A and AAAA and returns every address. */
export function createDohResolver(options: DohResolverOptions = {}): DnsResolver {
	const endpoints = (
		options.endpoint === undefined
			? DEFAULT_DOH_ENDPOINTS
			: typeof options.endpoint === "string"
				? [options.endpoint]
				: options.endpoint
	).slice();
	if (endpoints.length === 0) throw new TypeError("createDohResolver: no endpoints");
	for (const e of endpoints) {
		if (!e.startsWith("https://"))
			throw new TypeError("createDohResolver: endpoints must be https");
	}
	const timeoutMs = clamp(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 200, 15_000);
	const maxDepth = clamp(options.maxCnameDepth ?? DEFAULT_CNAME_DEPTH, 1, 16);
	const rejectPrivate = options.rejectPrivateAnswers !== false;

	return async (hostname: string): Promise<string[]> => {
		const screened = screenHostname(hostname);
		if (!screened.ok) throw dohError("invalid_host", screened.reason);
		const name = screened.host;
		const fetchImpl = options.fetchImpl ?? fetch;

		const controller = new AbortController();
		let timer: ReturnType<typeof setTimeout> | undefined;
		const deadline = new Promise<never>((_, reject) => {
			timer = setTimeout(() => {
				controller.abort();
				reject(dohError("timeout", "DoH resolution timed out"));
			}, timeoutMs);
		});
		// The race also covers runtimes where abort does not reach a stalled body stream.
		deadline.catch(() => undefined);

		const run = async (): Promise<string[]> => {
			let lastError: Error = dohError("transport", "no DoH endpoint answered");
			for (const endpoint of endpoints) {
				try {
					const [a, aaaa] = await Promise.all([
						queryOne(endpoint, name, "A", fetchImpl, controller.signal),
						queryOne(endpoint, name, "AAAA", fetchImpl, controller.signal),
					]);
					for (const q of [a, aaaa]) {
						if (q.status !== 0 && q.status !== 3) {
							throw dohError("servfail", `DNS status ${q.status}`);
						}
					}
					if (a.status === 3 && aaaa.status === 3) return [];
					return collectAddresses(name, [...a.records, ...aaaa.records], maxDepth, rejectPrivate);
				} catch (err) {
					const e = err instanceof Error ? err : dohError("transport", "unknown failure");
					const code = (e as { code?: DohErrorCode }).code;
					// Transport level problems fall through to the next endpoint; verdicts do not.
					if (
						code === "transport" ||
						code === "bad_status" ||
						code === "servfail" ||
						code === "bad_response"
					) {
						lastError = e;
						continue;
					}
					throw e;
				}
			}
			throw lastError;
		};

		try {
			return await Promise.race([run(), deadline]);
		} finally {
			if (timer !== undefined) clearTimeout(timer);
			controller.abort();
		}
	};
}
