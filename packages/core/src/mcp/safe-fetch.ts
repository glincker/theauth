/**
 * SSRF-safe JSON fetcher.
 * - accepts https URLs only, with no credentials and the default port;
 * - resolves the hostname (node:dns only through a guarded dynamic import, so Workers, Deno and Bun never load it; fetch-only resolvers such as createDohResolver work everywhere) and rejects loopback, private (RFC 1918), link-local, carrier-grade NAT, multicast, unique-local IPv6 and cloud metadata ranges;
 * - never follows redirects (`redirect: "manual"`, any 3xx fails);
 * - enforces a small body cap while streaming;
 * - accepts `application/json` (or `+json`) responses only;
 * - times out, with one budget that covers the headers and the body (slow-drip bodies are aborted);
 * - sends `cache: "no-store"`, no credentials, no referrer, minimal headers;
 * - returns generic errors; detail goes only to `onEvent`;
 * - on Node and Bun (node:https through a guarded dynamic import, see safe-fetch-node.ts) the connection is pinned to the addresses that were vetted, so the name is never resolved a second time and DNS rebinding at connect is closed. Proxy environment variables are not used on that path;
 * - fails closed: every error becomes an `{ ok: false }` result. Residual risk on runtimes without a controllable connection (Workers, Deno) and with a custom `fetchImpl`: the platform `fetch` resolves the name again when it connects, so a DNS rebinding attacker with a very short TTL can still win the race between our check and the connection.
 */

/** `signal` aborts when the fetch budget ends; resolvers that can cancel should honor it. */
export type DnsResolver = (hostname: string, signal?: AbortSignal) => Promise<string[]>;

import { isPublicIp, screenHostname } from "./cimd-url.js";
import { DeadlineError, defaultDnsResolver, loadNodeDns, withDeadline } from "./safe-fetch-dns.js";
import {
	loadNodeHttps,
	PinnedConnectRefused,
	pinnedHttpsGet,
	publicVetter,
} from "./safe-fetch-node.js";

export { defaultDnsResolver, setNodeDnsForTests } from "./safe-fetch-dns.js";
export { setNodeHttpsForTests } from "./safe-fetch-node.js";

/** Resolver selection: a function, "auto" (node:dns when importable, otherwise fails closed), or "none" (names only). */
export type SafeFetchResolver = DnsResolver | "auto" | "none";

/** Detail for operators. Never returned to the requester. */
export interface SafeFetchEvent {
	type: "safe_fetch.failed" | "safe_fetch.resolver_unavailable";
	reason?: SafeFetchFailure;
	/** Internal detail, for logs only. */
	detail: string;
	/** Origin and path of the URL, without query. Absent for resolver_unavailable. */
	url?: string;
}

export interface SafeFetchOptions {
	/** "auto" (default): node:dns when this runtime has it, otherwise fails closed (see onResolverUnavailable) and reports once through onEvent. "none": hostname rules only. Or a resolver such as createDohResolver(). */
	resolver?: SafeFetchResolver;
	/** What "auto" does on a runtime with no DNS resolver. Default "fail" (every fetch fails closed). "names_only" skips the address check; use it only when the hosts are vetted another way, such as an allow list. */
	onResolverUnavailable?: "fail" | "names_only";
	/** Receives failure detail and runtime notices. Fire and forget, errors swallowed. */
	onEvent?: (event: SafeFetchEvent) => void;
	/** TEST ONLY. Lets http, any port and loopback hosts through so a local server can be used. Never set in production. */
	allowLoopbackForTests?: boolean;
	/** Fetch implementation. Defaults to global fetch. Setting it turns the pinned connect off (the supplied function owns the connection). */
	fetchImpl?: typeof fetch;
	/** "auto" (default): on Node and Bun connect through node:https pinned to the vetted addresses; elsewhere use fetch. "off": always use fetch. Pinned requests ignore HTTP_PROXY, HTTPS_PROXY and NO_PROXY on purpose, so an unvetted proxy can never carry the request. */
	pinnedConnect?: "auto" | "off";
	/** TEST ONLY. PEM CA added to the pinned connection's trust store so a local self signed server validates. */
	caForTests?: string;
	/** Maximum response body size in bytes. Default 5120. */
	maxBytes?: number;
	/** Timeout in milliseconds. Default 5000. */
	timeoutMs?: number;
}

export type SafeFetchResult =
	| { ok: true; json: unknown; cacheControl?: string }
	| { ok: false; reason: SafeFetchFailure; message: string };

export type SafeFetchFailure =
	| "invalid_url"
	| "blocked_host"
	| "dns_failure"
	| "redirect"
	| "http_error"
	| "bad_content_type"
	| "too_large"
	| "invalid_json"
	| "timeout"
	| "network_error";

const DEFAULT_MAX_BYTES = 5 * 1024;
const DEFAULT_TIMEOUT_MS = 5_000;

const BLOCKED_HOSTNAMES = new Set([
	"localhost",
	"metadata.google.internal",
	"metadata",
	"instance-data",
	"kubernetes.default.svc",
]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa"];

function parseIPv4(input: string): number[] | null {
	const parts = input.split(".");
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		const n = Number(part);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

/** Parse an IPv6 literal into eight 16-bit groups, or null when malformed. */
function parseIPv6(input: string): number[] | null {
	let addr = input;
	const zone = addr.indexOf("%");
	if (zone !== -1) addr = addr.slice(0, zone);
	if (!addr.includes(":")) return null;

	// Embedded IPv4 tail (e.g. ::ffff:10.0.0.1)
	const lastColon = addr.lastIndexOf(":");
	const tail = addr.slice(lastColon + 1);
	if (tail.includes(".")) {
		const v4 = parseIPv4(tail);
		if (!v4) return null;
		const hi = ((v4[0] ?? 0) << 8) | (v4[1] ?? 0);
		const lo = ((v4[2] ?? 0) << 8) | (v4[3] ?? 0);
		addr = `${addr.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`;
	}

	const halves = addr.split("::");
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(":") : [];
	const rest = halves.length === 2 && halves[1] ? (halves[1] as string).split(":") : [];
	let groups: string[];
	if (halves.length === 2) {
		const missing = 8 - head.length - rest.length;
		if (missing < 1) return null;
		groups = [...head, ...new Array<string>(missing).fill("0"), ...rest];
	} else {
		groups = head;
	}
	if (groups.length !== 8) return null;
	const out: number[] = [];
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		out.push(Number.parseInt(g, 16));
	}
	return out;
}

function isBlockedIPv4(o: number[]): boolean {
	const [a = 0, b = 0, c = 0] = o;
	if (a === 0) return true; // 0.0.0.0/8
	if (a === 10) return true; // RFC 1918
	if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10 (also Alibaba metadata)
	if (a === 127) return true; // loopback
	if (a === 169 && b === 254) return true; // link-local + cloud metadata
	if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
	if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments
	if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
	if (a === 192 && b === 168) return true; // RFC 1918
	if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
	if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
	if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
	if (a >= 224) return true; // multicast, reserved, broadcast
	return false;
}

function isBlockedIPv6(g: number[]): boolean {
	const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = g;
	const allZeroUpTo5 = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
	if (allZeroUpTo5 && g5 === 0 && g6 === 0 && (g7 === 0 || g7 === 1)) return true; // :: and ::1
	// IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
	if (allZeroUpTo5 && (g5 === 0xffff || g5 === 0)) {
		return isBlockedIPv4([g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff]);
	}
	// NAT64 64:ff9b::/96 embeds an IPv4 address
	if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
		return isBlockedIPv4([g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff]);
	}
	// 6to4 2002::/16 embeds an IPv4 address
	if (g0 === 0x2002) {
		return isBlockedIPv4([g1 >> 8, g1 & 0xff, g2 >> 8, g2 & 0xff]);
	}
	if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local (incl. fd00:ec2::254)
	if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
	if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
	if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
	if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true; // discard-only
	return false;
}

/** True when the address is loopback, private, link-local, metadata, multicast or otherwise not a routable public address. Unparseable input counts as blocked (fail closed). */
export function isBlockedIp(address: string): boolean {
	const trimmed = address.trim().replace(/^\[|\]$/g, "");
	const v4 = parseIPv4(trimmed);
	if (v4) return isBlockedIPv4(v4);
	const v6 = parseIPv6(trimmed);
	if (v6) return isBlockedIPv6(v6);
	return true;
}

export function isIpLiteral(host: string): boolean {
	const h = host.replace(/^\[|\]$/g, "");
	return parseIPv4(h) !== null || h.includes(":");
}

const LOOPBACK_TEST_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/** Check a URL's scheme, authority and host. Returns a failure or the parsed URL. */
export function checkFetchableUrl(
	raw: string,
	opts: { allowLoopbackForTests?: boolean } = {},
): { ok: true; url: URL } | { ok: false; message: string } {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return { ok: false, message: "not a valid URL" };
	}
	const host = url.hostname.toLowerCase().replace(/\.$/, "");
	if (opts.allowLoopbackForTests === true && LOOPBACK_TEST_HOSTS.has(host)) {
		return { ok: true, url };
	}
	if (url.protocol !== "https:") return { ok: false, message: "only https URLs are allowed" };
	if (url.username || url.password) return { ok: false, message: "credentials in URL" };
	if (url.port && url.port !== "443") return { ok: false, message: "non-default port" };
	if (!host) return { ok: false, message: "empty host" };
	if (BLOCKED_HOSTNAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
		return { ok: false, message: "host is not allowed" };
	}
	return { ok: true, url };
}

const GENERIC_MESSAGE: Record<SafeFetchFailure, string> = {
	invalid_url: "url is not allowed",
	blocked_host: "host is not allowed",
	dns_failure: "host could not be verified",
	redirect: "request could not be completed",
	http_error: "request could not be completed",
	bad_content_type: "response is not usable",
	too_large: "response is not usable",
	invalid_json: "response is not usable",
	timeout: "request timed out",
	network_error: "request could not be completed",
};

/** Reads the body up to `maxBytes` before `deadline`. Returns null when over the cap. Throws DeadlineError on a slow drip. */
async function readCapped(
	response: Response,
	maxBytes: number,
	deadline: number,
): Promise<string | null> {
	const declared = response.headers.get("content-length");
	if (declared !== null && Number(declared) > maxBytes) {
		await response.body?.cancel().catch(() => undefined);
		return null;
	}
	if (!response.body) {
		const text = await withDeadline(response.text(), deadline);
		return new TextEncoder().encode(text).length > maxBytes ? null : text;
	}
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		for (;;) {
			const { done, value } = await withDeadline(reader.read(), deadline);
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				void reader.cancel().catch(() => undefined);
				return null;
			}
			chunks.push(value);
		}
	} catch (err) {
		void reader.cancel().catch(() => undefined);
		throw err;
	}
	const merged = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		merged.set(c, offset);
		offset += c.byteLength;
	}
	return new TextDecoder().decode(merged);
}

const reportedUnavailable = new WeakSet<object>();

function emit(onEvent: SafeFetchOptions["onEvent"], event: SafeFetchEvent): void {
	if (!onEvent) return;
	try {
		onEvent(event);
	} catch {
		// Observers must never affect the fetch.
	}
}

/** Fetch a JSON document from an untrusted https URL without exposing the server to SSRF. Never throws. */
export async function safeFetchJson(
	rawUrl: string,
	options: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
	let eventUrl: string | undefined;
	const fail = (reason: SafeFetchFailure, detail: string): SafeFetchResult => {
		emit(options.onEvent, {
			type: "safe_fetch.failed",
			reason,
			detail,
			...(eventUrl ? { url: eventUrl } : {}),
		});
		return { ok: false, reason, message: GENERIC_MESSAGE[reason] };
	};
	try {
		return await run(rawUrl, options, fail, (u) => {
			eventUrl = u;
		});
	} catch (err) {
		return fail("network_error", `unexpected: ${err instanceof Error ? err.message : "unknown"}`);
	}
}

async function run(
	rawUrl: string,
	options: SafeFetchOptions,
	fail: (reason: SafeFetchFailure, detail: string) => SafeFetchResult,
	setEventUrl: (u: string) => void,
): Promise<SafeFetchResult> {
	const loopbackOk = options.allowLoopbackForTests === true;
	const checked = checkFetchableUrl(rawUrl, { allowLoopbackForTests: loopbackOk });
	if (!checked.ok) return fail("invalid_url", checked.message);
	const url = checked.url;
	setEventUrl(`${url.origin}${url.pathname}`);
	const host = url.hostname.toLowerCase().replace(/\.$/, "");
	const isTestLoopback = loopbackOk && LOOPBACK_TEST_HOSTS.has(host);
	let pinAddresses: string[] | null = isTestLoopback
		? [host === "localhost" ? "127.0.0.1" : host.replace(/^\[|\]$/g, "")]
		: null;

	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	// One budget for name resolution, headers and body.
	const deadline = Date.now() + timeoutMs;

	if (!isTestLoopback) {
		const mode = options.resolver ?? "auto";
		let addresses: string[] | null = null;
		if (!isIpLiteral(host)) {
			const screened = screenHostname(host);
			if (!screened.ok) return fail("blocked_host", screened.reason);
		}
		if (isIpLiteral(host)) {
			addresses = [host];
		} else if (mode === "none") {
			addresses = null;
		} else {
			let resolve: DnsResolver | null;
			if (mode === "auto") {
				const hasDns = await withDeadline(loadNodeDns(), deadline).catch(() => null);
				resolve = hasDns ? defaultDnsResolver : null;
				if (!resolve) {
					if (options.onEvent && !reportedUnavailable.has(options.onEvent)) {
						reportedUnavailable.add(options.onEvent);
						emit(options.onEvent, {
							type: "safe_fetch.resolver_unavailable",
							detail:
								"no DNS resolver on this runtime; set resolver to createDohResolver() or a custom resolver, or none for hostname rules only",
						});
					}
					if (options.onResolverUnavailable !== "names_only") {
						return fail("dns_failure", "no DNS resolver on this runtime");
					}
				}
			} else {
				resolve = mode;
			}
			if (resolve) {
				const abort = new AbortController();
				try {
					addresses = await withDeadline(resolve(host, abort.signal), deadline);
				} catch (err) {
					abort.abort();
					if (err instanceof DeadlineError) return fail("timeout", "dns lookup timed out");
					return fail(
						"dns_failure",
						`resolver failed: ${err instanceof Error ? err.message : "unknown"}`,
					);
				}
				if (!Array.isArray(addresses) || addresses.length === 0) {
					return fail("dns_failure", "hostname has no addresses");
				}
			}
		}
		if (addresses?.some((a) => typeof a !== "string" || !isPublicIp(a))) {
			return fail("blocked_host", "host resolves to a non-public address");
		}
		pinAddresses = addresses ?? null;
	}

	// Pinned connect: only where the connection is ours to control and the addresses were vetted.
	const pinnedHttps =
		options.fetchImpl === undefined &&
		options.pinnedConnect !== "off" &&
		pinAddresses !== null &&
		url.protocol === "https:"
			? await withDeadline(loadNodeHttps(), deadline).catch(() => null)
			: null;

	const fetchImpl = options.fetchImpl ?? fetch;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), Math.max(1, deadline - Date.now()));
	try {
		let response: Response;
		try {
			const headers = { Accept: "application/json", "User-Agent": "theauth-cimd/1" };
			response = await withDeadline(
				pinnedHttps && pinAddresses
					? pinnedHttpsGet(pinnedHttps, {
							url,
							addresses: pinAddresses,
							vet: publicVetter(isTestLoopback),
							signal: controller.signal,
							headers,
							...(options.caForTests !== undefined ? { ca: options.caForTests } : {}),
						})
					: fetchImpl(url.toString(), {
							method: "GET",
							headers,
							redirect: "manual",
							credentials: "omit",
							cache: "no-store",
							referrer: "",
							referrerPolicy: "no-referrer",
							signal: controller.signal,
						}),
				deadline,
			);
		} catch (err) {
			controller.abort();
			if (err instanceof PinnedConnectRefused) {
				return fail("blocked_host", `connection refused: ${err.message}`);
			}
			if (
				err instanceof DeadlineError ||
				(err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError"))
			) {
				return fail("timeout", "headers not received in time");
			}
			return fail(
				"network_error",
				`fetch failed: ${err instanceof Error ? err.message : "unknown"}`,
			);
		}

		if (response.status >= 300 && response.status < 400) {
			void response.body?.cancel().catch(() => undefined);
			return fail("redirect", `redirect status ${response.status}`);
		}
		// Opaque redirect responses (type "opaqueredirect") report status 0.
		if (response.type === "opaqueredirect") return fail("redirect", "opaque redirect");
		if (response.status !== 200) {
			void response.body?.cancel().catch(() => undefined);
			return fail("http_error", `unexpected status ${response.status}`);
		}

		const contentType =
			(response.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
		if (
			contentType !== "application/json" &&
			!/^application\/[a-z0-9.+-]+\+json$/.test(contentType)
		) {
			void response.body?.cancel().catch(() => undefined);
			return fail("bad_content_type", `content type ${contentType || "missing"}`);
		}

		let text: string | null;
		try {
			text = await readCapped(response, maxBytes, deadline);
		} catch (err) {
			controller.abort();
			if (err instanceof DeadlineError) return fail("timeout", "body not received in time");
			if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
				return fail("timeout", "body aborted");
			}
			return fail("network_error", "failed to read response");
		}
		if (text === null) return fail("too_large", `response exceeds ${maxBytes} bytes`);

		try {
			const cacheControl = response.headers.get("cache-control");
			return {
				ok: true,
				json: JSON.parse(text) as unknown,
				...(cacheControl !== null ? { cacheControl } : {}),
			};
		} catch {
			return fail("invalid_json", "response is not valid JSON");
		}
	} finally {
		clearTimeout(timer);
	}
}
