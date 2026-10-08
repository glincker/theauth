/**
 * SSRF-safe JSON fetcher.
 *
 * Used to retrieve Client ID Metadata Documents from URLs that an
 * unauthenticated party chose. The fetcher:
 *
 * - accepts https URLs only, with no credentials and the default port;
 * - resolves the hostname and rejects loopback, private (RFC 1918), link-local,
 *   carrier-grade NAT, multicast, unique-local IPv6 and cloud metadata ranges;
 * - never follows redirects (`redirect: "manual"`, any 3xx fails);
 * - enforces a small body cap while streaming;
 * - accepts `application/json` (or `+json`) responses only;
 * - times out;
 * - fails closed: every error becomes an `{ ok: false }` result.
 *
 * Residual risk: the platform `fetch` resolves the name again when it connects,
 * so a DNS rebinding attacker with a very short TTL can still win the race
 * between our check and the connection. Deployments that need to close that gap
 * pass a `fetchImpl` that pins the connection to the validated address.
 */

export type DnsResolver = (hostname: string) => Promise<string[]>;

export interface SafeFetchOptions {
	/** Resolve a hostname to IP address strings. Defaults to Node's dns lookup. */
	resolver?: DnsResolver;
	/** Fetch implementation. Defaults to global fetch. */
	fetchImpl?: typeof fetch;
	/** Maximum response body size in bytes. Default 5120. */
	maxBytes?: number;
	/** Timeout in milliseconds. Default 5000. */
	timeoutMs?: number;
}

export type SafeFetchResult =
	| { ok: true; json: unknown }
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

// ─── IP classification ──────────────────────────────────────────────────────

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

/**
 * True when the address is loopback, private, link-local, metadata, multicast
 * or otherwise not a routable public address. Unparseable input counts as
 * blocked (fail closed).
 */
export function isBlockedIp(address: string): boolean {
	const trimmed = address.trim().replace(/^\[|\]$/g, "");
	const v4 = parseIPv4(trimmed);
	if (v4) return isBlockedIPv4(v4);
	const v6 = parseIPv6(trimmed);
	if (v6) return isBlockedIPv6(v6);
	return true;
}

function isIpLiteral(host: string): boolean {
	const h = host.replace(/^\[|\]$/g, "");
	return parseIPv4(h) !== null || h.includes(":");
}

// ─── DNS ────────────────────────────────────────────────────────────────────

/**
 * Default resolver: Node's `dns.lookup` with `all: true`. On runtimes without
 * `node:dns` the import fails and the fetch is rejected (fail closed); pass a
 * `resolver` there.
 */
export const defaultDnsResolver: DnsResolver = async (hostname) => {
	const dns = await import("node:dns/promises");
	const records = await dns.lookup(hostname, { all: true, verbatim: true });
	return records.map((r) => r.address);
};

// ─── Fetch ──────────────────────────────────────────────────────────────────

/** Check a URL's scheme, authority and host. Returns a failure or the parsed URL. */
export function checkFetchableUrl(
	raw: string,
): { ok: true; url: URL } | { ok: false; message: string } {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return { ok: false, message: "not a valid URL" };
	}
	if (url.protocol !== "https:") return { ok: false, message: "only https URLs are allowed" };
	if (url.username || url.password) return { ok: false, message: "credentials in URL" };
	if (url.port && url.port !== "443") return { ok: false, message: "non-default port" };
	const host = url.hostname.toLowerCase().replace(/\.$/, "");
	if (!host) return { ok: false, message: "empty host" };
	if (BLOCKED_HOSTNAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
		return { ok: false, message: "host is not allowed" };
	}
	return { ok: true, url };
}

async function readCapped(response: Response, maxBytes: number): Promise<string | null> {
	const declared = response.headers.get("content-length");
	if (declared !== null && Number(declared) > maxBytes) return null;
	if (!response.body) {
		const text = await response.text();
		return new TextEncoder().encode(text).length > maxBytes ? null : text;
	}
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel().catch(() => undefined);
			return null;
		}
		chunks.push(value);
	}
	const merged = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		merged.set(c, offset);
		offset += c.byteLength;
	}
	return new TextDecoder().decode(merged);
}

/**
 * Fetch a JSON document from an untrusted https URL without exposing the
 * server to SSRF. Never throws.
 */
export async function safeFetchJson(
	rawUrl: string,
	options: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
	const fail = (reason: SafeFetchFailure, message: string): SafeFetchResult => ({
		ok: false,
		reason,
		message,
	});

	const checked = checkFetchableUrl(rawUrl);
	if (!checked.ok) return fail("invalid_url", checked.message);
	const url = checked.url;
	const host = url.hostname.toLowerCase().replace(/\.$/, "");

	// Resolve and screen every address the name maps to.
	let addresses: string[];
	if (isIpLiteral(host)) {
		addresses = [host];
	} else {
		try {
			addresses = await (options.resolver ?? defaultDnsResolver)(host);
		} catch {
			return fail("dns_failure", "hostname could not be resolved");
		}
	}
	if (addresses.length === 0) return fail("dns_failure", "hostname has no addresses");
	if (addresses.some((a) => isBlockedIp(a))) {
		return fail("blocked_host", "host resolves to a non-public address");
	}

	const fetchImpl = options.fetchImpl ?? fetch;
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	let response: Response;
	try {
		response = await fetchImpl(url.toString(), {
			method: "GET",
			headers: { Accept: "application/json" },
			redirect: "manual",
			credentials: "omit",
			signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
		});
	} catch (err) {
		if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
			return fail("timeout", "request timed out");
		}
		return fail("network_error", "request failed");
	}

	if (response.status >= 300 && response.status < 400) {
		return fail("redirect", "redirects are not followed");
	}
	// Opaque redirect responses (type "opaqueredirect") report status 0.
	if (response.type === "opaqueredirect") return fail("redirect", "redirects are not followed");
	if (!response.ok) return fail("http_error", `unexpected status ${response.status}`);

	const contentType = (response.headers.get("content-type") ?? "").split(";")[0]?.trim() ?? "";
	if (
		contentType.toLowerCase() !== "application/json" &&
		!contentType.toLowerCase().endsWith("+json")
	) {
		return fail("bad_content_type", "response is not JSON");
	}

	let text: string | null;
	try {
		text = await readCapped(response, maxBytes);
	} catch {
		return fail("network_error", "failed to read response");
	}
	if (text === null) return fail("too_large", `response exceeds ${maxBytes} bytes`);

	try {
		return { ok: true, json: JSON.parse(text) as unknown };
	} catch {
		return fail("invalid_json", "response is not valid JSON");
	}
}
