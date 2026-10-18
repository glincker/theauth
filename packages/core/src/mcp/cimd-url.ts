/**
 * CIMD client_id URL rules and hostname screening. Pure functions, no I/O, no node: imports,
 * so they run unchanged on Cloudflare Workers, Deno and Bun.
 *
 * - `checkClientIdUrl` is the strict parser: a client_id is accepted only when it is already in
 *   canonical form (the draft compares client ids as plain strings).
 * - `canonicalizeClientIdUrl` is the lenient sibling (case, IDN, explicit :443, one trailing dot)
 *   for tooling that wants to suggest the canonical string.
 * - `screenHostname` applies the always-on name rules and the allow and deny policy.
 * - `classifyIp` labels a resolved address so resolvers can refuse non-public answers.
 *
 * None of this stops DNS rebinding; see the design notes in safe-fetch.ts.
 */

export type ClientIdUrlCheck = { ok: true; url: URL; host: string } | { ok: false; reason: string };

export interface HostPolicy {
	/** Exact hosts or "*.example.com" (strict subdomains). When set (even empty), nothing else passes. */
	allowedHosts?: readonly string[];
	/** Same pattern syntax. Checked before allowedHosts. */
	deniedHosts?: readonly string[];
}

export type HostScreen =
	| { ok: true; host: string }
	| { ok: false; reason: string; code: "blocked_host" | "host_not_allowed" };

export type IpClass =
	| "public"
	| "loopback"
	| "private"
	| "link-local"
	| "cgnat"
	| "unique-local"
	| "multicast"
	| "reserved"
	| "metadata"
	| "unspecified"
	| "invalid";

export const MAX_CLIENT_ID_LENGTH = 2048;

const BLOCKED_HOSTNAMES = new Set([
	"localhost",
	"metadata",
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
	"kubernetes",
	"kubernetes.default",
	"kubernetes.default.svc",
]);

const BLOCKED_SUFFIXES = [
	".localhost",
	".local",
	".internal",
	".localdomain",
	".home.arpa",
	".arpa",
	".lan",
	".home",
	".corp",
	".intranet",
	".private",
	".test",
	".invalid",
	".onion",
	".svc",
	".cluster",
	".cluster.local",
	".consul",
	".docker",
	".domain",
	".lcl",
];

const WILDCARD_DNS_DOMAINS = [
	"nip.io",
	"sslip.io",
	"xip.io",
	"traefik.me",
	"lvh.me",
	"localtest.me",
	"vcap.me",
	"lacolhost.com",
	"rbndr.us",
	"local.gd",
	"localh.st",
	"1u.ms",
	"nip.name",
	"xip.name",
];

const IPV4_IN_LABELS = /(^|[.-])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})([.-]|$)/;

function normalizeHostString(host: string): string {
	return host.trim().toLowerCase().replace(/\.$/, "");
}

/** "a.com" matches exactly, "*.a.com" matches strict subdomains only. */
export function matchesHostPattern(host: string, pattern: string): boolean {
	const h = normalizeHostString(host);
	const p = normalizeHostString(pattern);
	if (h === "" || p === "") return false;
	if (p.startsWith("*.")) {
		const base = p.slice(2);
		if (base === "" || base.includes("*")) return false;
		return h.length > base.length + 1 && h.endsWith(`.${base}`);
	}
	if (p.includes("*")) return false;
	return h === p;
}

function labelsValid(host: string): boolean {
	if (host.length > 253) return false;
	for (const label of host.split(".")) {
		if (!/^[a-z0-9-]{1,63}$/.test(label)) return false;
		if (label.startsWith("-") || label.endsWith("-")) return false;
	}
	return true;
}

const blockedName = (reason: string): HostScreen => ({
	ok: false,
	reason,
	code: "blocked_host",
});

/**
 * Always-on hostname rules plus optional allow and deny lists. Accepts what `URL.hostname` yields
 * (and, defensively, raw user strings: IDN, odd IPv4 notations and fullwidth digits are normalized
 * through the WHATWG parser before screening). allowedHosts never overrides a name rule.
 */
export function screenHostname(hostname: string, policy: HostPolicy = {}): HostScreen {
	if (typeof hostname !== "string" || hostname === "" || hostname.length > 260) {
		return blockedName("host is empty or too long");
	}
	if (hostname.includes(":") || hostname.includes("[") || hostname.includes("]")) {
		return blockedName("IP literals and ports are not allowed");
	}
	if (/[\s\p{Cc}\\/?#@%]/u.test(hostname)) return blockedName("invalid host");

	let parsedHost: string;
	try {
		const parsed = new URL(`https://${hostname}/`);
		if (parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.port) {
			return blockedName("invalid host");
		}
		if (parsed.username || parsed.password) return blockedName("invalid host");
		parsedHost = parsed.hostname;
	} catch {
		return blockedName("invalid host");
	}
	const host = parsedHost.toLowerCase().replace(/\.$/, "");
	if (host === "" || host.endsWith(".")) return blockedName("invalid host");
	if (host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
		return blockedName("IP literals are not allowed");
	}
	if (!labelsValid(host)) return blockedName("invalid host");
	if (!host.includes(".")) return blockedName("single-label hosts are not allowed");
	const tld = host.slice(host.lastIndexOf(".") + 1);
	if (!/^(xn--[a-z0-9-]+|[a-z][a-z0-9-]*)$/.test(tld)) {
		return blockedName("numeric top-level domains are not allowed");
	}
	if (BLOCKED_HOSTNAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
		return blockedName("internal host names are not allowed");
	}
	if (WILDCARD_DNS_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) {
		return blockedName("wildcard DNS services are not allowed");
	}
	if (IPV4_IN_LABELS.test(host)) return blockedName("host spells an IP address");

	if (policy.deniedHosts?.some((p) => matchesHostPattern(host, p))) {
		return { ok: false, reason: "host is denied", code: "host_not_allowed" };
	}
	if (policy.allowedHosts && !policy.allowedHosts.some((p) => matchesHostPattern(host, p))) {
		return { ok: false, reason: "host is not on the allow list", code: "host_not_allowed" };
	}
	return { ok: true, host };
}

/** Cheap prefix test, no parsing. */
export function looksLikeCimdClientId(clientId: string): boolean {
	return typeof clientId === "string" && clientId.startsWith("https://");
}

type Structure = { ok: true; url: URL } | { ok: false; reason: string };

function parseStructure(raw: string, canonical: boolean): Structure {
	const fail = (reason: string): Structure => ({ ok: false, reason });
	if (typeof raw !== "string" || raw === "") return fail("client_id is empty");
	if (raw.length > MAX_CLIENT_ID_LENGTH) return fail("client_id is too long");
	if (/[\p{Cc}\p{Cf}\p{Z}\\]/u.test(raw)) {
		return fail("client_id contains control, whitespace or backslash characters");
	}
	if (!canonical && /[^\x21-\x7e]/.test(raw)) return fail("client_id must be ASCII");
	const prefix = canonical ? /^https:\/\//i : /^https:\/\//;
	if (!prefix.test(raw)) return fail("client_id must use https");

	const rest = raw.slice("https://".length);
	const authorityEnd = rest.search(/[/?#]/);
	let authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd);
	const tail = authorityEnd === -1 ? "" : rest.slice(authorityEnd);
	if (authority === "") return fail("client_id has no host");
	if (authority.includes("@")) return fail("client_id must not contain credentials");
	if (canonical) authority = authority.replace(/:443$/, "");
	if (authority.includes("[") || authority.includes("]"))
		return fail("IP literals are not allowed");
	if (authority.includes(":")) return fail("client_id must use the default port");
	if (tail.includes("?")) return fail("client_id must not contain a query");
	if (tail.includes("#")) return fail("client_id must not contain a fragment");
	if (tail === "" || tail === "/") return fail("client_id needs a path");

	if (/%(?![0-9a-fA-F]{2})/.test(tail)) return fail("malformed percent encoding");
	const lower = tail.toLowerCase();
	if (lower.includes("%2f") || lower.includes("%5c")) {
		return fail("encoded slashes and backslashes are not allowed");
	}
	if (lower.includes("%00")) return fail("encoded NUL is not allowed");
	if (lower.includes("%25")) return fail("double percent encoding is not allowed");
	if (lower.includes("%2e")) return fail("encoded dots are not allowed");
	const segments = tail.split("/").slice(1);
	for (let i = 0; i < segments.length; i++) {
		const seg = segments[i];
		if (seg === "." || seg === "..") return fail("dot segments are not allowed");
		if (seg === "" && i < segments.length - 1) return fail("empty path segments are not allowed");
	}

	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return fail("client_id is not a valid URL");
	}
	if (url.protocol !== "https:") return fail("client_id must use https");
	if (url.username || url.password) return fail("client_id must not contain credentials");
	if (url.port) return fail("client_id must use the default port");
	if (url.search || url.hash) return fail("client_id must not contain a query or fragment");
	if (url.hostname.endsWith(".")) {
		if (!canonical) return fail("trailing dot in host is not allowed");
		url.hostname = url.hostname.slice(0, -1);
	}
	if (url.pathname === "/" || url.pathname === "") return fail("client_id needs a path");
	return { ok: true, url };
}

/** Draft section 3 rules plus our policy. The input must already be in canonical form. */
export function checkClientIdUrl(raw: string): ClientIdUrlCheck {
	const parsed = parseStructure(raw, false);
	if (!parsed.ok) return parsed;
	const { url } = parsed;
	if (url.href !== raw) return { ok: false, reason: "client_id is not in canonical form" };
	const screened = screenHostname(url.hostname);
	if (!screened.ok) return { ok: false, reason: screened.reason };
	return { ok: true, url, host: screened.host };
}

/** Lenient form: lowercase host, punycode IDN, drop :443 and one trailing dot. Null when unusable. */
export function canonicalizeClientIdUrl(raw: string): string | null {
	const parsed = parseStructure(raw, true);
	if (!parsed.ok) return null;
	const screened = screenHostname(parsed.url.hostname);
	if (!screened.ok) return null;
	return parsed.url.href;
}

// ---------------------------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------------------------

/** Dotted decimal only. Leading zeros are refused (octal ambiguity), so they fail closed. */
export function parseIPv4Strict(input: string): number[] | null {
	const parts = input.split(".");
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const part of parts) {
		if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
		const n = Number(part);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

/** Eight 16-bit groups, or null when malformed. Zone ids are malformed here. */
export function parseIPv6Strict(input: string): number[] | null {
	let addr = input;
	if (!addr.includes(":") || /[^0-9a-fA-F:.]/.test(addr)) return null;
	const lastColon = addr.lastIndexOf(":");
	const tail = addr.slice(lastColon + 1);
	if (tail.includes(".")) {
		const v4 = parseIPv4Strict(tail);
		if (!v4) return null;
		const hi = ((v4[0] ?? 0) << 8) | (v4[1] ?? 0);
		const lo = ((v4[2] ?? 0) << 8) | (v4[3] ?? 0);
		addr = `${addr.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`;
	}
	const halves = addr.split("::");
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(":") : [];
	const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
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

function classifyV4(o: number[]): IpClass {
	const [a = 0, b = 0, c = 0, d = 0] = o;
	if (
		a === 169 &&
		b === 254 &&
		((c === 169 && (d === 254 || d === 253)) || (c === 170 && d === 2))
	) {
		return "metadata";
	}
	if (a === 100 && b === 100 && c === 100 && d === 200) return "metadata";
	if (a === 168 && b === 63 && c === 129 && d === 16) return "metadata";
	if (a === 192 && b === 0 && c === 0 && d === 192) return "metadata";
	if (a === 0) return o.every((x) => x === 0) ? "unspecified" : "reserved";
	if (a === 10) return "private";
	if (a === 100 && b >= 64 && b <= 127) return "cgnat";
	if (a === 127) return "loopback";
	if (a === 169 && b === 254) return "link-local";
	if (a === 172 && b >= 16 && b <= 31) return "private";
	if (a === 192 && b === 168) return "private";
	if (a === 192 && b === 0 && (c === 0 || c === 2)) return "reserved";
	if (a === 192 && b === 88 && c === 99) return "reserved";
	if (a === 198 && (b === 18 || b === 19)) return "reserved";
	if (a === 198 && b === 51 && c === 100) return "reserved";
	if (a === 203 && b === 0 && c === 113) return "reserved";
	if (a >= 224 && a <= 239) return "multicast";
	if (a >= 240) return "reserved";
	return "public";
}

function embeddedV4(hi: number, lo: number): number[] {
	return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff];
}

function classifyV6(g: number[]): IpClass {
	const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = g;
	const zeroTo3 = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0;
	if (zeroTo3 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 0) return "unspecified";
	if (zeroTo3 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) return "loopback";
	if (zeroTo3 && g4 === 0 && g5 === 0xffff) return classifyV4(embeddedV4(g6, g7));
	if (zeroTo3 && g4 === 0xffff && g5 === 0) return "reserved"; // SIIT ::ffff:0:0:0/96
	if (zeroTo3 && g4 === 0 && g5 === 0) {
		// Deprecated IPv4-compatible ::a.b.c.d, never a legitimate public destination.
		const inner = classifyV4(embeddedV4(g6, g7));
		return inner === "public" ? "reserved" : inner;
	}
	if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
		return classifyV4(embeddedV4(g6, g7)); // NAT64
	}
	if (g0 === 0x64 && g1 === 0xff9b && g2 === 1) return "reserved";
	if (g0 === 0x2002) return classifyV4(embeddedV4(g1, g2)); // 6to4
	if (g0 === 0x2001 && g1 === 0) return "reserved"; // Teredo
	if (g0 === 0xfd00 && g1 === 0x0ec2) return "metadata"; // AWS fd00:ec2::/32
	if ((g0 & 0xfe00) === 0xfc00) return "unique-local";
	if ((g0 & 0xffc0) === 0xfe80) return "link-local";
	if ((g0 & 0xffc0) === 0xfec0) return "reserved"; // site-local
	if ((g0 & 0xff00) === 0xff00) return "multicast";
	if (g0 === 0x2001 && g1 === 0x0db8) return "reserved";
	if (g0 === 0x2001 && g1 === 0x0002 && g2 === 0) return "reserved";
	if (g0 === 0x2001 && (g1 & 0xfff0) === 0x0010) return "reserved"; // ORCHID
	if (g0 === 0x3fff && (g1 & 0xf000) === 0) return "reserved";
	if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return "reserved";
	if (g0 === 0x5f00) return "reserved";
	if ((g0 & 0xe000) !== 0x2000) return "reserved"; // outside 2000::/3
	return "public";
}

/** Label a resolved address. Anything except "public" must be refused. Bad input is "invalid". */
export function classifyIp(address: string): IpClass {
	if (typeof address !== "string") return "invalid";
	const trimmed = address.trim().replace(/^\[|\]$/g, "");
	const v4 = parseIPv4Strict(trimmed);
	if (v4) return classifyV4(v4);
	const v6 = parseIPv6Strict(trimmed);
	if (v6) return classifyV6(v6);
	return "invalid";
}

export function isPublicIp(address: string): boolean {
	return classifyIp(address) === "public";
}
