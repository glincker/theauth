/** CIMD client_id URL rules, hostname screening and IP classification. */
import { describe, expect, it } from "vitest";
import {
	canonicalizeClientIdUrl,
	checkClientIdUrl,
	classifyIp,
	looksLikeCimdClientId,
	matchesHostPattern,
	screenHostname,
} from "../src/mcp/cimd-url.js";

/** Full client_id table: every row is run through checkClientIdUrl. */
const ACCEPTED_URLS: string[] = [
	"https://client.example/c",
	"https://app.example/oauth/client.json",
	"https://app.example/a/b/c",
	"https://sub.app.example/c",
	"https://app.example/metadata/",
	"https://xn--80ak6aa92e.com/c",
	"https://xn--bcher-kva.example/c",
	"https://a-b.example/c",
	"https://app.example/c-d_e.f~g",
	"https://app.example/%7Euser/c",
	"https://app.example/c%20x",
	"https://app.example/c=1;v=2",
	"https://app.example/.well-known/client",
	"https://app.example/a..b",
	"https://app.example/...",
	"https://123.example/c",
	"https://app1.example.com/c",
	"https://a.b.c.d.e.example.com/c",
	"https://modelcontextprotocol.io/clients/x.json",
	"https://example.com/ünicode".replaceAll("ü", "%C3%BC"),
];

const REFUSED_URLS: Array<[string, string]> = [
	["http://client.example/c", "scheme"],
	["HTTPS://client.example/c", "scheme upper"],
	["ftp://client.example/c", "ftp"],
	["//client.example/c", "scheme relative"],
	["client.example/c", "no scheme"],
	["", "empty"],
	["https://", "no host"],
	["https:///c", "empty authority"],
	["https:/client.example/c", "single slash"],
	["https://u:p@client.example/c", "userinfo"],
	["https://u@client.example/c", "user only"],
	["https://client.example@evil.example/c", "userinfo trick"],
	["https://client.example%40evil.example/c", "encoded at"],
	["https://evil.example\\@client.example/c", "backslash userinfo"],
	["https://client.example\\.evil.example/c", "backslash host"],
	["https://client.example/c\\d", "backslash path"],
	["https://client.example/c%5Cd", "encoded backslash"],
	["https://client.example/c%5cd", "encoded backslash lower"],
	["https://client.example/a%2Fb", "encoded slash"],
	["https://client.example/a%2fb", "encoded slash lower"],
	["https://client.example/a%252Fb", "double encoded slash"],
	["https://client.example/a%252e%252e/c", "double encoded dots"],
	["https://client.example/a/%2e%2e/c", "encoded dot dot"],
	["https://client.example/a/%2E%2E/c", "encoded dot dot upper"],
	["https://client.example/a/%2e/c", "encoded dot"],
	["https://client.example/a/.%2e/c", "mixed dot"],
	["https://client.example/a/../c", "dot dot"],
	["https://client.example/a/./c", "dot"],
	["https://client.example/..", "trailing dot dot"],
	["https://client.example/c/..", "trailing dot dot 2"],
	["https://client.example/c/.", "trailing dot"],
	["https://client.example//c", "empty first segment"],
	["https://client.example/a//c", "empty middle segment"],
	["https://client.example/c%00", "encoded nul"],
	["https://client.example/c%", "dangling percent"],
	["https://client.example/c%zz", "bad percent"],
	["https://client.example/", "root path"],
	["https://client.example", "no path"],
	["https://client.example/c?x=1", "query"],
	["https://client.example/c?", "empty query"],
	["https://client.example?x=1", "query no path"],
	["https://client.example/c#f", "fragment"],
	["https://client.example/c#", "empty fragment"],
	["https://client.example/c?a#b", "query and fragment"],
	["https://client.example:8443/c", "port"],
	["https://client.example:443/c", "explicit default port"],
	["https://client.example:80/c", "port 80"],
	["https://client.example:/c", "empty port"],
	["https://Client.Example/c", "uppercase host"],
	["https://client.example./c", "trailing dot host"],
	["https://client.example../c", "two trailing dots"],
	["https://client..example/c", "empty label"],
	["https://.client.example/c", "leading dot"],
	["https://-client.example/c", "leading hyphen"],
	["https://client-.example/c", "trailing hyphen"],
	["https://cli_ent.example/c", "underscore"],
	["https://cli ent.example/c", "space in host"],
	["https://client.example/c d", "space in path"],
	["https://client.example/c\td", "tab in path"],
	["https://client.example/c\nd", "newline in path"],
	["https://client.example/c\r\nHost: evil", "crlf"],
	["https://client.example/c\u0000", "nul char"],
	["https://client.example/\u202ec", "bidi override"],
	["https://client.example/c\u200b", "zero width space"],
	["https://client.example/c\u00a0", "nbsp"],
	["https://client.example/é", "non ascii path"],
	["https://münchen.example/c", "idn unicode host"],
	["https://аpple.com/c", "cyrillic a homograph"],
	["https://pаypal.com/c", "cyrillic a homograph 2"],
	["https://ехаmple.com/c", "cyrillic homograph 3"],
	["https://ａpple.com/c", "fullwidth a"],
	["https://client.example／c", "fullwidth slash"],
	["https://client。example/c", "ideographic full stop"],
	["https://%63lient.example/c", "percent encoded host"],
	[`https://client.example/c${"a".repeat(2040)}`, "too long"],
	["https://localhost/c", "localhost"],
	["https://LOCALHOST/c", "LOCALHOST"],
	["https://localhost./c", "localhost dot"],
	["https://127.0.0.1/c", "loopback"],
	["https://2130706433/c", "decimal ip"],
	["https://0x7f.1/c", "hex partial ip"],
	["https://0x7f000001/c", "hex ip"],
	["https://017700000001/c", "octal ip"],
	["https://0177.0.0.1/c", "octal dotted ip"],
	["https://127.1/c", "partial ip"],
	["https://127.0.1/c", "partial ip 3"],
	["https://[::1]/c", "ipv6 loopback"],
	["https://[::ffff:10.0.0.1]/c", "mapped ipv6"],
	["https://[fd00:ec2::254]/c", "aws v6 metadata"],
	["https://[2606:4700::1111]/c", "public ipv6 literal"],
	["https://93.184.216.34/c", "public ipv4 literal"],
	["https://169.254.169.254/latest", "metadata"],
	["https://metadata.google.internal/c", "gcp metadata"],
	["https://intranet/c", "single label"],
	["https://a.local/c", "mdns"],
	["https://a.internal/c", "internal"],
	["https://a.home.arpa/c", "home arpa"],
	["https://a.lan/c", "lan"],
	["https://x.localtest.me/c", "localtest"],
	["https://lvh.me/c", "lvh"],
	["https://10.0.0.1.nip.io/c", "nip"],
	["https://127-0-0-1.sslip.io/c", "sslip"],
	["https://10.0.0.1.example.com/c", "ip in labels"],
	["https://192-168-1-1.example.com/c", "ip in dashed labels"],
];

describe("checkClientIdUrl", () => {
	it.each(ACCEPTED_URLS)("accepts %s", (raw) => {
		const r = checkClientIdUrl(raw);
		expect(r.ok).toBe(true);
		if (r.ok) expect(r.url.href).toBe(raw);
	});

	it.each(REFUSED_URLS)("refuses %s (%s)", (raw) => {
		expect(checkClientIdUrl(raw).ok).toBe(false);
	});

	it("returns the host of an accepted id", () => {
		const r = checkClientIdUrl("https://Sub.App.example/c".replace("Sub.App", "sub.app"));
		expect(r).toMatchObject({ ok: true, host: "sub.app.example" });
	});

	it("exposes a human readable reason without echoing the input", () => {
		const r = checkClientIdUrl("https://client.example/c?x=1");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.reason).not.toContain("x=1");
	});

	it("accepts the exact length limit and refuses one over", () => {
		const prefix = "https://client.example/";
		const ok = prefix + "a".repeat(2048 - prefix.length);
		expect(checkClientIdUrl(ok).ok).toBe(true);
		expect(checkClientIdUrl(`${ok}a`).ok).toBe(false);
	});

	it("refuses non strings", () => {
		expect(checkClientIdUrl(undefined as unknown as string).ok).toBe(false);
		expect(checkClientIdUrl(42 as unknown as string).ok).toBe(false);
	});
});

describe("canonicalizeClientIdUrl", () => {
	it.each([
		["https://Client.Example/c", "https://client.example/c"],
		["https://client.example:443/c", "https://client.example/c"],
		["HTTPS://client.example/c", "https://client.example/c"],
		["https://client.example./c", "https://client.example/c"],
		["https://münchen.example/c", "https://xn--mnchen-3ya.example/c"],
		["https://аpple.com/c", "https://xn--pple-43d.com/c"],
	])("%s -> %s", (raw, expected) => {
		expect(canonicalizeClientIdUrl(raw)).toBe(expected);
	});

	it.each([
		"https://client.example/c?x=1",
		"https://client.example:8443/c",
		"https://client.example/a/../c",
		"https://127.0.0.1/c",
		"https://u:p@client.example/c",
		"http://client.example/c",
		"https://client.example/",
	])("returns null for %s", (raw) => {
		expect(canonicalizeClientIdUrl(raw)).toBeNull();
	});

	it("produces output that the strict checker accepts", () => {
		const c = canonicalizeClientIdUrl("https://Client.Example:443/c");
		expect(c).not.toBeNull();
		expect(checkClientIdUrl(c as string).ok).toBe(true);
	});
});

describe("looksLikeCimdClientId", () => {
	it("is a cheap https prefix test", () => {
		expect(looksLikeCimdClientId("https://x")).toBe(true);
		expect(looksLikeCimdClientId("http://x")).toBe(false);
		expect(looksLikeCimdClientId("client_123")).toBe(false);
		expect(looksLikeCimdClientId("")).toBe(false);
	});
});

const ALLOWED_HOSTS = [
	"client.example",
	"app.example.com",
	"a.b.c.example.org",
	"xn--80ak6aa92e.com",
	"xn--mnchen-3ya.example",
	"münchen.example",
	"EXAMPLE.COM",
	"example.com.",
	"my-app.example.com",
	"app1.example.io",
	"v1-2-3.example.com",
	"modelcontextprotocol.io",
	"localhost-app.example.com",
	"nipio.example.com",
	"mylocal.example.com",
	"internal-tools.example.com",
];

const BLOCKED_HOSTS = [
	"localhost",
	"LOCALHOST",
	"localhost.",
	"foo.localhost",
	"127.0.0.1",
	"127.1",
	"127.0.1",
	"2130706433",
	"0x7f000001",
	"0x7f.1",
	"0x7f.0x0.0x0.0x1",
	"017700000001",
	"0177.0.0.1",
	"0.0.0.0",
	"0",
	"10.0.0.1",
	"172.16.0.1",
	"192.168.0.1",
	"169.254.169.254",
	"100.100.100.200",
	"255.255.255.255",
	"93.184.216.34",
	"８.８.８.８",
	"127。0。0。1",
	"[::1]",
	"::1",
	"[::ffff:10.0.0.1]",
	"::ffff:7f00:1",
	"[fd00:ec2::254]",
	"[fe80::1]",
	"fe80::1%eth0",
	"[fe80::1%25eth0]",
	"[2606:4700::1111]",
	"[::]",
	"[::ffff:127.0.0.1]",
	"[64:ff9b::7f00:1]",
	"[2002:7f00:1::]",
	"intranet",
	"printer",
	"a",
	"metadata",
	"metadata.google.internal",
	"instance-data",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local",
	"svc.cluster.local",
	"a.local",
	"a.b.local",
	"a.internal",
	"ip-10-0-0-1.ec2.internal",
	"a.localdomain",
	"a.home.arpa",
	"x.in-addr.arpa",
	"a.lan",
	"a.home",
	"a.corp",
	"a.intranet",
	"a.private",
	"a.test",
	"a.invalid",
	"abc.onion",
	"web.consul",
	"a.cluster",
	"a.svc",
	"a.docker",
	"10.0.0.1.nip.io",
	"nip.io",
	"127-0-0-1.sslip.io",
	"a.xip.io",
	"a.traefik.me",
	"lvh.me",
	"x.localtest.me",
	"localtest.me",
	"foo.vcap.me",
	"a.lacolhost.com",
	"7f000001.c0a80001.rbndr.us",
	"a.local.gd",
	"a.localh.st",
	"10.0.0.1.example.com",
	"192-168-1-1.example.com",
	"a.169.254.169.254.example.com",
	"x-127-0-0-1.example.com",
	"example.123",
	"1.2.3.4.5",
	"a..b.example",
	".example.com",
	"-a.example.com",
	"a-.example.com",
	"cli_ent.example.com",
	"a b.example.com",
	"example.com/path",
	"example.com?x",
	"example.com#x",
	"user@example.com",
	"example.com:443",
	"example.com\\evil.com",
	"exa%6dple.com",
	"",
	`${"a".repeat(64)}.example.com`,
	`${"a.".repeat(130)}com`,
];

describe("screenHostname", () => {
	it.each(ALLOWED_HOSTS)("allows %s", (host) => {
		expect(screenHostname(host).ok).toBe(true);
	});

	it.each(BLOCKED_HOSTS)("blocks %j", (host) => {
		const r = screenHostname(host);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.code).toBe("blocked_host");
	});

	it("returns the normalized host", () => {
		expect(screenHostname("EXAMPLE.COM.")).toEqual({ ok: true, host: "example.com" });
		expect(screenHostname("münchen.example")).toEqual({
			ok: true,
			host: "xn--mnchen-3ya.example",
		});
	});

	it("never lets allowedHosts override a name rule", () => {
		expect(screenHostname("localhost", { allowedHosts: ["localhost"] }).ok).toBe(false);
		expect(screenHostname("a.internal", { allowedHosts: ["*.internal"] }).ok).toBe(false);
		expect(screenHostname("127.0.0.1", { allowedHosts: ["127.0.0.1"] }).ok).toBe(false);
	});

	it("applies deniedHosts before allowedHosts", () => {
		const policy = { allowedHosts: ["*.example.com"], deniedHosts: ["bad.example.com"] };
		expect(screenHostname("bad.example.com", policy)).toMatchObject({
			ok: false,
			code: "host_not_allowed",
		});
		expect(screenHostname("good.example.com", policy).ok).toBe(true);
	});

	it("denies subdomains with a wildcard deny pattern", () => {
		const policy = { deniedHosts: ["*.evil.example"] };
		expect(screenHostname("a.evil.example", policy).ok).toBe(false);
		expect(screenHostname("evil.example", policy).ok).toBe(true);
	});

	it("requires a match when allowedHosts is set", () => {
		expect(screenHostname("other.example", { allowedHosts: ["app.example"] })).toMatchObject({
			ok: false,
			code: "host_not_allowed",
		});
		expect(screenHostname("app.example", { allowedHosts: ["app.example"] }).ok).toBe(true);
		expect(screenHostname("sub.app.example", { allowedHosts: ["app.example"] }).ok).toBe(false);
	});

	it("fails closed on an empty allow list", () => {
		expect(screenHostname("app.example", { allowedHosts: [] }).ok).toBe(false);
	});

	it("is case and trailing dot insensitive for policies", () => {
		expect(screenHostname("APP.example.", { allowedHosts: ["App.Example"] }).ok).toBe(true);
	});
});

describe("matchesHostPattern", () => {
	it.each([
		["a.com", "a.com", true],
		["A.COM.", "a.com", true],
		["b.a.com", "a.com", false],
		["b.a.com", "*.a.com", true],
		["c.b.a.com", "*.a.com", true],
		["a.com", "*.a.com", false],
		["xa.com", "*.a.com", false],
		["evila.com", "*.a.com", false],
		["a.com.evil.com", "*.a.com", false],
		["a.com", "*", false],
		["a.com", "*.", false],
		["a.com", "a.*", false],
		["a.com", "*a.com", false],
		["a.com", "", false],
		["", "a.com", false],
		["x.a.com", "*.*.com", false],
	])("%s vs %s is %s", (host, pattern, expected) => {
		expect(matchesHostPattern(host, pattern)).toBe(expected);
	});
});

const IP_CLASSES: Array<[string, string]> = [
	["8.8.8.8", "public"],
	["93.184.216.34", "public"],
	["1.1.1.1", "public"],
	["172.15.255.255", "public"],
	["172.32.0.1", "public"],
	["100.63.255.255", "public"],
	["100.128.0.1", "public"],
	["2606:4700::1111", "public"],
	["[2606:4700::1111]", "public"],
	["2001:4860:4860::8888", "public"],
	["::ffff:8.8.8.8", "public"],
	["127.0.0.1", "loopback"],
	["127.255.255.254", "loopback"],
	["::1", "loopback"],
	["0:0:0:0:0:0:0:1", "loopback"],
	["::ffff:127.0.0.1", "loopback"],
	["10.0.0.1", "private"],
	["10.255.255.255", "private"],
	["172.16.0.1", "private"],
	["172.31.255.255", "private"],
	["192.168.1.1", "private"],
	["::ffff:10.0.0.1", "private"],
	["::ffff:c0a8:101", "private"],
	["169.254.1.1", "link-local"],
	["fe80::1", "link-local"],
	["febf::1", "link-local"],
	["100.64.0.1", "cgnat"],
	["100.127.255.255", "cgnat"],
	["fc00::1", "unique-local"],
	["fd12:3456::1", "unique-local"],
	["fdff::1", "unique-local"],
	["224.0.0.1", "multicast"],
	["239.255.255.255", "multicast"],
	["ff02::1", "multicast"],
	["240.0.0.1", "reserved"],
	["255.255.255.255", "reserved"],
	["0.1.2.3", "reserved"],
	["192.0.2.1", "reserved"],
	["198.18.0.1", "reserved"],
	["198.51.100.1", "reserved"],
	["203.0.113.1", "reserved"],
	["2001:db8::1", "reserved"],
	["2001::1", "reserved"],
	["fec0::1", "reserved"],
	["100::1", "reserved"],
	["::ffff:0:0:0", "reserved"],
	["::10.0.0.1", "private"],
	["::8.8.8.8", "reserved"],
	["64:ff9b::a00:1", "private"],
	["64:ff9b::808:808", "public"],
	["2002:a00:1::", "private"],
	["2002:808:808::", "public"],
	["1::1", "reserved"],
	["0.0.0.0", "unspecified"],
	["::", "unspecified"],
	["169.254.169.254", "metadata"],
	["169.254.170.2", "metadata"],
	["169.254.169.253", "metadata"],
	["100.100.100.200", "metadata"],
	["168.63.129.16", "metadata"],
	["192.0.0.192", "metadata"],
	["fd00:ec2::254", "metadata"],
	["fd00:ec2::253", "metadata"],
	["::ffff:169.254.169.254", "metadata"],
	["::ffff:a9fe:a9fe", "metadata"],
	["64:ff9b::a9fe:a9fe", "metadata"],
	["", "invalid"],
	["abc", "invalid"],
	["1.2.3", "invalid"],
	["1.2.3.4.5", "invalid"],
	["256.1.1.1", "invalid"],
	["010.0.0.1", "invalid"],
	["1.2.3.04", "invalid"],
	["0x7f.0.0.1", "invalid"],
	["fe80::1%eth0", "invalid"],
	["::g", "invalid"],
	["1:2:3:4:5:6:7:8:9", "invalid"],
	["1::2::3", "invalid"],
	["12345::1", "invalid"],
	[":::1", "invalid"],
];

describe("classifyIp", () => {
	it.each(IP_CLASSES)("%s is %s", (address, expected) => {
		expect(classifyIp(address)).toBe(expected);
	});
});
