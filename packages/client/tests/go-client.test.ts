import { afterEach, describe, expect, it, vi } from "vitest";
import { createTheAuthGoClient } from "../src/go-client.js";
import { base64UrlToBuffer, bufferToBase64Url } from "../src/webauthn.js";

interface Reply {
	status: number;
	body?: unknown;
	headers?: Record<string, string>;
}

type Client = ReturnType<typeof createTheAuthGoClient>;

function reply(r: Reply) {
	let text = "";
	if (typeof r.body === "string") text = r.body;
	else if (r.body !== undefined) text = JSON.stringify(r.body);
	return {
		ok: r.status >= 200 && r.status < 300,
		status: r.status,
		headers: new Headers(r.headers),
		text: () => Promise.resolve(text),
	};
}

function stubFetch(r: Reply) {
	return vi.fn().mockResolvedValue(reply(r));
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("login", () => {
	const cases: Array<[string, Reply, unknown]> = [
		["full session", { status: 200, body: { ok: true, step: "full" } }, { status: "ok" }],
		["totp required", { status: 200, body: { step: "totp_required" } }, { status: "mfa_required" }],
	];
	it.each(cases)("maps %s", async (_name, r, expected) => {
		const fetchFn = stubFetch(r);
		const res = await createTheAuthGoClient({ fetch: fetchFn }).login({
			email: "a@b.co",
			password: "pw",
		});
		expect(res).toEqual({ success: true, data: expected });
		const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/auth/email-password/signin");
		expect(init.method).toBe("POST");
		expect(init.credentials).toBe("include");
		expect(JSON.parse(init.body as string)).toEqual({ email: "a@b.co", password: "pw" });
	});

	it("honours baseUrl and basePath", async () => {
		const fetchFn = stubFetch({ status: 200, body: { ok: true } });
		const client = createTheAuthGoClient({
			baseUrl: "https://x.test/",
			basePath: "/api/auth",
			fetch: fetchFn,
		});
		await client.login({ email: "a", password: "b" });
		expect(fetchFn.mock.calls[0]?.[0]).toBe("https://x.test/api/auth/email-password/signin");
	});

	const errors: Array<[string, Reply, { code: string; status: number; retryAfter?: number }]> = [
		[
			"invalid credentials",
			{ status: 401, body: { code: "INVALID_CREDENTIALS", message: "bad" } },
			{ code: "INVALID_CREDENTIALS", status: 401 },
		],
		[
			"rate limited",
			{
				status: 429,
				body: { code: "RATE_LIMITED", message: "slow" },
				headers: { "Retry-After": "30" },
			},
			{ code: "RATE_LIMITED", status: 429, retryAfter: 30 },
		],
		["plain text body", { status: 400, body: "invalid body" }, { code: "HTTP_ERROR", status: 400 }],
	];
	it.each(errors)("returns typed error for %s", async (_n, r, expected) => {
		const res = await createTheAuthGoClient({ fetch: stubFetch(r) }).login({
			email: "a",
			password: "b",
		});
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error).toMatchObject(expected);
	});

	it("returns NETWORK_ERROR when fetch rejects", async () => {
		const client = createTheAuthGoClient({ fetch: vi.fn().mockRejectedValue(new Error("down")) });
		const res = await client.login({ email: "a", password: "b" });
		expect(res).toEqual({
			success: false,
			error: { code: "NETWORK_ERROR", message: "down", status: 0 },
		});
	});
});

describe("plain routes", () => {
	const cases: Array<[string, (c: Client) => Promise<unknown>, Reply, string, string]> = [
		["logout", (c) => c.logout(), { status: 204 }, "DELETE", "/auth/sessions/current"],
		["session.get", (c) => c.session.get(), { status: 200, body: { id: "u1" } }, "GET", "/auth/me"],
		[
			"passkeys.list",
			(c) => c.passkeys.list(),
			{ status: 200, body: [] },
			"GET",
			"/auth/webauthn/credentials",
		],
		[
			"passkeys.remove",
			(c) => c.passkeys.remove("01X"),
			{ status: 204 },
			"DELETE",
			"/auth/webauthn/credentials/01X",
		],
		[
			"totp.enrollBegin",
			(c) => c.totp.enrollBegin(),
			{ status: 200, body: { enrollmentId: "e" } },
			"POST",
			"/auth/totp/enroll/begin",
		],
		[
			"totp.enrollFinish",
			(c) => c.totp.enrollFinish({ enrollmentId: "e", code: "1" }),
			{ status: 200, body: { recoveryCodes: ["a"] } },
			"POST",
			"/auth/totp/enroll/finish",
		],
		[
			"totp.verify",
			(c) => c.totp.verify("123456"),
			{ status: 200, body: { ok: true } },
			"POST",
			"/auth/totp/verify",
		],
		[
			"totp.recovery",
			(c) => c.totp.recovery("abc"),
			{ status: 200, body: { ok: true } },
			"POST",
			"/auth/totp/recovery",
		],
		["totp.disable", (c) => c.totp.disable(), { status: 204 }, "DELETE", "/auth/totp/"],
	];
	it.each(cases)("%s hits the right route", async (_n, run, r, method, path) => {
		const fetchFn = stubFetch(r);
		const res = (await run(createTheAuthGoClient({ fetch: fetchFn }))) as { success: boolean };
		expect(res.success).toBe(true);
		const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(path);
		expect(init.method).toBe(method);
	});
});

describe("passkeys", () => {
	it("reports unsupported without WebAuthn", async () => {
		const fetchFn = stubFetch({ status: 200, body: {} });
		const res = await createTheAuthGoClient({ fetch: fetchFn }).passkeys.register();
		expect(res).toMatchObject({ success: false, error: { code: "PASSKEY_UNSUPPORTED" } });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("round-trips a registration ceremony", async () => {
		class FakeCredential {
			id = "cred";
			type = "public-key";
			rawId = new Uint8Array([1, 2, 3]).buffer;
			authenticatorAttachment = null;
			response = {
				clientDataJSON: new Uint8Array([4]).buffer,
				attestationObject: new Uint8Array([5]).buffer,
				getTransports: () => ["internal"],
			};
			getClientExtensionResults() {
				return {};
			}
		}
		const create = vi.fn().mockResolvedValue(new FakeCredential());
		vi.stubGlobal("window", { PublicKeyCredential: FakeCredential });
		vi.stubGlobal("PublicKeyCredential", FakeCredential);
		vi.stubGlobal("navigator", { credentials: { create } });

		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(
				reply({
					status: 200,
					body: {
						publicKey: {
							challenge: "AQID",
							rp: { name: "x" },
							user: { id: "BAU", name: "a", displayName: "a" },
							pubKeyCredParams: [],
							excludeCredentials: [{ id: "Bg", type: "public-key" }],
						},
					},
				}),
			)
			.mockResolvedValueOnce(reply({ status: 201, body: { id: "p1", name: "Laptop" } }));
		const res = await createTheAuthGoClient({ fetch: fetchFn }).passkeys.register("Laptop");

		expect(res).toEqual({ success: true, data: { id: "p1", name: "Laptop" } });
		const opts = create.mock.calls[0]?.[0].publicKey;
		expect(new Uint8Array(opts.challenge)).toEqual(new Uint8Array([1, 2, 3]));
		expect(new Uint8Array(opts.excludeCredentials[0].id)).toEqual(new Uint8Array([6]));
		const [url, init] = fetchFn.mock.calls[1] as [string, RequestInit];
		expect(url).toBe("/auth/webauthn/register/finish?name=Laptop");
		const sent = JSON.parse(init.body as string);
		expect(sent.rawId).toBe("AQID");
		expect(sent.response.attestationObject).toBe("BQ");
	});

	it("maps NotAllowedError to PASSKEY_CANCELLED", async () => {
		class FakeCredential {}
		vi.stubGlobal("window", { PublicKeyCredential: FakeCredential });
		vi.stubGlobal("navigator", {
			credentials: { get: vi.fn().mockRejectedValue(new DOMException("no", "NotAllowedError")) },
		});
		const fetchFn = stubFetch({ status: 200, body: { publicKey: { challenge: "AQID" } } });
		const res = await createTheAuthGoClient({ fetch: fetchFn }).passkeys.login();
		expect(res).toMatchObject({ success: false, error: { code: "PASSKEY_CANCELLED" } });
	});
});

describe("base64url helpers", () => {
	it("round-trips bytes", () => {
		const bytes = new Uint8Array([250, 251, 252, 253, 254, 255]);
		const encoded = bufferToBase64Url(bytes.buffer);
		expect(encoded).not.toMatch(/[+/=]/);
		expect(new Uint8Array(base64UrlToBuffer(encoded))).toEqual(bytes);
	});
});
