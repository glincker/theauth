import { afterEach, describe, expect, it, vi } from "vitest";
import { postmark } from "../src/email/postmark.js";
import { ses } from "../src/email/ses.js";

const MAIL = { to: "u@example.com", subject: "Hi", html: "<p>Hi</p>", text: "Hi" };

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("postmark", () => {
	it("requires a server token", () => {
		expect(() => postmark({ serverToken: "" })).toThrow(/serverToken/);
	});

	it("posts to the Postmark API and returns the message id", async () => {
		const fetchMock = vi.fn(
			async () => new Response(JSON.stringify({ MessageID: "m-1" }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		const result = await postmark({ serverToken: "tok", from: "a@b.com" }).send(MAIL);
		expect(result.id).toBe("m-1");
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.postmarkapp.com/email");
		expect((init.headers as Record<string, string>)["X-Postmark-Server-Token"]).toBe("tok");
		const body = JSON.parse(String(init.body)) as Record<string, string>;
		expect(body).toMatchObject({
			From: "a@b.com",
			To: MAIL.to,
			HtmlBody: MAIL.html,
			TextBody: "Hi",
		});
	});

	it("throws on a non-ok response", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("bad", { status: 422 })),
		);
		await expect(postmark({ serverToken: "tok" }).send(MAIL)).rejects.toThrow(/422/);
	});
});

describe("ses", () => {
	const cfg = {
		region: "us-east-1",
		accessKeyId: "AKIDEXAMPLE",
		secretAccessKey: "secret",
		from: "a@b.com",
	};

	it("validates credentials", () => {
		expect(() => ses({ ...cfg, accessKeyId: "" })).toThrow(/required/);
	});

	it("sends a SigV4 signed SES v2 request", async () => {
		const fetchMock = vi.fn(
			async () => new Response(JSON.stringify({ MessageId: "ses-1" }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		const result = await ses({ ...cfg, sessionToken: "sess" }).send(MAIL);
		expect(result.id).toBe("ses-1");
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://email.us-east-1.amazonaws.com/v2/email/outbound-emails");
		const h = init.headers as Record<string, string>;
		expect(h.Authorization).toMatch(
			/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/us-east-1\/ses\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$/,
		);
		expect(h["x-amz-security-token"]).toBe("sess");
		const body = JSON.parse(String(init.body)) as {
			FromEmailAddress: string;
			Destination: { ToAddresses: string[] };
		};
		expect(body.FromEmailAddress).toBe("a@b.com");
		expect(body.Destination.ToAddresses).toEqual([MAIL.to]);
	});

	it("produces a deterministic signature for a fixed clock", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-10-08T12:00:00Z"));
		const sigs: string[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_u: string, init: RequestInit) => {
				sigs.push((init.headers as Record<string, string>).Authorization ?? "");
				return new Response("{}", { status: 200 });
			}),
		);
		await ses(cfg).send(MAIL);
		await ses(cfg).send(MAIL);
		vi.useRealTimers();
		expect(sigs[0]).toBe(sigs[1]);
		expect(sigs[0]).toContain("20261008/us-east-1/ses/aws4_request");
	});

	it("throws on a non-ok response", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("denied", { status: 403 })),
		);
		await expect(ses(cfg).send(MAIL)).rejects.toThrow(/403/);
	});
});
