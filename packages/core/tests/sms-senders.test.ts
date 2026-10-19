/** SMS senders with a mocked fetch: request shape, error hygiene, config validation. */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { OtpMessage } from "../src/auth/otp-senders.js";
import { twilioOtpSender } from "../src/auth/otp-senders.js";
import { plivoOtpSender, vonageOtpSender } from "../src/auth/sms-senders.js";

const MSG: OtpMessage = {
	channel: "sms",
	to: "+15551112222",
	code: "424242",
	purpose: "sign-in",
	expiresInSeconds: 300,
};

afterEach(() => vi.unstubAllGlobals());

function stub(response: Response) {
	const fetchMock = vi.fn(async () => response);
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

function call(fetchMock: ReturnType<typeof stub>): [string, RequestInit] {
	return fetchMock.mock.calls[0] as unknown as [string, RequestInit];
}

describe("vonageOtpSender", () => {
	it("posts a basic-auth JSON body to the Messages API", async () => {
		const f = stub(new Response("{}", { status: 202 }));
		await vonageOtpSender({ apiKey: "key", apiSecret: "sec", from: "15550000000" }).send(MSG);
		const [url, init] = call(f);
		expect(url).toBe("https://api.nexmo.com/v1/messages");
		expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("key:sec")}`);
		const body = JSON.parse(String(init.body));
		expect(body).toMatchObject({ channel: "sms", message_type: "text", from: "15550000000" });
		expect(body.to).toBe("15551112222");
		expect(body.text).toContain("424242");
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("uses the regional host", async () => {
		const f = stub(new Response("{}", { status: 202 }));
		await vonageOtpSender({ apiKey: "k", apiSecret: "s", from: "Acme", region: "api-eu" }).send(
			MSG,
		);
		expect(call(f)[0]).toBe("https://api-eu.nexmo.com/v1/messages");
	});

	it("keeps secrets, numbers and codes out of errors", async () => {
		const leak = JSON.stringify({
			title: "1170",
			detail: "bad recipient +15551112222 text 424242 sec",
		});
		stub(new Response(leak, { status: 422 }));
		const err = await vonageOtpSender({ apiKey: "key", apiSecret: "sec", from: "x" })
			.send(MSG)
			.catch((e: Error) => e);
		expect((err as Error).message).toMatch(/422/);
		expect((err as Error).message).toMatch(/1170/);
		for (const secret of ["sec", "424242", "5551112222", btoa("key:sec")]) {
			expect((err as Error).message).not.toContain(secret);
		}
	});

	it("rejects the email channel and bad config", async () => {
		const sender = vonageOtpSender({ apiKey: "k", apiSecret: "s", from: "x" });
		await expect(sender.send({ ...MSG, channel: "email" })).rejects.toThrow(/sms channel/);
		expect(() => vonageOtpSender({ apiKey: "", apiSecret: "s", from: "x" })).toThrow(/apiKey/);
		expect(() => vonageOtpSender({ apiKey: "k", apiSecret: "s", from: "" })).toThrow(/from/);
	});
});

describe("plivoOtpSender", () => {
	it("posts a basic-auth JSON body to the Message endpoint", async () => {
		const f = stub(new Response("{}", { status: 202 }));
		await plivoOtpSender({ authId: "MA1", authToken: "tok", from: "+15550000000" }).send(MSG);
		const [url, init] = call(f);
		expect(url).toBe("https://api.plivo.com/v1/Account/MA1/Message/");
		expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("MA1:tok")}`);
		expect(JSON.parse(String(init.body))).toMatchObject({
			src: "+15550000000",
			dst: "+15551112222",
		});
	});

	it("sends powerpack_uuid instead of src", async () => {
		const f = stub(new Response("{}", { status: 202 }));
		await plivoOtpSender({ authId: "MA1", authToken: "t", powerpackUuid: "pp-1" }).send(MSG);
		const body = JSON.parse(String(call(f)[1].body));
		expect(body.powerpack_uuid).toBe("pp-1");
		expect(body.src).toBeUndefined();
	});

	it("keeps the token and body out of errors, and validates config", async () => {
		stub(new Response("not json with tok 424242", { status: 401 }));
		const err = await plivoOtpSender({ authId: "MA1", authToken: "tok", from: "x" })
			.send(MSG)
			.catch((e: Error) => e);
		expect((err as Error).message).toMatch(/401/);
		expect((err as Error).message).not.toContain("tok");
		expect((err as Error).message).not.toContain("424242");
		expect(() => plivoOtpSender({ authId: "a", authToken: "b" })).toThrow(/from/);
		expect(() => plivoOtpSender({ authId: "", authToken: "b", from: "x" })).toThrow(/authId/);
	});
});

describe("twilioOtpSender hardening", () => {
	it("does not copy the response body into the error", async () => {
		stub(
			new Response(JSON.stringify({ code: 21211, message: "bad +15551112222 424242" }), {
				status: 400,
			}),
		);
		const err = await twilioOtpSender({ accountSid: "AC1", authToken: "tok", from: "+1555" })
			.send(MSG)
			.catch((e: Error) => e);
		expect((err as Error).message).toMatch(/400 \(21211\)/);
		expect((err as Error).message).not.toContain("424242");
		expect((err as Error).message).not.toContain("tok");
	});

	it("rejects the email channel", async () => {
		await expect(
			twilioOtpSender({ accountSid: "AC1", authToken: "t", from: "+1" }).send({
				...MSG,
				channel: "email",
			}),
		).rejects.toThrow(/sms channel/);
	});
});
