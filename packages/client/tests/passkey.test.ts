import { afterEach, describe, expect, it, vi } from "vitest";
import { createPasskeyClient } from "../src/passkey.js";

const buf = (...bytes: number[]) => new Uint8Array(bytes).buffer;

function assertionCredential() {
	return {
		id: "cred-1",
		rawId: buf(1, 2, 3),
		type: "public-key",
		authenticatorAttachment: "platform",
		getClientExtensionResults: () => ({}),
		response: {
			clientDataJSON: buf(4),
			authenticatorData: buf(5),
			signature: buf(6),
			userHandle: null,
		},
	};
}

function attestationCredential() {
	return {
		id: "cred-2",
		rawId: buf(9),
		type: "public-key",
		getClientExtensionResults: () => ({}),
		response: {
			clientDataJSON: buf(7),
			attestationObject: buf(8),
			getTransports: () => ["internal"],
		},
	};
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

const SERVER_AUTH_OPTIONS = {
	challenge: "AQID",
	rpId: "example.com",
	timeout: 60000,
	userVerification: "preferred",
	allowCredentials: [],
};
const SERVER_REG_OPTIONS = {
	challenge: "AQID",
	rp: { name: "Example", id: "example.com" },
	user: { id: "dXNlcg", name: "ada@example.com", displayName: "Ada" },
	pubKeyCredParams: [{ type: "public-key", alg: -7 }],
	timeout: 60000,
	attestation: "none",
	authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
	excludeCredentials: [],
};

function stubBrowser(credentials: { get?: unknown; create?: unknown }, conditional = true) {
	vi.stubGlobal("PublicKeyCredential", {
		isConditionalMediationAvailable: async () => conditional,
	});
	vi.stubGlobal("navigator", { credentials });
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("createPasskeyClient", () => {
	it("signs in with a modal prompt and returns the session", async () => {
		const get = vi.fn(async () => assertionCredential());
		stubBrowser({ get });
		const fetchMock = vi.fn(async (url: RequestInfo | URL) =>
			String(url).endsWith("/options")
				? json(SERVER_AUTH_OPTIONS)
				: json({ user: { id: "u1" }, session: { token: "tok" } }),
		);
		const client = createPasskeyClient({
			baseUrl: "/api/theauth/",
			fetch: fetchMock as unknown as typeof fetch,
		});

		const out = await client.signIn();
		expect(out).toEqual({ ok: true, data: { user: { id: "u1" }, session: { token: "tok" } } });
		const call = (get.mock.calls[0] as unknown as [{ mediation?: string }])[0];
		expect(call.mediation).toBeUndefined();
		const verify = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
		expect(verify[0]).toBe("/api/theauth/auth/passkey/authenticate/verify");
		const sent = JSON.parse(String(verify[1].body)) as {
			response: { id: string; response: { signature: string } };
		};
		expect(sent.response.id).toBe("cred-1");
		expect(sent.response.response.signature).toBe("Bg");
	});

	it("asks for conditional mediation and passes the abort signal", async () => {
		const get = vi.fn(async () => assertionCredential());
		stubBrowser({ get });
		const client = createPasskeyClient({
			baseUrl: "/a",
			fetch: (async (url: RequestInfo | URL) =>
				String(url).endsWith("/options")
					? json(SERVER_AUTH_OPTIONS)
					: json({ user: { id: "u1" } })) as unknown as typeof fetch,
		});
		const controller = new AbortController();
		await client.signIn({ conditional: true, signal: controller.signal });
		const call = (
			get.mock.calls[0] as unknown as [{ mediation?: string; signal?: AbortSignal }]
		)[0];
		expect(call.mediation).toBe("conditional");
		expect(call.signal).toBe(controller.signal);
		expect(await client.isConditionalAvailable()).toBe(true);
	});

	it("reports a dismissed prompt as cancelled, not an error", async () => {
		stubBrowser({
			get: async () => {
				throw new DOMException("denied", "NotAllowedError");
			},
		});
		const client = createPasskeyClient({
			baseUrl: "/a",
			fetch: (async () => json(SERVER_AUTH_OPTIONS)) as unknown as typeof fetch,
		});
		const out = await client.signIn();
		expect(out).toMatchObject({ ok: false, reason: "cancelled" });
	});

	it("surfaces a rejected assertion and reports unsupported browsers", async () => {
		stubBrowser({ get: async () => assertionCredential() });
		const client = createPasskeyClient({
			baseUrl: "/a",
			fetch: (async (url: RequestInfo | URL) =>
				String(url).endsWith("/options")
					? json(SERVER_AUTH_OPTIONS)
					: json({ error: "Authentication failed" }, 401)) as unknown as typeof fetch,
		});
		expect(await client.signIn()).toMatchObject({
			ok: false,
			reason: "failed",
			status: 401,
			message: "Authentication failed",
		});

		vi.unstubAllGlobals();
		vi.stubGlobal("navigator", {});
		expect(client.isSupported()).toBe(false);
		expect(await client.signIn()).toMatchObject({ ok: false, reason: "unsupported" });
		expect(await client.isConditionalAvailable()).toBe(false);
	});

	it("registers a passkey with transports and the device name", async () => {
		const create = vi.fn(async () => attestationCredential());
		stubBrowser({ create });
		const fetchMock = vi.fn(async (url: RequestInfo | URL) =>
			String(url).endsWith("/options")
				? json(SERVER_REG_OPTIONS)
				: json({ credential: { id: "cred-2" } }),
		);
		const client = createPasskeyClient({
			baseUrl: "/a",
			fetch: fetchMock as unknown as typeof fetch,
			headers: { Authorization: "Bearer s" },
		});

		const out = await client.register("MacBook");
		expect(out).toEqual({ ok: true, data: { credentialId: "cred-2" } });
		const optionsCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect((optionsCall[1].headers as Headers).get("authorization")).toBe("Bearer s");
		const verify = JSON.parse(
			String((fetchMock.mock.calls[1] as unknown as [string, RequestInit])[1].body),
		) as {
			response: { deviceName: string; transports: string[]; id: string };
		};
		expect(verify.response).toMatchObject({
			id: "cred-2",
			deviceName: "MacBook",
			transports: ["internal"],
		});
	});
});
