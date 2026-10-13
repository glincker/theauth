import { describe, expect, it } from "vitest";
import { createDPoPClient } from "../../client/src/dpop.js";
import { createExtensionAuth, createMemoryKeyStore } from "../src/index.js";
import type { FakeServer } from "./helpers.js";
import { baseOptions, fakeServer, fakeStorage, tokenCalls, tokenJson } from "./helpers.js";

function decodeProof(jwt: string) {
	const [h, p] = jwt.split(".");
	const dec = (s: string | undefined) =>
		JSON.parse(atob((s ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
	return { header: dec(h), claims: dec(p) };
}

describe("DPoP", () => {
	it("attaches a proof to the token request and uses the DPoP scheme for resources", async () => {
		const server: FakeServer = fakeServer();
		server.onToken = () => tokenJson({ token_type: "DPoP" });
		const seen: Request[] = [];
		const base = server.fetch;
		const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const req = new Request(input, init);
			if (new URL(req.url).origin === "https://api.example.test") {
				seen.push(req);
				return new Response("ok");
			}
			return base(req);
		}) as typeof fetch;
		const keyStore = createMemoryKeyStore();
		const auth = createExtensionAuth(
			baseOptions(server, fakeStorage(), {
				fetch: fetchImpl,
				keyStore,
				dpop: { module: { createDPoPClient } },
			}),
		);
		const session = await auth.signIn();
		expect(session.tokenType).toBe("DPoP");

		const exchange = tokenCalls(server)[0];
		const proof = exchange?.headers.get("DPoP") ?? "";
		const { header, claims } = decodeProof(proof);
		expect(header.typ).toBe("dpop+jwt");
		expect(header.alg).toBe("ES256");
		expect(claims.htm).toBe("POST");
		expect(claims.htu).toBe("https://auth.example.test/token");
		expect(claims.ath).toBeUndefined();

		await auth.fetch("https://api.example.test/things?x=1");
		const call = seen[0];
		expect(call?.headers.get("Authorization")).toBe("DPoP at-1");
		const rsProof = decodeProof(call?.headers.get("DPoP") ?? "");
		expect(rsProof.claims.htu).toBe("https://api.example.test/things");
		expect(typeof rsProof.claims.ath).toBe("string");
		// The key pair is persisted for the next worker.
		expect(await keyStore.get("theauth:ext:ext-client:dpop")).toBeDefined();
	});

	it("retries once on use_dpop_nonce", async () => {
		const server = fakeServer();
		server.onToken = (_call, n) =>
			n === 1
				? Response.json(
						{ error: "use_dpop_nonce" },
						{ status: 400, headers: { "DPoP-Nonce": "n-1" } },
					)
				: tokenJson({ token_type: "DPoP" });
		const auth = createExtensionAuth(
			baseOptions(server, fakeStorage(), { dpop: { module: { createDPoPClient } } }),
		);
		await auth.signIn();
		const calls = tokenCalls(server);
		expect(calls).toHaveLength(2);
		const retry = decodeProof(calls[1]?.headers.get("DPoP") ?? "");
		expect(retry.claims.nonce).toBe("n-1");
	});

	it("sends plain Bearer requests when DPoP is off", async () => {
		const server = fakeServer();
		const auth = createExtensionAuth(baseOptions(server, fakeStorage()));
		await auth.signIn();
		expect(tokenCalls(server)[0]?.headers.get("DPoP")).toBeNull();
	});

	it("reports invalid_config when DPoP cannot be loaded", async () => {
		const server = fakeServer();
		const auth = createExtensionAuth(
			baseOptions(server, fakeStorage(), {
				dpop: {
					module: {
						createDPoPClient: async () => {
							throw new Error("boom");
						},
					},
				},
			}),
		);
		await expect(auth.signIn()).rejects.toMatchObject({ code: "invalid_config" });
	});
});
