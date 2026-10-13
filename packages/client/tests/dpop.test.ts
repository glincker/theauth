import { describe, expect, it, vi } from "vitest";
import { createDPoPClient, createDPoPProver, normalizeHtu } from "../src/dpop.js";

function b64urlToBytes(s: string): Uint8Array {
	const pad = "=".repeat((4 - (s.length % 4)) % 4);
	const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function decode(jwt: string) {
	const [h, p, s] = jwt.split(".") as [string, string, string];
	const dec = new TextDecoder();
	return {
		header: JSON.parse(dec.decode(b64urlToBytes(h))) as Record<string, unknown>,
		payload: JSON.parse(dec.decode(b64urlToBytes(p))) as Record<string, unknown>,
		signingInput: new TextEncoder().encode(`${h}.${p}`),
		signature: b64urlToBytes(s),
	};
}

async function verify(jwt: string): Promise<boolean> {
	const d = decode(jwt);
	const key = await crypto.subtle.importKey(
		"jwk",
		d.header.jwk as JsonWebKey,
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["verify"],
	);
	return crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		key,
		d.signature as BufferSource,
		d.signingInput as BufferSource,
	);
}

async function sha256Url(value: string): Promise<string> {
	const hash = new Uint8Array(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
	);
	return btoa(String.fromCharCode(...hash))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

describe("normalizeHtu", () => {
	it("drops query and fragment and lowercases the host", () => {
		expect(normalizeHtu("https://Example.COM/a/b?x=1#f")).toBe("https://example.com/a/b");
	});
	it("throws on a relative URL", () => {
		expect(() => normalizeHtu("/relative")).toThrow();
	});
});

describe("createDPoPProver", () => {
	it("builds a verifiable ES256 dpop+jwt with htm, htu, iat, jti", async () => {
		const prover = await createDPoPProver({ now: () => 1_700_000_000_000 });
		const jwt = await prover.createProof({ method: "post", url: "https://as.test/token?a=b" });
		const d = decode(jwt);
		expect(d.header.typ).toBe("dpop+jwt");
		expect(d.header.alg).toBe("ES256");
		expect(d.payload.htm).toBe("POST");
		expect(d.payload.htu).toBe("https://as.test/token");
		expect(d.payload.iat).toBe(1_700_000_000);
		expect(typeof d.payload.jti).toBe("string");
		expect(d.payload.ath).toBeUndefined();
		expect(await verify(jwt)).toBe(true);
	});

	it("never exposes private JWK members in the proof header", async () => {
		const prover = await createDPoPProver();
		const jwk = decode(await prover.createProof({ method: "GET", url: "https://rs.test/x" })).header
			.jwk as Record<string, unknown>;
		expect(Object.keys(jwk).sort()).toEqual(["crv", "kty", "x", "y"]);
	});

	it("uses a fresh jti per proof", async () => {
		const prover = await createDPoPProver();
		const a = decode(await prover.createProof({ method: "GET", url: "https://rs.test/x" }));
		const b = decode(await prover.createProof({ method: "GET", url: "https://rs.test/x" }));
		expect(a.payload.jti).not.toBe(b.payload.jti);
	});

	it("adds ath for resource requests and nonce when given", async () => {
		const prover = await createDPoPProver();
		const jwt = await prover.createProof({
			method: "GET",
			url: "https://rs.test/x",
			accessToken: "tok-123",
			nonce: "n-1",
		});
		const d = decode(jwt);
		expect(d.payload.ath).toBe(await sha256Url("tok-123"));
		expect(d.payload.nonce).toBe("n-1");
	});

	it("thumbprint is RFC 7638 sha256 of the canonical JWK and stable", async () => {
		const prover = await createDPoPProver();
		const jwk = prover.publicJwk;
		const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
		expect(await prover.thumbprint()).toBe(await sha256Url(canonical));
		expect(await prover.thumbprint()).toBe(await prover.thumbprint());
	});

	it("accepts an existing key pair", async () => {
		const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
			"sign",
			"verify",
		]);
		const a = await createDPoPProver({ keyPair });
		const b = await createDPoPProver({ keyPair });
		expect(await a.thumbprint()).toBe(await b.thumbprint());
	});

	it("caches nonces per origin", async () => {
		const prover = await createDPoPProver();
		prover.setNonce("https://as.test/token", "n1");
		expect(prover.getNonce("https://as.test/other")).toBe("n1");
		expect(prover.getNonce("https://rs.test/")).toBeUndefined();
	});
});

describe("createDPoPClient fetch", () => {
	it("sends a DPoP header and DPoP authorization scheme with ath", async () => {
		const fetchFn = vi.fn(async (_req: Request) => new Response("{}", { status: 200 }));
		const client = await createDPoPClient({ fetch: fetchFn as unknown as typeof fetch });
		await client.fetch("https://rs.test/tools?cursor=1", undefined, { accessToken: "AT" });
		const req = fetchFn.mock.calls[0]?.[0] as Request;
		expect(req.headers.get("authorization")).toBe("DPoP AT");
		const d = decode(req.headers.get("dpop") ?? "");
		expect(d.payload.htu).toBe("https://rs.test/tools");
		expect(d.payload.htm).toBe("GET");
		expect(d.payload.ath).toBe(await sha256Url("AT"));
	});

	it("retries once on use_dpop_nonce (400 body) with the server nonce and replays the body", async () => {
		let calls = 0;
		const bodies: string[] = [];
		const fetchFn = vi.fn(async (req: Request) => {
			calls++;
			bodies.push(await req.text());
			if (calls === 1) {
				return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
					status: 400,
					headers: { "DPoP-Nonce": "srv-1", "Content-Type": "application/json" },
				});
			}
			return new Response("{}", { status: 200, headers: { "DPoP-Nonce": "srv-2" } });
		});
		const client = await createDPoPClient({ fetch: fetchFn as unknown as typeof fetch });
		const res = await client.fetch("https://as.test/token", {
			method: "POST",
			body: "grant_type=x",
		});
		expect(res.status).toBe(200);
		expect(calls).toBe(2);
		expect(bodies).toEqual(["grant_type=x", "grant_type=x"]);
		const second = fetchFn.mock.calls[1]?.[0] as Request;
		expect(decode(second.headers.get("dpop") ?? "").payload.nonce).toBe("srv-1");
		// Latest nonce is cached and used proactively next time.
		await client.fetch("https://as.test/token", { method: "POST", body: "a=b" });
		const third = fetchFn.mock.calls[2]?.[0] as Request;
		expect(decode(third.headers.get("dpop") ?? "").payload.nonce).toBe("srv-2");
	});

	it("retries on a 401 WWW-Authenticate use_dpop_nonce challenge", async () => {
		let calls = 0;
		const fetchFn = vi.fn(async () => {
			calls++;
			return calls === 1
				? new Response("", {
						status: 401,
						headers: { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "rs-1" },
					})
				: new Response("ok", { status: 200 });
		});
		const client = await createDPoPClient({ fetch: fetchFn as unknown as typeof fetch });
		const res = await client.fetch("https://rs.test/tools", undefined, { accessToken: "AT" });
		expect(res.status).toBe(200);
		expect(calls).toBe(2);
	});

	it("does not loop: a second nonce challenge is returned to the caller", async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
					status: 400,
					headers: { "DPoP-Nonce": "again" },
				}),
		);
		const client = await createDPoPClient({ fetch: fetchFn as unknown as typeof fetch });
		const res = await client.fetch("https://as.test/token", { method: "POST", body: "x=1" });
		expect(res.status).toBe(400);
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it("does not retry when the 400 is a different error", async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: "invalid_grant" }), {
					status: 400,
					headers: { "DPoP-Nonce": "n" },
				}),
		);
		const client = await createDPoPClient({ fetch: fetchFn as unknown as typeof fetch });
		await client.fetch("https://as.test/token", { method: "POST", body: "x=1" });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it("resolves the access token from a getter", async () => {
		const fetchFn = vi.fn(async (_req: Request) => new Response("", { status: 200 }));
		const client = await createDPoPClient({
			fetch: fetchFn as unknown as typeof fetch,
			accessToken: async () => "from-getter",
		});
		await client.fetch("https://rs.test/x");
		expect((fetchFn.mock.calls[0]?.[0] as Request).headers.get("authorization")).toBe(
			"DPoP from-getter",
		);
	});
});
