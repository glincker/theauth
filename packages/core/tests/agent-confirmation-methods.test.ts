/** Certificate bound agent tokens (RFC 8705) and other proofs of possession through `agents.confirmation.methods`. */

import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../src/http/index.js";
import type { TheAuth } from "../src/theauth.js";
import {
	AUTHORIZE_URL,
	boundAgent,
	CALL,
	codeOf,
	makeAuth,
	newKeys,
	proof,
} from "./agent-dpop-helpers.js";

describe("certificate bound tokens (RFC 8705) as a pluggable method", () => {
	const X5T = "x5t#S256";
	const thumb = "c".repeat(43);
	const makeMtls = () =>
		makeAuth({
			methods: { [X5T]: (request) => request.headers.get("x-client-cert-sha256") },
		});
	const withCert = async (auth: TheAuth, token: string, cert?: string): Promise<Response> =>
		createTheAuthHandler(auth, { rateLimit: false })(
			new Request(AUTHORIZE_URL, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
					...(cert ? { "x-client-cert-sha256": cert } : {}),
				},
				body: JSON.stringify(CALL),
			}),
		);

	it("accepts the matching certificate thumbprint and refuses a missing or different one", async () => {
		const auth = await makeMtls();
		const agent = await boundAgent(auth, { [X5T]: thumb });
		expect((await withCert(auth, agent.token, thumb)).status).toBe(200);
		expect((await withCert(auth, agent.token)).status).toBe(401);
		const wrong = await withCert(auth, agent.token, "d".repeat(43));
		expect(wrong.status).toBe(401);
		expect(await codeOf(wrong)).toBe("confirmation_failed");
	});

	it("needs every member when a token is bound to a key and a certificate", async () => {
		const auth = await makeAuth({
			dpop: {},
			methods: { [X5T]: (request) => request.headers.get("x-client-cert-sha256") },
		});
		const keys = await newKeys();
		const agent = await boundAgent(auth, { jkt: keys.jkt, [X5T]: thumb });
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const send = (cert: string | undefined, withProof: boolean) =>
			proof(keys, agent.token).then((p) =>
				handler(
					new Request(AUTHORIZE_URL, {
						method: "POST",
						headers: {
							Authorization: `${withProof ? "DPoP" : "Bearer"} ${agent.token}`,
							"Content-Type": "application/json",
							...(withProof ? { DPoP: p } : {}),
							...(cert ? { "x-client-cert-sha256": cert } : {}),
						},
						body: JSON.stringify(CALL),
					}),
				),
			);
		expect((await send(thumb, true)).status).toBe(200);
		expect((await send(undefined, true)).status).toBe(401);
		expect((await send(thumb, false)).status).toBe(401);
	});

	it("treats an extractor that throws as proof of nothing", async () => {
		const auth = await makeAuth({
			methods: {
				[X5T]: () => {
					throw new Error("proxy header parser crashed");
				},
			},
		});
		const agent = await boundAgent(auth, { [X5T]: thumb });
		expect((await withCert(auth, agent.token, thumb)).status).toBe(401);
	});

	it("refuses a token bound to a member nothing can prove", async () => {
		const auth = await makeAuth({ dpop: {} });
		const agent = await boundAgent(auth, { [X5T]: thumb });
		expect((await withCert(auth, agent.token, thumb)).status).toBe(401);
	});
});
