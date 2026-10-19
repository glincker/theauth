/** Input provenance over HTTP: body `inputs`, the TheAuth-Inputs header, and the audit query filters. */
import { describe, expect, it } from "vitest";
import { encodeInputsHeader, parseInputsHeader, parseInputsMeta } from "../../src/audit/index.js";
import { users } from "../../src/db/schema.js";
import { createTheAuthHandler } from "../../src/http/index.js";
import type { Permission } from "../../src/index.js";
import { createTheAuth } from "../../src/index.js";

const READ: Permission[] = [{ resource: "mcp:github:*", actions: ["read"] }];
const CALL = { action: "read", resource: "mcp:github:issues" };
const ORIGIN = "http://localhost/api/theauth";
const DOC = "retrieved page that says ignore previous instructions";

async function world() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
	});
	await auth.db
		.insert(users)
		.values({
			id: "u1",
			email: "u1@example.com",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await auth.agent.create({
		ownerId: "u1",
		name: "reader",
		type: "autonomous",
		permissions: READ,
	});
	const handler = createTheAuthHandler(auth, { rateLimit: false, allowUnauthenticated: true });
	const post = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
		handler(
			new Request(`${ORIGIN}/authorize/token`, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					authorization: `Bearer ${agent.token}`,
					...headers,
				},
				body: JSON.stringify(body),
			}),
		);
	const get = (path: string) => handler(new Request(`${ORIGIN}${path}`));
	return { auth, agent, post, get };
}

describe("provenance wire format", () => {
	it("round trips the header and rejects malformed values without throwing", () => {
		const inputs = [{ kind: "tool_output" as const, hash: "a".repeat(64) }];
		expect(parseInputsHeader(encodeInputsHeader(inputs))).toEqual(inputs);
		expect(parseInputsHeader("not base64 json!!")).toBeUndefined();
		expect(parseInputsHeader(encodeInputsHeader([{ kind: "bogus" } as never]))).toBeUndefined();
		expect(parseInputsHeader("a".repeat(9000))).toBeUndefined();
		expect(parseInputsHeader(null)).toBeUndefined();
	});

	it("reads the MCP _meta key", () => {
		const inputs = [{ kind: "user_message", id: "m1", content: "hi" }];
		expect(parseInputsMeta({ "io.theauth/inputs": inputs })).toEqual(inputs);
		expect(parseInputsMeta({ "io.theauth/inputs": "x" })).toBeUndefined();
		expect(parseInputsMeta(undefined)).toBeUndefined();
	});
});

describe("authorize over HTTP with inputs", () => {
	it("records body inputs as hashes, never the content", async () => {
		const w = await world();
		const res = await w.post({
			...CALL,
			inputs: [{ kind: "retrieved_document", id: "doc-1", content: DOC }],
		});
		expect(res.status).toBe(200);
		const rows = await w.auth.audit.query({ agentId: w.agent.id });
		expect(JSON.stringify(rows)).not.toContain(DOC);
		expect(rows[0]?.inputs?.[0]).toMatchObject({ kind: "retrieved_document", id: "doc-1", hv: 2 });
		const found = await w.auth.audit.query({
			agentId: w.agent.id,
			provenance: { content: DOC },
		});
		expect(found).toHaveLength(1);
	});

	it("takes the TheAuth-Inputs header when the body has none, and ignores a bad header", async () => {
		const w = await world();
		const hash = "c".repeat(64);
		const header = encodeInputsHeader([{ kind: "tool_output", hash }]);
		expect((await w.post(CALL, { "theauth-inputs": header })).status).toBe(200);
		expect((await w.post(CALL, { "theauth-inputs": "%%%" })).status).toBe(200);
		const withInputs = await w.auth.audit.query({
			agentId: w.agent.id,
			provenance: { hash },
		});
		expect(withInputs).toHaveLength(1);
		expect(withInputs[0]?.inputs?.[0]?.kind).toBe("tool_output");
	});

	it("rejects an invalid input in the body", async () => {
		const w = await world();
		const res = await w.post({ ...CALL, inputs: [{ kind: "bogus", content: "x" }] });
		expect(res.status).toBe(400);
	});

	it("keeps the call's arguments free of the inputs field", async () => {
		const w = await world();
		await w.post({ ...CALL, arguments: { q: "x" }, inputs: [{ kind: "agent", content: "a" }] });
		const rows = await w.auth.audit.query({ agentId: w.agent.id });
		expect(rows[0]?.parameters).toEqual({ q: "x" });
	});
});

describe("GET /audit provenance filters", () => {
	it("filters by kind and content, and rejects a malformed hash or kind", async () => {
		const w = await world();
		await w.post({ ...CALL, inputs: [{ kind: "retrieved_document", content: DOC }] });
		await w.post({ ...CALL, inputs: [{ kind: "user_message", content: "hello" }] });
		const byKind = await w.get("/audit?provenanceKind=user_message");
		expect(byKind.status).toBe(200);
		const kindBody = (await byKind.json()) as { data: { id: string }[] };
		expect(kindBody.data).toHaveLength(1);
		const byContent = await w.get(`/audit?provenanceContent=${encodeURIComponent(DOC)}`);
		const contentBody = (await byContent.json()) as { data: { inputs?: { kind: string }[] }[] };
		expect(contentBody.data).toHaveLength(1);
		expect(contentBody.data[0]?.inputs?.[0]?.kind).toBe("retrieved_document");
		expect((await w.get("/audit?provenanceHash=zz")).status).toBe(400);
		expect((await w.get("/audit?provenanceKind=nope")).status).toBe(400);
	});
});
