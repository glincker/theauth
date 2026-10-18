import { describe, expect, it } from "vitest";
import { requireAgent, statusForDecisionCode } from "../../src/http/index.js";
import type { DecisionCode } from "../../src/permission/codes.js";
import { DECISION_CODES } from "../../src/permission/codes.js";
import type { TheAuth } from "../../src/theauth.js";
import type { AgentIdentity, AuthorizeResult } from "../../src/types.js";
import { makeAuth, newAgent } from "./helpers.js";

const URL_ = "http://localhost/x";
const withToken = (token?: string) =>
	new Request(URL_, token ? { headers: { Authorization: `Bearer ${token}` } } : undefined);
const opts = { action: "read", resource: "docs" };

/** A TheAuth stand-in that reports a fixed decision, to cover each code. */
function stub(result: AuthorizeResult, agent: AgentIdentity | null = null): TheAuth {
	return {
		authorizeByToken: async () => result,
		agent: { validateToken: async () => agent },
	} as unknown as TheAuth;
}

const UNAUTHENTICATED: DecisionCode[] = [
	"invalid_token",
	"agent_not_found",
	"agent_revoked",
	"agent_expired",
];

describe("requireAgent decision code to status", () => {
	const denials = Object.values(DECISION_CODES).filter(
		(c) => c !== "allowed" && c !== "approval_consumed",
	);

	it.each(denials)("%s maps to the right status and echoes the code", async (code) => {
		const result = await requireAgent(
			stub({ allowed: false, reason: "some free text", auditId: "a1", code }),
			withToken("kv_x"),
			opts,
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		const expected = UNAUTHENTICATED.includes(code) ? 401 : 403;
		expect(result.status).toBe(expected);
		expect(statusForDecisionCode(code)).toBe(expected);
		expect(result.code).toBe(code);
		expect(result.response.status).toBe(expected);
		expect(await result.response.json()).toEqual({
			error: { code, message: "some free text" },
		});
	});

	it("does not look at the reason text", async () => {
		const result = await requireAgent(
			stub({
				allowed: false,
				reason: "Invalid or expired agent token",
				auditId: "",
				code: "no_permission",
			}),
			withToken("kv_x"),
			opts,
		);
		expect(result.ok === false && result.status).toBe(403);
	});

	it("answers 401 invalid_token with WWW-Authenticate when the header is missing", async () => {
		const result = await requireAgent(stub({ allowed: true, auditId: "a" }), withToken(), opts);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.status).toBe(401);
		expect(result.code).toBe("invalid_token");
		expect(result.response.headers.get("www-authenticate")).toBe("Bearer");
	});

	it("accepts a lowercase bearer scheme", async () => {
		const req = new Request(URL_, { headers: { Authorization: "bearer kv_x" } });
		const result = await requireAgent(
			stub({ allowed: false, auditId: "", code: "invalid_token" }),
			req,
			opts,
		);
		expect(result.ok === false && result.code).toBe("invalid_token");
	});
});

describe("requireAgent with a real agent", () => {
	it("returns the agent without its token and the audit id", async () => {
		const auth = await makeAuth();
		const agent = await newAgent(auth, "alice");
		const result = await requireAgent(auth, withToken(agent.token), opts);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.agent.id).toBe(agent.id);
		expect("token" in result.agent).toBe(false);
		expect(result.auditId).toBeTruthy();
	});

	it("401 for an unknown token, 403 for a missing permission, 401 once revoked", async () => {
		const auth = await makeAuth();
		const agent = await newAgent(auth, "alice");

		const unknown = await requireAgent(auth, withToken("kv_unknown"), opts);
		expect(unknown.ok === false && unknown.status).toBe(401);

		const denied = await requireAgent(auth, withToken(agent.token), {
			action: "write",
			resource: "docs",
		});
		expect(denied.ok === false && denied.status).toBe(403);
		expect(denied.ok === false && denied.code).toBe("no_permission");

		await auth.agent.revoke(agent.id);
		const revoked = await requireAgent(auth, withToken(agent.token), opts);
		expect(revoked.ok === false && revoked.status).toBe(401);
	});

	it("passes the client ip to authorization", async () => {
		const auth = await makeAuth();
		const agent = await auth.agent.create({
			ownerId: (await newAgent(auth, "alice")).ownerId,
			name: "ip",
			type: "service",
			permissions: [
				{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: ["10.0.0.1"] } },
			],
		});
		const ok = await requireAgent(auth, withToken(agent.token), {
			...opts,
			clientIp: () => "10.0.0.1",
		});
		expect(ok.ok).toBe(true);
		const blocked = await requireAgent(auth, withToken(agent.token), {
			...opts,
			clientIp: () => "10.0.0.2",
		});
		expect(blocked.ok === false && blocked.code).toBe("ip_not_allowed");
	});
});
