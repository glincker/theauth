/** Table-driven parsing checks for bearer headers and agent token prefixes (fast-check is not a dependency). */
import { describe, expect, it } from "vitest";
import { agentTokenLookupPrefix, isAgentToken } from "../src/agent/token-format.js";
import { agentCredentialOf, bearerTokenOf } from "../src/http/require-agent.js";

const withAuth = (value: string | null) =>
	new Request("http://localhost/x", value === null ? {} : { headers: { authorization: value } });

describe("bearerTokenOf and agentCredentialOf", () => {
	const rows: Array<[string, string | null, string, "Bearer" | "DPoP" | null]> = [
		["no header", null, "", null],
		["empty header", "", "", null],
		["scheme only", "Bearer", "", null],
		["scheme and spaces", "Bearer    ", "", null],
		["basic scheme", "Basic dXNlcjpwYXNz", "", null],
		["token without scheme", "ta_abc", "", null],
		["lowercase scheme", "bearer ta_abc", "ta_abc", "Bearer"],
		["uppercase scheme", "BEARER ta_abc", "ta_abc", "Bearer"],
		["extra whitespace", "Bearer    ta_abc  ", "ta_abc", "Bearer"],
		["dpop scheme", "DPoP ta_abc", "", "DPoP"],
		["prefix lookalike", "Bearerx ta_abc", "", null],
		["tab separator", "Bearer\tta_abc", "ta_abc", "Bearer"],
	];
	for (const [name, header, bearer, scheme] of rows) {
		it(name, () => {
			expect(bearerTokenOf(withAuth(header))).toBe(bearer);
			expect(agentCredentialOf(withAuth(header))?.scheme ?? null).toBe(scheme);
		});
	}

	it("never throws on arbitrary printable header values", () => {
		let seed = 42;
		const next = () => {
			seed = (seed * 1103515245 + 12345) & 0x7fffffff;
			return seed;
		};
		const alphabet = "Bearer DPoPta_kv-.,;=\"'\\/+%0123456789 \t";
		for (let i = 0; i < 500; i++) {
			const len = next() % 40;
			let s = "";
			for (let j = 0; j < len; j++) s += alphabet[next() % alphabet.length];
			const r = withAuth(s.trim());
			expect(() => bearerTokenOf(r)).not.toThrow();
			expect(() => agentCredentialOf(r)).not.toThrow();
		}
	});
});

describe("isAgentToken", () => {
	const rows: Array<[string, unknown, boolean]> = [
		["current prefix", `ta_${"A".repeat(43)}`, true],
		["legacy prefix", "kv_legacy", true],
		["empty", "", false],
		["jwt", "eyJhbGciOiJIUzI1NiJ9.e30.sig", false],
		["wrong case", "TA_abc", false],
		["leading space", " ta_abc", false],
		["non string", 42, false],
		["null", null, false],
	];
	for (const [name, value, want] of rows) {
		it(name, () => expect(isAgentToken(value as string)).toBe(want));
	}

	it("lookup prefix is the token prefix plus 8 secret characters", () => {
		expect(agentTokenLookupPrefix(`ta_${"abcdefgh"}rest`)).toBe("ta_abcdefgh");
	});
});
