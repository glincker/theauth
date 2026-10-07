import { describe, expect, it } from "vitest";
import {
	evaluateFilter,
	matchFilter,
	parseFilter,
	ScimFilterError,
} from "../src/auth/scim-filter.js";

const bjensen = {
	id: "2819c223-7f76-453a-919d-413861904646",
	userName: "bjensen",
	name: { givenName: "Barbara", familyName: "Jensen" },
	emails: [
		{ value: "bjensen@example.com", type: "work", primary: true },
		{ value: "barb@home.example", type: "home" },
	],
	userType: "Employee",
	active: true,
	meta: { lastModified: "2026-01-15T10:00:00Z" },
	"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
		department: "Engineering",
		employeeNumber: "E-42",
	},
};

const jsmith = {
	id: "aabbccdd",
	userName: "jsmith",
	name: { givenName: "John", familyName: "Smith" },
	emails: [{ value: "jsmith@other.org", type: "work" }],
	userType: "Admin",
	active: false,
	meta: { lastModified: "2024-06-01T00:00:00Z" },
};

describe("scim-filter: parseFilter", () => {
	it("parses a simple eq expression", () => {
		const ast = parseFilter('userName eq "bjensen"');
		expect(ast.kind).toBe("cmp");
	});

	it("rejects an empty expression", () => {
		expect(() => parseFilter("")).toThrow(ScimFilterError);
	});

	it("rejects an unknown operator", () => {
		expect(() => parseFilter('userName foo "x"')).toThrow(ScimFilterError);
	});

	it("rejects unterminated strings", () => {
		expect(() => parseFilter('userName eq "bje')).toThrow(ScimFilterError);
	});

	it("rejects trailing garbage", () => {
		expect(() => parseFilter('userName eq "x" nonsense')).toThrow(ScimFilterError);
	});

	it("parses parenthesized groups without losing structure", () => {
		const ast = parseFilter('(userName eq "a") or (userName eq "b")');
		expect(ast.kind).toBe("or");
	});

	it("applies precedence: and binds tighter than or", () => {
		const ast = parseFilter('a eq "1" or b eq "2" and c eq "3"');
		// Expected: or(a, and(b, c))
		expect(ast.kind).toBe("or");
		if (ast.kind === "or") {
			expect(ast.right.kind).toBe("and");
		}
	});

	it("parses not(...)", () => {
		const ast = parseFilter('not (userType eq "Admin")');
		expect(ast.kind).toBe("not");
	});

	it("parses value-path expressions", () => {
		const ast = parseFilter('emails[type eq "work"]');
		expect(ast.kind).toBe("valuePath");
	});
});

describe("scim-filter: eq / ne", () => {
	it("eq matches case-insensitively per RFC 7644", () => {
		expect(matchFilter('userName eq "BJensen"', bjensen)).toBe(true);
	});
	it("eq fails for a different value", () => {
		expect(matchFilter('userName eq "jsmith"', bjensen)).toBe(false);
	});
	it("ne inverts eq", () => {
		expect(matchFilter('userName ne "bjensen"', bjensen)).toBe(false);
		expect(matchFilter('userName ne "jsmith"', bjensen)).toBe(true);
	});
	it("eq works on booleans", () => {
		expect(matchFilter("active eq true", bjensen)).toBe(true);
		expect(matchFilter("active eq false", jsmith)).toBe(true);
	});
});

describe("scim-filter: co / sw / ew", () => {
	it("co matches a substring in any email value", () => {
		expect(matchFilter('emails.value co "@example.com"', bjensen)).toBe(true);
	});
	it("sw matches a prefix", () => {
		expect(matchFilter('userName sw "bj"', bjensen)).toBe(true);
		expect(matchFilter('userName sw "smith"', bjensen)).toBe(false);
	});
	it("ew matches a suffix", () => {
		expect(matchFilter('emails.value ew "@example.com"', bjensen)).toBe(true);
	});
});

describe("scim-filter: pr", () => {
	it("pr is true when attribute is present and non-empty", () => {
		expect(matchFilter("emails pr", bjensen)).toBe(true);
	});
	it("pr is false when attribute is absent", () => {
		expect(matchFilter("nickName pr", bjensen)).toBe(false);
	});
});

describe("scim-filter: gt / ge / lt / le", () => {
	it("gt on ISO 8601 strings via lexical compare", () => {
		expect(matchFilter('meta.lastModified gt "2025-01-01T00:00:00Z"', bjensen)).toBe(true);
		expect(matchFilter('meta.lastModified gt "2025-01-01T00:00:00Z"', jsmith)).toBe(false);
	});
	it("lt on ISO 8601 strings", () => {
		expect(matchFilter('meta.lastModified lt "2025-01-01T00:00:00Z"', jsmith)).toBe(true);
	});
	it("ge includes equal", () => {
		expect(matchFilter('meta.lastModified ge "2024-06-01T00:00:00Z"', jsmith)).toBe(true);
	});
	it("le includes equal", () => {
		expect(matchFilter('meta.lastModified le "2024-06-01T00:00:00Z"', jsmith)).toBe(true);
	});
});

describe("scim-filter: logical combinators", () => {
	it("and requires both clauses", () => {
		expect(matchFilter('userName eq "bjensen" and active eq true', bjensen)).toBe(true);
		expect(matchFilter('userName eq "bjensen" and active eq false', bjensen)).toBe(false);
	});
	it("or accepts either", () => {
		expect(matchFilter('userName eq "bjensen" or userName eq "jsmith"', bjensen)).toBe(true);
		expect(matchFilter('userName eq "bjensen" or userName eq "jsmith"', jsmith)).toBe(true);
		expect(matchFilter('userName eq "alice" or userName eq "bob"', bjensen)).toBe(false);
	});
	it("not negates", () => {
		expect(matchFilter('not (userType eq "Admin")', bjensen)).toBe(true);
		expect(matchFilter('not (userType eq "Admin")', jsmith)).toBe(false);
	});
});

describe("scim-filter: value-path expressions", () => {
	it("matches when any array element satisfies the inner filter", () => {
		expect(matchFilter('emails[type eq "work"]', bjensen)).toBe(true);
	});
	it("is false when no element satisfies", () => {
		expect(matchFilter('emails[type eq "school"]', bjensen)).toBe(false);
	});
	it("nested attributes inside value-path combinators", () => {
		const filter = 'emails[type eq "work" and value ew "@example.com"]';
		expect(matchFilter(filter, bjensen)).toBe(true);
	});
});

describe("scim-filter: schema-URN prefixed attributes", () => {
	it("reads attributes from the enterprise extension", () => {
		const filter =
			'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Engineering"';
		expect(matchFilter(filter, bjensen)).toBe(true);
	});
});

describe("scim-filter: precedence and grouping combined", () => {
	it("parenthesized or with trailing and", () => {
		const filter = '(userName eq "bjensen" or userName eq "jsmith") and active eq true';
		expect(matchFilter(filter, bjensen)).toBe(true);
		expect(matchFilter(filter, jsmith)).toBe(false);
	});
});

describe("scim-filter: RFC 7644 3.4.2.2 example list", () => {
	it('userName eq "bjensen"', () => {
		expect(matchFilter('userName eq "bjensen"', bjensen)).toBe(true);
	});
	it('name.familyName co "jens"', () => {
		expect(matchFilter('name.familyName co "jens"', bjensen)).toBe(true);
	});
	it('userName sw "J"', () => {
		expect(matchFilter('userName sw "J"', jsmith)).toBe(true);
	});
	it("title pr", () => {
		expect(matchFilter("title pr", bjensen)).toBe(false);
	});
	it('emails.value ew "example.com"', () => {
		expect(matchFilter('emails.value ew "example.com"', bjensen)).toBe(true);
	});
});

describe("scim-filter: evaluateFilter pure AST path", () => {
	it("exposes parseFilter and evaluateFilter as independent pieces", () => {
		const ast = parseFilter('userName eq "bjensen"');
		expect(evaluateFilter(ast, bjensen)).toBe(true);
		expect(evaluateFilter(ast, jsmith)).toBe(false);
	});
});
