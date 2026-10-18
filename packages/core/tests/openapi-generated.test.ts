/** The checked-in sdks/openapi.json must match what the route table generates. */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listRoutes } from "../src/http/router.js";
import { generateOpenAPISpec } from "../src/openapi.js";
import { ADMIN_API_ROUTES, OPERATIONS } from "../src/openapi-operations.js";
import { renderOpenAPIJson } from "../src/openapi-render.js";
import { DECISION_CODES } from "../src/permission/codes.js";

const here = dirname(fileURLToPath(import.meta.url));
const CHECKED_IN = resolve(here, "../../../sdks/openapi.json");

interface Schema {
	type?: string | string[];
	enum?: string[];
	properties?: Record<string, Schema>;
	required?: string[];
}

function schemas(): Record<string, Schema> {
	return generateOpenAPISpec().components.schemas as Record<string, Schema>;
}

describe("generated OpenAPI document", () => {
	it("matches sdks/openapi.json (regenerate with scripts/generate-openapi.ts when this fails)", () => {
		expect(renderOpenAPIJson()).toBe(readFileSync(CHECKED_IN, "utf8"));
	});

	it("is deterministic", () => {
		expect(renderOpenAPIJson()).toBe(renderOpenAPIJson());
	});

	it("documents every served route, with metadata for each", () => {
		const spec = generateOpenAPISpec();
		for (const route of listRoutes()) {
			const path = route.path.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
			const op = spec.paths[path]?.[route.method.toLowerCase()];
			expect(op, `${route.method} ${route.path}`).toBeDefined();
			expect(OPERATIONS[`${route.method} ${route.path}`]).toBeDefined();
		}
	});

	it("has no operation metadata for a route that does not exist", () => {
		const known = new Set(
			[...listRoutes(), ...ADMIN_API_ROUTES].map((r) => `${r.method} ${r.path}`),
		);
		for (const key of Object.keys(OPERATIONS)) expect(known.has(key), key).toBe(true);
	});

	it("uses unique operation ids", () => {
		const ids = Object.values(OPERATIONS).map((o) => o.operationId);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("lists the admin API approval routes the plugin registers", () => {
		const source = readFileSync(resolve(here, "../src/admin-api/plugin.ts"), "utf8");
		const registered = [
			...source.matchAll(/add\(\s*"(GET|POST|PATCH|DELETE)",\s*"(\/approvals[^"]*)"/g),
		].map((m) => `${m[1]} ${m[2]}`);
		const documented = ADMIN_API_ROUTES.map((r) => `${r.method} ${r.path}`);
		expect(documented.sort()).toEqual(registered.sort());
	});

	it("AuthorizeResult carries code, one of the decision codes", () => {
		const result = schemas().AuthorizeResult;
		expect(result?.required).toContain("code");
		expect(schemas().DecisionCode?.enum).toEqual(Object.values(DECISION_CODES));
	});

	it("explain and delegation shapes expose the decision chain", () => {
		const explain = schemas().ExplainResult;
		expect(Object.keys(explain?.properties ?? {})).toEqual(
			expect.arrayContaining(["delegation", "constraints", "nearMisses", "trace"]),
		);
		const chain = schemas().DelegationChain;
		expect(Object.keys(chain?.properties ?? {})).toEqual(
			expect.arrayContaining(["rootOwnerId", "path"]),
		);
	});

	it("accepts approvalId on authorize bodies", () => {
		const spec = generateOpenAPISpec();
		const body = spec.paths["/authorize"]?.post?.requestBody?.content["application/json"]?.schema;
		expect(Object.keys((body as Schema).properties ?? {})).toContain("approvalId");
	});

	it("leaves out routes the handler options turn off", () => {
		const spec = generateOpenAPISpec({
			handler: { routes: { explain: false, mcp: false } },
			adminApi: false,
		});
		expect(spec.paths["/explain"]).toBeUndefined();
		expect(spec.paths["/mcp/introspect"]).toBeUndefined();
		expect(spec.paths["/approvals"]).toBeUndefined();
		expect(spec.paths["/agents"]).toBeDefined();
	});
});
