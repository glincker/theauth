/** The checked-in sdks/openapi.json must match what the route table generates. */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listRoutes } from "../src/http/router.js";
import { generateOpenAPISpec } from "../src/openapi.js";
import { ADMIN_SHARED_WITH_CORE } from "../src/openapi-admin.js";
import { ADMIN_API_ROUTES, OPERATIONS } from "../src/openapi-operations.js";

const ADMIN_SOURCES = ["../src/admin-api/plugin.ts", "../src/admin-api/revocations.ts"];

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

	it("lists every admin API route the plugin registers", () => {
		const registered = [
			...ADMIN_SOURCES.flatMap((file) => {
				const source = readFileSync(resolve(here, file), "utf8");
				return [...source.matchAll(/add\(\s*"(GET|POST|PATCH|PUT|DELETE)",\s*"(\/[^"]*)"/g)].map(
					(m) => `${m[1]} ${m[2]}`,
				);
			}),
		];
		expect(registered.length).toBeGreaterThanOrEqual(14);
		const documented = [
			...ADMIN_API_ROUTES.map((r) => `${r.method} ${r.path}`),
			...ADMIN_SHARED_WITH_CORE,
		];
		expect(documented.sort()).toEqual(registered.sort());
		for (const key of documented) expect(OPERATIONS[key], key).toBeDefined();
	});

	it("documents the revocation routes with their request body", () => {
		const spec = generateOpenAPISpec();
		const post = spec.paths["/revocations"]?.post;
		expect(post?.operationId).toBe("adminCreateRevocation");
		const body = post?.requestBody?.content["application/json"]?.schema as Schema;
		expect(JSON.stringify(body)).toContain("AdminRevocationInput");
		expect(schemas().AdminRevocationInput?.required).toEqual(
			expect.arrayContaining(["kind", "id"]),
		);
		expect(spec.paths["/revocations/delegations"]?.get).toBeDefined();
		expect(spec.paths["/sessions"]?.get).toBeDefined();
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
