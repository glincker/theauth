/**
 * Tests for the OpenAPI spec generation plugin.
 *
 * Covers:
 * - generateSpec: uses sensible defaults when called with no config
 * - generateSpec: custom title is reflected in spec info
 * - generateSpec: custom version is reflected in spec info
 * - generateSpec: custom description is included in spec info
 * - generateSpec: custom serverUrl is set on the first server entry
 * - generateSpec: custom basePath prefixes all endpoint paths
 * - generateSpec: include filter limits paths to specified groups only
 * - generateSpec: include filter with a single group
 * - generateSpec: include with all groups matches the default
 * - generateSpec: agents group endpoints are present by default
 * - generateSpec: auth group endpoints are present by default
 * - generateSpec: oauth group endpoints are present by default
 * - generateSpec: mcp group endpoints are present by default
 * - generateSpec: admin group endpoints are present by default
 * - generateSpec: organizations group endpoints are present by default
 * - generateSpec: sessions group endpoints are present by default
 * - generateSpec: api-keys group endpoints are present by default
 * - generateSpec: webhooks group endpoints are present by default
 * - generateSpec: openapi field is always "3.1.0"
 * - generateSpec: BearerAuth security scheme is always defined
 * - generateSpec: every secured endpoint references BearerAuth
 * - generateSpec: request body schemas have required fields defined
 * - generateSpec: each operation has a unique operationId
 * - generateSpec: tags list only includes selected groups
 * - generateSpec: error response schemas have code and message properties
 * - handleRequest: returns Response with JSON for /openapi.json path
 * - handleRequest: Content-Type header is application/json
 * - handleRequest: returns null for unrelated paths
 * - handleRequest: returns null for partial path match without suffix
 * - handleRequest: response body is valid JSON and parses to a document
 * - handleRequest: forwards config to generateSpec
 */

import { describe, expect, it } from "vitest";
import type { EndpointGroup, OpenApiDocument, OpenApiOperation } from "../src/auth/openapi.js";
import { createOpenApiModule } from "../src/auth/openapi.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(url: string): Request {
	return new Request(url);
}

function collectOperations(doc: OpenApiDocument): OpenApiOperation[] {
	const ops: OpenApiOperation[] = [];
	const methods = ["get", "post", "put", "patch", "delete"] as const;
	for (const pathItem of Object.values(doc.paths)) {
		for (const method of methods) {
			const op = pathItem[method];
			if (op !== undefined) ops.push(op);
		}
	}
	return ops;
}

// ---------------------------------------------------------------------------
// generateSpec — defaults
// ---------------------------------------------------------------------------

describe("OpenApiModule.generateSpec defaults", () => {
	const mod = createOpenApiModule();

	it("uses default title when none supplied", () => {
		const spec = mod.generateSpec();
		expect(spec.info.title).toBe("TheAuth API");
	});

	it("uses default version when none supplied", () => {
		const spec = mod.generateSpec();
		expect(spec.info.version).toBe("0.0.1");
	});

	it("uses '/' as default serverUrl", () => {
		const spec = mod.generateSpec();
		expect(spec.servers[0]?.url).toBe("/");
	});

	it("openapi field is always 3.1.0", () => {
		const spec = mod.generateSpec();
		expect(spec.openapi).toBe("3.1.0");
	});

	it("includes all endpoint groups by default", () => {
		const spec = mod.generateSpec();
		const paths = Object.keys(spec.paths);
		// Spot-check one path from each group
		expect(paths.some((p) => p.includes("/agents"))).toBe(true);
		expect(paths.some((p) => p.includes("/sign-in"))).toBe(true);
		expect(paths.some((p) => p.includes("/auth/{provider}"))).toBe(true);
		expect(paths.some((p) => p.includes("/mcp/"))).toBe(true);
		expect(paths.some((p) => p.includes("/admin/"))).toBe(true);
		expect(paths.some((p) => p.includes("/organizations"))).toBe(true);
		expect(paths.some((p) => p.includes("/sessions"))).toBe(true);
		expect(paths.some((p) => p.includes("/api-keys"))).toBe(true);
		expect(paths.some((p) => p.includes("/webhooks"))).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// generateSpec — custom config
// ---------------------------------------------------------------------------

describe("OpenApiModule.generateSpec custom config", () => {
	const mod = createOpenApiModule();

	it("reflects custom title in info", () => {
		const spec = mod.generateSpec({ title: "Acme Auth API" });
		expect(spec.info.title).toBe("Acme Auth API");
	});

	it("reflects custom version in info", () => {
		const spec = mod.generateSpec({ version: "2.0.0" });
		expect(spec.info.version).toBe("2.0.0");
	});

	it("includes description when provided", () => {
		const spec = mod.generateSpec({ description: "Authentication services for Acme Inc." });
		expect(spec.info.description).toBe("Authentication services for Acme Inc.");
	});

	it("omits description key when not provided", () => {
		const spec = mod.generateSpec({ title: "No desc" });
		expect("description" in spec.info).toBe(false);
	});

	it("uses custom serverUrl on first server entry", () => {
		const spec = mod.generateSpec({ serverUrl: "https://api.example.com" });
		expect(spec.servers[0]?.url).toBe("https://api.example.com");
	});

	it("prefixes all paths with custom basePath", () => {
		const spec = mod.generateSpec({ basePath: "/v2/auth" });
		const paths = Object.keys(spec.paths);
		for (const path of paths) {
			expect(path.startsWith("/v2/auth")).toBe(true);
		}
	});

	it("default basePath prefixes all paths with /api/kavach", () => {
		const spec = mod.generateSpec();
		const paths = Object.keys(spec.paths);
		for (const path of paths) {
			expect(path.startsWith("/api/kavach")).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// generateSpec — include filter
// ---------------------------------------------------------------------------

describe("OpenApiModule.generateSpec include filter", () => {
	const mod = createOpenApiModule();

	it("restricts paths to specified groups only (agents only)", () => {
		const spec = mod.generateSpec({ include: ["agents"] });
		const paths = Object.keys(spec.paths);
		expect(paths.every((p) => p.includes("/agents"))).toBe(true);
		expect(paths.some((p) => p.includes("/admin/"))).toBe(false);
	});

	it("single group include returns only that group's paths", () => {
		const spec = mod.generateSpec({ include: ["sessions"] });
		const paths = Object.keys(spec.paths);
		expect(paths.some((p) => p.includes("/sessions"))).toBe(true);
		expect(paths.some((p) => p.includes("/agents"))).toBe(false);
	});

	it("multi-group include returns exactly those groups", () => {
		const include: EndpointGroup[] = ["auth", "api-keys"];
		const spec = mod.generateSpec({ include });
		const paths = Object.keys(spec.paths);
		// auth paths present
		expect(paths.some((p) => p.includes("/sign-in"))).toBe(true);
		// api-keys paths present
		expect(paths.some((p) => p.includes("/api-keys"))).toBe(true);
		// others absent
		expect(paths.some((p) => p.includes("/agents"))).toBe(false);
		expect(paths.some((p) => p.includes("/admin/"))).toBe(false);
	});

	it("tags list only includes selected groups", () => {
		const spec = mod.generateSpec({ include: ["agents", "sessions"] });
		const tagNames = spec.tags.map((t) => t.name);
		expect(tagNames).toContain("Agents");
		expect(tagNames).toContain("Sessions");
		expect(tagNames).not.toContain("Admin");
		expect(tagNames).not.toContain("Auth");
	});

	it("include with all groups produces same paths as default", () => {
		const all: EndpointGroup[] = [
			"agents",
			"auth",
			"oauth",
			"mcp",
			"admin",
			"organizations",
			"sessions",
			"api-keys",
			"webhooks",
		];
		const withInclude = mod.generateSpec({ include: all });
		const withDefault = mod.generateSpec();
		expect(Object.keys(withInclude.paths).sort()).toEqual(Object.keys(withDefault.paths).sort());
	});
});

// ---------------------------------------------------------------------------
// generateSpec — security
// ---------------------------------------------------------------------------

describe("OpenApiModule.generateSpec security", () => {
	const mod = createOpenApiModule();

	it("BearerAuth security scheme is always defined", () => {
		const spec = mod.generateSpec();
		expect(spec.components.securitySchemes.BearerAuth).toBeDefined();
		expect(spec.components.securitySchemes.BearerAuth?.type).toBe("http");
		expect(spec.components.securitySchemes.BearerAuth?.scheme).toBe("bearer");
	});

	it("every operation tagged Agents references BearerAuth", () => {
		const spec = mod.generateSpec({ include: ["agents"] });
		const ops = collectOperations(spec);
		for (const op of ops) {
			expect(op.security).toBeDefined();
			expect(op.security?.some((req) => "BearerAuth" in req)).toBe(true);
		}
	});

	it("sign-in endpoint has no security requirement (public route)", () => {
		const spec = mod.generateSpec({ include: ["auth"] });
		const signInOp = spec.paths["/api/kavach/sign-in/email"]?.post;
		expect(signInOp).toBeDefined();
		// Public routes have undefined security (no restriction)
		expect(signInOp?.security).toBeUndefined();
	});

	it("session GET endpoint requires BearerAuth", () => {
		const spec = mod.generateSpec({ include: ["auth"] });
		const sessionOp = spec.paths["/api/kavach/session"]?.get;
		expect(sessionOp?.security?.some((req) => "BearerAuth" in req)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// generateSpec — schema validity
// ---------------------------------------------------------------------------

describe("OpenApiModule.generateSpec schemas", () => {
	const mod = createOpenApiModule();

	it("each operation has a unique operationId", () => {
		const spec = mod.generateSpec();
		const ops = collectOperations(spec);
		const ids = ops.map((op) => op.operationId);
		const unique = new Set(ids);
		expect(unique.size).toBe(ids.length);
	});

	it("POST request bodies have required fields defined", () => {
		const spec = mod.generateSpec();
		const methods = ["post"] as const;
		for (const pathItem of Object.values(spec.paths)) {
			for (const method of methods) {
				const op = pathItem[method];
				if (op?.requestBody) {
					const jsonContent = op.requestBody.content["application/json"];
					if (jsonContent) {
						// If properties exist, required should be an array
						if (jsonContent.schema.properties !== undefined) {
							expect(Array.isArray(jsonContent.schema.required)).toBe(true);
						}
					}
				}
			}
		}
	});

	it("Error component schema has code and message properties", () => {
		const spec = mod.generateSpec();
		const errorSchema = spec.components.schemas.Error;
		expect(errorSchema?.properties?.code).toBeDefined();
		expect(errorSchema?.properties?.message).toBeDefined();
	});

	it("ErrorResponse component schema has success and error properties", () => {
		const spec = mod.generateSpec();
		const errResponse = spec.components.schemas.ErrorResponse;
		expect(errResponse?.properties?.success).toBeDefined();
		expect(errResponse?.properties?.error).toBeDefined();
	});

	it("400 response is defined on all POST endpoints", () => {
		const spec = mod.generateSpec();
		for (const [path, pathItem] of Object.entries(spec.paths)) {
			if (pathItem.post) {
				expect(
					pathItem.post.responses["400"],
					`Missing 400 response on POST ${path}`,
				).toBeDefined();
			}
		}
	});

	it("all operations have at least one tag", () => {
		const spec = mod.generateSpec();
		const ops = collectOperations(spec);
		for (const op of ops) {
			expect(op.tags.length).toBeGreaterThan(0);
		}
	});

	it("agents paths include rotate endpoint", () => {
		const spec = mod.generateSpec({ include: ["agents"] });
		const rotatePath = spec.paths["/api/kavach/agents/{id}/rotate"];
		expect(rotatePath?.post).toBeDefined();
		expect(rotatePath?.post?.operationId).toBe("rotateAgent");
	});

	it("api-keys rotate endpoint is present", () => {
		const spec = mod.generateSpec({ include: ["api-keys"] });
		const rotatePath = spec.paths["/api/kavach/api-keys/{id}/rotate"];
		expect(rotatePath?.post).toBeDefined();
		expect(rotatePath?.post?.operationId).toBe("rotateApiKey");
	});

	it("mcp token endpoint uses form-encoded content type", () => {
		const spec = mod.generateSpec({ include: ["mcp"] });
		const tokenOp = spec.paths["/api/kavach/mcp/token"]?.post;
		expect(tokenOp?.requestBody?.content["application/x-www-form-urlencoded"]).toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// handleRequest
// ---------------------------------------------------------------------------

describe("OpenApiModule.handleRequest", () => {
	const mod = createOpenApiModule();

	it("returns a Response for a path ending in /openapi.json", () => {
		const req = makeRequest("https://api.example.com/api/kavach/openapi.json");
		const res = mod.handleRequest(req);
		expect(res).toBeInstanceOf(Response);
	});

	it("returns HTTP 200 status", () => {
		const req = makeRequest("https://api.example.com/openapi.json");
		const res = mod.handleRequest(req);
		expect(res?.status).toBe(200);
	});

	it("Content-Type is application/json", () => {
		const req = makeRequest("https://api.example.com/openapi.json");
		const res = mod.handleRequest(req);
		expect(res?.headers.get("Content-Type")).toBe("application/json");
	});

	it("returns null for a path that does not end in /openapi.json", () => {
		const req = makeRequest("https://api.example.com/api/kavach/session");
		const res = mod.handleRequest(req);
		expect(res).toBeNull();
	});

	it("returns null for the root path", () => {
		const req = makeRequest("https://api.example.com/");
		const res = mod.handleRequest(req);
		expect(res).toBeNull();
	});

	it("returns null for a partial match like /openapi.json.bak", () => {
		const req = makeRequest("https://api.example.com/openapi.json.bak");
		// .endsWith('/openapi.json') is false here
		expect(mod.handleRequest(req)).toBeNull();
	});

	it("response body parses to a valid OpenAPI document", async () => {
		const req = makeRequest("https://api.example.com/openapi.json");
		const res = mod.handleRequest(req);
		expect(res).not.toBeNull();
		const body = (await res!.json()) as OpenApiDocument;
		expect(body.openapi).toBe("3.1.0");
		expect(body.info).toBeDefined();
		expect(body.paths).toBeDefined();
		expect(body.components).toBeDefined();
	});

	it("forwards config to generateSpec when provided", async () => {
		const req = makeRequest("https://api.example.com/openapi.json");
		const res = mod.handleRequest(req, { title: "Custom Title", version: "3.0.0" });
		const body = (await res!.json()) as OpenApiDocument;
		expect(body.info.title).toBe("Custom Title");
		expect(body.info.version).toBe("3.0.0");
	});
});
