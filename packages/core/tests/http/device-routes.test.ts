import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { generateOpenAPISpec } from "../../src/openapi.js";
import { createTheAuth } from "../../src/theauth.js";
import { bundleKey } from "../device-helpers.js";
import { BASE, SESSION_SECRET, sessionToken } from "./helpers.js";

async function setup() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		auth: { session: { secret: SESSION_SECRET } },
		devices: { bundleSigning: await bundleKey() },
	});
	const handler = createTheAuthHandler(auth, { rateLimit: false });
	const t1 = await sessionToken(auth, "u1");
	const t2 = await sessionToken(auth, "u2");
	const call = (method: string, path: string, opts: { token?: string; body?: unknown } = {}) =>
		handler(
			new Request(`${BASE}${path}`, {
				method,
				headers: {
					...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
					...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
				},
				body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
			}),
		);
	return { auth, call, t1, t2 };
}

const PERMS = [{ resource: "mqtt:sensors:*", actions: ["publish"] }];

describe("device management routes", () => {
	it("need a session and keep owners apart", async () => {
		const { call, t1, t2 } = await setup();
		expect((await call("GET", "/devices")).status).toBe(401);
		const res = await call("POST", "/devices", {
			token: t1,
			body: { ownerId: "u1", name: "s1", permissions: PERMS, credential: { kind: "psk" } },
		});
		expect(res.status).toBe(201);
		const { data } = (await res.json()) as {
			data: { device: { id: string }; credential: { secret: string } };
		};
		expect(data.credential.secret).toMatch(/^tdk_/);
		expect(
			(await call("POST", "/devices", { token: t1, body: { ownerId: "u2", name: "x" } })).status,
		).toBe(403);
		expect((await call("GET", `/devices/${data.device.id}`, { token: t2 })).status).toBe(404);
		expect((await call("POST", `/devices/${data.device.id}/suspend`, { token: t2 })).status).toBe(
			404,
		);
		expect((await call("GET", "/devices?ownerId=u1", { token: t2 })).status).toBe(403);
		const mine = (await (await call("GET", "/devices", { token: t2 })).json()) as {
			data: unknown[];
		};
		expect(mine.data).toHaveLength(0);
		const got = await call("GET", `/devices/${data.device.id}`, { token: t1 });
		const body = (await got.json()) as { data: { credentials: Array<Record<string, unknown>> } };
		expect(body.data.credentials[0]).not.toHaveProperty("secret");
		expect(JSON.stringify(body)).not.toContain(data.credential.secret);
		expect((await call("POST", `/devices/${data.device.id}/suspend`, { token: t1 })).status).toBe(
			200,
		);
		expect(
			(await call("POST", `/devices/${data.device.id}/resume`, { token: t1, body: {} })).status,
		).toBe(200);
		expect((await call("DELETE", `/devices/${data.device.id}`, { token: t1 })).status).toBe(200);
	});
});

describe("device facing routes", () => {
	it("enroll with a claim code, authorize with the PSK, fetch a bundle and the JWKS", async () => {
		const { call, t1, t2 } = await setup();
		const created = await call("POST", "/devices/enrollment-tokens", {
			token: t1,
			body: { ownerId: "u1", kind: "claim", permissions: PERMS },
		});
		expect(created.status).toBe(201);
		const { data: token } = (await created.json()) as { data: { id: string; token: string } };
		expect(
			(await call("DELETE", `/devices/enrollment-tokens/${token.id}`, { token: t2 })).status,
		).toBe(404);

		const enrolled = await call("POST", "/device/enroll", {
			body: { token: token.token, name: "thermo", credential: { kind: "psk" } },
		});
		expect(enrolled.status).toBe(201);
		const { data } = (await enrolled.json()) as { data: { credential: { secret: string } } };
		const psk = data.credential.secret;
		expect(
			(
				await call("POST", "/device/enroll", {
					body: { token: token.token, name: "again", credential: { kind: "psk" } },
				})
			).status,
		).toBe(401);

		const allowed = await call("POST", "/device/authorize", {
			token: psk,
			body: { action: "publish", resource: "mqtt:sensors:t" },
		});
		expect(allowed.status).toBe(200);
		const denied = await call("POST", "/device/authorize", {
			token: psk,
			body: { action: "publish", resource: "mqtt:cmd:t" },
		});
		expect(denied.status).toBe(403);
		const bad = await call("POST", "/device/authorize", {
			token: `tdk_${"A".repeat(43)}`,
			body: { action: "publish", resource: "mqtt:sensors:t" },
		});
		expect(bad.status).toBe(401);
		expect(bad.headers.get("www-authenticate")).toContain("Bearer");
		// A session token is not a device credential.
		expect(
			(await call("POST", "/device/authorize", { token: t1, body: { action: "x", resource: "y" } }))
				.status,
		).toBe(401);

		const bundle = await call("GET", "/device/bundle", { token: psk });
		expect(bundle.status).toBe(200);
		const jwks = (await (await call("GET", "/device/jwks")).json()) as {
			keys: Array<{ kid: string }>;
		};
		expect(jwks.keys[0]?.kid).toBe("bundle-1");
	});

	it("answer 404 when devices are not configured", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true },
		});
		const handler = createTheAuthHandler(auth, { rateLimit: false, allowUnauthenticated: true });
		expect((await handler(new Request(`${BASE}/device/jwks`))).status).toBe(404);
	});
});

describe("device routes in OpenAPI", () => {
	it("every device route has operation metadata and the device security scheme", () => {
		const spec = generateOpenAPISpec();
		expect(spec.paths["/devices"]?.post?.operationId).toBe("registerDevice");
		expect(spec.paths["/device/authorize"]?.post?.security).toEqual([{ DeviceCredential: [] }]);
		expect(spec.paths["/device/jwks"]?.get?.security).toEqual([]);
		expect(spec.components.securitySchemes).toHaveProperty("DeviceCredential");
	});

	it("drops the device facing routes with routes.devices false", () => {
		const spec = generateOpenAPISpec({ handler: { routes: { devices: false } } });
		expect(spec.paths["/device/enroll"]).toBeUndefined();
		expect(spec.paths["/devices"]).toBeDefined();
	});
});
