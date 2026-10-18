import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	runDoctor,
	runLiveDoctorChecks,
	runProjectDoctorChecks,
	satisfiesRange,
} from "../src/doctor-live.js";
import { generateSecret, parseDoctorArgs } from "../src/tools-commands.js";

interface FakeRoutes {
	[path: string]: { status: number; body?: unknown };
}

let server: Server | null = null;

async function listen(routes: FakeRoutes): Promise<string> {
	server = createServer((req, res) => {
		const hit = routes[(req.url ?? "").split("?")[0] ?? ""];
		if (!hit) {
			res.writeHead(404, { "content-type": "application/json" }).end("{}");
			return;
		}
		res
			.writeHead(hit.status, { "content-type": "application/json" })
			.end(JSON.stringify(hit.body ?? {}));
	});
	await new Promise<void>((r) => server?.listen(0, "127.0.0.1", r));
	return `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
}

afterEach(async () => {
	await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
	server = null;
});

const noConfig = async () => null;
const byId = (checks: Array<{ id: string }>, id: string) => checks.find((c) => c.id === id);

describe("satisfiesRange", () => {
	it("handles the ranges adapters publish", () => {
		expect(satisfiesRange("1.3.0", ">=0.7.1 <2.0.0")).toBe(true);
		expect(satisfiesRange("2.0.0", ">=0.7.1 <2.0.0")).toBe(false);
		expect(satisfiesRange("0.7.0", ">=0.7.1 <2.0.0")).toBe(false);
		expect(satisfiesRange("1.4.2", "^1.2.0")).toBe(true);
		expect(satisfiesRange("2.0.0", "^1.2.0")).toBe(false);
		expect(satisfiesRange("1.2.9", "~1.2.3")).toBe(true);
		expect(satisfiesRange("1.3.0", "~1.2.3")).toBe(false);
		expect(satisfiesRange("1.0.0", "^0.9.0 || ^1.0.0")).toBe(true);
	});
});

describe("parseDoctorArgs --live", () => {
	it("takes an optional url", () => {
		expect(parseDoctorArgs(["--live", "http://x/api"], "/c").live).toBe("http://x/api");
		expect(parseDoctorArgs(["--live=http://x/api"], "/c").live).toBe("http://x/api");
		expect(parseDoctorArgs(["--live", "--json"], "/c")).toMatchObject({ live: "", json: true });
		expect(parseDoctorArgs(["--live", "--url", "http://y"], "/c").live).toBe("http://y");
		expect(parseDoctorArgs([], "/c").live).toBeNull();
	});
});

describe("runLiveDoctorChecks", () => {
	it("passes for a healthy server", async () => {
		const url = await listen({
			"/agents": { status: 401 },
			"/.well-known/oauth-authorization-server": { status: 404 },
			"/.well-known/oauth-protected-resource": { status: 404 },
		});
		const checks = await runLiveDoctorChecks({ cwd: ".", url, loadConfig: noConfig });
		expect(checks.map((c) => `${c.id}:${c.status}`)).toEqual([
			"live-reachable:pass",
			"live-protected-401:pass",
			"live-mcp-metadata:pass",
		]);
	});

	it("fails when the metadata advertises an endpoint that answers 404", async () => {
		const routes: FakeRoutes = { "/agents": { status: 401 }, "/mcp/token": { status: 405 } };
		const base = await listen(routes);
		routes["/.well-known/oauth-authorization-server"] = {
			status: 200,
			body: { token_endpoint: `${base}/mcp/token`, revocation_endpoint: `${base}/mcp/revoke` },
		};
		const checks = await runLiveDoctorChecks({ cwd: ".", url: base, loadConfig: noConfig });
		const meta = byId(checks, "live-mcp-metadata") as { status: string; message: string };
		expect(meta.status).toBe("fail");
		expect(meta.message).toContain("revocation_endpoint");
		expect(meta.message).not.toContain("token_endpoint");
	});

	it("fails when a protected route answers 200 without a token", async () => {
		const url = await listen({ "/agents": { status: 200, body: { data: [] } } });
		const checks = await runLiveDoctorChecks({ cwd: ".", url, loadConfig: noConfig });
		expect((byId(checks, "live-protected-401") as { status: string }).status).toBe("fail");
	});

	it("fails when nothing is mounted at the url", async () => {
		const url = await listen({});
		const checks = await runLiveDoctorChecks({ cwd: ".", url, loadConfig: noConfig });
		expect((byId(checks, "live-reachable") as { status: string }).status).toBe("fail");
	});

	it("fails when the server is not running", async () => {
		const checks = await runLiveDoctorChecks({
			cwd: ".",
			url: "http://127.0.0.1:1",
			loadConfig: noConfig,
		});
		expect(checks).toHaveLength(1);
		expect(checks[0]).toMatchObject({ id: "live-reachable", status: "fail" });
	});
});

describe("runProjectDoctorChecks", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "theauth-doctor-live-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("warns about pending migrations in the ledger", async () => {
		const core = await import("@glinr/theauth");
		const file = join(dir, "app.db");
		const db = await core.createDatabase({ provider: "sqlite-native", url: file });
		await core.runSchemaMigrations(db, "sqlite-native", { to: "0001" });
		(db as any).$client.close();
		const checks = await runProjectDoctorChecks({
			cwd: dir,
			env: { DATABASE_URL: file },
			loadConfig: noConfig,
		});
		const schema = byId(checks, "schema") as { status: string; message: string };
		expect(schema.status).toBe("warn");
		expect(schema.message).toContain("pending");
	});

	it("warns when the SQLite file does not exist yet", async () => {
		const checks = await runProjectDoctorChecks({
			cwd: dir,
			env: { DATABASE_URL: "./missing.db" },
			loadConfig: noConfig,
		});
		expect((byId(checks, "schema") as { message: string }).message).toContain("does not exist");
	});

	it("flags allowUnauthenticated, a failure in production", async () => {
		await mkdir(join(dir, "src"));
		await writeFile(
			join(dir, "src/server.ts"),
			'import { theAuthHono } from "@glinr/theauth-hono";\ntheAuthHono(auth, { allowUnauthenticated: true });\n',
		);
		const dev = await runProjectDoctorChecks({ cwd: dir, env: {}, loadConfig: noConfig });
		expect((byId(dev, "allow-unauthenticated") as { status: string }).status).toBe("warn");
		const prod = await runProjectDoctorChecks({
			cwd: dir,
			env: { NODE_ENV: "production" },
			loadConfig: noConfig,
		});
		expect((byId(prod, "allow-unauthenticated") as { status: string }).status).toBe("fail");
		expect((byId(prod, "trusted-proxy") as { status: string }).status).toBe("warn");
	});

	it("fails when core is outside an adapter peer range", async () => {
		await writeFile(
			join(dir, "package.json"),
			JSON.stringify({
				dependencies: { "@glinr/theauth": "2.0.0", "@glinr/theauth-hono": "5.1.0" },
			}),
		);
		const put = async (name: string, body: object) => {
			const d = join(dir, "node_modules", ...name.split("/"));
			await mkdir(d, { recursive: true });
			await writeFile(join(d, "package.json"), JSON.stringify(body));
		};
		await put("@glinr/theauth", { name: "@glinr/theauth", version: "2.0.0" });
		await put("@glinr/theauth-hono", {
			name: "@glinr/theauth-hono",
			version: "5.1.0",
			peerDependencies: { "@glinr/theauth": ">=0.7.1 <2.0.0" },
		});
		const checks = await runProjectDoctorChecks({ cwd: dir, env: {}, loadConfig: noConfig });
		const core = byId(checks, "core-version") as { status: string; message: string };
		expect(core.status).toBe("fail");
		expect(core.message).toContain("@glinr/theauth-hono");
	});
});

describe("runDoctor", () => {
	it("keeps the documented json shape", async () => {
		const dir = await mkdtemp(join(tmpdir(), "theauth-doctor-json-"));
		try {
			await writeFile(join(dir, ".env"), `THEAUTH_SECRET=${generateSecret(32, "hex")}\n`);
			const { text } = await runDoctor(
				{ json: true, live: null, cwd: dir, help: false, error: null },
				{},
				"v22.0.0",
			);
			const parsed = JSON.parse(text) as {
				ok: boolean;
				checks: Array<{ id: string; status: string; message: string }>;
			};
			expect(Object.keys(parsed).sort()).toEqual(["checks", "ok"]);
			for (const check of parsed.checks) {
				expect(["pass", "warn", "fail"]).toContain(check.status);
				expect(typeof check.id).toBe("string");
				expect(typeof check.message).toBe("string");
			}
			expect(parsed.checks.map((c) => c.id)).toContain("node");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
