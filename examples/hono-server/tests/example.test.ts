import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

type RunningExample = {
	baseUrl: string;
	stop: () => Promise<void>;
};

async function getFreePort(): Promise<number> {
	return await new Promise((resolve, reject) => {
		const server = net.createServer();
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			if (!address || typeof address === "string") {
				server.close();
				reject(new Error("Failed to resolve free port"));
				return;
			}
			server.close((error) => {
				if (error) {
					reject(error);
					return;
				}
				resolve(address.port);
			});
		});
		server.on("error", reject);
	});
}

async function waitForServer(baseUrl: string): Promise<void> {
	const startedAt = Date.now();
	while (Date.now() - startedAt < 15_000) {
		try {
			const response = await fetch(`${baseUrl}/`);
			if (response.ok) {
				return;
			}
		} catch {}
		await new Promise((resolve) => setTimeout(resolve, 150));
	}
	throw new Error(`Timed out waiting for ${baseUrl}`);
}

async function startExample(): Promise<RunningExample> {
	const port = await getFreePort();
	const dir = await mkdtemp(join(tmpdir(), "theauth-hono-example-"));
	const dbPath = join(dir, "theauth-example.db");
	const pnpmCmd = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
	const child = spawn(pnpmCmd, ["start"], {
		cwd: process.cwd(),
		env: {
			...process.env,
			PORT: String(port),
			THEAUTH_DB_PATH: dbPath,
		},
		stdio: ["ignore", "pipe", "pipe"],
	});

	let output = "";
	child.stdout.on("data", (chunk) => {
		output += chunk.toString();
	});
	child.stderr.on("data", (chunk) => {
		output += chunk.toString();
	});

	const exitPromise = new Promise<number | null>((resolve) => {
		child.on("exit", (code) => resolve(code));
	});

	try {
		await waitForServer(`http://localhost:${port}`);
	} catch (error) {
		child.kill("SIGTERM");
		const code = await exitPromise;
		throw new Error(
			`Server failed to start (code ${code ?? "signal"}): ${output}\n${String(error)}`,
		);
	}

	return {
		baseUrl: `http://localhost:${port}`,
		stop: async () => {
			child.kill("SIGTERM");
			await exitPromise;
			await rm(dir, { recursive: true, force: true });
		},
	};
}

const running: RunningExample[] = [];

afterEach(async () => {
	await Promise.all(running.splice(0).map((entry) => entry.stop()));
});

describe("hono-server example", () => {
	it("serves the homepage and the documented agent flow", async () => {
		const app = await startExample();
		running.push(app);

		const homeRes = await fetch(`${app.baseUrl}/`);
		expect(homeRes.status).toBe(200);
		expect(await homeRes.text()).toContain("TheAuth");

		const createRes = await fetch(`${app.baseUrl}/api/agents`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				ownerId: "user-1",
				name: "example-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:*", actions: ["read"] }],
			}),
		});
		expect(createRes.status).toBe(201);
		const created = (await createRes.json()) as {
			data: { id: string; token: string; name: string };
		};
		expect(created.data.name).toBe("example-agent");
		expect(created.data.token).toMatch(/^kv_/);

		const listRes = await fetch(`${app.baseUrl}/api/agents?userId=user-1`);
		expect(listRes.status).toBe(200);
		const listed = (await listRes.json()) as { data: Array<{ id: string; name: string }> };
		expect(listed.data).toHaveLength(1);
		expect(listed.data[0]?.id).toBe(created.data.id);

		const authorizeRes = await fetch(`${app.baseUrl}/api/authorize/token`, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${created.data.token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				action: "read",
				resource: "mcp:github:repos",
			}),
		});
		expect(authorizeRes.status).toBe(200);
		const authorized = (await authorizeRes.json()) as { data: { allowed: boolean } };
		expect(authorized.data.allowed).toBe(true);

		const auditRes = await fetch(`${app.baseUrl}/api/audit`);
		expect(auditRes.status).toBe(200);
		const audit = (await auditRes.json()) as { data: unknown[] };
		expect(audit.data.length).toBeGreaterThan(0);
	});
});
