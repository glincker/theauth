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
	const dir = await mkdtemp(join(tmpdir(), "theauth-mcp-example-"));
	const dbPath = join(dir, "mcp-example.db");
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

describe("mcp-server example", () => {
	it("serves MCP metadata and protects the tool routes with agent tokens", async () => {
		const app = await startExample();
		running.push(app);

		const homeRes = await fetch(`${app.baseUrl}/`);
		expect(homeRes.status).toBe(200);
		expect(await homeRes.text()).toContain("TheAuth MCP Server");

		const metadataRes = await fetch(`${app.baseUrl}/api/.well-known/oauth-authorization-server`);
		expect(metadataRes.status).toBe(200);
		const metadata = (await metadataRes.json()) as {
			issuer: string;
			registration_endpoint: string;
		};
		expect(metadata.issuer).toBe(app.baseUrl);
		expect(metadata.registration_endpoint).toBe(`${app.baseUrl}/api/mcp/register`);

		const createRes = await fetch(`${app.baseUrl}/api/agents`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				ownerId: "user-1",
				name: "mcp-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:*", actions: ["read", "execute"] }],
			}),
		});
		expect(createRes.status).toBe(201);
		const created = (await createRes.json()) as { data: { token: string } };
		expect(created.data.token).toMatch(/^kv_/);

		const listToolsRes = await fetch(`${app.baseUrl}/tools/list`, {
			headers: { Authorization: `Bearer ${created.data.token}` },
		});
		expect(listToolsRes.status).toBe(200);
		const tools = (await listToolsRes.json()) as { tools: Array<{ name: string }> };
		expect(tools.tools.map((tool) => tool.name)).toEqual([
			"list_files",
			"read_file",
			"run_command",
		]);

		const callToolRes = await fetch(`${app.baseUrl}/tools/call`, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${created.data.token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				name: "list_files",
				arguments: { path: "/tmp" },
			}),
		});
		expect(callToolRes.status).toBe(200);
		const result = (await callToolRes.json()) as {
			content: Array<{ type: string; text: string }>;
		};
		expect(result.content[0]?.type).toBe("text");
		expect(result.content[0]?.text).toContain("[simulated] list_files called");

		const unauthorizedRes = await fetch(`${app.baseUrl}/tools/list`);
		expect(unauthorizedRes.status).toBe(401);
	});
});
