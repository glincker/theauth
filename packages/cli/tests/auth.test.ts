import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceFlowError, loginWithDeviceFlow } from "../src/auth/device-flow.js";
import {
	clearCredential,
	credentialsPath,
	listServers,
	loadCredential,
	saveCredential,
} from "../src/auth/token-cache.js";
import { parseAuthArgs } from "../src/auth-commands.js";

let dir: string;
let path: string;
beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "theauth-cli-"));
	path = join(dir, "nested", "credentials.json");
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const cred = (over = {}) => ({
	accessToken: "tok",
	tokenType: "Bearer",
	savedAt: Date.now(),
	...over,
});

describe("credentialsPath", () => {
	it("picks an OS appropriate location", () => {
		expect(credentialsPath({ platform: "linux", env: {}, home: "/home/a" })).toBe(
			"/home/a/.config/theauth/credentials.json",
		);
		expect(
			credentialsPath({ platform: "darwin", env: { XDG_CONFIG_HOME: "/x" }, home: "/Users/a" }),
		).toBe("/x/theauth/credentials.json");
		expect(
			credentialsPath({ platform: "win32", env: { APPDATA: "C:\\A" }, home: "C:\\u" }),
		).toContain("theauth");
		expect(credentialsPath({ env: { THEAUTH_CREDENTIALS_FILE: "/tmp/c.json" } })).toBe(
			"/tmp/c.json",
		);
	});
});

describe("token cache", () => {
	it("saves with 0600 on the file, round trips, and normalises the server url", async () => {
		await saveCredential("https://a.com/auth/", cred(), { path });
		if (process.platform !== "win32") {
			expect((await stat(path)).mode & 0o777).toBe(0o600);
			expect((await stat(join(dir, "nested"))).mode & 0o777).toBe(0o700);
		}
		expect((await loadCredential("https://a.com/auth", { path }))?.accessToken).toBe("tok");
		expect(await listServers({ path })).toEqual(["https://a.com/auth"]);
	});

	it("keeps servers separate and clears one at a time", async () => {
		await saveCredential("https://a.com", cred({ accessToken: "A" }), { path });
		await saveCredential("https://b.com", cred({ accessToken: "B" }), { path });
		expect(await clearCredential("https://a.com", { path })).toBe(true);
		expect(await loadCredential("https://a.com", { path })).toBeNull();
		expect((await loadCredential("https://b.com", { path }))?.accessToken).toBe("B");
		expect(await clearCredential("https://a.com", { path })).toBe(false);
		await clearCredential("https://b.com", { path });
		await expect(readFile(path)).rejects.toThrow();
	});

	it("treats expired credentials as absent and survives a corrupt file", async () => {
		await saveCredential("https://a.com", cred({ expiresAt: Date.now() - 1 }), { path });
		expect(await loadCredential("https://a.com", { path })).toBeNull();
		const { writeFile } = await import("node:fs/promises");
		await writeFile(path, "{not json");
		expect(await loadCredential("https://a.com", { path })).toBeNull();
		await saveCredential("https://a.com", cred(), { path });
		expect(await loadCredential("https://a.com", { path })).not.toBeNull();
	});
});

function server(script: Array<{ status?: number; body: object }>) {
	const calls: Array<{ url: string; body: unknown }> = [];
	let i = 0;
	const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
		const u = String(url);
		calls.push({ url: u, body: init?.body ? JSON.parse(String(init.body)) : undefined });
		if (u.endsWith("/auth/device/code")) {
			return Response.json({
				device_code: "dc",
				user_code: "BCDF-GHJK",
				verification_uri: "https://a.com/device",
				verification_uri_complete: "https://a.com/device?user_code=BCDF-GHJK",
				expires_in: 900,
				interval: 5,
			});
		}
		const step = script[Math.min(i++, script.length - 1)] as { status?: number; body: object };
		return Response.json(step.body, { status: step.status ?? 200 });
	});
	return { f: f as unknown as typeof fetch, calls };
}

describe("loginWithDeviceFlow", () => {
	const base = { serverUrl: "https://a.com/api/", onPrompt: () => {} };

	it("polls through pending and slow_down, then saves the token", async () => {
		const sleeps: number[] = [];
		const { f, calls } = server([
			{ status: 400, body: { error: "authorization_pending" } },
			{ status: 400, body: { error: "slow_down", interval: 10 } },
			{ body: { access_token: "T", token_type: "Bearer", expires_in: 60, user_id: "u1" } },
		]);
		const prompt = vi.fn();
		const out = await loginWithDeviceFlow({
			...base,
			onPrompt: prompt,
			fetch: f,
			sleep: async (ms) => void sleeps.push(ms),
			cache: { path },
			clientId: "cli",
		});
		expect(out).toMatchObject({ accessToken: "T", userId: "u1" });
		expect(sleeps).toEqual([5000, 5000, 10000]);
		expect(prompt).toHaveBeenCalledWith(expect.objectContaining({ userCode: "BCDF-GHJK" }));
		expect(calls[0]).toMatchObject({
			url: "https://a.com/api/auth/device/code",
			body: { client_id: "cli" },
		});
		expect(calls[1]?.body).toMatchObject({
			device_code: "dc",
			grant_type: "urn:ietf:params:oauth:grant-type:device_code",
		});
		expect((await loadCredential("https://a.com/api", { path }))?.accessToken).toBe("T");
	});

	it("does not save when save is false", async () => {
		const { f } = server([{ body: { access_token: "T" } }]);
		await loginWithDeviceFlow({
			...base,
			fetch: f,
			sleep: async () => {},
			save: false,
			cache: { path },
		});
		expect(await loadCredential("https://a.com/api", { path })).toBeNull();
	});

	it.each([
		["access_denied", "access_denied"],
		["expired_token", "expired_token"],
	])("maps %s to a typed error", async (error, code) => {
		const { f } = server([{ status: 400, body: { error } }]);
		await expect(
			loginWithDeviceFlow({ ...base, fetch: f, sleep: async () => {}, cache: { path } }),
		).rejects.toMatchObject({ code });
	});

	it("explains a server that approves but issues no token", async () => {
		const { f } = server([{ body: { authorized: true, user_id: "u" } }]);
		await expect(
			loginWithDeviceFlow({ ...base, fetch: f, sleep: async () => {}, cache: { path } }),
		).rejects.toBeInstanceOf(DeviceFlowError);
	});

	it("honours abort and a failed browser open does not break login", async () => {
		const ac = new AbortController();
		const { f } = server([{ status: 400, body: { error: "authorization_pending" } }]);
		await expect(
			loginWithDeviceFlow({ ...base, fetch: f, signal: ac.signal, sleep: async () => ac.abort() }),
		).rejects.toMatchObject({ code: "aborted" });
		const ok = server([{ body: { access_token: "T" } }]);
		await expect(
			loginWithDeviceFlow({
				...base,
				fetch: ok.f,
				sleep: async () => {},
				save: false,
				openBrowser: () => {
					throw new Error("no display");
				},
			}),
		).resolves.toMatchObject({ accessToken: "T" });
	});
});

describe("parseAuthArgs", () => {
	it("parses flags in both forms", () => {
		expect(parseAuthArgs(["--server", "https://a", "--no-browser", "--client-id=x"])).toMatchObject(
			{ server: "https://a", noBrowser: true, clientId: "x", unknown: null },
		);
		expect(parseAuthArgs(["--bogus"]).unknown).toBe("--bogus");
	});
});
