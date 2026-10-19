import { createTheAuth } from "@glinr/theauth";
import { describe, expect, it } from "vitest";
import { parseDeviceArgs, parsePerm, runDevice } from "../src/device-commands.js";

async function devices() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true },
		devices: {},
	});
	await auth.user.create({ id: "u1", email: "u1@test.com" });
	if (!auth.device) throw new Error("no devices");
	return auth.device;
}

describe("parsePerm", () => {
	it("splits on the last = and keeps colons and stars", () => {
		expect(parsePerm("mqtt:sensors:*=publish,subscribe")).toEqual({
			resource: "mqtt:sensors:*",
			actions: ["publish", "subscribe"],
		});
		expect(parsePerm("nope")).toBeNull();
		expect(parsePerm("x=")).toBeNull();
	});
});

describe("parseDeviceArgs", () => {
	it("parses register and enroll-token", () => {
		expect(
			parseDeviceArgs([
				"register",
				"--config",
				"c.mjs",
				"--owner",
				"u1",
				"--name",
				"t1",
				"--group",
				"hvac",
				"--perm",
				"mqtt:a=publish",
				"--psk",
			]),
		).toMatchObject({
			sub: "register",
			owner: "u1",
			name: "t1",
			groups: ["hvac"],
			psk: true,
			error: null,
		});
		expect(
			parseDeviceArgs([
				"enroll-token",
				"--config",
				"c.mjs",
				"--owner",
				"u1",
				"--kind",
				"bulk",
				"--max-uses",
				"5",
			]),
		).toMatchObject({ tokenKind: "bulk", maxUses: 5, error: null });
	});

	it("reports missing pieces", () => {
		expect(parseDeviceArgs(["register", "--owner", "u1"]).error).toMatch(/--config/);
		expect(parseDeviceArgs(["revoke", "--config", "c.mjs"]).error).toMatch(/device id/);
		expect(
			parseDeviceArgs(["enroll-token", "--config", "c", "--owner", "u", "--kind", "x"]).error,
		).toMatch(/claim or bulk/);
		expect(parseDeviceArgs(["bogus"]).error).toMatch(/Unknown device command/);
		expect(parseDeviceArgs([]).help).toBe(true);
	});
});

describe("runDevice", () => {
	it("registers, lists, suspends and revokes, printing the PSK once", async () => {
		const d = await devices();
		const reg = parseDeviceArgs([
			"register",
			"--config",
			"c",
			"--owner",
			"u1",
			"--name",
			"t1",
			"--psk",
			"--perm",
			"mqtt:a=publish",
		]);
		const out = await runDevice(reg, d);
		expect(out).toMatch(/PSK \(shown once\): tdk_/);
		const id = out.split(" ")[0] ?? "";
		expect(await runDevice(parseDeviceArgs(["list", "--config", "c"]), d)).toContain("t1");
		expect(await runDevice(parseDeviceArgs(["suspend", id, "--config", "c"]), d)).toBe("Suspended");
		const json = await runDevice(parseDeviceArgs(["revoke", id, "--config", "c", "--json"]), d);
		expect(JSON.parse(json)).toEqual({ revokedDelegations: [] });
		const token = await runDevice(
			parseDeviceArgs(["enroll-token", "--config", "c", "--owner", "u1", "--kind", "claim"]),
			d,
		);
		expect(token).toMatch(/claim token \(shown once\): [0-9A-Z]{5}-[0-9A-Z]{5}/);
	});
});
