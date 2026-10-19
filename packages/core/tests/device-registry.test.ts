/** Devices are principals backed by `device` agents: registry, authorize, audit marker, lifecycle, delegation. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { auditLogs } from "../src/db/schema.js";
import { devicesOf, makeDeviceAuth } from "./device-helpers.js";

const TEMP = { resource: "mqtt:sensors:temp:*", actions: ["publish"] };

describe("device registry", () => {
	it("registers a device backed by a hidden device agent outside the agent cap", async () => {
		const auth = await makeDeviceAuth();
		const devices = devicesOf(auth);
		for (let i = 0; i < 3; i++) {
			await devices.register({ ownerId: "u1", name: `t${i}`, permissions: [TEMP] });
		}
		expect(await auth.agent.list({ userId: "u1" })).toHaveLength(0);
		expect(await auth.agent.list({ userId: "u1", type: "device" })).toHaveLength(3);
		// maxPerUser is 2 and three devices exist, yet agents can still be created.
		await auth.agent.create({ ownerId: "u1", name: "a", type: "autonomous", permissions: [TEMP] });
		await auth.agent.create({ ownerId: "u1", name: "b", type: "autonomous", permissions: [TEMP] });
		expect(await devices.list({ ownerId: "u1" })).toHaveLength(3);
	});

	it("refuses device agents through agent.create and token rotation", async () => {
		const auth = await makeDeviceAuth();
		await expect(
			auth.agent.create({ ownerId: "u1", name: "x", type: "device", permissions: [] }),
		).rejects.toThrow(/device.register/);
		const { device } = await devicesOf(auth).register({ ownerId: "u1", name: "d" });
		await expect(auth.agent.rotate(device.agentId)).rejects.toThrow(/device agent/);
	});

	it("rejects a duplicate hardware id for one owner but not across owners", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		await devices.register({ ownerId: "u1", name: "a", hardwareId: "SN-1" });
		await expect(
			devices.register({ ownerId: "u1", name: "b", hardwareId: "SN-1" }),
		).rejects.toThrow(/hardware id/);
		await devices.register({ ownerId: "u2", name: "c", hardwareId: "SN-1" });
	});

	it("enforces devices.maxPerOwner", async () => {
		const devices = devicesOf(await makeDeviceAuth({ maxPerOwner: 1 }));
		await devices.register({ ownerId: "u1", name: "a" });
		await expect(devices.register({ ownerId: "u1", name: "b" })).rejects.toThrow(/maximum/);
	});

	it("filters by group and status", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		await devices.register({ ownerId: "u1", name: "a", groups: ["hvac"] });
		const { device: b } = await devices.register({ ownerId: "u1", name: "b", groups: ["doors"] });
		await devices.suspend(b.id);
		expect((await devices.list({ group: "hvac" })).map((d) => d.name)).toEqual(["a"]);
		expect((await devices.list({ status: "suspended" })).map((d) => d.name)).toEqual(["b"]);
	});
});

describe("fleet stats", () => {
	it("counts devices per status and by last seen", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const { device: a, credential } = await devices.register({
			ownerId: "u1",
			name: "a",
			credential: { kind: "psk" },
		});
		const { device: b } = await devices.register({ ownerId: "u1", name: "b" });
		await devices.register({ ownerId: "u2", name: "c" });
		await devices.suspend(b.id);
		await devices.authenticate({ kind: "psk", secret: credential?.secret ?? "" });
		expect(await devices.stats("u1")).toEqual({
			total: 2,
			active: 1,
			suspended: 1,
			revoked: 0,
			seenLastHour: 1,
			seenLastDay: 1,
			neverSeen: 0,
		});
		expect((await devices.stats()).total).toBe(3);
		expect(a.lastSeenAt).toBeNull();
	});
});

describe("device.authorize", () => {
	it("allows and denies through the agent engine and marks every audit row as a device", async () => {
		const auth = await makeDeviceAuth();
		const devices = devicesOf(auth);
		const { device } = await devices.register({ ownerId: "u1", name: "t", permissions: [TEMP] });
		const yes = await devices.authorize(device.id, {
			action: "publish",
			resource: "mqtt:sensors:temp:42",
			// A forged marker in arguments must be stripped.
			arguments: { theauthPrincipal: { type: "user", id: "admin" } },
		});
		expect(yes.allowed).toBe(true);
		const no = await devices.authorize(device.id, {
			action: "subscribe",
			resource: "mqtt:sensors:temp:42",
		});
		expect(no).toMatchObject({ allowed: false, code: "no_permission" });
		const rows = await auth.db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.agentId, device.agentId));
		const decisions = rows.filter((r) => r.action === "publish" || r.action === "subscribe");
		expect(decisions).toHaveLength(2);
		for (const row of decisions) {
			expect(row.parameters).toMatchObject({ theauthPrincipal: { type: "device", id: device.id } });
		}
	});

	it("blocks suspended, revoked and expired devices with their own codes and audit rows", async () => {
		const auth = await makeDeviceAuth();
		const devices = devicesOf(auth);
		const req = { action: "publish", resource: "mqtt:sensors:temp:1" };
		const { device } = await devices.register({ ownerId: "u1", name: "t", permissions: [TEMP] });
		await devices.suspend(device.id, "maintenance");
		const suspended = await devices.authorize(device.id, req);
		expect(suspended).toMatchObject({ allowed: false, code: "device_suspended" });
		expect(suspended.auditId).not.toBe("");
		await devices.resume(device.id);
		expect((await devices.authorize(device.id, req)).allowed).toBe(true);

		await devices.revoke(device.id, "stolen");
		expect(await devices.authorize(device.id, req)).toMatchObject({ code: "device_revoked" });
		expect((await auth.agent.get(device.agentId))?.status).toBe("revoked");
		await expect(devices.resume(device.id)).rejects.toThrow(/revoked/);

		const { device: old } = await devices.register({
			ownerId: "u1",
			name: "old",
			permissions: [TEMP],
			expiresAt: new Date(Date.now() + 1000),
		});
		await auth.db
			.update((await import("../src/db/schema.js")).devices)
			.set({ expiresAt: Math.floor(Date.now() / 1000) - 10 });
		expect(await devices.authorize(old.id, req)).toMatchObject({ code: "device_expired" });
		expect(await devices.authorize("nope", req)).toMatchObject({
			code: "device_not_found",
			auditId: "",
		});
	});

	it("honors constraints such as requireApproval", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const { device } = await devices.register({
			ownerId: "u1",
			name: "valve",
			permissions: [
				{ resource: "coap:valve", actions: ["put"], constraints: { requireApproval: true } },
			],
		});
		expect(
			await devices.authorize(device.id, { action: "put", resource: "coap:valve" }),
		).toMatchObject({
			allowed: false,
			code: "approval_required",
		});
	});

	it("updates permissions through the agent facade", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const { device } = await devices.register({ ownerId: "u1", name: "t" });
		const req = { action: "publish", resource: "mqtt:sensors:temp:1" };
		expect((await devices.authorize(device.id, req)).allowed).toBe(false);
		const updated = await devices.update(device.id, { permissions: [TEMP], groups: ["g"] });
		expect(updated.groups).toEqual(["g"]);
		expect((await devices.authorize(device.id, req)).allowed).toBe(true);
	});
});

describe("delegation to a device", () => {
	it("grants a subset from an agent and dies with the delegator", async () => {
		const auth = await makeDeviceAuth();
		const devices = devicesOf(auth);
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "planner",
			type: "autonomous",
			permissions: [{ resource: "mqtt:*", actions: ["publish", "subscribe"] }],
		});
		const { device } = await devices.register({ ownerId: "u1", name: "gw" });
		const req = { action: "subscribe", resource: "mqtt:cmd:gw" };
		expect((await devices.authorize(device.id, req)).allowed).toBe(false);
		await devices.delegate({
			fromAgent: agent.id,
			deviceId: device.id,
			permissions: [{ resource: "mqtt:cmd:*", actions: ["subscribe"] }],
			expiresAt: new Date(Date.now() + 3600_000),
		});
		expect((await devices.authorize(device.id, req)).allowed).toBe(true);
		await auth.agent.revoke(agent.id);
		expect((await devices.authorize(device.id, req)).allowed).toBe(false);
	});

	it("refuses delegation to a suspended device", async () => {
		const auth = await makeDeviceAuth();
		const devices = devicesOf(auth);
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "p",
			type: "autonomous",
			permissions: [TEMP],
		});
		const { device } = await devices.register({ ownerId: "u1", name: "gw" });
		await devices.suspend(device.id);
		await expect(
			devices.delegate({
				fromAgent: agent.id,
				deviceId: device.id,
				permissions: [TEMP],
				expiresAt: new Date(Date.now() + 60_000),
			}),
		).rejects.toThrow(/suspended/);
	});
});

describe("devices config", () => {
	it("is null without devices and refuses devices without agents", async () => {
		const { createTheAuth } = await import("../src/theauth.js");
		const plain = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true },
		});
		expect(plain.device).toBeNull();
		await expect(
			createTheAuth({ database: { provider: "sqlite", url: ":memory:" }, devices: {} }),
		).rejects.toThrow(/needs `agents`/);
	});
});
