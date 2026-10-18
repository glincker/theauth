/** A `*` before the last segment of a device resource is refused unless path matching defines it as one segment. */
import { describe, expect, it } from "vitest";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";
import { devicesOf } from "./device-helpers.js";

async function make(resourceMatching?: "path") {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 20, defaultPermissions: [], auditAll: true },
		devices: {},
		...(resourceMatching && { resourceMatching }),
	});
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
	return auth;
}

const MID = [{ resource: "mqtt:a:*:b", actions: ["publish"] }];
const OK = [
	{ resource: "mqtt:a:*", actions: ["publish"] },
	{ resource: "mqtt:a:b", actions: ["publish"] },
];

describe("device permission with a mid `*`", () => {
	it("register refuses it by default", async () => {
		const devices = devicesOf(await make());
		await expect(
			devices.register({ ownerId: "u1", name: "d", permissions: MID }),
		).rejects.toMatchObject({
			code: "INVALID_INPUT",
			message: expect.stringContaining("only allowed as the final segment"),
		});
	});

	it("update refuses it by default", async () => {
		const devices = devicesOf(await make());
		const { device } = await devices.register({ ownerId: "u1", name: "d", permissions: OK });
		await expect(devices.update(device.id, { permissions: MID })).rejects.toMatchObject({
			code: "INVALID_INPUT",
		});
	});

	it("accepts a final segment wildcard and exact resources", async () => {
		const devices = devicesOf(await make());
		await expect(
			devices.register({ ownerId: "u1", name: "d", permissions: OK }),
		).resolves.toBeDefined();
	});

	it("path mode accepts it, since the wildcard then means one segment", async () => {
		const devices = devicesOf(await make("path"));
		await expect(
			devices.register({ ownerId: "u1", name: "d", permissions: MID }),
		).resolves.toBeDefined();
	});
});
