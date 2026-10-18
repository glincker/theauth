import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DeviceDetail, DeviceFleetStats, DeviceRow } from "../src/api/device-types.js";
import { createDeviceApi, deviceQuery } from "../src/api/devices.js";
import { DeviceDetailPanel, DeviceTable, FleetStats } from "../src/components/device-tables.js";
import { devicesUnavailable } from "../src/pages/devices.js";
import {
	activeCredentialKinds,
	buildEnrollmentInput,
	formatLastSeen,
	statusTone,
} from "../src/pages/devices-format.js";

afterEach(() => vi.unstubAllGlobals());

const NOW = Date.parse("2026-10-18T12:00:00.000Z");

function device(overrides: Partial<DeviceRow> = {}): DeviceRow {
	return {
		id: "dev_1",
		agentId: "agent_1",
		ownerId: "u1",
		name: "Arm 7",
		kind: "robot",
		status: "active",
		groups: ["line-a"],
		expiresAt: null,
		lastSeenAt: "2026-10-18T11:55:00.000Z",
		createdAt: "2026-10-01T00:00:00.000Z",
		updatedAt: "2026-10-01T00:00:00.000Z",
		...overrides,
	};
}

const noop = () => {};
const handlers = { onSelect: noop, onSuspend: noop, onResume: noop, onRevoke: noop };

describe("device formatting", () => {
	it("formats last seen relative to a fixed now", () => {
		expect(formatLastSeen(null, NOW)).toBe("never");
		expect(formatLastSeen("2026-10-18T11:59:30.000Z", NOW)).toBe("just now");
		expect(formatLastSeen("2026-10-18T11:55:00.000Z", NOW)).toBe("5m ago");
		expect(formatLastSeen("2026-10-18T09:00:00.000Z", NOW)).toBe("3h ago");
		expect(formatLastSeen("2026-10-16T12:00:00.000Z", NOW)).toBe("2d ago");
		expect(formatLastSeen("not a date", NOW)).toBe("unknown");
	});

	it("maps status to a tone", () => {
		expect([statusTone("active"), statusTone("suspended"), statusTone("revoked")]).toEqual([
			"green",
			"yellow",
			"red",
		]);
	});

	it("lists the kinds of active credentials only", () => {
		const base = { deviceId: "d", lookup: "l", expiresAt: null, lastUsedAt: null, createdAt: "x" };
		expect(
			activeCredentialKinds([
				{ ...base, id: "1", kind: "psk", status: "revoked" },
				{ ...base, id: "2", kind: "jwk", status: "active" },
				{ ...base, id: "3", kind: "jwk", status: "active" },
				{ ...base, id: "4", kind: "x509", status: "active" },
			]),
		).toBe("jwk, x509");
		expect(activeCredentialKinds([])).toBe("none");
	});
});

describe("buildEnrollmentInput", () => {
	const form = {
		ownerId: " u1 ",
		kind: "bulk" as const,
		maxUses: "20",
		ttlMinutes: "30",
		groups: "line-a, line-b,",
		deviceKind: "robot",
	};

	it("trims, converts minutes to seconds and splits groups", () => {
		expect(buildEnrollmentInput(form)).toEqual({
			ownerId: "u1",
			kind: "bulk",
			maxUses: 20,
			ttlSeconds: 1800,
			groups: ["line-a", "line-b"],
			deviceKind: "robot",
		});
	});

	it("omits empty optional fields", () => {
		expect(
			buildEnrollmentInput({ ...form, maxUses: "", ttlMinutes: "", groups: "", deviceKind: "" }),
		).toEqual({ ownerId: "u1", kind: "bulk" });
	});

	it("returns a message for bad input", () => {
		expect(buildEnrollmentInput({ ...form, ownerId: " " })).toBe("An owner id is required");
		expect(buildEnrollmentInput({ ...form, maxUses: "0" })).toContain("Max uses");
		expect(buildEnrollmentInput({ ...form, ttlMinutes: "1.5" })).toContain("Lifetime");
	});
});

describe("device api", () => {
	it("builds the list query from the route's filters", () => {
		expect(deviceQuery()).toBe("");
		expect(deviceQuery({ status: "suspended", group: "g", limit: 10, offset: 20 })).toBe(
			"?status=suspended&group=g&limit=10&offset=20",
		);
	});

	it("calls the core routes with the right methods", async () => {
		const seen: Array<{ path: string; method: string; body?: string }> = [];
		const api = createDeviceApi(async <T,>(path: string, options?: RequestInit) => {
			seen.push({
				path,
				method: options?.method ?? "GET",
				...(typeof options?.body === "string" && { body: options.body }),
			});
			return { success: true, data: {} as T };
		});
		await api.getDevices({ status: "active" });
		await api.getDeviceStats();
		await api.suspendDevice("a/b", "maintenance");
		await api.resumeDevice("d1");
		await api.revokeDevice("d1", "lost");
		await api.createEnrollmentToken({ ownerId: "u1", kind: "claim" });
		expect(seen).toEqual([
			{ path: "/api/devices?status=active", method: "GET" },
			{ path: "/api/devices/stats", method: "GET" },
			{ path: "/api/devices/a%2Fb/suspend", method: "POST", body: '{"reason":"maintenance"}' },
			{ path: "/api/devices/d1/resume", method: "POST" },
			{ path: "/api/devices/d1?reason=lost", method: "DELETE" },
			{
				path: "/api/devices/enrollment-tokens",
				method: "POST",
				body: '{"ownerId":"u1","kind":"claim"}',
			},
		]);
	});

	it("tells the page when devices are not configured", () => {
		expect(devicesUnavailable({ code: "HTTP_404" })).toBe(true);
		expect(devicesUnavailable({ code: "HTTP_500" })).toBe(false);
	});
});

describe("device components", () => {
	it("renders the fleet counters", () => {
		const stats: DeviceFleetStats = {
			total: 12,
			active: 9,
			suspended: 2,
			revoked: 1,
			seenLastHour: 7,
			seenLastDay: 10,
			neverSeen: 3,
		};
		const html = renderToStaticMarkup(<FleetStats stats={stats} />);
		expect(html).toContain("Seen in 1h");
		expect(html).toContain(">12<");
		expect(html).toContain("Never seen");
	});

	it("shows dashes before stats load", () => {
		expect(renderToStaticMarkup(<FleetStats stats={null} />)).toContain(">-<");
	});

	it("offers suspend and revoke for active, resume and revoke for suspended, nothing for revoked", () => {
		const html = renderToStaticMarkup(
			<DeviceTable
				devices={[
					device(),
					device({ id: "d2", name: "Cam 2", status: "suspended", lastSeenAt: null }),
					device({ id: "d3", name: "Old 3", status: "revoked" }),
				]}
				now={NOW}
				{...handlers}
			/>,
		);
		expect(html).toContain('aria-label="Suspend Arm 7"');
		expect(html).toContain('aria-label="Revoke Arm 7"');
		expect(html).toContain('aria-label="Resume Cam 2"');
		expect(html).not.toContain('aria-label="Suspend Cam 2"');
		expect(html).not.toContain('aria-label="Revoke Old 3"');
		expect(html).toContain("5m ago");
		expect(html).toContain("never");
	});

	it("renders the empty state", () => {
		expect(renderToStaticMarkup(<DeviceTable devices={[]} now={NOW} {...handlers} />)).toContain(
			"No devices",
		);
	});

	it("shows credential kinds in the detail panel without key material", () => {
		const detail: DeviceDetail = {
			...device({ hardwareId: "hw-9" }),
			credentials: [
				{
					id: "c1",
					deviceId: "dev_1",
					kind: "jwk",
					lookup: "thumb123",
					status: "active",
					expiresAt: null,
					lastUsedAt: null,
					createdAt: "x",
				},
			],
		};
		const html = renderToStaticMarkup(<DeviceDetailPanel device={detail} />);
		expect(html).toContain("jwk");
		expect(html).toContain("thumb123");
		expect(html).toContain("hw-9");
	});
});
