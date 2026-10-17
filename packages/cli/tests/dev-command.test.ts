import { describe, expect, it } from "vitest";
import {
	createDevInstance,
	formatWalkthrough,
	parseDevArgs,
	seedDevWorkspace,
} from "../src/dev-command.js";

describe("parseDevArgs", () => {
	it("uses the default port and reads env and flags", () => {
		expect(parseDevArgs([], {}).port).toBe(3100);
		expect(parseDevArgs([], { THEAUTH_DEV_PORT: "4000" }).port).toBe(4000);
		expect(parseDevArgs(["--port", "5000"], { THEAUTH_DEV_PORT: "4000" }).port).toBe(5000);
		expect(parseDevArgs(["--port=6000", "--smoke"], {})).toMatchObject({ port: 6000, smoke: true });
	});

	it("rejects bad ports and unknown flags", () => {
		expect(parseDevArgs(["--port", "abc"], {}).error).toMatch(/Invalid port/);
		expect(parseDevArgs(["--nope"], {}).error).toMatch(/Unknown option/);
	});
});

describe("seedDevWorkspace", () => {
	it("allows the delegated read, denies the delete, and keeps the audit chain intact", async () => {
		const theauth = await createDevInstance();
		const ws = await seedDevWorkspace(theauth);
		const byAction = (a: string) => ws.calls.filter((c) => c.action === a);
		expect(byAction("read")[0]?.allowed).toBe(true);
		expect(byAction("delete")[0]?.allowed).toBe(false);
		expect(ws.calls.some((c) => c.allowed)).toBe(true);
		expect(ws.auditRows).toBeGreaterThanOrEqual(3);
		expect(ws.chainOk).toBe(true);

		const text = formatWalkthrough(ws, { dashboard: null, api: "http://localhost:3100/api" });
		expect(text).toContain("ALLOWED");
		expect(text).toContain("DENIED");
		expect(text).toContain("API only");
		expect(text).not.toMatch(new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`));
	});
});
