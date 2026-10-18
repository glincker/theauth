/** MCP revocations become CAEP session-revoked events when the signals bridge is wired. */
import { describe, expect, it, vi } from "vitest";
import { createRevocationBus } from "../src/mcp/revocation-bus.js";
import type { McpRevocationEvent } from "../src/mcp/revocation-types.js";
import { createEmissionBridge } from "../src/signals/index.js";
import { CAEP_SESSION_REVOKED } from "../src/signals/types.js";

const ISS = "https://idp.example";

function event(over: Partial<McpRevocationEvent> = {}): McpRevocationEvent {
	return {
		kind: "dlg",
		ids: ["link-1", "link-2"],
		revokedAt: new Date(),
		reason: "delegation.revoke",
		userId: "u1",
		sourceId: "link-1",
		...over,
	};
}

type Sent = { type: string; payload?: Record<string, unknown>; subject: unknown };

describe("signals: MCP revocation", () => {
	it("emits one session-revoked per revoked id with a complex subject", async () => {
		const emit = vi.fn(async () => undefined);
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		await bridge.onMcpRevocation(event());
		const sent = emit.mock.calls.map((c) => c[0] as unknown as Sent);
		expect(sent).toHaveLength(2);
		expect(sent[0]?.type).toBe(CAEP_SESSION_REVOKED);
		expect(sent.map((s) => s.subject)).toEqual([
			{
				format: "complex",
				user: { format: "iss_sub", iss: ISS, sub: "u1" },
				session: { format: "opaque", id: "dlg:link-1" },
			},
			{
				format: "complex",
				user: { format: "iss_sub", iss: ISS, sub: "u1" },
				session: { format: "opaque", id: "dlg:link-2" },
			},
		]);
		expect(sent[0]?.payload).toMatchObject({ reason_admin: { en: "delegation.revoke" } });
	});

	it("covers agent and sub kinds", async () => {
		const emit = vi.fn(async () => undefined);
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		await bridge.onMcpRevocation(event({ kind: "agent", ids: ["ag1"], reason: "agent.revoke" }));
		await bridge.onMcpRevocation(event({ kind: "sub", ids: ["u1"], reason: "session.revokeAll" }));
		const ids = emit.mock.calls.map(
			(c) => ((c[0] as unknown as Sent).subject as { session: { id: string } }).session.id,
		);
		expect(ids).toEqual(["agent:ag1", "sub:u1"]);
	});

	it("emits nothing for jti or client revocations, or when the user is unknown", async () => {
		const emit = vi.fn(async () => undefined);
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		await bridge.onMcpRevocation(event({ kind: "jti", ids: ["j"] }));
		await bridge.onMcpRevocation(event({ kind: "client", ids: ["c"] }));
		await bridge.onMcpRevocation(event({ userId: undefined }));
		expect(emit).not.toHaveBeenCalled();
	});

	it("carries no token material or secrets", async () => {
		const emit = vi.fn(async () => undefined);
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		await bridge.onMcpRevocation(event());
		const text = JSON.stringify(emit.mock.calls);
		expect(text).not.toMatch(/eyJ|Bearer|ta_|secret|token/i);
	});

	it("swallows emit failures", async () => {
		const bridge = createEmissionBridge({
			emit: async () => {
				throw new Error("receiver down");
			},
			issuer: ISS,
		});
		await expect(bridge.onMcpRevocation(event())).resolves.toBeUndefined();
	});

	it("delivery is asynchronous: the bus does not wait for the receiver", async () => {
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const emit = vi.fn(async () => {
			await gate;
		});
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		const bus = createRevocationBus({ onRevoked: bridge.onMcpRevocation });
		await bus.publish(event(), []);
		await vi.waitFor(() => expect(emit).toHaveBeenCalledTimes(1));
		release();
	});

	it("no event is sent when no bridge is configured", async () => {
		const emit = vi.fn(async () => undefined);
		const bus = createRevocationBus({});
		await bus.publish(event(), []);
		await Promise.resolve();
		expect(emit).not.toHaveBeenCalled();
	});
});
