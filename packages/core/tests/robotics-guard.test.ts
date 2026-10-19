import { describe, expect, it, vi } from "vitest";
import { guardRobotCommand } from "../src/robotics/index.js";

function reply(status: number, body: unknown): typeof fetch {
	return vi.fn(
		async () => new Response(JSON.stringify(body), { status }),
	) as unknown as typeof fetch;
}

const base = { baseUrl: "https://auth.example.com/api/auth/", token: "tok" };
const cmd = { action: "publish", resource: "ros2:/cmd_vel" };

describe("guardRobotCommand", () => {
	it("runs the command on an explicit allow and sends the bearer token", async () => {
		const fetchImpl = reply(200, { data: { allowed: true, auditId: "a1", code: "allowed" } });
		const run = vi.fn(async () => 7);
		const result = await guardRobotCommand({ ...base, fetch: fetchImpl }, cmd, run);
		expect(result).toEqual({ ok: true, value: 7, bypassed: false, auditId: "a1" });
		const call = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
			string,
			RequestInit,
		];
		expect(call[0]).toBe("https://auth.example.com/api/auth/authorize/token");
		expect((call[1].headers as Record<string, string>).authorization).toBe("Bearer tok");
		expect(JSON.parse(String(call[1].body))).toEqual(cmd);
	});

	it("forwards arguments and approvalId and accepts a token function", async () => {
		const fetchImpl = reply(200, { data: { allowed: true } });
		await guardRobotCommand(
			{ ...base, token: async () => "rotated", fetch: fetchImpl },
			{ ...cmd, arguments: { speed: 1 }, approvalId: "ap_1" },
			() => 1,
		);
		const call = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
			string,
			RequestInit,
		];
		expect((call[1].headers as Record<string, string>).authorization).toBe("Bearer rotated");
		expect(JSON.parse(String(call[1].body))).toMatchObject({
			arguments: { speed: 1 },
			approvalId: "ap_1",
		});
	});

	it("refuses and does not run when policy denies", async () => {
		const run = vi.fn();
		const result = await guardRobotCommand(
			{
				...base,
				fetch: reply(403, {
					data: { allowed: false, code: "no_permission", reason: "nope", auditId: "a2" },
				}),
			},
			cmd,
			run,
		);
		expect(result).toEqual({
			ok: false,
			code: "no_permission",
			reason: "nope",
			approvalRequired: false,
			auditId: "a2",
		});
		expect(run).not.toHaveBeenCalled();
	});

	it("flags approval and step up holds", async () => {
		for (const code of ["approval_required", "step_up_required"]) {
			const result = await guardRobotCommand(
				{ ...base, fetch: reply(403, { data: { allowed: false, code, reason: "held" } }) },
				cmd,
				() => 1,
			);
			expect(result).toMatchObject({ ok: false, code, approvalRequired: true });
		}
	});

	it("fails closed on network errors, server errors, junk bodies and allowed:false with 200", async () => {
		const run = vi.fn();
		const cases: (typeof fetch)[] = [
			vi.fn(async () => {
				throw new Error("connection refused");
			}) as unknown as typeof fetch,
			reply(500, { error: { code: "INTERNAL", message: "boom" } }),
			vi.fn(async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch,
			reply(200, { data: { allowed: false, code: "no_permission" } }),
			reply(200, { data: {} }),
			reply(200, {}),
		];
		for (const fetchImpl of cases) {
			const result = await guardRobotCommand({ ...base, fetch: fetchImpl }, cmd, run);
			expect(result.ok).toBe(false);
		}
		expect(run).not.toHaveBeenCalled();
	});

	it("fails closed on timeout", async () => {
		const hang = vi.fn(
			(_url: string, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
				}),
		) as unknown as typeof fetch;
		const run = vi.fn();
		const result = await guardRobotCommand({ ...base, fetch: hang, timeoutMs: 20 }, cmd, run);
		expect(result).toMatchObject({ ok: false, code: "guard_error" });
		expect(run).not.toHaveBeenCalled();
	});

	it("lets a listed safety stop through without any network call", async () => {
		const fetchImpl = vi.fn(async () => {
			throw new Error("network is down");
		}) as unknown as typeof fetch;
		const onSafetyStop = vi.fn(async () => {
			throw new Error("notifier failed");
		});
		const run = vi.fn(async () => "stopped");
		const result = await guardRobotCommand(
			{ ...base, fetch: fetchImpl, safetyStops: ["ros2:/e_stop"], onSafetyStop },
			{ action: "publish", resource: "ros2:/e_stop" },
			run,
		);
		expect(result).toEqual({ ok: true, value: "stopped", bypassed: true });
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(onSafetyStop).toHaveBeenCalledOnce();
	});

	it("matches safety stops literally, never by wildcard or prefix", async () => {
		const fetchImpl = reply(403, { data: { allowed: false, code: "no_permission" } });
		const options = { ...base, fetch: fetchImpl, safetyStops: ["ros2:/e_stop"] };
		for (const resource of ["ros2:/e_stop2", "ros2:/e_stop/", "ros2:*", "ros2:/cmd_vel"]) {
			const run = vi.fn();
			const result = await guardRobotCommand(options, { action: "publish", resource }, run);
			expect(result.ok).toBe(false);
			expect(run).not.toHaveBeenCalled();
		}
		expect(
			guardRobotCommand(
				{ ...base, fetch: fetchImpl },
				{ action: "publish", resource: "ros2:/e_stop" },
				() => 1,
			),
		).resolves.toMatchObject({ ok: false });
	});

	it("does not swallow errors thrown by the command itself", async () => {
		await expect(
			guardRobotCommand({ ...base, fetch: reply(200, { data: { allowed: true } }) }, cmd, () => {
				throw new Error("actuator fault");
			}),
		).rejects.toThrow("actuator fault");
	});
});
