import { describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";
import type { ApiOf } from "../src/plugin/typed-endpoint.js";
import { defineEndpoint } from "../src/plugin/typed-endpoint.js";
import type { EndpointContext } from "../src/plugin/types.js";

const ctx = {} as EndpointContext;

const invite = defineEndpoint({
	method: "POST",
	path: "/team/:teamId/invite",
	params: z.object({ teamId: z.string().min(1) }),
	query: z.object({ notify: z.enum(["yes", "no"]).default("yes") }),
	body: z.object({ email: z.string().email() }),
	response: z.object({ invited: z.string(), notify: z.boolean() }),
	async handler({ params, query, body }) {
		return { invited: `${body.email}@${params.teamId}`, notify: query.notify === "yes" };
	},
});

const ping = defineEndpoint({
	method: "GET",
	path: "/ping",
	async handler() {
		return { pong: true };
	},
});

const endpoints = [invite, ping] as const;
type Api = ApiOf<typeof endpoints>;

function post(path: string, body: unknown): Request {
	return new Request(`https://x.test${path}`, {
		method: "POST",
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

describe("defineEndpoint runtime", () => {
	it("validates and hands typed input to the handler", async () => {
		const res = await invite.handler(
			post("/team/x?_param_teamId=t1&notify=no", { email: "a@b.co" }),
			ctx,
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ invited: "a@b.co@t1", notify: false });
	});

	it("answers 400 with issues when input does not match", async () => {
		const res = await invite.handler(post("/team/x?_param_teamId=t1", { email: "nope" }), ctx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as {
			error: { code: string; issues: Array<{ where: string; path: string }> };
		};
		expect(body.error.code).toBe("INVALID_INPUT");
		expect(body.error.issues[0]).toMatchObject({ where: "body", path: "email" });
	});

	it("rejects a body that is not JSON and a missing path param", async () => {
		const bad = await invite.handler(post("/team/x?_param_teamId=t1", "{oops"), ctx);
		expect((await bad.json()) as { error: { code: string } }).toMatchObject({
			error: { code: "INVALID_JSON" },
		});
		const missing = await invite.handler(post("/team/x", { email: "a@b.co" }), ctx);
		expect(missing.status).toBe(400);
	});

	it("passes a Response through untouched", async () => {
		const raw = defineEndpoint({
			method: "GET",
			path: "/raw",
			async handler() {
				return new Response("x", { status: 202 });
			},
		});
		expect((await raw.handler(new Request("https://x.test/raw"), ctx)).status).toBe(202);
	});
});

describe("defineEndpoint types", () => {
	it("keys the route map by method and path and carries the shapes", () => {
		expectTypeOf<keyof Api>().toEqualTypeOf<"POST /team/:teamId/invite" | "GET /ping">();
		expectTypeOf<Api["POST /team/:teamId/invite"]["body"]>().toEqualTypeOf<{ email: string }>();
		expectTypeOf<Api["POST /team/:teamId/invite"]["response"]>().toEqualTypeOf<{
			invited: string;
			notify: boolean;
		}>();
		expectTypeOf<Api["GET /ping"]["response"]>().toEqualTypeOf<{ pong: boolean }>();
	});
});
