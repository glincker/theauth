import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthMiddleware } from "../src/adapter.js";

describe("nest middleware handler cache", () => {
	it("builds one handler no matter how the mount path is spelled", async () => {
		const theauth = await createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const app = express();
			app.use("/api/theauth", theAuthMiddleware({ theauth, allowUnauthenticated: true }));
			// One startup guard warning is emitted per handler built.
			const builtAtStartup = warn.mock.calls.length;
			for (let i = 0; i < 64; i++) {
				const prefix = "/api/theauth"
					.split("")
					.map((c, j) => ((i >> (j % 6)) & 1 ? c.toUpperCase() : c))
					.join("");
				await request(app).get(`${prefix}/.well-known/oauth-authorization-server`);
			}
			// At most one more handler (the lowercase mount, built on first use); never one per spelling.
			expect(warn.mock.calls.length - builtAtStartup).toBeLessThanOrEqual(1);
		} finally {
			warn.mockRestore();
		}
	});
});
