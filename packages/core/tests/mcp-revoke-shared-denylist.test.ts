/** RFC 7009 /mcp/revoke writes the shared denylist: a revoke on one instance is refused by the others on the same database. */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../src/http/index.js";
import { validateAccessToken } from "../src/mcp/validate.js";
import {
	bootEndpoints,
	formRequest,
	REVOKE_URL,
	RS_AUDIENCE,
	revokeAs,
	SECRETS,
} from "./mcp-endpoint-fixture.js";
import { basicAuth, codeFlow, tokenRequest } from "./mcp-test-harness.js";

const validate = (ctx: Parameters<typeof validateAccessToken>[0], token: string) =>
	validateAccessToken(ctx, token, { expectedAudience: RS_AUDIENCE, freshness: "live" });

describe("/mcp/revoke on the shared denylist", () => {
	it("a revoke on instance 1 makes validation fail on instance 2", async () => {
		const w = await bootEndpoints();
		const one = w.instance();
		const two = w.instance();
		const { jwt } = await w.issue();
		expect((await validate(one, jwt)).success).toBe(true);
		expect((await validate(two, jwt)).success).toBe(true);

		const res = await revokeAs(one, "app", jwt, "access_token");
		expect(res.success).toBe(true);

		for (const ctx of [one, two]) {
			const after = await validate(ctx, jwt);
			expect(after.success).toBe(false);
			if (!after.success) {
				expect(after.error.code).toBe("INVALID_TOKEN");
				expect(after.error.details?.revocation).toMatchObject({ reason: "revoked" });
			}
		}
	});

	it("also dies in cached mode on the revoking instance at once", async () => {
		const w = await bootEndpoints({ revocation: { mode: "cached", maxStalenessMs: 60_000 } });
		const one = w.instance();
		const { jwt } = await w.issue();
		const cached = () => validateAccessToken(one, jwt, { expectedAudience: RS_AUDIENCE });
		expect((await cached()).success).toBe(true);
		await revokeAs(one, "app", jwt);
		expect((await cached()).success).toBe(false);
	});

	it("answers 200 for an unknown token, garbage, and another client's token (which stays valid)", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		for (const token of ["does-not-exist", "a.b.c", "x".repeat(20000)]) {
			const res = await revokeAs(w.ctx, "app", token);
			expect(res.success).toBe(true);
		}
		const foreign = await revokeAs(w.ctx, "other", jwt);
		expect(foreign.success).toBe(true);
		expect((await validate(w.instance(), jwt)).success).toBe(true);
	});

	it("still refuses unauthenticated and wrongly authenticated callers", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		const { handleRevocation } = await import("../src/mcp/revocation.js");
		const none = await handleRevocation(w.ctx, formRequest(REVOKE_URL, { token: jwt }, {}));
		expect(none.success).toBe(false);
		if (!none.success) expect(none.error.code).toBe("INVALID_CLIENT");
		const bad = await handleRevocation(
			w.ctx,
			formRequest(REVOKE_URL, { token: jwt }, basicAuth("app", "wrong")),
		);
		expect(bad.success).toBe(false);
		expect((await validate(w.instance(), jwt)).success).toBe(true);
	});

	it("revoking a refresh token kills its family and its access token on every instance", async () => {
		const w = await bootEndpoints();
		const reg = await w.d.mcp.registerClient({
			redirect_uris: ["https://app.theauth.test/callback"],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code", "refresh_token"],
			client_name: "Public",
			scope: "mcp:read offline_access",
		});
		if (!reg.success) throw new Error(reg.error.message);
		const clientId = reg.data.client_id;
		const tokens = await codeFlow(w.d.h, clientId, { scope: "mcp:read offline_access" });
		const refreshToken = tokens.refresh_token ?? "";
		expect(refreshToken).toBeTruthy();
		const one = w.instance();
		const two = w.instance();
		expect((await validate(two, tokens.access_token)).success).toBe(true);

		const res = await (await import("../src/mcp/revocation.js")).handleRevocation(
			one,
			formRequest(REVOKE_URL, {
				token: refreshToken,
				token_type_hint: "refresh_token",
				client_id: clientId,
			}),
		);
		expect(res.success).toBe(true);

		const used = await w.d.mcp.token(
			tokenRequest({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: clientId,
			}),
		);
		expect(used.success).toBe(false);
		expect((await validate(two, tokens.access_token)).success).toBe(false);
		expect((await validate(one, tokens.access_token)).success).toBe(false);
	});

	it("serves RFC 7009 over HTTP: no-store, 200 for unknown, 413 over the limit", async () => {
		const w = await bootEndpoints();
		const handler = createTheAuthHandler(w.d.auth, {
			mcp: w.module(),
			rateLimit: false,
			routes: { management: false, explain: false },
			maxBodyBytes: 1024,
		});
		const { jwt } = await w.issue();
		const post = (body: string, headers: Record<string, string>) =>
			handler(
				new Request("http://localhost/api/theauth/mcp/revoke", {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
					body,
				}),
			);
		const auth = basicAuth("app", SECRETS.app ?? "");
		const unknown = await post("token=nope", auth);
		expect(unknown.status).toBe(200);
		expect(unknown.headers.get("cache-control")).toBe("no-store");
		const revoked = await post(new URLSearchParams({ token: jwt }).toString(), auth);
		expect(revoked.status).toBe(200);
		expect((await validate(w.instance(), jwt)).success).toBe(false);
		expect((await post(`token=${"a".repeat(4000)}`, auth)).status).toBe(413);
		const unauth = await post("token=nope", {});
		expect(unauth.status).toBe(401);
		expect(unauth.headers.get("www-authenticate")).toMatch(/^Basic/);
	});
});
