import { describe, expect, it } from "vitest";
import { providerPresets, resolveProviderPreset } from "../src/vault/presets.js";
import { refreshTokens } from "../src/vault/refresh.js";

const presets = Object.values(providerPresets);

describe("token vault provider presets", () => {
	it("has unique non-empty ids matching their keys", () => {
		const ids = presets.map((p) => p.id);
		expect(new Set(ids).size).toBe(ids.length);
		for (const [key, p] of Object.entries(providerPresets)) {
			expect(p.id).not.toBe("");
			expect(p.id).toBe(key);
		}
	});

	it.each(
		presets.map((p) => [p.id, p] as const),
	)("%s uses https URLs and empty default scopes", (_id, p) => {
		for (const u of [p.authorizationUrl, p.tokenUrl, p.docsUrl]) {
			expect(new URL(u).protocol).toBe("https:");
		}
		expect(p.defaultScopes).toEqual([]);
		expect(p.exampleScopes.length).toBeGreaterThanOrEqual(2);
		expect(p.exampleScopes.length).toBeLessThanOrEqual(3);
	});

	it.each([
		["github", "https://github.com/login/oauth/access_token", "client_secret_post"],
		["google", "https://oauth2.googleapis.com/token", "client_secret_post"],
		["slack", "https://slack.com/api/oauth.v2.access", "client_secret_post"],
		["linear", "https://api.linear.app/oauth/token", "client_secret_post"],
		[
			"microsoft",
			"https://login.microsoftonline.com/common/oauth2/v2.0/token",
			"client_secret_post",
		],
		["discord", "https://discord.com/api/oauth2/token", "client_secret_basic"],
	])("resolves %s", (id, tokenUrl, authStyle) => {
		const r = resolveProviderPreset(id, { clientId: "cid", clientSecret: "sec" });
		expect(r.tokenUrl).toBe(tokenUrl);
		expect(r.authStyle).toBe(authStyle);
		expect(r.clientId).toBe("cid");
	});

	it("rejects unknown ids", () => {
		expect(() => resolveProviderPreset("nope", { clientId: "a", clientSecret: "b" })).toThrow();
	});

	it("sends credentials per auth style on refresh", async () => {
		const seen: { headers: Record<string, string>; body: string }[] = [];
		const doFetch = (async (_u: string, init: RequestInit) => {
			seen.push({ headers: init.headers as Record<string, string>, body: String(init.body) });
			return new Response(JSON.stringify({ access_token: "a" }), { status: 200 });
		}) as unknown as typeof fetch;
		const provider = { tokenUrl: "https://x.example/token" } as never;
		await refreshTokens({ provider, clientId: "cid", clientSecret: "sec" }, "rt", doFetch);
		await refreshTokens(
			{ provider, clientId: "cid", clientSecret: "sec", authStyle: "client_secret_basic" },
			"rt",
			doFetch,
		);
		expect(seen[0]?.body).toContain("client_secret=sec");
		expect(seen[0]?.headers.Authorization).toBeUndefined();
		expect(seen[1]?.body).not.toContain("client_secret");
		expect(seen[1]?.headers.Authorization).toBe(`Basic ${btoa("cid:sec")}`);
	});
});
