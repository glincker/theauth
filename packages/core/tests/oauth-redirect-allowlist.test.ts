/** `allowedRedirectUris` on the OAuth module. */

import { describe, expect, it } from "vitest";
import { createOAuthModule } from "../src/auth/oauth/module.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

const provider = {
	getAuthorizationUrl: async (state: string, _v: string, redirectUri: string) =>
		`https://idp.example/authorize?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
} as unknown as OAuthProvider;

async function make(allowed?: string[]) {
	const db: Database = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return createOAuthModule(db, {
		providers: { idp: provider },
		...(allowed && { allowedRedirectUris: allowed }),
	});
}

const OK = "https://app.example.com/auth/oauth/callback/idp";

describe("allowedRedirectUris", () => {
	it("accepts an exact entry", async () => {
		const m = await make([OK]);
		expect((await m.getAuthorizationUrl("idp", OK)).url).toContain("idp.example");
	});

	for (const bad of [
		"https://evil.com/cb",
		`${OK}/extra`,
		`${OK}#frag`,
		"https://app.example.com@evil.com/auth/oauth/callback/idp",
		"//evil.com/cb",
		"javascript:alert(1)",
		"/auth/oauth/callback/idp",
	]) {
		it(`rejects ${bad}`, async () => {
			const m = await make([OK]);
			await expect(m.getAuthorizationUrl("idp", bad)).rejects.toThrow(/allowedRedirectUris/);
			await expect(m.handleCallback("idp", "c", "s", bad)).rejects.toThrow(/allowedRedirectUris/);
		});
	}

	it("is off when not configured", async () => {
		const m = await make();
		expect((await m.getAuthorizationUrl("idp", "https://anything.example/cb")).url).toContain(
			"idp.example",
		);
	});
});
