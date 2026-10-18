/**
 * Wave 8 review probe: the security doctor (`theauth doctor`) tells users to set `auth.session.cookieName` to a
 * `__Host-` name. The built-in readers (plugin endpoints, headless module handlers, sign-out) must then
 * read and clear that cookie, not the default `theauth_session`.
 */
import { describe, expect, it } from "vitest";
import { createRequestUserResolver } from "../src/auth/request-user.js";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/index.js";
import { createEndpointContext } from "../src/plugin/core-wiring.js";

const SECRET = `${"k".repeat(16)}Zq8!xW2@pL5#nR7$`;
const NAME = "__Host-theauth";

async function setup() {
	const config = {
		database: { provider: "sqlite" as const, url: ":memory:" },
		baseUrl: "https://app.example.com",
		auth: { session: { secret: SECRET, cookieName: NAME } },
	};
	const theauth = await createTheAuth(config);
	const now = new Date();
	await theauth.db
		.insert(users)
		.values({ id: "u1", email: "u1@example.com", createdAt: now, updatedAt: now })
		.run();
	const sessions = theauth.auth.session;
	if (!sessions) throw new Error("no session manager");
	const { token } = await sessions.create("u1");
	return { theauth, config, sessions, token };
}

const withCookie = (name: string, token: string) =>
	new Request("https://app.example.com/x", { headers: { cookie: `${name}=${token}` } });

describe("auth.session.cookieName is honored", () => {
	it("the session manager reports the configured name", async () => {
		const { sessions } = await setup();
		expect(sessions.cookieName).toBe(NAME);
	});

	it("headless module handlers read the configured cookie", async () => {
		const { theauth, sessions, token } = await setup();
		const resolve = createRequestUserResolver(theauth.db, sessions, null);
		expect(await resolve(withCookie(NAME, token))).toEqual({ id: "u1" });
		expect(await resolve(withCookie("theauth_session", token))).toBeNull();
	});

	it("plugin endpoints read the configured cookie", async () => {
		const { theauth, config, sessions, token } = await setup();
		const ctx = createEndpointContext(theauth.db, config, sessions);
		expect((await ctx.getUser(withCookie(NAME, token)))?.id).toBe("u1");
	});
});
