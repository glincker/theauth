import { describe, expect, it } from "vitest";
import { emailOtp } from "../src/auth/email-otp-plugin.js";
import { magicLink } from "../src/auth/magic-link-plugin.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

describe("plugin form creates the same tables as the config form", () => {
	it("magicLink plugin creates theauth_magic_links", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			plugins: [magicLink({ appUrl: "https://app.example.com", sendMagicLink: async () => {} })],
		});
		const res = await auth.plugins.handleRequest(
			new Request("http://localhost/auth/magic-link/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "a@example.com" }),
			}),
		);
		expect(res?.status).toBe(200);
	});

	it("emailOtp plugin creates theauth_email_otps", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			plugins: [emailOtp({ sendOtp: async () => {} })],
		});
		const res = await auth.plugins.handleRequest(
			new Request("http://localhost/auth/email-otp/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "a@example.com" }),
			}),
		);
		expect(res?.status).toBe(200);
	});
});
