import { afterEach, describe, expect, it, vi } from "vitest";
import { facebookProvider } from "../src/auth/oauth/providers/presets.js";

afterEach(() => vi.unstubAllGlobals());

function stubUserinfo(body: Record<string, unknown>) {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })),
	);
}

describe("facebookProvider userinfo", () => {
	it("maps the Graph API id (no sub) to the profile id", async () => {
		stubUserinfo({
			id: "10234",
			email: "ada@example.com",
			name: "Ada",
			picture: { data: { url: "https://cdn.example/a.jpg" } },
		});
		const info = await facebookProvider("id", "secret").getUserInfo("tok");
		expect(info).toMatchObject({
			id: "10234",
			email: "ada@example.com",
			name: "Ada",
			avatar: "https://cdn.example/a.jpg",
		});
	});

	it("rejects a response with no id or email", async () => {
		stubUserinfo({ name: "No Email", id: "1" });
		await expect(facebookProvider("id", "secret").getUserInfo("tok")).rejects.toThrow(
			/usable id or email/,
		);
	});
});
