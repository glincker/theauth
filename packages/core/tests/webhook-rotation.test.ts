import { describe, expect, it, vi } from "vitest";
import { buildWebhookHeaders, verify, webhooks } from "../src/webhook/index.js";

const OLD = "o".repeat(32);
const NEW = "n".repeat(32);
const BODY = JSON.stringify({ hello: "world" });
const ts = () => String(Math.floor(Date.now() / 1000));

async function signed(secret: Parameters<typeof buildWebhookHeaders>[0]) {
	const timestamp = ts();
	const h = await buildWebhookHeaders(secret, BODY, "user.signIn", "d1", timestamp);
	return { h, timestamp };
}

describe("webhook signing rotation", () => {
	it("single string stays compatible, including short secrets", async () => {
		const { h, timestamp } = await signed("short");
		expect(h["X-TheAuth-Key-Id"]).toBeUndefined();
		expect(
			await verify({
				secret: "short",
				rawBody: BODY,
				signature: h["X-TheAuth-Signature"],
				timestamp,
			}),
		).toBe(true);
	});

	it("signs with the current key, receiver accepting both verifies old and new", async () => {
		const oldSigned = await signed(OLD);
		const newSigned = await signed([NEW, OLD]);
		const receiver = [NEW, OLD];
		for (const { h, timestamp } of [oldSigned, newSigned]) {
			expect(
				await verify({
					secret: receiver,
					rawBody: BODY,
					signature: h["X-TheAuth-Signature"],
					timestamp,
				}),
			).toBe(true);
		}
		// New signature is not valid for a receiver that only knows the old key.
		expect(
			await verify({
				secret: OLD,
				rawBody: BODY,
				signature: newSigned.h["X-TheAuth-Signature"],
				timestamp: newSigned.timestamp,
			}),
		).toBe(false);
	});

	it("removed old key stops verifying", async () => {
		const { h, timestamp } = await signed(OLD);
		expect(
			await verify({
				secret: [NEW],
				rawBody: BODY,
				signature: h["X-TheAuth-Signature"],
				timestamp,
			}),
		).toBe(false);
	});

	it("emits X-TheAuth-Key-Id and accepts it on verify", async () => {
		const { h, timestamp } = await signed([
			{ id: "2026-10", secret: NEW },
			{ id: "2026-04", secret: OLD },
		]);
		expect(h["X-TheAuth-Key-Id"]).toBe("2026-10");
		expect(
			await verify({
				secret: [
					{ id: "2026-10", secret: NEW },
					{ id: "2026-04", secret: OLD },
				],
				rawBody: BODY,
				signature: h["X-TheAuth-Signature"],
				timestamp,
				keyId: h["X-TheAuth-Key-Id"] as string,
			}),
		).toBe(true);
	});

	it("rejects tampered body, malformed signature and stale timestamp", async () => {
		const { h, timestamp } = await signed([NEW, OLD]);
		const sig = h["X-TheAuth-Signature"];
		const base = { secret: [NEW, OLD], rawBody: BODY, signature: sig, timestamp };
		expect(await verify({ ...base, rawBody: `${BODY} ` })).toBe(false);
		expect(await verify({ ...base, signature: "sha256=zz" })).toBe(false);
		expect(await verify({ ...base, signature: sig.slice(0, -2) })).toBe(false);
		expect(await verify({ ...base, timestamp: String(Number(timestamp) - 1000) })).toBe(false);
	});

	it("rotation form validates secrets", async () => {
		await expect(buildWebhookHeaders([NEW, "short"], BODY, "e", "d", ts())).rejects.toThrow(
			/at least 32/,
		);
		await expect(buildWebhookHeaders([NEW, NEW], BODY, "e", "d", ts())).rejects.toThrow(
			/duplicate/,
		);
		await expect(buildWebhookHeaders("", BODY, "e", "d", ts())).rejects.toThrow(/empty/);
	});

	it("webhooks() fails fast on a bad endpoint secret and delivers with the current key", async () => {
		expect(() =>
			webhooks({
				endpoints: [{ url: "https://a.example/h", events: ["user.signIn"], secret: [] }],
			}),
		).toThrow(/at least one/);

		const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);
		try {
			const plugin = webhooks({
				endpoints: [
					{
						url: "https://a.example/h",
						events: ["user.signIn"],
						secret: [
							{ id: "k2", secret: NEW },
							{ id: "k1", secret: OLD },
						],
					},
				],
			});
			await plugin.dispatchAwait("user.signIn", { a: 1 });
			const init = fetchMock.mock.calls[0]?.[1] as {
				headers: Record<string, string>;
				body: string;
			};
			expect(init.headers["X-TheAuth-Key-Id"]).toBe("k2");
			expect(
				await verify({
					secret: [{ id: "k2", secret: NEW }],
					rawBody: init.body,
					signature: init.headers["X-TheAuth-Signature"] as string,
					timestamp: init.headers["X-TheAuth-Timestamp"] as string,
					keyId: "k2",
				}),
			).toBe(true);
		} finally {
			vi.unstubAllGlobals();
		}
	});
});
