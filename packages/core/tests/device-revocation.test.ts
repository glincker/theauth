/** Signed revocation snapshots for offline devices: opt in, bounded age, fail closed. */
import { importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { verifyDeviceBundle } from "../src/device/bundle.js";
import { signRevocationSnapshot, verifyRevocationSnapshot } from "../src/device/revocation.js";
import { bundleKey, devicesOf, makeDeviceAuth } from "./device-helpers.js";

async function setup(revocations: { ttlSeconds?: number; maxEntries?: number } = {}) {
	const auth = await makeDeviceAuth({ bundleSigning: await bundleKey(), revocations });
	const devices = devicesOf(auth);
	const make = (name: string, ownerId = "u1") =>
		devices.register({
			ownerId,
			name,
			permissions: [{ resource: "mqtt:*", actions: ["publish"] }],
		});
	return { devices, make };
}

describe("device revocation snapshots", () => {
	it("is absent unless configured", async () => {
		const auth = await makeDeviceAuth({ bundleSigning: await bundleKey() });
		const devices = devicesOf(auth);
		const { device } = await devices.register({ ownerId: "u1", name: "a" });
		expect((await devices.issueBundle(device.id)).revocations).toBeUndefined();
	});

	it("lists revoked and suspended devices of the owner only", async () => {
		const { devices, make } = await setup();
		const a = (await make("a")).device;
		const b = (await make("b")).device;
		const c = (await make("c")).device;
		const other = (await make("o", "u2")).device;
		await devices.revoke(b.id);
		await devices.suspend(c.id);
		await devices.revoke(other.id);
		const bundle = await devices.issueBundle(a.id);
		if (!bundle.revocations) throw new Error("no snapshot");
		const snap = await verifyRevocationSnapshot(bundle.revocations.token, {
			keys: devices.jwks(),
			owner: "u1",
			maxAgeSeconds: 60,
		});
		if (!snap.ok) throw new Error(snap.message);
		expect(snap.claims.n).toBe(2);
		expect(await snap.has(b.id)).toBe(true);
		expect(await snap.has(c.id)).toBe(true);
		expect(await snap.has(a.id)).toBe(false);
		expect(await snap.has(other.id)).toBe(false);
	});

	it("bundle verification refuses a listed device and passes a clean one", async () => {
		const { devices, make } = await setup();
		const a = (await make("a")).device;
		const b = (await make("b")).device;
		// b still holds a valid bundle from before it was revoked.
		const oldBundleOfB = await devices.issueBundle(b.id);
		await devices.revoke(b.id);
		const fresh = await devices.issueBundle(a.id);
		const keys = devices.jwks();
		const revocations = { token: fresh.revocations?.token, maxAgeSeconds: 600 };
		expect(
			await verifyDeviceBundle(fresh.token, { keys, deviceId: a.id, revocations }),
		).toMatchObject({
			ok: true,
		});
		expect(
			await verifyDeviceBundle(oldBundleOfB.token, { keys, deviceId: b.id, revocations }),
		).toMatchObject({ ok: false, reason: "revoked" });
	});

	it("fails closed on a missing, stale or expired snapshot when the device opts in", async () => {
		const { devices, make } = await setup({ ttlSeconds: 3600 });
		const a = (await make("a")).device;
		const bundle = await devices.issueBundle(a.id);
		const base = { keys: devices.jwks(), deviceId: a.id };
		const missing = await verifyDeviceBundle(bundle.token, {
			...base,
			revocations: { token: undefined, maxAgeSeconds: 300 },
		});
		expect(missing).toMatchObject({ ok: false, reason: "stale_revocations" });
		const later = new Date(Date.now() + 301_000);
		const stale = await verifyDeviceBundle(bundle.token, {
			...base,
			now: later,
			revocations: { token: bundle.revocations?.token, maxAgeSeconds: 300 },
		});
		expect(stale).toMatchObject({ ok: false, reason: "stale_revocations" });
		const inside = await verifyDeviceBundle(bundle.token, {
			...base,
			now: new Date(Date.now() + 200_000),
			revocations: { token: bundle.revocations?.token, maxAgeSeconds: 300 },
		});
		expect(inside.ok).toBe(true);
		const expired = await verifyRevocationSnapshot(bundle.revocations?.token ?? "", {
			keys: devices.jwks(),
			maxAgeSeconds: 10 ** 9,
			now: new Date(Date.now() + 3600_000 + 31_000),
		});
		expect(expired).toMatchObject({ ok: false, reason: "stale" });
	});

	it("without the option the verifier ignores snapshots", async () => {
		const { devices, make } = await setup();
		const a = (await make("a")).device;
		const bundle = await devices.issueBundle(a.id);
		const res = await verifyDeviceBundle(bundle.token, { keys: devices.jwks(), deviceId: a.id });
		expect(res.ok).toBe(true);
	});

	it("refuses a snapshot for another owner, a rollback, and tampered lists", async () => {
		const { devices, make } = await setup();
		const a = (await make("a")).device;
		const s = await devices.issueBundle(a.id);
		const token = s.revocations?.token ?? "";
		const keys = devices.jwks();
		expect(
			await verifyRevocationSnapshot(token, { keys, owner: "u2", maxAgeSeconds: 60 }),
		).toMatchObject({ ok: false, reason: "invalid" });
		expect(
			await verifyRevocationSnapshot(token, {
				keys,
				maxAgeSeconds: 60,
				lastSeq: (s.revocations?.claims.seq ?? 0) + 1,
			}),
		).toMatchObject({ ok: false, reason: "rollback" });
		const [h, p, sig] = token.split(".");
		const bad = `${h}.${p?.slice(0, -2)}AA.${sig}`;
		expect(await verifyRevocationSnapshot(bad, { keys, maxAgeSeconds: 60 })).toMatchObject({
			ok: false,
			reason: "invalid",
		});
	});

	it("refuses unsorted lists and count mismatches even when signed", async () => {
		const signing = await bundleKey();
		const key = await importJWK(signing.privateKey, "ES256");
		const keys = {
			keys: [{ ...signing.privateKey, d: undefined, kid: signing.kid, alg: "ES256" }],
		};
		const now = Math.floor(Date.now() / 1000);
		const forge = async (ids: string, n: number) =>
			new SignJWT({
				iss: "theauth",
				sub: "u1",
				iat: now,
				nbf: now,
				exp: now + 600,
				jti: "x",
				seq: 1,
				n,
				h: "sha256-64",
				ids,
			})
				.setProtectedHeader({ alg: "ES256", typ: "device-revocations+jwt", kid: signing.kid })
				.sign(key);
		const hi = "_".repeat(11);
		const lo = "A".repeat(11);
		expect(
			await verifyRevocationSnapshot(await forge(hi + lo, 2), { keys, maxAgeSeconds: 60 }),
		).toMatchObject({ ok: false, reason: "invalid" });
		expect(
			await verifyRevocationSnapshot(await forge(lo + hi, 3), { keys, maxAgeSeconds: 60 }),
		).toMatchObject({ ok: false, reason: "invalid" });
		expect(
			await verifyRevocationSnapshot(await forge(lo + lo, 2), { keys, maxAgeSeconds: 60 }),
		).toMatchObject({ ok: false, reason: "invalid" });
		expect(
			await verifyRevocationSnapshot(await forge(lo + hi, 2), { keys, maxAgeSeconds: 60 }),
		).toMatchObject({ ok: true });
	});

	it("refuses to sign a list over maxEntries", async () => {
		const { devices, make } = await setup({ maxEntries: 1 });
		const a = (await make("a")).device;
		const b = (await make("b")).device;
		const c = (await make("c")).device;
		await devices.revoke(b.id);
		await devices.revoke(c.id);
		await expect(devices.issueBundle(a.id)).rejects.toThrow(/maxEntries/);
	});

	it("signs deterministic sorted digests", async () => {
		const signing = await bundleKey();
		const x = await signRevocationSnapshot({
			signing,
			issuer: "theauth",
			ownerId: "o",
			deviceIds: ["b", "a", "a"],
			ttlSeconds: 60,
		});
		const y = await signRevocationSnapshot({
			signing,
			issuer: "theauth",
			ownerId: "o",
			deviceIds: ["a", "b"],
			ttlSeconds: 60,
		});
		expect(x.claims.n).toBe(2);
		expect(x.claims.ids).toBe(y.claims.ids);
	});
});
