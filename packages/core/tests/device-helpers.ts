import type { JWK } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { users } from "../src/db/schema.js";
import type { DeviceConfig } from "../src/device/types.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

export async function bundleKey(): Promise<NonNullable<DeviceConfig["bundleSigning"]>> {
	const pair = await generateKeyPair("ES256", { extractable: true });
	return { alg: "ES256", kid: "bundle-1", privateKey: await exportJWK(pair.privateKey) };
}

export async function makeDeviceAuth(devices: DeviceConfig = {}): Promise<TheAuth> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 2,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		devices,
	});
	for (const id of ["u1", "u2"]) {
		const now = new Date();
		await auth.db
			.insert(users)
			.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now })
			.onConflictDoNothing();
	}
	return auth;
}

export function devicesOf(auth: TheAuth) {
	if (!auth.device) throw new Error("devices not configured");
	return auth.device;
}

export async function deviceKey(alg: "ES256" | "EdDSA" = "ES256") {
	const pair =
		alg === "ES256"
			? await generateKeyPair("ES256", { extractable: true })
			: await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
	const publicJwk = (await exportJWK(pair.publicKey)) as JWK;
	return { pair, publicJwk, alg };
}

export async function assertion(
	key: Awaited<ReturnType<typeof deviceKey>>,
	opts: {
		deviceId: string;
		kid: string;
		aud?: string;
		iss?: string;
		lifetime?: number;
		jti?: string;
		iat?: number;
		typ?: string;
	},
): Promise<string> {
	const iat = opts.iat ?? Math.floor(Date.now() / 1000);
	return new SignJWT({ jti: opts.jti ?? crypto.randomUUID() })
		.setProtectedHeader({ alg: key.alg, typ: opts.typ ?? "device-assertion+jwt", kid: opts.kid })
		.setIssuer(opts.iss ?? opts.deviceId)
		.setSubject(opts.deviceId)
		.setAudience(opts.aud ?? "theauth")
		.setIssuedAt(iat)
		.setExpirationTime(iat + (opts.lifetime ?? 60))
		.sign(key.pair.privateKey);
}
