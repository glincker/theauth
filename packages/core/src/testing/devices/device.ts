import type { JWK } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { BundleDecision } from "../../device/bundle.js";
import { evaluateDeviceBundle, verifyDeviceBundle } from "../../device/bundle.js";
import type { DeviceBundleClaims } from "../../device/types.js";
import { DECISION_CODES } from "../../permission/codes.js";

/** What a simulated device needs from its fleet. */
export interface DeviceHost {
	/** Send a request to the real handler. */
	send(path: string, init: RequestInit): Promise<Response>;
	/** Server side virtual time in ms. */
	serverNowMs(): number;
	/** Bundle verification keys. */
	jwks(): { keys: JWK[] };
	audience: string;
	issuer: string;
}

/** Header the fleet handler reads as the rate limit key of a simulated device. */
export const FLEET_KEY_HEADER = "x-fleet-device";

export class DeviceOfflineError extends Error {
	constructor() {
		super("Device is offline");
		this.name = "DeviceOfflineError";
	}
}

export interface OfflineDecision extends BundleDecision {
	/** False when the bundle or snapshot could not be verified, so nothing was evaluated (fail closed). */
	verified: boolean;
}

export interface DeviceState {
	online: boolean;
	/** Device clock minus server clock, in ms. Positive means the device runs fast. */
	skewMs: number;
}

/**
 * One simulated device: holds its own key, clock offset and last accepted bundle, talks to the real
 * handler while online, and decides from its stored bundle while offline.
 */
export class SimulatedDevice {
	readonly state: DeviceState = { online: true, skewMs: 0 };
	id = "";
	credentialId = "";
	bundleToken: string | undefined;
	snapshotToken: string | undefined;
	claims: DeviceBundleClaims | undefined;
	lastSeq: number | undefined;
	lastSnapshotSeq: number | undefined;
	private privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"] | undefined;
	private kid = "";
	private counter = 0;

	constructor(
		readonly index: number,
		private readonly host: DeviceHost,
	) {}

	/** Time as this device sees it. */
	nowMs(): number {
		return this.host.serverNowMs() + this.state.skewMs;
	}

	goOffline(): void {
		this.state.online = false;
	}

	goOnline(): void {
		this.state.online = true;
	}

	setSkew(ms: number): void {
		this.state.skewMs = ms;
	}

	/** Enroll with a bulk token and an ES256 key generated here. */
	async enroll(token: string): Promise<void> {
		const pair = await generateKeyPair("ES256", { extractable: true });
		this.privateKey = pair.privateKey;
		const jwk = (await exportJWK(pair.publicKey)) as JWK;
		const res = await this.call("/device/enroll", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token,
				name: `sim-${this.index}`,
				hardwareId: `sim-hw-${this.index}`,
				credential: { kind: "jwk", jwk },
			}),
		});
		if (res.status !== 201) throw new Error(`Enrollment failed with ${res.status}`);
		const body = (await res.json()) as {
			data: { device: { id: string }; credential: { lookup: string; id: string } };
		};
		this.id = body.data.device.id;
		this.credentialId = body.data.credential.id;
		this.kid = body.data.credential.lookup;
	}

	/** A device assertion (RFC 7523 layout) stamped with the device clock. */
	async assertion(lifetimeSeconds = 60): Promise<string> {
		if (!this.privateKey) throw new Error("Device is not enrolled");
		const iat = Math.floor(this.nowMs() / 1000);
		return new SignJWT({
			jti: `sim-${this.index}-${++this.counter}-${this.host.serverNowMs()}-xxxx`,
		})
			.setProtectedHeader({ alg: "ES256", typ: "device-assertion+jwt", kid: this.kid })
			.setIssuer(this.id)
			.setSubject(this.id)
			.setAudience(this.host.audience)
			.setIssuedAt(iat)
			.setExpirationTime(iat + lifetimeSeconds)
			.sign(this.privateKey);
	}

	/** Ask the server for a decision (needs the network). */
	async authorize(
		action: string,
		resource: string,
	): Promise<{ status: number; allowed: boolean; code?: string }> {
		const res = await this.call("/device/authorize", {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${await this.assertion()}`,
			},
			body: JSON.stringify({ action, resource }),
		});
		if (res.status === 401) return { status: 401, allowed: false };
		const body = (await res.json()) as { data?: { allowed: boolean; code?: string } };
		return { status: res.status, allowed: body.data?.allowed === true, code: body.data?.code };
	}

	/** Fetch a fresh bundle and snapshot (needs the network). Stored but not verified yet. */
	async fetchBundle(): Promise<{ status: number }> {
		const res = await this.call("/device/bundle", {
			method: "GET",
			headers: { authorization: `Bearer ${await this.assertion()}` },
		});
		if (res.status === 200) {
			const body = (await res.json()) as {
				data: { token: string; revocations?: { token: string } };
			};
			this.bundleToken = body.data.token;
			this.snapshotToken = body.data.revocations?.token;
		}
		return { status: res.status };
	}

	/**
	 * Verify the stored bundle the way a device must: with its own clock, the last accepted sequence numbers, and the revocation snapshot. On success the sequence numbers move forward.
	 */
	async verifyBundle(maxSnapshotAgeSeconds = 3600) {
		if (!this.bundleToken)
			return { ok: false as const, reason: "invalid" as const, message: "No bundle" };
		const result = await verifyDeviceBundle(this.bundleToken, {
			keys: this.host.jwks(),
			deviceId: this.id,
			issuer: this.host.issuer,
			now: new Date(this.nowMs()),
			...(this.lastSeq !== undefined && { lastSeq: this.lastSeq }),
			revocations: {
				token: this.snapshotToken,
				maxAgeSeconds: maxSnapshotAgeSeconds,
				...(this.lastSnapshotSeq !== undefined && { lastSeq: this.lastSnapshotSeq }),
			},
		});
		if (result.ok) {
			this.claims = result.claims;
			this.lastSeq = result.claims.seq;
			if (result.revocations) this.lastSnapshotSeq = result.revocations.seq;
		}
		return result;
	}

	/** Decide with no network: verify the stored bundle again, then evaluate. Unverifiable means denied. */
	async decideOffline(
		action: string,
		resource: string,
		maxSnapshotAgeSeconds = 3600,
	): Promise<OfflineDecision> {
		// The stored bundle has the same seq as the last accepted one, which rollback protection allows.
		const verified = await this.verifyBundle(maxSnapshotAgeSeconds);
		if (!verified.ok) {
			return {
				allowed: false,
				code: DECISION_CODES.DEVICE_EXPIRED,
				reason: verified.message,
				verified: false,
			};
		}
		return {
			...evaluateDeviceBundle(verified.claims, {
				action,
				resource,
				now: new Date(this.nowMs()),
			}),
			verified: true,
		};
	}

	private call(path: string, init: RequestInit): Promise<Response> {
		if (!this.state.online) return Promise.reject(new DeviceOfflineError());
		// The handler rate limits per client key. Each simulated device gets its own, like a device on its own address.
		const headers = new Headers(init.headers);
		headers.set(FLEET_KEY_HEADER, `sim-${this.index}`);
		return this.host.send(path, { ...init, headers });
	}
}
