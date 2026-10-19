import type { JWK } from "jose";
import type { SecondaryStorage } from "../storage/types.js";
import {
	isDevicePsk,
	normalizeX509Thumbprint,
	peekAssertion,
	pskLookup,
	pskMatches,
	verifyDeviceAssertion,
} from "./credentials.js";
import type { DeviceRegistry } from "./registry.js";
import { nowSec } from "./registry.js";
import { deviceBlock } from "./state.js";
import type { DeviceAuthResult, DeviceConfig, DevicePresentation } from "./types.js";

interface AuthDeps {
	registry: DeviceRegistry;
	storage: SecondaryStorage;
	config: DeviceConfig;
}

const BAD: DeviceAuthResult = {
	ok: false,
	code: "invalid_credential",
	message: "Device credential is invalid",
};

/** Read how a device proved itself: `Authorization: Bearer tdk_...` (PSK), a bearer JWT (assertion), or the host supplied certificate thumbprint. */
export async function devicePresentationOf(
	request: Request,
	config: DeviceConfig,
): Promise<DevicePresentation | null> {
	const header = request.headers.get("authorization") ?? "";
	const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
	const token = match?.[1];
	if (token) {
		if (isDevicePsk(token)) return { kind: "psk", secret: token };
		if (token.split(".").length === 3) return { kind: "assertion", jwt: token };
		return null;
	}
	if (config.clientCertThumbprint) {
		const thumbprint = await config.clientCertThumbprint(request);
		if (thumbprint) return { kind: "x509", thumbprint };
	}
	return null;
}

export function createDeviceAuthenticator(deps: AuthDeps) {
	const { registry, storage, config } = deps;

	/**
	 * Authenticate a device credential. Every credential problem answers the same `invalid_credential` so a caller cannot probe which ids or keys exist; only a known device in a blocking state, and assertion replay, get their own codes.
	 */
	async function authenticate(
		presentation: DevicePresentation,
		context: { ip?: string } = {},
	): Promise<DeviceAuthResult> {
		let row: Awaited<ReturnType<DeviceRegistry["findCredential"]>> = null;
		if (presentation.kind === "psk") {
			if (!isDevicePsk(presentation.secret)) return BAD;
			row = await registry.findCredential("psk", pskLookup(presentation.secret));
			if (!row?.secretHash || !(await pskMatches(presentation.secret, row.secretHash))) return BAD;
		} else if (presentation.kind === "x509") {
			const thumbprint = normalizeX509Thumbprint(presentation.thumbprint);
			if (!thumbprint) return BAD;
			row = await registry.findCredential("x509", thumbprint);
		} else {
			const peek = peekAssertion(presentation.jwt);
			if (!peek) return BAD;
			row = await registry.findCredential("jwk", peek.kid);
			if (!row || row.deviceId !== peek.iss || !row.publicJwk) return BAD;
		}
		if (row?.status !== "active") return BAD;
		if (row.expiresAt != null && row.expiresAt <= nowSec()) return BAD;

		const deviceRow = await registry.getRow(row.deviceId);
		if (!deviceRow) return BAD;

		// Signature first, so a caller holding only a public key id learns nothing about the device.
		if (presentation.kind === "assertion") {
			const check = await verifyDeviceAssertion({
				jwt: presentation.jwt,
				deviceId: deviceRow.id,
				publicJwk: row.publicJwk as JWK,
				audience: config.audience ?? "theauth",
				storage,
			});
			if (!check.ok) return { ok: false, code: check.code, message: check.message };
		}

		const device = await registry.toDevice(deviceRow);
		const blocked = deviceBlock(device);
		if (blocked) {
			return {
				ok: false,
				code: blocked as "device_suspended" | "device_revoked" | "device_expired",
				message: `Device is ${blocked.replace("device_", "")}`,
			};
		}

		await registry.touch(deviceRow, row.id, context.ip).catch(() => {});
		return { ok: true, device, credentialId: row.id };
	}

	async function authenticateRequest(
		request: Request,
		context: { ip?: string } = {},
	): Promise<DeviceAuthResult> {
		const presentation = await devicePresentationOf(request, config);
		if (!presentation) return BAD;
		return authenticate(presentation, context);
	}

	return { authenticate, authenticateRequest };
}
