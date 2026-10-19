import { recordAuditEvent } from "../audit/record.js";
import type { Database } from "../db/database.js";
import { singleUseFor } from "../db/store/for-database.js";
import { DECISION_CODES } from "../permission/codes.js";
import { verifyAppleAssertion } from "./attestation/apple-assertion.js";
import type { DeviceRegistry } from "./registry.js";
import { deviceBlock, devicePrincipal } from "./state.js";
import type { Device } from "./types.js";

export type DeviceAppAssertionFailure =
	| "device_not_found"
	| "device_blocked"
	| "not_app_attest"
	| "nonce_invalid"
	| "assertion_invalid"
	| "assertion_replayed";

export type DeviceAppAssertionResult =
	| { ok: true; device: Device; counter: number }
	| { ok: false; code: DeviceAppAssertionFailure; message: string };

export interface DeviceAppAssertionInput {
	/** The assertion object from `DCAppAttestService.generateAssertion`, base64 or base64url. */
	assertion: string;
	/** The exact bytes the app hashed into `clientDataHash`. It must contain the nonce. */
	clientData: string;
	/** A nonce from `device.attestationNonce()`. Single use. Required unless `devices.attestation.requireNonce` is false. */
	nonce?: string;
}

interface Deps {
	db: Database;
	registry: DeviceRegistry;
	spendNonce(nonce: string): Promise<boolean>;
	requireNonce: boolean;
}

/**
 * Verify an Apple App Attest assertion from an enrolled device (see `verifyAppleAssertion`). The key and App ID come from the claims stored at enrollment (`attestedPublicKey`, `appId`), the counter from `theauth_devices.app_attest_counter`. The counter moves forward with one conditional UPDATE after the signature checks, so two requests with the same assertion cannot both succeed.
 */
export function createDeviceAppAssertion(deps: Deps) {
	const { db, registry } = deps;

	async function refused(device: Device, code: DeviceAppAssertionFailure, message: string) {
		await recordAuditEvent(db, {
			agentId: device.agentId,
			userId: device.ownerId,
			action: "device.app_assertion.refused",
			resource: `device:${device.id}`,
			result: "denied",
			reason: message,
			decisionCode: DECISION_CODES.NO_PERMISSION,
			parameters: { code, ...devicePrincipal(device.id) },
		}).catch(() => {});
		return { ok: false as const, code, message };
	}

	return async function verifyAppAssertion(
		deviceId: string,
		input: DeviceAppAssertionInput,
	): Promise<DeviceAppAssertionResult> {
		const row = await registry.getRow(deviceId);
		if (!row) return { ok: false, code: "device_not_found", message: "Device not found" };
		const device = await registry.toDevice(row);
		if (deviceBlock(device)) {
			return { ok: false, code: "device_blocked", message: `Device is ${device.status}` };
		}
		const claims = device.attestation;
		const appId = claims?.appId;
		const publicKey = claims?.attestedPublicKey;
		if (
			claims?.format !== "apple-app-attest" ||
			typeof appId !== "string" ||
			typeof publicKey !== "string"
		) {
			return await refused(
				device,
				"not_app_attest",
				"Device has no App Attest key (it enrolled without Apple evidence, or before attestedPublicKey was stored)",
			);
		}
		if (input.nonce === undefined && deps.requireNonce) {
			return await refused(device, "nonce_invalid", "Assertion needs a nonce");
		}
		if (input.nonce !== undefined && !input.clientData.includes(input.nonce)) {
			return await refused(device, "nonce_invalid", "Client data does not contain the nonce");
		}
		const result = await verifyAppleAssertion({
			assertion: input.assertion,
			clientData: input.clientData,
			appId,
			publicKey,
			previousCounter: row.appAttestCounter,
		});
		if (!result.ok) {
			const replay = result.reason === "Assertion counter did not increase";
			return await refused(
				device,
				replay ? "assertion_replayed" : "assertion_invalid",
				result.reason,
			);
		}
		if (input.nonce !== undefined && !(await deps.spendNonce(input.nonce))) {
			return await refused(device, "nonce_invalid", "Nonce is unknown, expired or used");
		}
		// The one writer that moves the counter forward wins. A concurrent request with the same counter finds it already raised.
		const advanced = await singleUseFor(db).devices.advanceAppAttestCounter(
			device.id,
			result.counter,
		);
		if (!advanced) {
			return await refused(device, "assertion_replayed", "Assertion counter did not increase");
		}
		return { ok: true, device, counter: result.counter };
	};
}
