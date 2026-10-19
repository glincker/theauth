import type { DecisionCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { Device } from "./types.js";

/** The marker every device audit row carries in `parameters`. Reserved key, so arguments cannot forge it. */
export function devicePrincipal(deviceId: string): Record<string, unknown> {
	return { theauthPrincipal: { type: "device", id: deviceId } };
}

/** Device level state that blocks a decision before permissions are looked at, or null. */
export function deviceBlock(device: Pick<Device, "status" | "expiresAt">): DecisionCode | null {
	if (device.status === "revoked") return DECISION_CODES.DEVICE_REVOKED;
	if (device.status === "suspended") return DECISION_CODES.DEVICE_SUSPENDED;
	if (device.expiresAt && device.expiresAt.getTime() <= Date.now())
		return DECISION_CODES.DEVICE_EXPIRED;
	return null;
}
