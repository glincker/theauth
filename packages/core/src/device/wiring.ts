import type { TheAuthConfig } from "../types.js";
import type { DeviceModuleDeps } from "./module.js";
import { createDeviceModule } from "./module.js";

/** `theauth.device`: null unless both `devices` and `agents` are configured (devices are backed by agent rows). */
export function createConfiguredDeviceModule(
	config: TheAuthConfig,
	deps: Omit<DeviceModuleDeps, "config">,
): ReturnType<typeof createDeviceModule> | null {
	if (!config.devices) return null;
	if (!config.agents) {
		throw new Error(
			"TheAuth: `devices` needs `agents` to be configured, devices are backed by agent rows.",
		);
	}
	return createDeviceModule({ ...deps, config: config.devices });
}
