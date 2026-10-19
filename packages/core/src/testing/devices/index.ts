/**
 * Device conformance kit and fleet simulator. Import from `@glinr/theauth/testing/devices`.
 * Simulates N devices (enroll, assert, fetch bundle and revocation snapshot, offline and online,
 * clock skew, revoke mid session) against the real HTTP handler with a deterministic clock.
 * Nothing here imports vitest or jest.
 */

export type { VirtualClock } from "./clock.js";
export { createVirtualClock, DEFAULT_START_MS } from "./clock.js";
export type { ConformanceReport, ScenarioResult } from "./conformance.js";
export {
	assertionScenario,
	bundleScenario,
	clockSkewScenario,
	enrollmentScenario,
	offlineScenario,
	revocationScenario,
	rollbackScenario,
	runDeviceConformance,
} from "./conformance.js";
export type { DeviceHost, DeviceState, OfflineDecision } from "./device.js";
export { DeviceOfflineError, SimulatedDevice } from "./device.js";
export type { DeviceFleet, DeviceFleetOptions } from "./fleet.js";
export { createDeviceFleet } from "./fleet.js";
export type { LatencySummary, MemorySample } from "./stats.js";
export { LatencyRecorder, percentile, sampleMemory, summarize } from "./stats.js";
