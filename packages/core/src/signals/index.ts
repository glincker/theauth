/**
 * OpenID Shared Signals Framework 1.0 with CAEP and RISC events.
 * - `signSet` / `verifySet`: Security Event Tokens (RFC 8417)
 * - `createTransmitter` and `createTransmitterEndpoints`: SSF transmitter
 * - `createReceiver`: SET verification, replay cache and handlers
 * - `sharedSignals`: plugin that mounts either or both
 */

export { backoffMs, pushSet, validateDeliveryUrl } from "./delivery.js";
export type { EmissionBridge, EmissionBridgeOptions } from "./emitters.js";
export { createEmissionBridge } from "./emitters.js";
export type { BuiltEvent } from "./events.js";
export { events } from "./events.js";
export type { SharedSignalsConfig, SharedSignalsPlugin } from "./plugin.js";
export { sharedSignals } from "./plugin.js";
export type {
	EventHandler,
	ReceivedEvent,
	ReceiveOutcome,
	ReceiveResult,
	Receiver,
	ReceiverConfig,
} from "./receiver.js";
export { createReceiver } from "./receiver.js";
export type { DefaultHandlersOptions } from "./receiver-defaults.js";
export { createDefaultHandlers } from "./receiver-defaults.js";
export type { SigningKey, SignSetParams, VerifyKey, VerifySetOptions } from "./set.js";
export { signSet, verifySet } from "./set.js";
export type { SignalsStore } from "./store.js";
export { createSignalsStore } from "./store.js";
export { candidateKeys, parseSubject, subjectKey } from "./subjects.js";
export type {
	CreateStreamInput,
	EmitInput,
	EmitResult,
	Transmitter,
	TransmitterConfig,
	TransmitterDeliveryConfig,
} from "./transmitter.js";
export { createTransmitter } from "./transmitter.js";
export { createTransmitterEndpoints } from "./transmitter-endpoints.js";
export * from "./types.js";
