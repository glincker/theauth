/**
 * `sharedSignals()` plugin: mounts the SSF transmitter and/or receiver.
 */

import type { TheAuthPlugin } from "../plugin/types.js";
import type { EmissionBridge } from "./emitters.js";
import { createEmissionBridge } from "./emitters.js";
import type { Receiver, ReceiverConfig } from "./receiver.js";
import { createReceiver } from "./receiver.js";
import type { DefaultHandlersOptions } from "./receiver-defaults.js";
import { createDefaultHandlers } from "./receiver-defaults.js";
import type { EmitInput, EmitResult, Transmitter, TransmitterConfig } from "./transmitter.js";
import { createTransmitter } from "./transmitter.js";
import { createTransmitterEndpoints } from "./transmitter-endpoints.js";
import type { SubjectIdentifier } from "./types.js";

export interface SharedSignalsConfig {
	transmitter?: Omit<TransmitterConfig, "db">;
	receiver?: ReceiverConfig & {
		/** Path the push endpoint is mounted at. Default `/ssf/receive`. */
		path?: string;
		/**
		 * Revoke local sessions on session-revoked, sessions-revoked and
		 * account-disabled. Default true when a session manager is configured.
		 */
		revokeSessions?: boolean;
		resolveUserId?: DefaultHandlersOptions["resolveUserId"];
		onRevoked?: DefaultHandlersOptions["onRevoked"];
	};
	/** Subject for a local user when emitting from the hooks. Default `iss_sub`. */
	subjectForUser?: (userId: string) => SubjectIdentifier | Promise<SubjectIdentifier>;
}

export interface SharedSignalsPlugin extends TheAuthPlugin {
	/** Emit an event to matching streams. No-op result before init or without a transmitter. */
	emit(input: EmitInput): Promise<EmitResult>;
	/** Callbacks to pass into session, admin, password reset, TOTP and passkey configs. */
	readonly bridge: EmissionBridge;
	/** Set after init. */
	readonly transmitter: Transmitter | null;
	readonly receiver: Receiver | null;
}

export function sharedSignals(config: SharedSignalsConfig): SharedSignalsPlugin {
	let transmitter: Transmitter | null = null;
	let receiver: Receiver | null = null;

	const emit = async (input: EmitInput): Promise<EmitResult> =>
		transmitter ? transmitter.emit(input) : { queued: [] };

	const issuer = config.transmitter?.issuer ?? config.receiver?.issuer ?? "";
	const bridge = createEmissionBridge({
		emit,
		issuer,
		...(config.subjectForUser ? { subjectForUser: config.subjectForUser } : {}),
	});

	return {
		id: "theauth-shared-signals",
		bridge,
		emit,
		get transmitter(): Transmitter | null {
			return transmitter;
		},
		get receiver(): Receiver | null {
			return receiver;
		},

		async init(ctx): Promise<undefined> {
			if (!config.transmitter && !config.receiver) {
				throw new Error("sharedSignals needs a transmitter, a receiver, or both.");
			}
			if (config.transmitter) {
				transmitter = createTransmitter({ ...config.transmitter, db: ctx.db });
				for (const endpoint of createTransmitterEndpoints(transmitter)) ctx.addEndpoint(endpoint);
			}
			if (config.receiver) {
				const { path, revokeSessions, resolveUserId, onRevoked, ...receiverConfig } =
					config.receiver;
				const defaults =
					revokeSessions !== false && ctx.sessionManager
						? createDefaultHandlers({
								sessionManager: ctx.sessionManager,
								issuer: receiverConfig.issuer,
								db: ctx.db,
								...(resolveUserId ? { resolveUserId } : {}),
								...(onRevoked ? { onRevoked } : {}),
							})
						: {};
				receiver = createReceiver({
					...receiverConfig,
					// Explicit handlers win over the defaults.
					handlers: { ...defaults, ...(receiverConfig.handlers ?? {}) },
				});
				const active = receiver;
				ctx.addEndpoint({
					method: "POST",
					path: path ?? "/ssf/receive",
					metadata: {
						rateLimit: { window: 60, max: 600 },
						description: "SSF push delivery receiver (RFC 8935)",
					},
					handler: (request) => active.handleRequest(request),
				});
			}
			return undefined;
		},
	};
}
