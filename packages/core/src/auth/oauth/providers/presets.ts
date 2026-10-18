/** Preset OAuth provider configs. Each factory takes `(clientId, clientSecret)` and returns a config for `genericOIDC`, or a plain provider with explicit endpoints (no discovery call). */

import type { GenericOIDCConfig } from "./generic.js";

export * from "./presets-consumer.js";
export * from "./presets-platform.js";
export type { GenericOIDCConfig };
